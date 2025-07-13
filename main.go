package main

import (
	"compress/gzip"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/andreimerlescu/checkfs"
	"github.com/andreimerlescu/checkfs/file"
	"github.com/andreimerlescu/figtree/v2"
	"github.com/go-ini/ini"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const (
	Err404 = "Page Not Found"
	Err500 = "Internal Server Error"

	HeadAuthorization = "Authorization"
	HeadContentType   = "Content-Type"
	HeadUserAgent     = "User-Agent"
	HeadForwarded     = "X-Forwarded-For"
	BodyTypeJSON      = "application/json"

	SqlCreateTable string = `
		CREATE TABLE IF NOT EXISTS requests (
			ip TEXT PRIMARY KEY,
			count INTEGER,
			last_visit TEXT
		)
	`
	SqlIndexes string = `
		CREATE INDEX IF NOT EXISTS idx_hits_date ON hits(year, month, day);
		CREATE INDEX IF NOT EXISTS idx_requests_last_visit ON requests(last_visit);
	`
	SqlQueryFindHitsByYearMonth string = `
		SELECT year, month, SUM(hits) FROM hits GROUP BY year, month
	`
	SqlCreateHitsTable string = `
		CREATE TABLE IF NOT EXISTS hits (
			year INTEGER,
			month INTEGER,
			day INTEGER,
			hour INTEGER,
			minute INTEGER,
			hits INTEGER,
			PRIMARY KEY (year, month, day, hour, minute)
		)
	`
	SqlCreateHitSummaryTable string = `
		CREATE TABLE IF NOT EXISTS hit_summary (
			year INTEGER,
			month INTEGER,
			hits INTEGER,
			last_calculated_on TEXT,
			PRIMARY KEY (year, month)
		)
	`
	SqlFindLatest string = `
		SELECT count, last_visit 
		FROM requests 
		WHERE ip = ?
	`
	SqlNewRow string = `
		INSERT INTO requests (ip, count, last_visit) 
		VALUES (?, 1, ?)
	`
	SqlUpdateRow string = `
		UPDATE requests 
		SET count = ?, last_visit = ? 
		WHERE ip = ?
	`
	SqlNewHitSummary = `
		INSERT OR REPLACE INTO hit_summary 
			(year, month, hits, last_calculated_on) 
		VALUES (?, ?, ?, ?)
	`
	SqlFindTotalHits = `
		SELECT COALESCE(SUM(hits), 0) FROM hits
	`
	SqlFlushBatchBase = `
		INSERT INTO hits (year, month, day, hour, minute, hits) VALUES 
	`
	SqlFlushBatchSecond = `
		ON CONFLICT(year, month, day, hour, minute) DO UPDATE SET hits = hits + excluded.hits
    `
	TemplateBytesIndex = `
		<!DOCTYPE html>
		<html lang="en" aria-description="your internet protocol address finder">
			<head>
				<title>Your IP Address</title>
			</head>
			<body>
				<h1>Your IP Address</h1>
				<p>IPv4: {{.IPv4}}</p>
				<p>IPv6: {{.IPv6}}</p>
				<p>Visit Count: {{.VisitCount}}</p>
				<p>Last Visit: {{.LastVisit}}</p>
				<p>Total Hits: {{.TotalHits}}</p>
			</body>
		</html>
	`

	AppName     string = "dev.ishere.ip"
	kConfigFile string = "IP_CONFIG_FILE"

	argDomain               string = "domain"
	argPortSecure           string = "https"
	argPortUnsecure         string = "http"
	argCert                 string = "cert"
	argKey                  string = "key"
	argDatabase             string = "database"
	argConnections          string = "connections"
	argAdvanced             string = "advanced"
	argRateLimitEnabled     string = "ratelimit_enabled"
	argRateLimitWindow      string = "ratelimit_window_seconds"
	argRateLimitMaxRequests string = "ratelimit_max_requests"
	argRateLimitCleanup     string = "ratelimit_cleanup_seconds"
	argVersion              string = "version"
	argAliasVersion         string = "v"
	argAbout                string = "about"
	argAliasAbout           string = "a"
	argHitBatchSize         string = "hit_batch_size"
	argHitFlushInterval     string = "hit_flush_interval"
	argEnvironment          string = "environment"
	argEnableCSP            string = "enable-csp"
	argEnableCORS           string = "enable-cors"
	argEnablePrometheus     string = "enable-prometheus"
	argEnableHealth         string = "enable-health"
	argEnableStats          string = "enable-stats"
	argCspPolicy            string = "csp_policy"
	argCorsAllowedOrigins   string = "cors_allowed_origins"
	argCorsAllowedMethods   string = "cors_allowed_methods"
	argCorsAllowedHeaders   string = "cors_allowed_headers"
	argCorsExposedHeaders   string = "cors_exposed_headers"
	argCorsAllowCredentials string = "cors_allow_credentials"
	argCorsMaxAge           string = "cors_max_age"
	argEnableBackups        string = "backups"
	argBackupPath           string = "backup_path"
	argCompressBackup       string = "compress_backup"
	argEndpointHealth       string = "endpoint-health"
	argEndpointStats        string = "endpoint-stats"
	argEndpointReader       string = "endpoint-read"
	argEndpointMetrics      string = "endpoint-metrics"
	argShutdownTimeout      string = "shutdown_timeout"
	argRequestTimeout       string = "request_timeout"
	argTrustedProxies       string = "trusted-proxies"
)

type (
	IPData struct {
		IPv4       string
		IPv6       string
		VisitCount int
		LastVisit  string
		TotalHits  int64
	}
	IPResponse struct {
		IPv4 string `json:"ipv4"`
		IPv6 string `json:"ipv6"`
	}
	statusRecorder struct {
		http.ResponseWriter
		statusCode int
	}
	ErrRollback struct {
		Query string
		Err   error
	}
	ErrQuery struct {
		Query string
		Err   error
	}
	ErrDatabase struct {
		Action string
		Err    error
	}
	ErrCommit struct {
		Err error
	}
	RateLimitConfig struct {
		WindowSize    time.Duration
		MaxRequests   int
		CleanupPeriod time.Duration
		Enabled       bool
	}
	ClientRecord struct {
		Count     int
		Window    time.Time
		LastSeen  time.Time
		Blocked   bool
		BlockedAt time.Time
	}
	RateLimiter struct {
		clients map[string]*ClientRecord
		config  RateLimitConfig
		mu      sync.RWMutex
		stats   RateLimitStats
	}
	RateLimitStats struct {
		TotalRequests   int64
		BlockedRequests int64
		ActiveClients   int64
	}
)

var (
	//go:embed VERSION
	versionBytes embed.FS

	currentVersion  string
	figs            figtree.Plant
	rateLimiter     *RateLimiter
	hitChan         chan time.Time
	hitWG           sync.WaitGroup
	totalHitsCache  atomic.Int64
	logger          *zap.Logger
	maintenanceMode atomic.Int32
	indexTemplate   *template.Template
	requestsTotal   = promauto.NewCounter(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests",
	})
	hitsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "hits_total",
		Help: "Total hits recorded",
	})
	ignore = func(in any) {
		if in != nil {
			fmt.Printf("ignore(%s)", in)
		}
	}
	defaultTrustedProxies = []string{
		"127.0.0.1/32",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
)

func Version() string {
	if len(currentVersion) == 0 {
		versionBytes, err := versionBytes.ReadFile("VERSION")
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to read embedded VERSION file: %v", err.Error())
			return "v0.0.0"
		}
		currentVersion = strings.TrimSpace(string(versionBytes))
	}
	return currentVersion
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	renderErr := render()
	if renderErr != nil {
		log.Fatal(renderErr)
	}

	figs = figtree.With(figtree.Options{
		ConfigFile:        configFile(),
		Tracking:          false,
		Germinate:         false,
		IgnoreEnvironment: true,
	})
	figs = configure(figs)
	configErr := figs.Load()
	if configErr != nil {
		log.Fatal(configErr)
	}

	if *figs.Bool(argAbout) {
		about()
		os.Exit(0)
	}

	if *figs.Bool(argVersion) {
		fmt.Println(Version())
		os.Exit(0)
	}

	if strings.HasPrefix(*figs.String(argEnvironment), "prod") {
		logger, _ = zap.NewProduction()
	} else {
		logger, _ = zap.NewDevelopment()
	}

	defer func() {
		ignore(logger.Sync())
	}()

	// Initialize rate limiter
	rateLimitConfig := RateLimitConfig{
		WindowSize:    time.Duration(*figs.Int(argRateLimitWindow)) * time.Second,
		MaxRequests:   *figs.Int(argRateLimitMaxRequests),
		CleanupPeriod: time.Duration(*figs.Int(argRateLimitCleanup)) * time.Second,
		Enabled:       *figs.Bool(argRateLimitEnabled),
	}
	rateLimiter = NewRateLimiter(rateLimitConfig)

	databasePath := *figs.String(argDatabase)
	db, err := sql.Open("sqlite3", databasePath+"?_journal_mode=WAL")
	if err != nil {
		logger.Error(fmt.Sprintf("sql.Open(%s) failed with err", databasePath), zap.Error(err))
		log.Fatal(err)
	}
	defer func(db *sql.DB) {
		ignore(db.Close())
	}(db)
	connections := *figs.Int(argConnections)

	db.SetMaxOpenConns(connections)
	db.SetMaxIdleConns(connections)
	db.SetConnMaxLifetime(time.Duration(connections) * time.Second)

	msg := "db.Exec err: "

	_, err = db.Exec(SqlCreateTable)
	if err != nil {
		logger.Fatal(msg, zap.Error(err))
	}

	_, err = db.Exec(SqlCreateHitsTable)
	if err != nil {
		logger.Fatal(msg, zap.Error(err))
	}

	_, err = db.Exec(SqlCreateHitSummaryTable)
	if err != nil {
		logger.Fatal(msg, zap.Error(err))
	}

	_, err = db.Exec(SqlIndexes)
	if err != nil {
		logger.Fatal(msg, zap.Error(err))
	}

	hitChan = make(chan time.Time, 1000)
	go hitConsumer(ctx, db, hitChan)

	// update cache worker
	go func(ctx context.Context) {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				updateCache(db)
			}
		}
	}(ctx)

	// update summary worker
	go func(ctx context.Context) {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				updateSummary(db)
			}
		}
	}(ctx)

	// enable backups
	if *figs.Bool(argEnableBackups) {
		go scheduleBackups(ctx, db, databasePath, connections)()
	}

	// setup router
	wrappedMux := mux(figs, db)

	hasCert, hasKey, isSecure := false, false, false

	certFile := *figs.String(argCert)
	if err := checkfs.File(certFile, file.Options{Exists: true}); err != nil {
		logger.Warn("invalid TLS certificate provided: %v", zap.Error(err))
	} else {
		hasCert = true
	}

	keyFile := *figs.String(argKey)
	if err := checkfs.File(keyFile, file.Options{Exists: true, LessPermissiveThan: 0700}); err != nil {
		logger.Warn("invalid TLS certificate private key provided: %v", zap.Error(err))
	} else {
		hasKey = true
	}

	isSecure = hasCert && hasKey

	httpPort := fmt.Sprintf(":%d", *figs.Int(argPortUnsecure))
	httpsPort := fmt.Sprintf(":%d", *figs.Int(argPortSecure))

	if strings.EqualFold(httpPort, ":") || (isSecure && strings.EqualFold(httpsPort, ":")) {
		logger.Fatal(fmt.Sprintf("invalid http %s https %s provided", httpPort, httpsPort))
	}

	var httpServer, httpsServer *http.Server
	var httpHandler, httpsHandler http.Handler

	if isSecure {
		httpHandler = http.HandlerFunc(redirectToHTTPS)
		httpsHandler = wrappedMux
	} else {
		httpHandler = wrappedMux
		httpsHandler = wrappedMux
	}

	if isSecure {
		httpsServer = &http.Server{
			Addr:    httpsPort,
			Handler: httpsHandler,
		}
		go func() {
			log.Printf("Starting HTTPS server on %s", httpsPort)
			err := httpsServer.ListenAndServeTLS(certFile, keyFile)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("HTTPS server error: %v", err)
			}
		}()
	}

	httpServer = &http.Server{
		Addr:    httpPort,
		Handler: httpHandler,
	}
	go func() {
		log.Printf("Starting HTTP server on %s", httpPort)
		err := httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server error: %v", zap.Error(err))
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutdown signal received")

	close(hitChan)

	ctx2, cancel2 := context.WithTimeout(ctx, *figs.UnitDuration(argShutdownTimeout))
	defer cancel2()

	if err := httpServer.Shutdown(ctx2); err != nil {
		logger.Error("HTTP shutdown error: %v", zap.Error(err))
	}
	if err := httpsServer.Shutdown(ctx2); err != nil {
		logger.Error("HTTPS shutdown error: %v", zap.Error(err))
	}

	logger.Info("Shutdown complete")
}

func render() error {
	var err error
	indexTemplate, err = template.New("index").Parse(TemplateBytesIndex)
	return err
}

func mux(figs figtree.Plant, db *sql.DB) http.Handler {
	mux := http.NewServeMux()
	route := func(ext string) string {
		switch ext {
		case "json":
			return fmt.Sprintf("%s.json", *figs.String(argEndpointReader))
		case "yaml":
			return fmt.Sprintf("%s.yaml", *figs.String(argEndpointReader))
		case "ini":
			return fmt.Sprintf("%s.ini", *figs.String(argEndpointReader))
		default:
			return fmt.Sprintf("%s", *figs.String(argEndpointReader))
		}
	}
	mux.HandleFunc("/", rateLimitMiddleware(figs, GetIP(figs, db)))
	mux.HandleFunc(route(""), rateLimitMiddleware(figs, GetIP(figs, db)))
	mux.HandleFunc(route("json"), rateLimitMiddleware(figs, GetIP(figs, db)))
	mux.HandleFunc(route("yaml"), rateLimitMiddleware(figs, GetIP(figs, db)))
	mux.HandleFunc(route("ini"), rateLimitMiddleware(figs, GetIP(figs, db)))
	mux.HandleFunc(*figs.String(argEndpointStats), GetStats())
	mux.Handle(*figs.String(argEndpointMetrics), promhttp.Handler())
	mux.HandleFunc(*figs.String(argEndpointHealth), GetHealth(db))

	// Activate Maintenance Middleware
	wrappedMux := maintenanceMiddleware(mux)
	// Attach Request ID to each Request
	wrappedMux = requestIDMiddleware(wrappedMux)
	// Accept 30s timeout for Requests
	wrappedMux = timeoutMiddleware(wrappedMux)
	if *figs.Bool(argEnableCSP) {
		// Enable CSP Protections
		wrappedMux = cspMiddleware(wrappedMux)
	}
	if *figs.Bool(argEnableCORS) {
		// Enable CORS Protections
		wrappedMux = corsMiddleware(wrappedMux)
	}
	// Handle 404 Not Found Errors
	wrappedMux = wrapNotFound(wrappedMux)

	return wrappedMux
}

func GetIP(figs figtree.Plant, db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hitChan <- time.Now().UTC()
		requestsTotal.Inc()
		hitsTotal.Inc()

		var ipv4, ipv6 string
		if *figs.Bool(argAdvanced) {
			ipv4, ipv6 = getClientIPAdvanced(r)
		} else {
			ipv4, ipv6 = getClientIP(figs, r)
		}

		data, err := updateRequestTracking(db, ipv4, ipv6)
		if err != nil {
			w.Header().Set(HeadContentType, BodyTypeJSON)
			ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
			w.WriteHeader(http.StatusInternalServerError)
			logger.Error("Error updating request tracking: %v", zap.Error(err))
			return
		}

		data.TotalHits = totalHitsCache.Load()

		isCurl := strings.Contains(strings.ToLower(r.Header.Get(HeadUserAgent)), "curl")

		format := ""
		switch r.URL.Path {
		case "/", "/read":
			format = "html"
		case "/read.json":
			format = "json"
		case "/read.yaml":
			format = "yaml"
		case "/read.ini":
			format = "ini"
		default:
			http.NotFound(w, r)
			return
		}

		switch format {
		case "html":
			if isCurl {
				w.Header().Set(HeadContentType, "text/plain")
				_, _ = fmt.Fprintf(w, "IPv4: %s\nIPv6: %s\n", data.IPv4, data.IPv6)
			} else {
				w.Header().Set(HeadContentType, "text/html")
				tmpl := template.Must(template.New("index").Parse(TemplateBytesIndex))
				if err := tmpl.Execute(w, data); err != nil {
					w.Header().Set(HeadContentType, BodyTypeJSON)
					ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
					w.WriteHeader(http.StatusInternalServerError)
					logger.Error("Template execute error: %v", zap.Error(err))
				}
			}
			return
		case "json":
			w.Header().Set(HeadContentType, BodyTypeJSON)
			if err := json.NewEncoder(w).Encode(IPResponse{IPv4: data.IPv4, IPv6: data.IPv6}); err != nil {
				w.Header().Set(HeadContentType, BodyTypeJSON)
				ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
				w.WriteHeader(http.StatusInternalServerError)
				logger.Error("JSON encode error: %v", zap.Error(err))
			}
			return
		case "yaml":
			yamlBytes, err := yaml.Marshal(IPResponse{IPv4: data.IPv4, IPv6: data.IPv6})
			if err != nil {
				w.Header().Set(HeadContentType, BodyTypeJSON)
				ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
				w.WriteHeader(http.StatusInternalServerError)
				logger.Error("YAML marshal error: %v", zap.Error(err))
				return
			}
			w.Header().Set(HeadContentType, "application/x-yaml")
			if _, err := w.Write(yamlBytes); err != nil {
				logger.Error("Write error: %v", zap.Error(err))
			}
			return
		case "ini":
			cfg := ini.Empty()
			sec, err := cfg.NewSection("ip")
			if err != nil {
				w.Header().Set(HeadContentType, BodyTypeJSON)
				ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
				w.WriteHeader(http.StatusInternalServerError)
				logger.Error("INI section error: %v", zap.Error(err))
				return
			}
			if _, err := sec.NewKey("ipv4", data.IPv4); err != nil {
				w.Header().Set(HeadContentType, BodyTypeJSON)
				ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
				w.WriteHeader(http.StatusInternalServerError)
				logger.Error("INI key error: %v", zap.Error(err))
				return
			}
			if _, err := sec.NewKey("ipv6", data.IPv6); err != nil {
				w.Header().Set(HeadContentType, BodyTypeJSON)
				ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
				w.WriteHeader(http.StatusInternalServerError)
				logger.Error("INI key error: %v", zap.Error(err))
				return
			}
			w.Header().Set(HeadContentType, "text/plain")
			if _, err := cfg.WriteTo(w); err != nil {
				w.Header().Set(HeadContentType, BodyTypeJSON)
				ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
				w.WriteHeader(http.StatusInternalServerError)
				logger.Error("INI write error: %v", zap.Error(err))
			}
			return
		}

		w.Header().Set(HeadContentType, "text/html")
		errExec := indexTemplate.Execute(w, data)
		if errExec != nil {
			http.Error(w, Err500, http.StatusInternalServerError)
			log.Printf("Error rendering template: %v", errExec)
			return
		}
	}
}

func GetHealth(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := db.Ping(); err != nil {
			http.Error(w, "Database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set(HeadContentType, "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "OK")
	}
}

func GetStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats := rateLimiter.GetStats()

		response := map[string]interface{}{
			"rate_limiting": map[string]interface{}{
				"enabled":          rateLimiter.config.Enabled,
				"window_seconds":   int(rateLimiter.config.WindowSize.Seconds()),
				"max_requests":     rateLimiter.config.MaxRequests,
				"cleanup_seconds":  int(rateLimiter.config.CleanupPeriod.Seconds()),
				"total_requests":   stats.TotalRequests,
				"blocked_requests": stats.BlockedRequests,
				"active_clients":   stats.ActiveClients,
			},
		}

		w.Header().Set(HeadContentType, BodyTypeJSON)
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			http.Error(w, "error encoding json", http.StatusInternalServerError)
		}
	}
}

func scheduleBackups(ctx context.Context, db *sql.DB, databasePath string, connections int) func() {
	return func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				backupPath := *figs.String("backup_path")
				maintenanceMode.Store(1)
				close(hitChan)
				hitWG.Wait()
				if err := db.Close(); err != nil {
					logger.Error("Failed to close DB for backup", zap.Error(err))
				}
				if err := copyFile(databasePath, backupPath); err != nil {
					logger.Error("DB file copy failed", zap.Error(err))
				} else {
					if err := gzipFile(backupPath); err != nil {
						logger.Error("DB backup compression failed", zap.Error(err))
					}
				}
				var err error
				db, err = sql.Open("sqlite3", databasePath+"?_journal_mode=WAL")
				if err != nil {
					logger.Fatal("Failed to reopen DB after backup", zap.Error(err))
				}
				db.SetMaxOpenConns(connections)
				db.SetMaxIdleConns(connections)
				db.SetConnMaxLifetime(time.Duration(connections) * time.Second)
				if _, err = db.Exec(SqlCreateTable); err != nil {
					logger.Fatal("Re-create table failed", zap.Error(err))
				}
				if _, err = db.Exec(SqlCreateHitsTable); err != nil {
					logger.Fatal("Re-create hits table failed", zap.Error(err))
				}
				if _, err = db.Exec(SqlCreateHitSummaryTable); err != nil {
					logger.Fatal("Re-create summary table failed", zap.Error(err))
				}
				if _, err = db.Exec(SqlIndexes); err != nil {
					logger.Fatal("Re-create indexes failed", zap.Error(err))
				}
				hitChan = make(chan time.Time, 1000)
				hitWG.Add(1)
				go hitConsumer(ctx, db, hitChan)
				maintenanceMode.Store(0)
				logger.Info("DB backup completed", zap.String("path", backupPath+".gz"))
			}
		}
	}
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := uuid.New().String()[:8] // Short UUID
		ctx := context.WithValue(r.Context(), "reqID", reqID)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", reqID)
		next.ServeHTTP(w, r)
	})
}

func trustedProxies(figs figtree.Plant) (o []*net.IPNet) {
	proxies := *figs.List(argTrustedProxies)
	if proxies == nil || len(proxies) == 0 {
		return
	}
	results := make([]*net.IPNet, len(proxies))
	for _, proxy := range proxies {
		result, err := parseCIDR(proxy)
		if err != nil {
			logger.Error("parseCIDR() threw %v", zap.Error(err))
			continue
		}
		results = append(results, result)
	}
	return results
}

func rateLimitMiddleware(figs figtree.Plant, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ipv4, ipv6 string
		if *figs.Bool(argAdvanced) {
			ipv4, ipv6 = getClientIPAdvanced(r)
		} else {
			ipv4, ipv6 = getClientIP(figs, r)
		}

		clientIP := ipv4
		if clientIP == "" {
			clientIP = ipv6
		}

		if clientIP != "" && !rateLimiter.IsAllowed(clientIP) {
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rateLimiter.config.MaxRequests))
			w.Header().Set("X-RateLimit-Window", fmt.Sprintf("%d", int(rateLimiter.config.WindowSize.Seconds())))
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(rateLimiter.config.WindowSize.Seconds())))

			w.Header().Set(HeadContentType, BodyTypeJSON)
			err := json.NewEncoder(w).Encode(map[string]string{"error": "429"})
			if err != nil {
				logger.Warn("json encode err: %v", zap.Error(err))
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			}
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *statusRecorder) Write(p []byte) (int, error) {
	if rec.statusCode == http.StatusNotFound {
		return len(p), nil
	}
	return rec.ResponseWriter.Write(p)
}

func wrapNotFound(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.statusCode == http.StatusNotFound {
			w.Header().Set(HeadContentType, "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintln(w, Err404)
		}
	})
}

func timeoutMiddleware(next http.Handler) http.Handler {
	return http.TimeoutHandler(next, *figs.Duration(argRequestTimeout)*time.Millisecond, "Request timed out")
}

func parseCIDR(cidr string) (*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return ipnet, nil
}

func isTrustedProxy(figs figtree.Plant, ip net.IP) bool {
	proxies := trustedProxies(figs)
	if proxies == nil {
		return false
	}
	for _, trustedNet := range proxies {
		if trustedNet == nil {
			continue
		}
		if trustedNet.Contains(ip) {
			return true
		}
	}
	return false
}

func getClientIP(figs figtree.Plant, r *http.Request) (string, string) {
	// Get the direct connection IP
	remoteAddr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = host
	}

	remoteIP := net.ParseIP(remoteAddr)
	if remoteIP == nil {
		return remoteAddr, "" // fallback to original if parsing fails
	}

	var ipv4, ipv6 string

	// If direct connection is not from trusted proxy, use it directly
	if !isTrustedProxy(figs, remoteIP) {
		if remoteIP.To4() != nil {
			ipv4 = remoteAddr
		} else {
			ipv6 = remoteAddr
		}
		if len(ipv4) != 0 && len(ipv6) != 0 {
			return ipv4, ipv6
		}
	}

	// Helper function to extract IPv4 and IPv6 from IP list
	extractIPs := func(ips []string) (string, string) {
		var v4, v6 string

		// Process from rightmost (most reliable) to leftmost
		for i := len(ips) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(ips[i])
			if parsedIP := net.ParseIP(ip); parsedIP != nil && !isTrustedProxy(figs, parsedIP) {
				if parsedIP.To4() != nil {
					if v4 == "" { // Only set if not already found
						v4 = ip
					}
				} else {
					if v6 == "" { // Only set if not already found
						v6 = ip
					}
				}
			}
		}
		return v4, v6
	}

	// Check X-Forwarded-For header (use rightmost IP as most reliable)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if v4, v6 := extractIPs(ips); v4 != "" || v6 != "" {
			return v4, v6
		}
	}

	// Check X-Real-IP header (only if set by trusted proxy)
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if parsedIP := net.ParseIP(realIP); parsedIP != nil {
			if parsedIP.To4() != nil {
				return realIP, ""
			} else {
				return "", realIP
			}
		}
	}

	// Fallback to remote address
	if remoteIP.To4() != nil {
		return remoteAddr, ""
	} else {
		return "", remoteAddr
	}
}

func getClientIPAdvanced(r *http.Request) (ipv4, ipv6 string) {
	// Check common forwarded headers in order of preference
	headers := []string{
		"CF-Connecting-IP",    // Cloudflare
		"X-Real-IP",           // Nginx
		HeadForwarded,         // Standard
		"X-Client-IP",         // Apache
		"X-Cluster-Client-IP", // Cluster
	}

	for _, header := range headers {
		value := r.Header.Get(header)
		if value != "" {
			// Handle comma-separated IPs (X-Forwarded-For can have multiple)
			ips := strings.Split(value, ",")
			for _, ip := range ips {
				ip = strings.TrimSpace(ip)
				if parsedIP := net.ParseIP(ip); parsedIP != nil {
					if parsedIP.To4() != nil {
						// IPv4 address
						if ipv4 == "" {
							ipv4 = ip
						}
					} else {
						// IPv6 address
						if ipv6 == "" {
							// Check if it's an IPv4-mapped IPv6 address
							if parsedIP.To4() != nil {
								ipv4 = parsedIP.To4().String()
							} else {
								ipv6 = ip
							}
						}
					}
				}
			}
		}
	}

	// If we still don't have IPs, try RemoteAddr
	if ipv4 == "" && ipv6 == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// If SplitHostPort fails, try parsing the whole thing as IP
			host = r.RemoteAddr
		}

		if parsedIP := net.ParseIP(host); parsedIP != nil {
			if parsedIP.To4() != nil {
				ipv4 = host
			} else {
				// Check if it's an IPv4-mapped IPv6 address
				if parsedIP.To4() != nil {
					ipv4 = parsedIP.To4().String()
				} else {
					ipv6 = host
				}
			}
		}
	}

	return ipv4, ipv6
}

func updateRequestTracking(db *sql.DB, ipv4, ipv6 string) (IPData, error) {
	data := IPData{IPv4: ipv4, IPv6: ipv6}
	ip := ipv4
	if ip == "" {
		ip = ipv6
	}
	if ip == "" {
		return data, nil
	}

	if parsedIP := net.ParseIP(ip); parsedIP != nil {
		ip = parsedIP.String()
	}

	tx, err := db.Begin()
	if err != nil {
		return data, ErrDatabase{"db.Begin()", err}
	}

	var count int
	var lastVisit string
	err = tx.QueryRow(SqlFindLatest, ip).Scan(&count, &lastVisit)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.Exec(SqlNewRow, ip, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			errRollback := tx.Rollback()
			if errRollback != nil {
				return data, ErrRollback{SqlNewRow, errRollback}
			}
			return data, ErrQuery{SqlNewRow, err}
		}
		data.VisitCount = 1
		data.LastVisit = time.Now().UTC().Format(time.RFC3339)
	} else if err == nil {
		count++
		_, err = tx.Exec(SqlUpdateRow, count, time.Now().UTC().Format(time.RFC3339), ip)
		if err != nil {
			errRollback := tx.Rollback()
			if errRollback != nil {
				return data, ErrRollback{SqlUpdateRow, errRollback}
			}
			return data, ErrQuery{SqlUpdateRow, err}
		}
		data.VisitCount = count
		data.LastVisit = lastVisit
	} else {
		errRollback := tx.Rollback()
		if errRollback != nil {
			return data, ErrRollback{SqlFindLatest, errRollback}
		}
		return data, ErrQuery{SqlFindLatest, err}
	}

	errCommit := tx.Commit()
	if errCommit != nil {
		return data, ErrCommit{err}
	}
	return data, nil
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
}

func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string]*ClientRecord),
		config:  config,
	}

	// Start cleanup goroutine
	go rl.cleanupRoutine()

	return rl
}

func (rl *RateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(rl.config.CleanupPeriod)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanup()
	}
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.config.CleanupPeriod * 2) // Keep records for 2x cleanup period

	for ip, record := range rl.clients {
		if record.LastSeen.Before(cutoff) {
			delete(rl.clients, ip)
		}
	}
}

func (rl *RateLimiter) IsAllowed(ip string) bool {
	if !rl.config.Enabled {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Update stats
	atomic.AddInt64(&rl.stats.TotalRequests, 1)
	atomic.StoreInt64(&rl.stats.ActiveClients, int64(len(rl.clients)))

	record, exists := rl.clients[ip]
	if !exists {
		record = &ClientRecord{
			Count:    1,
			Window:   now,
			LastSeen: now,
		}
		rl.clients[ip] = record
		return true
	}

	record.LastSeen = now

	// Check if we need to reset the window
	if now.Sub(record.Window) >= rl.config.WindowSize {
		record.Count = 1
		record.Window = now
		record.Blocked = false
		return true
	}

	record.Count++

	// Check if limit exceeded
	if record.Count > rl.config.MaxRequests {
		if !record.Blocked {
			record.Blocked = true
			record.BlockedAt = now

			// Update blocked stats
			atomic.AddInt64(&rl.stats.BlockedRequests, 1)

			log.Printf("Rate limit exceeded for IP: %s (count: %d)", ip, record.Count)
		}
		return false
	}

	return true
}

func (rl *RateLimiter) GetStats() RateLimitStats {
	return RateLimitStats{
		TotalRequests:   atomic.LoadInt64(&rl.stats.TotalRequests),
		BlockedRequests: atomic.LoadInt64(&rl.stats.BlockedRequests),
		ActiveClients:   atomic.LoadInt64(&rl.stats.ActiveClients),
	}
}

func about() {
	fmt.Printf("%s %s\n", AppName, Version())
	domain := fmt.Sprintf("https://%s", *figs.String(argDomain))
	format := "\t%s%s%s\n"
	fmt.Printf("%s\n", "CURL Usage:")
	fmt.Printf("\t%s%s\n", `curl -s -L `, domain)
	fmt.Printf(format, `curl -sL`, domain, `/read.ini`)
	fmt.Printf(format, `curl -sL `, domain, `/read.json`)
	fmt.Printf(format, `curl -sL `, domain, `/read.yaml`)
	fmt.Printf(format, `curl -sL `, domain, `/read.json | jq -r '.ipv4'`)
	fmt.Printf(format, `curl -sL `, domain, ` | grep IPv4 | awk '{print $2}'`)
	fmt.Println("")
}

func hitConsumer(ctx context.Context, db *sql.DB, ch chan time.Time) {
	batchSize := *figs.Int(argHitBatchSize)
	flushInterval := *figs.UnitDuration(argHitFlushInterval)

	var batch []time.Time
	timer := time.NewTimer(flushInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case t, ok := <-ch:
			if !ok {
				if len(batch) > 0 {
					flushBatch(db, batch)
				}
				return
			}
			batch = append(batch, t)
			if len(batch) >= batchSize {
				flushBatch(db, batch)
				batch = batch[:0]
				timer.Reset(flushInterval)
			}
		case <-timer.C:
			if len(batch) > 0 {
				flushBatch(db, batch)
				batch = batch[:0]
			}
			timer.Reset(flushInterval)
		}
	}
}

func flushBatch(db *sql.DB, batch []time.Time) {
	if len(batch) == 0 {
		return
	}

	var placeholders []string
	var args []interface{}

	for _, t := range batch {
		t = t.UTC()
		year, mon, day := t.Date()
		hour, minutes, _ := t.Clock()

		placeholders = append(placeholders, "(?, ?, ?, ?, ?, 1)")
		args = append(args, year, int(mon), day, hour, minutes)
	}

	var builder strings.Builder
	builder.WriteString(SqlFlushBatchBase)
	builder.WriteString(strings.Join(placeholders, ", "))
	builder.WriteString(SqlFlushBatchSecond)
	query := builder.String()

	tx, err := db.Begin()
	if err != nil {
		logger.Error("flushBatch db.Begin error", zap.Error(err))
		return
	}

	_, err = tx.Exec(query, args...)
	if err != nil {
		logger.Error("flushBatch tx.Exec error", zap.Error(err))
		if rbErr := tx.Rollback(); rbErr != nil {
			logger.Error("flushBatch tx.Rollback error", zap.Error(err))
		}
		return
	}

	if err := tx.Commit(); err != nil {
		logger.Error("flushBatch tx.Commit error", zap.Error(err))
	}
}

func updateCache(db *sql.DB) {
	var total int64
	err := db.QueryRow(SqlFindTotalHits).Scan(&total)
	if err != nil {
		logger.Error("updateCache QueryRow error", zap.Error(err))
		return
	}
	totalHitsCache.Store(total)
}

func updateSummary(db *sql.DB) {
	rows, err := db.Query(SqlQueryFindHitsByYearMonth)
	if err != nil {
		logger.Error("updateSummary QueryRow error", zap.Error(err))
		return
	}
	defer func() {
		ignore(rows.Close())
	}()

	tx, err := db.Begin()
	if err != nil {
		logger.Error("updateSummary db.Begin error", zap.Error(err))
		return
	}

	stmt, err := tx.Prepare(SqlNewHitSummary)
	if err != nil {
		logger.Error("updateSummary tx.Prepare error", zap.Error(err))
		if rbErr := tx.Rollback(); rbErr != nil {
			logger.Error("updateSummary tx.Rollback error", zap.Error(rbErr))
		}
		return
	}
	defer func() {
		ignore(stmt.Close())
	}()

	nowStr := time.Now().UTC().Format(time.RFC3339)

	for rows.Next() {
		var year, month, hits int
		if err := rows.Scan(&year, &month, &hits); err != nil {
			logger.Error("updateSummary rows.Scan error", zap.Error(err))
			continue
		}
		_, err = stmt.Exec(year, month, hits, nowStr)
		if err != nil {
			logger.Error("updateSummary stmt.Exec error", zap.Error(err))
		}
	}

	if err := tx.Commit(); err != nil {
		logger.Error("updateSummary tx.Commit error", zap.Error(err))
	}
}

func maintenanceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if maintenanceMode.Load() == 1 {
			w.Header().Set("Retry-After", "60") // Suggest retry in 1 min
			w.WriteHeader(http.StatusServiceUnavailable)
			var err error
			_, err = fmt.Fprintln(w, "Service temporarily unavailable due to maintenance")
			if err != nil {
				logger.Error("fmt.Fprintln err: ", zap.Error(err))
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer ignore(in.Close())

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer ignore(out.Close())

	_, err = io.Copy(out, in)
	return err
}

func gzipFile(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		ignore(in.Close())
	}()

	out, err := os.Create(path + ".gz")
	if err != nil {
		return err
	}
	defer func() {
		ignore(out.Close())
	}()

	gz := gzip.NewWriter(out)
	defer ignore(gz.Close())

	_, err = io.Copy(gz, in)
	return err
}

func cspMiddleware(next http.Handler) http.Handler {
	cspPolicy := *figs.String(argCspPolicy)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", cspPolicy)
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	allowedOrigins := *figs.List(argCorsAllowedOrigins)
	allowedMethods := strings.Join(*figs.List(argCorsAllowedMethods), figtree.ListSeparator)
	allowedHeaders := strings.Join(*figs.List(argCorsAllowedHeaders), figtree.ListSeparator)
	exposedHeaders := *figs.String(argCorsExposedHeaders)
	allowCredentials := *figs.Bool(argCorsAllowCredentials)
	maxAge := *figs.Int(argCorsMaxAge)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Check allowed origins
		allowed := false
		for _, o := range allowedOrigins {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}
		if !allowed {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
		w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
		if exposedHeaders != "" {
			w.Header().Set("Access-Control-Expose-Headers", exposedHeaders)
		}
		if allowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", maxAge))

		// Handle preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func configure(figs figtree.Plant) figtree.Plant {
	// Configuration Declaration
	figs = figs.NewString(argDatabase, "", "Path to SQLite database for App")
	figs = figs.NewString(argDomain, "", "Domain Name of App")
	figs = figs.NewString(argCert, "", "Path to certificate in PEM format")
	figs = figs.NewString(argKey, "", "Path to certificate private key in PEM format")
	figs = figs.NewString(argEnvironment, "dev", "Environments: dev, staging, prod")
	figs = figs.NewString(argCspPolicy, "default-src 'self'", "Content Security Policy header value")
	figs = figs.NewList(argCorsAllowedOrigins, []string{"*"}, "list of allowed CORS origins")
	figs = figs.NewList(argCorsAllowedMethods, []string{"GET", "POST", "OPTIONS"}, "list of allowed CORS methods")
	figs = figs.NewList(argCorsAllowedHeaders, []string{HeadContentType, HeadAuthorization}, "list of allowed CORS headers")
	figs = figs.NewString(argCorsExposedHeaders, "", "Comma-separated list of exposed CORS headers")
	figs = figs.NewBool(argCorsAllowCredentials, false, "Whether to allow credentials in CORS requests")
	figs = figs.NewInt(argCorsMaxAge, 300, "Max age in seconds for CORS preflight cache")
	figs = figs.NewInt(argPortUnsecure, 8080, "HTTP port to use")
	figs = figs.NewInt(argPortSecure, 8443, "HTTPS port to use")
	figs = figs.NewInt(argConnections, 36, "Database connections to allow")
	figs = figs.NewInt(argHitBatchSize, 36, "Batch size for summaries")
	figs = figs.NewUnitDuration(argHitFlushInterval, time.Duration(36), time.Second, "Delay between flushing batches")
	figs = figs.NewBool(argAdvanced, false, "Advanced mode enabled for IP lookup")
	figs = figs.NewBool(argVersion, false, "Display app current version")
	figs = figs.NewBool(argAbout, false, "Display app about page")
	figs = figs.WithAlias(argVersion, argAliasVersion)
	figs = figs.WithAlias(argAbout, argAliasAbout)
	figs = figs.NewBool(argRateLimitEnabled, true, "Enable rate limiting")
	figs = figs.NewInt(argRateLimitWindow, 60, "Rate limit window in seconds")
	figs = figs.NewInt(argRateLimitMaxRequests, 100, "Maximum requests per window")
	figs = figs.NewInt(argRateLimitCleanup, 300, "Cleanup interval in seconds")
	figs = figs.NewBool(argEnableBackups, false, "Enable Automatic Database Backups")
	figs = figs.NewBool(argCompressBackup, false, "Enable GZIP compression on Database Backups")
	figs = figs.NewString(argBackupPath, "", "Path to backup file")
	figs = figs.NewBool(argEnableCSP, false, "Enable CSP Enforcement")
	figs = figs.NewBool(argEnableCORS, false, "Enable CORS Enforcement")
	figs = figs.NewBool(argEnablePrometheus, false, "Enable Prometheus Monitoring")
	figs = figs.NewBool(argEnableHealth, false, "Enable Health Check Endpoint")
	figs = figs.NewBool(argEnableStats, false, "Enable Stats Endpoint")
	figs = figs.NewString(argEndpointHealth, "/healthz", "HTTP Endpoint for Health Check Endpoint")
	figs = figs.NewString(argEndpointStats, "/stats", "HTTP Endpoint for Stats Endpoint")
	figs = figs.NewString(argEndpointReader, "/read", "HTTP Endpoint for Formatted READ Requests")
	figs = figs.NewString(argEndpointMetrics, "/metrics", "HTTP Endpoint for Prometheus Metrics")
	figs = figs.NewInt64(argShutdownTimeout, int64(10), "Millisecond to delay shutdown timeouts")
	figs = figs.NewInt64(argRequestTimeout, int64(30), "Millisecond to delay request timeouts")
	figs = figs.NewList(argTrustedProxies, defaultTrustedProxies, "List of Trusted Proxies for HTTP/HTTPS Server")

	// Configuration Validation
	figs = figs.WithValidator(argShutdownTimeout, figtree.AssureInt64InRange(36, 36_369_369))
	figs = figs.WithValidator(argShutdownTimeout, figtree.AssureInt64InRange(36, 36_369_369))
	figs = figs.WithValidator(argRequestTimeout, figtree.AssureInt64InRange(36, 36_369_369))
	figs = figs.WithValidator(argRequestTimeout, figtree.AssureInt64InRange(36, 36_369_369))
	figs = figs.WithValidator(argDatabase, figtree.AssureStringNotEmpty)
	figs = figs.WithValidator(argDomain, figtree.AssureStringNotEmpty)
	figs = figs.WithValidator(argDomain, figtree.AssureStringNoPrefixes([]string{"http://", "https://", "s3://", "op://", "ssh://"}))
	figs = figs.WithValidator(argDomain, figtree.AssureStringLengthGreaterThan(4))
	figs = figs.WithValidator(argDomain, figtree.AssureStringLengthLessThan(99))
	figs = figs.WithValidator(argCert, figtree.AssureStringNotEmpty)
	figs = figs.WithValidator(argKey, figtree.AssureStringNotEmpty)
	figs = figs.WithValidator(argPortSecure, figtree.AssureIntInRange(1, 65534))
	figs = figs.WithValidator(argPortUnsecure, figtree.AssureIntInRange(1, 65534))
	figs = figs.WithValidator(argConnections, figtree.AssureIntInRange(1, 1000))
	figs = figs.WithValidator(argHitBatchSize, figtree.AssureIntInRange(1, 1000))
	figs = figs.WithValidator(argHitFlushInterval, figtree.AssureDurationGreaterThan(1))
	figs = figs.WithValidator(argHitFlushInterval, figtree.AssureDurationLessThan(100))
	figs = figs.WithValidator(argRateLimitWindow, figtree.AssureIntInRange(1, 3600))
	figs = figs.WithValidator(argRateLimitMaxRequests, figtree.AssureIntInRange(1, 10000))
	figs = figs.WithValidator(argRateLimitCleanup, figtree.AssureIntInRange(60, 3600))
	figs = figs.WithValidator(argCorsMaxAge, figtree.AssureIntInRange(30, 30000))
	figs = figs.WithValidator(argCorsAllowedOrigins, figtree.AssureListNotEmpty)
	figs = figs.WithValidator(argCorsAllowedMethods, figtree.AssureListNotEmpty)
	figs = figs.WithValidator(argCorsAllowedHeaders, figtree.AssureListNotEmpty)
	figs = figs.WithValidator(argEndpointHealth, figtree.AssureStringHasPrefix(`/`))
	figs = figs.WithValidator(argEndpointHealth, figtree.AssureStringLengthGreaterThan(2))
	figs = figs.WithValidator(argEndpointStats, figtree.AssureStringHasPrefix(`/`))
	figs = figs.WithValidator(argEndpointStats, figtree.AssureStringLengthGreaterThan(2))
	figs = figs.WithValidator(argEndpointReader, figtree.AssureStringHasPrefix(`/`))
	figs = figs.WithValidator(argEndpointReader, figtree.AssureStringLengthGreaterThan(2))
	figs = figs.WithValidator(argEndpointMetrics, figtree.AssureStringHasPrefix(`/`))
	figs = figs.WithValidator(argEndpointMetrics, figtree.AssureStringLengthGreaterThan(2))

	return figs
}

func configFile() string {
	path, ok := os.LookupEnv(kConfigFile)
	if !ok {
		me, err := user.Current()
		if err == nil {
			configPath := filepath.Join(me.HomeDir, "."+AppName, "config.yaml")
			if err := checkfs.File(configPath, file.Options{Exists: true}); err == nil {
				return configPath
			}

		}
		return figtree.ConfigFilePath
	}
	if err := checkfs.File(path, file.Options{Exists: true}); err != nil {
		log.Printf("configFile() err: %v", err)
		return figtree.ConfigFilePath
	}
	return path
}

func (e ErrRollback) Error() string {
	return fmt.Sprintf("tx.Rollback(%s) threw %s", e.Query, e.Err.Error())
}

func (e ErrRollback) Unwrap() error {
	return e.Err
}

func (e ErrQuery) Error() string {
	return fmt.Sprintf("tx.Exec(%s) threw %s", e.Query, e.Err.Error())
}

func (e ErrQuery) Unwrap() error {
	return e.Err
}

func (e ErrDatabase) Error() string {
	return fmt.Sprintf("database %s threw %s", e.Action, e.Err.Error())
}

func (e ErrDatabase) Unwrap() error {
	return e.Err
}

func (e ErrCommit) Error() string {
	return fmt.Sprintf("tx.Commit() threw: %v", e.Err)
}

func (e ErrCommit) Unwrap() error {
	return e.Err
}
