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

//go:embed VERSION
var versionBytes embed.FS

var currentVersion string

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

type IPData struct {
	IPv4       string
	IPv6       string
	VisitCount int
	LastVisit  string
	TotalHits  int64
}

type IPResponse struct {
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

var figs figtree.Plant
var rateLimiter *RateLimiter
var hitChan chan time.Time
var hitWG sync.WaitGroup
var totalHitsCache atomic.Int64
var logger *zap.Logger
var maintenanceMode atomic.Int32

const (
	AppName     string = "dev.ishere.ip"
	kConfigFile string = "IP_CONFIG_FILE"
)

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

const (
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
)

var (
	requestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests",
	})
	hitsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "hits_total",
		Help: "Total hits recorded",
	})
)

func main() {
	figs = figtree.With(figtree.Options{
		ConfigFile:        configFile(),
		Tracking:          false,
		Germinate:         false,
		IgnoreEnvironment: true,
	})

	figs = figs.NewString(argDatabase, "", "Path to SQLite database for App")
	figs = figs.NewString(argDomain, "", "Domain Name of App")
	figs = figs.NewString(argCert, "", "Path to certificate in PEM format")
	figs = figs.NewString(argKey, "", "Path to certificate private key in PEM format")
	figs = figs.NewString(argEnvironment, "dev", "Environment of runtime. Options: dev, staging, prod")

	figs = figs.NewInt(argPortUnsecure, 8080, "HTTP port to use")
	figs = figs.NewInt(argPortSecure, 8443, "HTTPS port to use")
	figs = figs.NewInt(argConnections, 36, "Database connections to allow")
	figs = figs.NewInt(argHitBatchSize, 36, "Batch size for summaries")

	figs = figs.NewDuration(argHitFlushInterval, time.Duration(36)*time.Second, "Delay between flushing batches")

	figs = figs.NewBool(argAdvanced, false, "Advanced mode enabled for IP lookup")
	figs = figs.NewBool(argVersion, false, "Display app current version")
	figs = figs.NewBool(argAbout, false, "Display app about page")
	figs = figs.WithAlias(argVersion, argAliasVersion)
	figs = figs.WithAlias(argAbout, argAliasAbout)

	figs = figs.NewBool(argRateLimitEnabled, true, "Enable rate limiting")
	figs = figs.NewInt(argRateLimitWindow, 60, "Rate limit window in seconds")
	figs = figs.NewInt(argRateLimitMaxRequests, 100, "Maximum requests per window")
	figs = figs.NewInt(argRateLimitCleanup, 300, "Cleanup interval in seconds")

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

	figs = figs.WithValidator(argRateLimitWindow, figtree.AssureIntInRange(1, 3600))
	figs = figs.WithValidator(argRateLimitMaxRequests, figtree.AssureIntInRange(1, 10000))
	figs = figs.WithValidator(argRateLimitCleanup, figtree.AssureIntInRange(60, 3600))

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
	go hitConsumer(db, hitChan)

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			updateCache(db)
		}
	}()

	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			<-ticker.C
			updateSummary(db)
		}
	}()

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			backupPath := *figs.String("backup_path") // Assume added config as before

			// Enter maintenance mode
			maintenanceMode.Store(1)

			// Stop hit consumer to flush pending
			close(hitChan)
			hitWG.Wait()

			// Close DB
			if err := db.Close(); err != nil {
				logger.Error("Failed to close DB for backup", zap.Error(err))
				// Continue or abort; here continue
			}

			// Copy .db file (after close, WAL checkpointed)
			if err := copyFile(databasePath, backupPath); err != nil {
				logger.Error("DB file copy failed", zap.Error(err))
				// Reopen DB anyway
			} else {
				// Compress
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
			go hitConsumer(db, hitChan)

			maintenanceMode.Store(0)

			logger.Info("DB backup completed", zap.String("path", backupPath+".gz"))
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", rateLimitMiddleware(GetIP(db)))
	mux.HandleFunc("/read", rateLimitMiddleware(GetIP(db)))
	mux.HandleFunc("/read.json", rateLimitMiddleware(GetIP(db)))
	mux.HandleFunc("/read.yaml", rateLimitMiddleware(GetIP(db)))
	mux.HandleFunc("/read.ini", rateLimitMiddleware(GetIP(db)))
	mux.HandleFunc("/stats", GetStats())
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := db.Ping(); err != nil {
			http.Error(w, "Database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "OK")
	})

	// Activate Maintenance Middleware
	wrappedMux := maintenanceMiddleware(mux)
	// Attach Request ID to each Request
	wrappedMux = requestIDMiddleware(wrappedMux)
	// Accept 30s timeout for Requests
	wrappedMux = timeoutMiddleware(wrappedMux)
	// Handle 404 Not Found Errors
	wrappedMux = wrapNotFound(wrappedMux)

	certFile := *figs.String(argCert)
	if err := checkfs.File(certFile, file.Options{Exists: true}); err != nil {
		log.Fatalf("invalid TLS certificate provided: %v", err)
	}

	keyFile := *figs.String(argKey)
	if err := checkfs.File(keyFile, file.Options{Exists: true, LessPermissiveThan: 0700}); err != nil {
		log.Fatalf("invalid TLS certificate private key provided: %v", err)
	}

	httpPort := fmt.Sprintf(":%d", *figs.Int(argPortUnsecure))
	httpsPort := fmt.Sprintf(":%d", *figs.Int(argPortSecure))

	if strings.EqualFold(httpPort, ":") || strings.EqualFold(httpsPort, ":") {
		log.Fatalf("invalid http %s https %s provided", httpPort, httpsPort)
	}

	httpServer := &http.Server{
		Addr:    httpPort,
		Handler: http.HandlerFunc(redirectToHTTPS),
	}

	httpsServer := &http.Server{
		Addr:    httpsPort,
		Handler: wrappedMux,
	}

	go func() {
		log.Printf("Starting HTTPS server on %s", httpsPort)
		err := httpsServer.ListenAndServeTLS(certFile, keyFile)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTPS server error: %v", err)
		}
	}()

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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("HTTP shutdown error: %v", zap.Error(err))
	}
	if err := httpsServer.Shutdown(ctx); err != nil {
		logger.Error("HTTPS shutdown error: %v", zap.Error(err))
	}

	logger.Info("Shutdown complete")
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

// Rate limiting middleware
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ipv4, ipv6 string
		if *figs.Bool(argAdvanced) {
			ipv4, ipv6 = getClientIPAdvanced(r)
		} else {
			ipv4, ipv6 = getClientIP(r)
		}

		// Use the first available IP for rate limiting
		clientIP := ipv4
		if clientIP == "" {
			clientIP = ipv6
		}

		if clientIP != "" && !rateLimiter.IsAllowed(clientIP) {
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rateLimiter.config.MaxRequests))
			w.Header().Set("X-RateLimit-Window", fmt.Sprintf("%d", int(rateLimiter.config.WindowSize.Seconds())))
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(rateLimiter.config.WindowSize.Seconds())))

			w.Header().Set(HeadContentType, "application/json")
			json.NewEncoder(w).Encode(map[string]string{"error": "429"})
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// GetStats endpoint
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
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
	return http.TimeoutHandler(next, 10*time.Second, "Request timed out")
}

func GetIP(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		hitChan <- time.Now().UTC()
		requestsTotal.Inc()
		hitsTotal.Inc()

		var ipv4, ipv6 string
		if *figs.Bool(argAdvanced) {
			ipv4, ipv6 = getClientIPAdvanced(r)
		} else {
			ipv4, ipv6 = getClientIP(r)
		}

		data, err := updateRequestTracking(db, ipv4, ipv6)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
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
				tmpl := template.Must(template.New("index").Parse(string(TemplateBytesIndex)))
				if err := tmpl.Execute(w, data); err != nil {
					w.Header().Set("Content-Type", "application/json")
					ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
					w.WriteHeader(http.StatusInternalServerError)
					logger.Error("Template execute error: %v", zap.Error(err))
				}
			}
			return
		case "json":
			w.Header().Set(HeadContentType, "application/json")
			if err := json.NewEncoder(w).Encode(IPResponse{IPv4: data.IPv4, IPv6: data.IPv6}); err != nil {
				w.Header().Set("Content-Type", "application/json")
				ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
				w.WriteHeader(http.StatusInternalServerError)
				logger.Error("JSON encode error: %v", zap.Error(err))
			}
			return
		case "yaml":
			w.Header().Set(HeadContentType, "application/x-yaml")
			yamlBytes, err := yaml.Marshal(IPResponse{IPv4: data.IPv4, IPv6: data.IPv6})
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
				w.WriteHeader(http.StatusInternalServerError)
				logger.Error("YAML marshal error: %v", zap.Error(err))
				return
			}
			if _, err := w.Write(yamlBytes); err != nil {
				logger.Error("Write error: %v", zap.Error(err))
			}
			return
		case "ini":
			w.Header().Set(HeadContentType, "text/plain")
			cfg := ini.Empty()
			sec, err := cfg.NewSection("ip")
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
				w.WriteHeader(http.StatusInternalServerError)
				logger.Error("INI section error: %v", zap.Error(err))
				return
			}
			if _, err := sec.NewKey("ipv4", data.IPv4); err != nil {
				w.Header().Set("Content-Type", "application/json")
				ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
				w.WriteHeader(http.StatusInternalServerError)
				logger.Error("INI key error: %v", zap.Error(err))
				return
			}
			if _, err := sec.NewKey("ipv6", data.IPv6); err != nil {
				w.Header().Set("Content-Type", "application/json")
				ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
				w.WriteHeader(http.StatusInternalServerError)
				logger.Error("INI key error: %v", zap.Error(err))
				return
			}
			if _, err := cfg.WriteTo(w); err != nil {
				w.Header().Set("Content-Type", "application/json")
				ignore(json.NewEncoder(w).Encode(map[string]string{"error": Err500}))
				w.WriteHeader(http.StatusInternalServerError)
				logger.Error("INI write error: %v", zap.Error(err))
			}
			return
		}

		w.Header().Set(HeadContentType, "text/html")
		tmpl := template.Must(template.New("index").Parse(string(TemplateBytesIndex)))
		errExec := tmpl.Execute(w, data)
		if errExec != nil {
			http.Error(w, Err500, http.StatusInternalServerError)
			log.Printf("Error rendering template: %v", errExec)
			return
		}
	}
}

func getClientIP(r *http.Request) (ipv4, ipv6 string) {
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
							ipv6 = ip
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
				ipv6 = host
			}
		}
	}

	return ipv4, ipv6
}

// Alternative version that also handles IPv4-mapped IPv6 addresses
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

var ignore = func(in any) {
	if in != nil {
		fmt.Printf("ignore(%s)", in)
	}
}

type ErrRollback struct {
	Query string
	Err   error
}

func (e ErrRollback) Error() string {
	return fmt.Sprintf("tx.Rollback(%s) threw %s", e.Query, e.Err.Error())
}

func (e ErrRollback) Unwrap() error {
	return e.Err
}

type ErrQuery struct {
	Query string
	Err   error
}

func (e ErrQuery) Error() string {
	return fmt.Sprintf("tx.Exec(%s) threw %s", e.Query, e.Err.Error())
}

func (e ErrQuery) Unwrap() error {
	return e.Err
}

type ErrDatabase struct {
	Action string
	Err    error
}

func (e ErrDatabase) Error() string {
	return fmt.Sprintf("database %s threw %s", e.Action, e.Err.Error())
}

func (e ErrDatabase) Unwrap() error {
	return e.Err
}

type ErrCommit struct {
	Err error
}

func (e ErrCommit) Error() string {
	return fmt.Sprintf("tx.Commit() threw: %v", e.Err)
}

func (e ErrCommit) Unwrap() error {
	return e.Err
}

const (
	Err404 = "Page Not Found"
	Err500 = "Internal Server Error"

	HeadContentType = "Content-Type"
	HeadUserAgent   = "User-Agent"
	HeadForwarded   = "X-Forwarded-For"

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
)

// Rate limiting structures
type RateLimitConfig struct {
	WindowSize    time.Duration
	MaxRequests   int
	CleanupPeriod time.Duration
	Enabled       bool
}

type ClientRecord struct {
	Count     int
	Window    time.Time
	LastSeen  time.Time
	Blocked   bool
	BlockedAt time.Time
}

type RateLimiter struct {
	clients map[string]*ClientRecord
	config  RateLimitConfig
	mu      sync.RWMutex
	stats   RateLimitStats
}

type RateLimitStats struct {
	TotalRequests   int64
	BlockedRequests int64
	ActiveClients   int64
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

func hitConsumer(db *sql.DB, ch chan time.Time) {
	batchSize := *figs.Int(argHitBatchSize)
	flushInterval := *figs.Duration(argHitFlushInterval) * time.Second

	var batch []time.Time
	timer := time.NewTimer(flushInterval)
	defer timer.Stop()

	for {
		select {
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

	query := SqlFlushBatchBase + strings.Join(placeholders, ", ") + SqlFlushBatchSecond

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
	defer rows.Close()

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
	defer ignore(in.Close())

	out, err := os.Create(path + ".gz")
	if err != nil {
		return err
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	defer ignore(gz.Close())

	_, err = io.Copy(gz, in)
	return err
}
