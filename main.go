package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andreimerlescu/checkfs"
	"github.com/andreimerlescu/checkfs/file"
	"github.com/andreimerlescu/figtree/v2"
	"github.com/go-ini/ini"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

type IPData struct {
	IPv4       string
	IPv6       string
	VisitCount int
	LastVisit  string
}

type IPResponse struct {
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

var figs figtree.Plant
var rateLimiter *RateLimiter

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

	figs = figs.NewInt(argPortUnsecure, 8080, "HTTP port to use")
	figs = figs.NewInt(argPortSecure, 8443, "HTTPS port to use")
	figs = figs.NewInt(argConnections, 36, "Database connections to allow")

	figs = figs.NewBool(argAdvanced, false, "Advanced mode enabled for IP lookup")

	figs = figs.NewBool(argRateLimitEnabled, true, "Enable rate limiting")
	figs = figs.NewInt(argRateLimitWindow, 60, "Rate limit window in seconds")
	figs = figs.NewInt(argRateLimitMaxRequests, 100, "Maximum requests per window")
	figs = figs.NewInt(argRateLimitCleanup, 300, "Cleanup interval in seconds")

	figs = figs.WithValidator(argDatabase, figtree.AssureStringNotEmpty)
	figs = figs.WithValidator(argDomain, figtree.AssureStringNotEmpty)
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
		log.Printf("sql.Open(%s) failed with err: %v", databasePath, err)
		log.Fatal(err)
	}
	defer func(db *sql.DB) {
		ignore(db.Close())
	}(db)
	connections := *figs.Int(argConnections)

	db.SetMaxOpenConns(connections)
	db.SetMaxIdleConns(connections)
	db.SetConnMaxLifetime(time.Duration(connections) * time.Second)

	_, err = db.Exec(SqlCreateTable)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", rateLimitMiddleware(GetIP(db)))
	mux.HandleFunc("/read", rateLimitMiddleware(GetIP(db)))
	mux.HandleFunc("/read.json", rateLimitMiddleware(GetIP(db)))
	mux.HandleFunc("/read.yaml", rateLimitMiddleware(GetIP(db)))
	mux.HandleFunc("/read.ini", rateLimitMiddleware(GetIP(db)))
	mux.HandleFunc("/stats", GetStats())

	wrappedMux := wrapNotFound(mux)

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
			log.Printf("HTTP server error: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutdown signal received")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}
	if err := httpsServer.Shutdown(ctx); err != nil {
		log.Printf("HTTPS shutdown error: %v", err)
	}

	log.Println("Shutdown complete")
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

			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
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

func GetIP(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var ipv4, ipv6 string
		if *figs.Bool(argAdvanced) {
			ipv4, ipv6 = getClientIPAdvanced(r)
		} else {
			ipv4, ipv6 = getClientIP(r)
		}

		data, err := updateRequestTracking(db, ipv4, ipv6)
		if err != nil {
			http.Error(w, Err500, http.StatusInternalServerError)
			log.Printf("Error updating request tracking: %v", err)
			return
		}

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
					http.Error(w, Err500, http.StatusInternalServerError)
					log.Printf("Template execute error: %v", err)
				}
			}
			return
		case "json":
			w.Header().Set(HeadContentType, "application/json")
			if err := json.NewEncoder(w).Encode(IPResponse{IPv4: data.IPv4, IPv6: data.IPv6}); err != nil {
				http.Error(w, Err500, http.StatusInternalServerError)
				log.Printf("JSON encode error: %v", err)
			}
			return
		case "yaml":
			w.Header().Set(HeadContentType, "application/x-yaml")
			yamlBytes, err := yaml.Marshal(IPResponse{IPv4: data.IPv4, IPv6: data.IPv6})
			if err != nil {
				http.Error(w, Err500, http.StatusInternalServerError)
				log.Printf("YAML marshal error: %v", err)
				return
			}
			if _, err := w.Write(yamlBytes); err != nil {
				log.Printf("Write error: %v", err)
			}
			return
		case "ini":
			w.Header().Set(HeadContentType, "text/plain")
			cfg := ini.Empty()
			sec, err := cfg.NewSection("ip")
			if err != nil {
				http.Error(w, Err500, http.StatusInternalServerError)
				log.Printf("INI section error: %v", err)
				return
			}
			if _, err := sec.NewKey("ipv4", data.IPv4); err != nil {
				http.Error(w, Err500, http.StatusInternalServerError)
				log.Printf("INI key error: %v", err)
				return
			}
			if _, err := sec.NewKey("ipv6", data.IPv6); err != nil {
				http.Error(w, Err500, http.StatusInternalServerError)
				log.Printf("INI key error: %v", err)
				return
			}
			if _, err := cfg.WriteTo(w); err != nil {
				http.Error(w, Err500, http.StatusInternalServerError)
				log.Printf("INI write error: %v", err)
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
	return fmt.Sprintf("tx.Commit(%s) threw: %v")
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
	mu              sync.RWMutex
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
	rl.stats.mu.Lock()
	rl.stats.TotalRequests++
	rl.stats.ActiveClients = int64(len(rl.clients))
	rl.stats.mu.Unlock()

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
			rl.stats.mu.Lock()
			rl.stats.BlockedRequests++
			rl.stats.mu.Unlock()

			log.Printf("Rate limit exceeded for IP: %s (count: %d)", ip, record.Count)
		}
		return false
	}

	return true
}

func (rl *RateLimiter) GetStats() RateLimitStats {
	rl.stats.mu.RLock()
	defer rl.stats.mu.RUnlock()

	return RateLimitStats{
		TotalRequests:   rl.stats.TotalRequests,
		BlockedRequests: rl.stats.BlockedRequests,
		ActiveClients:   rl.stats.ActiveClients,
	}
}

func (rl *RateLimiter) GetClientInfo(ip string) (*ClientRecord, bool) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	record, exists := rl.clients[ip]
	if !exists {
		return nil, false
	}

	// Return a copy to avoid race conditions
	return &ClientRecord{
		Count:     record.Count,
		Window:    record.Window,
		LastSeen:  record.LastSeen,
		Blocked:   record.Blocked,
		BlockedAt: record.BlockedAt,
	}, true
}
