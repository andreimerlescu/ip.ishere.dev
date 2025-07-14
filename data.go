package main

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/figtree/v2"
	"github.com/andreimerlescu/sema"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
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
	argHitBuffer            string = "hit_buffer"
	argHitBatchSize         string = "hit_batch_size"
	argHitFlushInterval     string = "hit_flush_interval"
	argEnvironment          string = "environment"
	argEnableCSP            string = "enable_csp"
	argEnableCORS           string = "enable_cors"
	argEnablePrometheus     string = "enable_prometheus"
	argEnableHealth         string = "enable_health"
	argEnableStats          string = "enable_stats"
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
	argEndpointHealth       string = "endpoint_health"
	argEndpointStats        string = "endpoint_stats"
	argEndpointReader       string = "endpoint_read"
	argEndpointMetrics      string = "endpoint_metrics"
	argShutdownTimeout      string = "shutdown_timeout"
	argRequestTimeout       string = "request_timeout"
	argTrustedProxies       string = "trusted_proxies"
	argMaxConcurrency       string = "max_concurrency"
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
	concurrency           sema.Semaphore
	defaultTrustedProxies = []string{
		"127.0.0.1/32",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
)
