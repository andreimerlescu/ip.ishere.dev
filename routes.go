package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/andreimerlescu/figtree/v2"
	"github.com/go-ini/ini"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

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
	mux.HandleFunc("/index.html", rateLimitMiddleware(figs, GetIP(figs, db)))
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
	wrappedMux = notFoundMiddleware(wrappedMux)

	return wrappedMux
}

func GetIP(figs figtree.Plant, db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if concurrency != nil {
			concurrency.Acquire()
			defer func() {
				concurrency.Release()
			}()
		}
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
		if concurrency != nil {
			concurrency.Acquire()
			defer func() {
				concurrency.Release()
			}()
		}
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
		if concurrency != nil {
			concurrency.Acquire()
			defer func() {
				concurrency.Release()
			}()
		}
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
