package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/andreimerlescu/figtree/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

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

func timeoutMiddleware(next http.Handler) http.Handler {
	return http.TimeoutHandler(next, *figs.Duration(argRequestTimeout)*time.Millisecond, "Request timed out")
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

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := uuid.New().String()[:8] // Short UUID
		ctx := context.WithValue(r.Context(), "reqID", reqID)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", reqID)
		next.ServeHTTP(w, r)
	})
}

func notFoundMiddleware(next http.Handler) http.Handler {
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

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
}
