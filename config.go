package main

import (
	"log"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/andreimerlescu/checkfs"
	"github.com/andreimerlescu/checkfs/file"
	"github.com/andreimerlescu/figtree/v2"
)

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
	figs = figs.NewInt(argMaxConcurrency, 369, "Maximum number of requests permitted at a time")
	figs = figs.NewInt(argHitBuffer, 1000, "Number of hits to permit in the buffer")

	// Configuration Validation
	figs = figs.WithValidator(argHitBuffer, figtree.AssureIntInRange(1, 1_000_000))
	figs = figs.WithValidator(argMaxConcurrency, figtree.AssureIntInRange(17, 63_369))
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
