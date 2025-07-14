package main

import (
	"github.com/andreimerlescu/figtree/v2"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"
)

func TestVersion(t *testing.T) {
	v := Version()
	if v == "v0.0.0" {
		t.Errorf("Expected a version, got %s", v)
	}
}

func TestGetClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.0.2.1, 2001:db8::1")
	originalOsArgs := slices.Clone(os.Args)
	os.Args = []string{
		os.Args[0],
		"-domain", "ip.ishere.dev",
		"-database", "/tmp/ip.ishere.dev.test.db",
		"-shutdown_timeout", "36",
		"-request_timeout", "36",
		"-hit_flush_interval", "36",
		"-key", "/tmp/domain.key",
		"-cert", "/tmp/domain.cert",
	}
	figs := figtree.With(figtree.Options{Germinate: true, IgnoreEnvironment: true, Tracking: false})
	figs = configure(figs)
	err := figs.Parse()
	if err != nil {
		t.Errorf("Expected figs.Parse() to succeed: %v", err)
	}
	ipv4, ipv6 := getClientIP(figs, req)
	if ipv4 != "192.0.2.1" || ipv6 != "2001:db8::1" {
		t.Errorf("Expected IPv4:192.0.2.1 IPv6:2001:db8::1, got %s %s", ipv4, ipv6)
	}
	os.Args = originalOsArgs
}

func TestRateLimiter_IsAllowed(t *testing.T) {
	config := RateLimitConfig{Enabled: true, MaxRequests: 2, WindowSize: time.Second}
	rl := NewRateLimiter(config)
	if !rl.IsAllowed("test-ip") || !rl.IsAllowed("test-ip") || rl.IsAllowed("test-ip") {
		t.Error("Rate limiting not enforced correctly")
	}
}
