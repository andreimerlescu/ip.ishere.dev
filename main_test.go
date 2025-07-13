package main

import (
	"github.com/andreimerlescu/figtree/v2"
	"net/http/httptest"
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
	figs := figtree.With(figtree.Options{Germinate: true, Tracking: false})
	figs = configure(figs)
	ipv4, ipv6 := getClientIP(figs, req)
	if ipv4 != "192.0.2.1" || ipv6 != "2001:db8::1" {
		t.Errorf("Expected IPv4:192.0.2.1 IPv6:2001:db8::1, got %s %s", ipv4, ipv6)
	}
}

func TestRateLimiter_IsAllowed(t *testing.T) {
	config := RateLimitConfig{Enabled: true, MaxRequests: 2, WindowSize: time.Second}
	rl := NewRateLimiter(config)
	if !rl.IsAllowed("test-ip") || !rl.IsAllowed("test-ip") || rl.IsAllowed("test-ip") {
		t.Error("Rate limiting not enforced correctly")
	}
}
