package main

import (
	"log"
	"sync/atomic"
	"time"
)

func setupRateLimiter() *RateLimiter {
	// Initialize rate limiter
	rateLimitConfig := RateLimitConfig{
		WindowSize:    time.Duration(*figs.Int(argRateLimitWindow)) * time.Second,
		MaxRequests:   *figs.Int(argRateLimitMaxRequests),
		CleanupPeriod: time.Duration(*figs.Int(argRateLimitCleanup)) * time.Second,
		Enabled:       *figs.Bool(argRateLimitEnabled),
	}
	rateLimiter = NewRateLimiter(rateLimitConfig)
	return rateLimiter
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
