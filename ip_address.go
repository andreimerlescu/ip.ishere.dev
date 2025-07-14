package main

import (
	"github.com/andreimerlescu/figtree/v2"
	"net"
	"net/http"
	"strings"
)

func parseCIDR(cidr string) (*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return ipnet, nil
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
