package main

import (
	"github.com/andreimerlescu/figtree/v2"
	"go.uber.org/zap"
	"net"
)

func trustedProxies(figs figtree.Plant) (o []*net.IPNet) {
	proxies := *figs.List(argTrustedProxies)
	if proxies == nil || len(proxies) == 0 {
		return
	}
	results := make([]*net.IPNet, len(proxies))
	for _, proxy := range proxies {
		result, err := parseCIDR(proxy)
		if err != nil {
			logger.Error("parseCIDR() threw %v", zap.Error(err))
			continue
		}
		results = append(results, result)
	}
	return results
}

func isTrustedProxy(figs figtree.Plant, ip net.IP) bool {
	proxies := trustedProxies(figs)
	if proxies == nil {
		return false
	}
	for _, trustedNet := range proxies {
		if trustedNet == nil {
			continue
		}
		if trustedNet.Contains(ip) {
			return true
		}
	}
	return false
}
