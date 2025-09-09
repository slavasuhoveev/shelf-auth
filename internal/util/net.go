package util

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP extracts real client IP from common headers or RemoteAddr.
func ClientIP(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
