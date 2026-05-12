//go:build unit

package util

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP_HeadersAndRemoteAddr(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		headerVal  string
		remoteAddr string
		want       string
	}{
		{
			name:       "x-forwarded-for first address",
			headerName: "X-Forwarded-For",
			headerVal:  " 203.0.113.9, 10.0.0.1 ",
			remoteAddr: "192.0.2.10:1234",
			want:       "203.0.113.9",
		},
		{
			name:       "x-real-ip",
			headerName: "X-Real-IP",
			headerVal:  "198.51.100.7",
			remoteAddr: "192.0.2.10:1234",
			want:       "198.51.100.7",
		},
		{
			name:       "remote addr host port",
			remoteAddr: "192.0.2.10:1234",
			want:       "192.0.2.10",
		},
		{
			name:       "remote addr without port",
			remoteAddr: "192.0.2.10",
			want:       "192.0.2.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.headerName != "" {
				req.Header.Set(tt.headerName, tt.headerVal)
			}

			if got := ClientIP(req); got != tt.want {
				t.Fatalf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
