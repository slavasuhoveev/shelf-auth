package handlers

import (
	"net/http"
	"strconv"
	"time"
)

// jwksProvider is the minimal surface we need from the JWKS component.
// It mirrors the interface defined in the httpserver package.
type jwksProvider interface {
	Current() (body []byte, etag string, maxAge time.Duration)
}

// JWKS serves the current JWKS document with cache-friendly headers.
// It supports conditional GETs via If-None-Match/ETag to save bandwidth.
func JWKS(provider jwksProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, etag, maxAge := provider.Current()

		// Conditional GET: if ETag matches, return 304 to avoid sending body.
		if etag != "" && r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if maxAge > 0 {
			w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(maxAge.Seconds())))
		}
		if etag != "" {
			w.Header().Set("ETag", etag)
		}

		// For HEAD, send headers only (no body)
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}
