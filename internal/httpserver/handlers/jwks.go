package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// jwksProvider is the minimal surface we need from the JWKS component.
// It mirrors the interface defined in the httpserver package.
type jwksProvider interface {
	Current() (body []byte, etag string, maxAge time.Duration)
}

// JWKS serves the current JWKS document with cache-friendly headers.
// It supports conditional GETs via If-None-Match/ETag to save bandwidth.
func JWKSHandler(provider jwksProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, etag, maxAge := provider.Current()

		// Parse If-None-Match (may be a list and/or weak validators).
		if inm := r.Header.Get("If-None-Match"); etag != "" && inm != "" {
			for _, v := range strings.Split(inm, ",") {
				v = strings.TrimSpace(v)
				v = strings.TrimPrefix(v, "W/") // treat weak as match too
				if v == etag {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}

		w.Header().Set("Content-Type", "application/jwk-set+json")
		if maxAge > 0 {
			w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(maxAge.Seconds())))
		}
		if etag != "" {
			w.Header().Set("ETag", etag)
		}

		// For HEAD, send headers only (and length for caches/proxies).
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}
