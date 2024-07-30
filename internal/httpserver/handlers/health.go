package handlers

import (
	"net/http"
)

// Health returns a basic OK response with constant payload.
// Keep it fast and dependency-free for liveness checks.
func Health() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Keep the body tiny; infra only cares about the status code.
		_, _ = w.Write([]byte(`{"status":"ok","service":"shelf-auth"}`))
	}
}
