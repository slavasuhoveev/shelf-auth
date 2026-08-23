package handlers

import "net/http"

// Ready returns a basic OK response for readiness checks.
// Keep it dependency-free until startup/runtime dependencies need explicit checks.
func ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ready","service":"shelf-auth"}`))
	}
}
