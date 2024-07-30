package httpserver

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"

	"github.com/slavasuhoveev/shelf-auth/internal/httpserver/handlers"
)

// JWKSProvider exposes the current JWKS payload for the HTTP layer.
type JWKSProvider interface {
	// Current returns a serialized JWKS JSON, optional ETag, and cache max-age.
	Current() (body []byte, etag string, maxAge time.Duration)
}

// Service is the application service interface (register/login/refresh/logout).
// It is injected here for future endpoints.
type Service interface{}

// NewRouter wires middlewares and routes, delegating request handling to handlers.
func NewRouter(svc Service, jwks JWKSProvider, log zerolog.Logger) http.Handler {
	r := chi.NewRouter()

	// Core middlewares (keep them minimal to avoid surprises).
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(10 * time.Second))

	// Health endpoint (liveness). A separate /readyz can be added later.
	r.Get("/healthz", handlers.Health())
	r.Head("/healthz", handlers.Health())

	// JWKS endpoint for gateways to fetch public keys.
	r.Get("/.well-known/jwks.json", handlers.JWKS(jwks))
	r.Head("/.well-known/jwks.json", handlers.JWKS(jwks)) // accept HEAD too

	return r
}
