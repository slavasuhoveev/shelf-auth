package httpserver

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"

	"github.com/slavasuhoveev/shelf-auth/internal/httpserver/handlers"
	"github.com/slavasuhoveev/shelf-auth/internal/service"
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
func NewRouter(authSvc *service.AuthService, jwks JWKSProvider, log zerolog.Logger) http.Handler {
	r := chi.NewRouter()

	// Core middlewares (keep them minimal to avoid surprises).
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(10 * time.Second))

	// Health endpoint (liveness). A separate /readyz can be added later.
	r.Get("/healthz", handlers.HealthHandler())
	r.Head("/healthz", handlers.HealthHandler())

	// JWKS endpoint for gateways to fetch public keys.
	r.Get("/.well-known/jwks.json", handlers.JWKSHandler(jwks))
	r.Head("/.well-known/jwks.json", handlers.JWKSHandler(jwks)) // accept HEAD too

	// Auth
	r.Post("/login", handlers.LoginHandler(authSvc, log))
	r.Post("/register", handlers.RegisterHandler(authSvc, log))
	r.Post("/refresh", handlers.RefreshHandler(authSvc, log))

	return r
}
