package httpserver

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	chiCors "github.com/go-chi/cors"
	"github.com/rs/zerolog"

	"github.com/slavasuhoveev/shelf-auth/internal/httpserver/handlers"
	"github.com/slavasuhoveev/shelf-auth/internal/httpserver/middleware"
	"github.com/slavasuhoveev/shelf-auth/internal/service"
	"github.com/slavasuhoveev/shelf-auth/internal/tokens"
)

// JWKSProvider exposes the current JWKS payload for the HTTP layer.
type JWKSProvider interface {
	// Current returns a serialized JWKS JSON, optional ETag, and cache max-age.
	Current() (body []byte, etag string, maxAge time.Duration)
}

type Options struct {
	CORSOrigins []string
	CookieCfg   handlers.CookieCfg
}

// Service is the application service interface (register/login/refresh/logout).
// It is injected here for future endpoints.
type Service interface{}

// NewRouter wires middlewares and routes, delegating request handling to handlers.
func NewRouter(
	authSvc *service.AuthService,
	tokenVerifier tokens.Verifier,
	jwks JWKSProvider,
	log zerolog.Logger,
	opts Options,
) http.Handler {
	r := chi.NewRouter()

	// Core middlewares
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(10 * time.Second))
	r.Use(middleware.SecurityHeaders)

	// CORS (only if configured)
	if len(opts.CORSOrigins) > 0 {
		r.Use(chiCors.Handler(chiCors.Options{
			AllowedOrigins:   opts.CORSOrigins,
			AllowedMethods:   []string{"GET", "POST", "HEAD", "OPTIONS"},
			AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Device-ID"},
			AllowCredentials: true,
			MaxAge:           300,
		}))
	}
	// Health
	r.Get("/healthz", handlers.HealthHandler())
	r.Head("/healthz", handlers.HealthHandler())

	// JWKS
	r.Get("/.well-known/jwks.json", handlers.JWKSHandler(jwks))
	r.Head("/.well-known/jwks.json", handlers.JWKSHandler(jwks))

	// Auth
	r.Post("/register", handlers.RegisterHandler(authSvc, log))
	r.Post("/login", handlers.LoginHandler(authSvc, log, opts.CookieCfg))
	r.Post("/logout", handlers.LogoutHandler(authSvc, log, opts.CookieCfg))
	r.Post("/refresh", handlers.RefreshHandler(authSvc, log, opts.CookieCfg))
	r.Route("/", func(r chi.Router) {
		r.Use(middleware.AuthMiddleware(tokenVerifier, log))
		r.Get("/me", handlers.MeHandler(authSvc, log))
	})

	return r
}
