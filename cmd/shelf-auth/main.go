// cmd/shelf-auth/main.go
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/slavasuhoveev/shelf-auth/internal/auth/jwks"
	"github.com/slavasuhoveev/shelf-auth/internal/auth/signer"
	"github.com/slavasuhoveev/shelf-auth/internal/config"
	"github.com/slavasuhoveev/shelf-auth/internal/httpserver"
	"github.com/slavasuhoveev/shelf-auth/internal/logging"
	"github.com/slavasuhoveev/shelf-auth/internal/repo/postgres"
	"github.com/slavasuhoveev/shelf-auth/internal/service"
)

func main() {
	// Load configuration from environment. Exit if config is invalid.
	cfg, err := config.Load()
	if err != nil {
		log.Printf("config load error: %v", err)
		os.Exit(1)
	}

	// Initialize structured logger with configured log level.
	logger := logging.New(cfg.LogLevel)
	logger.Info().Msg("config loaded")

	// Open database connection (e.g., Postgres via pgxpool).
	// Ensure it is closed on application exit.
	db, err := postgres.Open(cfg.DatabaseURL)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to open database")
	}
	defer db.Close()

	// Initialize JWT signer (private keys, KID, algorithm, TTL)
	// and JWKS provider for publishing public keys.
	s := signer.New(cfg.KeysDir, cfg.SigningKeyKID, cfg.JWTAlg, cfg.AccessTTL)
	j := jwks.NewProvider(cfg.KeysDir, cfg.JWTAlg, cfg.JWKSMaxAge)

	// Build business service layer (register/login/refresh/logout).
	svc := service.New(db, s)

	// Setup HTTP router with handlers, middlewares, and JWKS endpoint.
	router := httpserver.NewRouter(svc, j, logger)

	// Configure HTTP server with sane defaults and timeouts.
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Create context that cancels on interrupt/terminate signals.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Channel to capture server errors.
	errCh := make(chan error, 1)

	// Start HTTP server in a separate goroutine.
	go func() {
		logger.Info().Msg("http server starting on " + cfg.HTTPAddr)
		errCh <- srv.ListenAndServe()
	}()

	// Wait until either a shutdown signal is received or server crashes.
	select {
	case <-ctx.Done():
		logger.Info().Msg("shutdown signal received")
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error().Err(err).Msg("server error")
		}
	}

	// Attempt graceful shutdown: stop new connections and drain existing ones.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error().Err(err).Msg("graceful shutdown failed")
		_ = srv.Close() // force close as a last resort
	}

	logger.Info().Msg("server stopped")
}
