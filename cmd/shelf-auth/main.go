// cmd/shelf-auth/main.go
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/slavasuhoveev/shelf-auth/internal/auth/jwks"
	"github.com/slavasuhoveev/shelf-auth/internal/auth/signer"
	"github.com/slavasuhoveev/shelf-auth/internal/config"
	"github.com/slavasuhoveev/shelf-auth/internal/httpserver"
	"github.com/slavasuhoveev/shelf-auth/internal/logging"
	"github.com/slavasuhoveev/shelf-auth/internal/repo/postgres"
	"github.com/slavasuhoveev/shelf-auth/internal/security"
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

	// Open database connection (Postgres via pgxpool) and ensure it is closed on exit.
	db, err := postgres.Open(cfg.DatabaseURL)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to open database")
	}
	defer db.Close()

	// Initialize key material:
	// - JWT access-token signer (RS256 with KID/issuer/audience)
	// - JWKS provider to expose public keys at /.well-known/jwks.json
	// load RSA private key from devkeys/<kid>.pem
	keyPath := filepath.Join(cfg.KeysDir, cfg.SigningKeyKID+".pem")
	privKey, err := signer.LoadRSAPrivateKeyFromPEM(keyPath)
	if err != nil {
		logger.Fatal().Err(err).Str("key", keyPath).Msg("failed to load private key")
	}

	// build access signer (RS256). alg из cfg сейчас не нужен здесь.
	accessSigner := signer.NewAccessSigner(
		privKey,
		cfg.SigningKeyKID,
		cfg.JWTIss,
		cfg.JWTAud,
	)

	j := jwks.NewProvider(cfg.KeysDir, cfg.JWTAlg, cfg.JWKSMaxAge)

	// Wire repositories.
	usersRepo := postgres.NewUsersRepo(db)
	sessionsRepo := postgres.NewSessionsRepo(db)

	// Password hashing options (bcrypt cost, optional pepper).
	pwOpts := security.DefaultOptions()
	// If you use pepper, uncomment:
	// pwOpts.Pepper = []byte(cfg.PasswordPepper)

	// Build auth service layer (login/refresh/logout to be added progressively).
	authSvc := service.NewAuthService(
		usersRepo,
		sessionsRepo,
		accessSigner,   // implements tokens.Signer for access JWTs
		cfg.AccessTTL,  // access token TTL
		cfg.RefreshTTL, // refresh token TTL
		pwOpts,
	)

	// Setup HTTP router with handlers, middlewares, and JWKS endpoint.
	router := httpserver.NewRouter(authSvc, j, logger)

	// Configure HTTP server with sane defaults and timeouts.
	srv := &http.Server{
		Addr:              cfg.HTTPAddr, // e.g. ":8081"
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
