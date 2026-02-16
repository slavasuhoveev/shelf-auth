// cmd/shelf-auth/main.go
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/slavasuhoveev/shelf-auth/internal/auth/jwks"
	"github.com/slavasuhoveev/shelf-auth/internal/auth/signer"
	"github.com/slavasuhoveev/shelf-auth/internal/config"
	"github.com/slavasuhoveev/shelf-auth/internal/httpserver"
	"github.com/slavasuhoveev/shelf-auth/internal/httpserver/handlers"
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

	// Initialize JWKS provider (publishes ALL public keys from KEYS_DIR).
	j := jwks.NewProvider(cfg.KeysDir, cfg.JWTAlg, cfg.JWKSMaxAge)

	// Initialize signer: loads keys, keeps active KID, embeds iss/aud.
	sign := signer.New(
		cfg.KeysDir,
		cfg.SigningKeyKID,
		cfg.JWTAlg,
		cfg.AccessTTL,
		cfg.JWTIss,
		cfg.JWTAud,
	)

	// Optional: runtime override of active KID (useful for hot rotation without restart).
	if kid := strings.TrimSpace(cfg.ActiveKIDRuntime); kid != "" && kid != cfg.SigningKeyKID {
		if err := sign.SetActiveKid(kid); err != nil {
			logger.Warn().Err(err).Str("kid", kid).Msg("failed to switch active kid at startup; continuing with SIGNING_KEY_KID")
		} else {
			logger.Info().Str("kid", kid).Msg("active kid overridden at startup")
		}
	}

	// Create a context that cancels on SIGINT/SIGTERM (Ctrl+C / docker stop).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start periodic reloaders (best-effort; keep last good state on errors).
	if cfg.KeysReloadInterval > 0 {
		go sign.StartAutoReload(ctx, cfg.KeysReloadInterval)
		go j.StartAutoRefresh(ctx, cfg.KeysReloadInterval)
	}

	// Wire repositories.
	usersRepo := postgres.NewUsersRepo(db)
	sessionsRepo := postgres.NewSessionsRepo(db)

	// Password hashing options (bcrypt cost, optional pepper).
	pwOpts := security.DefaultOptions()
	// If you use pepper, uncomment:
	// pwOpts.Pepper = []byte(cfg.PasswordPepper)

	// Build auth service layer (register/login/refresh/logout).
	authSvc := service.NewAuthService(
		usersRepo,
		sessionsRepo,
		sign,           // signer signs access JWTs with active KID
		cfg.AccessTTL,  // access token TTL
		cfg.RefreshTTL, // refresh token TTL
		pwOpts,
	)

	// Setup HTTP router with handlers, middlewares, and JWKS endpoint.
	router := httpserver.NewRouter(
		authSvc,
		accessSigner,
		j,
		logger,
		httpserver.Options{
			CORSOrigins: cfg.CORSOrigins,
			CookieCfg: handlers.CookieCfg{
				Secure:   cfg.CookieSecure,
				SameSite: httpserver.ParseSameSite(cfg.CookieSameSite),
				Domain:   cfg.CookieDomain,
			},
		},
	)

	// Configure HTTP server with sane defaults and timeouts.
	srv := &http.Server{
		Addr:              cfg.HTTPAddr, // e.g. ":8081"
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

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
