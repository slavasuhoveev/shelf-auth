package config

import (
	"errors"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config holds application runtime configuration loaded from environment.
type Config struct {
	// App / HTTP
	Env      string `env:"ENV"         envDefault:"dev"` // dev|prod
	HTTPAddr string `env:"HTTP_ADDR"   envDefault:":8080"`
	LogLevel string `env:"LOG_LEVEL"   envDefault:"info"` // debug|info|warn|error

	// JWT / JWKS
	JWTAlg        string        `env:"JWT_ALG"        envDefault:"RS256"`
	JWTIss        string        `env:"JWT_ISS"        envDefault:"shelf-auth"`
	JWTAud        string        `env:"JWT_AUD"        envDefault:"shelf-api"`
	AccessTTL     time.Duration `env:"ACCESS_TTL"     envDefault:"15m"`
	RefreshTTL    time.Duration `env:"REFRESH_TTL"    envDefault:"720h"` // 30d; used later
	JWKSMaxAge    time.Duration `env:"JWKS_MAX_AGE"   envDefault:"300s"` // cache for jwks.json
	KeysDir       string        `env:"KEYS_DIR"       envDefault:"./devkeys"`
	SigningKeyKID string        `env:"SIGNING_KEY_KID" envDefault:""`

	// Database (wired later for /login etc.)
	DatabaseURL string `env:"DATABASE_URL" envDefault:""`

	// CORS
	CORSOrigins []string `env:"CORS_ORIGINS" envSeparator:","`

	// Cookies
	CookieSecure   bool   `env:"COOKIE_SECURE" envDefault:"true"`
	CookieSameSite string `env:"COOKIE_SAMESITE" envDefault:"Lax"`
	CookieDomain   string `env:"COOKIE_DOMAIN"`
}

// Load parses environment variables into Config and validates required fields.
func Load() (Config, error) {
	var c Config
	if err := env.Parse(&c); err != nil {
		return c, err
	}
	// Minimal validation for early failures.
	if c.JWTAlg != "RS256" {
		return c, errors.New("JWT_ALG must be RS256 for now")
	}
	if c.KeysDir == "" {
		return c, errors.New("KEYS_DIR is required")
	}
	if c.SigningKeyKID == "" {
		return c, errors.New("SIGNING_KEY_KID is required (e.g. k1-2025-08-25)")
	}
	return c, nil
}
