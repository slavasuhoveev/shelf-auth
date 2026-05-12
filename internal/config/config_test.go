//go:build unit

package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoad_DefaultsAndParsedValues(t *testing.T) {
	t.Setenv("SIGNING_KEY_KID", "k-test")
	t.Setenv("CORS_ORIGINS", "http://localhost:3000,https://app.example.com")
	t.Setenv("ACCESS_TTL", "20m")
	t.Setenv("COOKIE_SECURE", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Env != "dev" {
		t.Fatalf("unexpected Env: %q", cfg.Env)
	}
	if cfg.JWTAlg != "RS256" {
		t.Fatalf("unexpected JWTAlg: %q", cfg.JWTAlg)
	}
	if cfg.AccessTTL != 20*time.Minute {
		t.Fatalf("unexpected AccessTTL: %v", cfg.AccessTTL)
	}
	if cfg.CookieSecure {
		t.Fatalf("expected CookieSecure=false")
	}
	if len(cfg.CORSOrigins) != 2 || cfg.CORSOrigins[1] != "https://app.example.com" {
		t.Fatalf("unexpected CORSOrigins: %#v", cfg.CORSOrigins)
	}
}

func TestLoad_Validation(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name: "unsupported jwt alg",
			env: map[string]string{
				"SIGNING_KEY_KID": "k-test",
				"JWT_ALG":         "HS256",
			},
			wantErr: "JWT_ALG must be RS256",
		},
		{
			name: "missing keys dir",
			env: map[string]string{
				"SIGNING_KEY_KID": "k-test",
				"KEYS_DIR":        "   ",
			},
			wantErr: "KEYS_DIR is required",
		},
		{
			name: "missing kid",
			env: map[string]string{
				"SIGNING_KEY_KID": "",
			},
			wantErr: "SIGNING_KEY_KID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			_, err := Load()
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q, got %v", tt.wantErr, err)
			}
		})
	}
}
