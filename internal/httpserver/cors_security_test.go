//go:build unit

package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
	"github.com/slavasuhoveev/shelf-auth/internal/httpserver/handlers"
	"github.com/slavasuhoveev/shelf-auth/internal/httpserver/middleware"
	"github.com/slavasuhoveev/shelf-auth/internal/tokens"
)

// fake JWKS provider so router can be built
type fakeJWKS struct{}

func (fakeJWKS) Current() ([]byte, string, time.Duration) {
	return []byte(`{"keys":[]}`), `W/"t"`, 60 * time.Second
}

type fakeVerifier struct{}

func (fakeVerifier) VerifyAccess(string) (*tokens.AccessClaims, error) {
	return &tokens.AccessClaims{}, nil
}

// minimal logger
func testLogger() zerolog.Logger {
	return zerolog.Nop()
}

func TestCORS_Preflight_AllowedOrigin(t *testing.T) {
	r := NewRouter(
		nil, // we don't hit auth handlers in these tests
		fakeVerifier{},
		fakeJWKS{},
		testLogger(),
		Options{
			CORSOrigins: []string{"http://localhost:3000"},
			CookieCfg: handlers.CookieCfg{
				Secure:   false,
				SameSite: ParseSameSite("None"),
				Domain:   "",
			},
		},
	)

	req := httptest.NewRequest(http.MethodOptions, "/login", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent && rr.Code != http.StatusOK {
		t.Fatalf("expected 204/200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("missing/invalid ACAO: %q", got)
	}
	if rr.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("missing ACAC=true")
	}
	// security headers should be present as well
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing security header nosniff")
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing security header X-Frame-Options")
	}
	if rr.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("missing security header Referrer-Policy")
	}
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("missing CSP header")
	}
}

func TestCORS_DisallowedOrigin_NoHeaders(t *testing.T) {
	r := NewRouter(
		nil,
		fakeVerifier{},
		fakeJWKS{},
		testLogger(),
		Options{
			CORSOrigins: []string{"https://app.example.com"},
			CookieCfg:   handlers.CookieCfg{Secure: true, SameSite: ParseSameSite("Lax")},
		},
	)

	req := httptest.NewRequest(http.MethodOptions, "/login", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// No CORS headers for disallowed origin
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("ACAO must be empty for disallowed origin")
	}
	// Security headers are still set
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing security header nosniff")
	}
}

func TestSecurityHeaders_OnHealthz(t *testing.T) {
	r := chi.NewRouter()
	// mount only our security headers middleware to test in isolation
	r.Use(func(next http.Handler) http.Handler {
		return middleware.SecurityHeaders(next)
	})
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" ||
		rr.Header().Get("X-Frame-Options") != "DENY" ||
		rr.Header().Get("Referrer-Policy") != "no-referrer" ||
		rr.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("security headers missing")
	}
}
