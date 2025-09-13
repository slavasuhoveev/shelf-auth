//go:build unit

package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSetRefreshCookie_FlagsApplied(t *testing.T) {
	rr := httptest.NewRecorder()
	cfg := CookieCfg{
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		Domain:   "example.com",
	}
	exp := time.Now().Add(10 * time.Minute).UTC()

	setRefreshCookie(rr, "opaque-token", exp, cfg)

	sc := rr.Header().Get("Set-Cookie")
	if sc == "" {
		t.Fatalf("missing Set-Cookie header")
	}
	// basic assertions
	if !strings.Contains(sc, "refresh_token=") {
		t.Fatalf("cookie name missing: %q", sc)
	}
	if !strings.Contains(sc, "HttpOnly") {
		t.Fatalf("HttpOnly missing: %q", sc)
	}
	if !strings.Contains(sc, "Secure") {
		t.Fatalf("Secure missing: %q", sc)
	}
	if !strings.Contains(sc, "SameSite=None") {
		t.Fatalf("SameSite=None missing: %q", sc)
	}
	if !strings.Contains(sc, "Domain=example.com") {
		t.Fatalf("Domain missing: %q", sc)
	}
	if !strings.Contains(sc, "Path=/") {
		t.Fatalf("Path=/ missing: %q", sc)
	}
	if !strings.Contains(sc, "Expires=") {
		t.Fatalf("Expires missing: %q", sc)
	}
}

func TestClearRefreshCookie_Deletes(t *testing.T) {
	rr := httptest.NewRecorder()
	cfg := CookieCfg{
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Domain:   "",
	}
	clearRefreshCookie(rr, cfg)

	sc := rr.Header().Get("Set-Cookie")
	if sc == "" {
		t.Fatalf("missing Set-Cookie")
	}
	if !strings.Contains(sc, "refresh_token=") {
		t.Fatalf("cookie name missing")
	}
	if !strings.Contains(sc, "Expires=") {
		t.Fatalf("Expires missing: %q", sc)
	}
	// SameSite/Path/HttpOnly flags preserved on deletion as well
	if !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "Path=/") {
		t.Fatalf("flags missing on delete: %q", sc)
	}
}
