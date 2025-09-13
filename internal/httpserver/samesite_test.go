//go:build unit

package httpserver

import (
	"net/http"
	"testing"
)

func TestParseSameSite(t *testing.T) {
	if got := ParseSameSite("Strict"); got != http.SameSiteStrictMode {
		t.Fatalf("Strict parsed wrong: %v", got)
	}
	if got := ParseSameSite("None"); got != http.SameSiteNoneMode {
		t.Fatalf("None parsed wrong: %v", got)
	}
	if got := ParseSameSite("Lax"); got != http.SameSiteLaxMode {
		t.Fatalf("Lax parsed wrong: %v", got)
	}
	if got := ParseSameSite("unknown"); got != http.SameSiteLaxMode {
		t.Fatalf("default should be Lax")
	}
}
