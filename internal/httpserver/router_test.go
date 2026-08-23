//go:build unit

package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouter_Readyz(t *testing.T) {
	r := NewRouter(nil, fakeVerifier{}, fakeJWKS{}, testLogger(), Options{})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got, want := rr.Body.String(), `{"status":"ready","service":"shelf-auth"}`; got != want {
		t.Fatalf("unexpected body: got %q want %q", got, want)
	}
}
