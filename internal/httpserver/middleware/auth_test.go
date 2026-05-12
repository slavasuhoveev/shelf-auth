//go:build unit

package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/httpserver/contextkeys"
	"github.com/slavasuhoveev/shelf-auth/internal/tokens"
)

type verifierFunc func(string) (*tokens.AccessClaims, error)

func (f verifierFunc) VerifyAccess(token string) (*tokens.AccessClaims, error) {
	return f(token)
}

func TestAuthMiddleware_RejectsMissingOrInvalidToken(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		verifier verifierFunc
	}{
		{
			name: "missing header",
			verifier: func(string) (*tokens.AccessClaims, error) {
				t.Fatal("verifier should not be called")
				return nil, nil
			},
		},
		{
			name:   "verifier error",
			header: "Bearer bad",
			verifier: func(string) (*tokens.AccessClaims, error) {
				return nil, errors.New("bad token")
			},
		},
		{
			name:   "invalid user id claim",
			header: "Bearer token",
			verifier: func(string) (*tokens.AccessClaims, error) {
				return &tokens.AccessClaims{UserID: "not-a-uuid"}, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("next should not be called")
			})
			handler := AuthMiddleware(tt.verifier, zerolog.Nop())(next)

			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestAuthMiddleware_PutsUserIDInContext(t *testing.T) {
	userID := domain.NewID()
	handler := AuthMiddleware(verifierFunc(func(token string) (*tokens.AccessClaims, error) {
		if token != "good" {
			t.Fatalf("token = %q, want good", token)
		}
		return &tokens.AccessClaims{UserID: userID.String()}, nil
	}), zerolog.Nop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := r.Context().Value(contextkeys.UserIDKey).(domain.ID)
		if !ok || got != userID {
			t.Fatalf("context user ID = %v (%t), want %s", got, ok, userID)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer good")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}
