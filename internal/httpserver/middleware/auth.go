package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/httpserver/contextkeys"
	"github.com/slavasuhoveev/shelf-auth/internal/tokens"
)

func AuthMiddleware(tokenVerifier tokens.Verifier, logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing auth header", http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := tokenVerifier.VerifyAccess(token)
			if err != nil {
				logger.Warn().
					Err(err).
					Msg("invalid access token")
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			userID, err := domain.ParseID(claims.UserID)
			if err != nil {
				logger.Warn().
					Err(err).
					Str("user_id", claims.UserID).
					Msg("invalid user id in token")
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), contextkeys.UserIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
