package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/httpserver/contextkeys"
	"github.com/slavasuhoveev/shelf-auth/internal/service"
)

type MeResponse struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
}

func MeHandler(auth *service.AuthService, logger zerolog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		userID, ok := r.Context().Value(contextkeys.UserIDKey).(domain.ID)

		if !ok || userID.IsZero() {
			writeAPIError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing auth context")
			return
		}

		res, err := auth.Me(r.Context(), userID)
		if err != nil {
			logger.Error().
				Err(err).
				Str("user_id", userID.String()).
				Msg("me failed")

			switch {
			case errors.Is(err, domain.ErrUserNotFound):
				writeAPIError(w, http.StatusUnauthorized, "UNAUTHORIZED", "user not found")
				return
			default:
				writeAPIError(w, http.StatusInternalServerError, "INTERNAL", "internal error")
				return
			}
		}

		writeJSON(w, http.StatusOK, MeResponse{
			ID:            res.ID.String(),
			Email:         res.Email,
			EmailVerified: res.EmailVerified,
			CreatedAt:     res.CreatedAt,
		})
	}
}
