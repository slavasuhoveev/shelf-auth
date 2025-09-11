package handlers

import (
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"github.com/slavasuhoveev/shelf-auth/internal/service"
)

func LogoutHandler(auth *service.AuthService, logger zerolog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var raw string
		if c, err := r.Cookie("refresh_token"); err == nil {
			raw = c.Value
		}

		if err := auth.Logout(r.Context(), raw); err != nil {
			logger.Warn().Err(err).Msg("logout encountered error")
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   0,
			Expires:  time.Unix(0, 0).UTC(),
		})

		w.WriteHeader(http.StatusNoContent)
	}
}
