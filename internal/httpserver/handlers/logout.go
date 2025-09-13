package handlers

import (
	"net/http"

	"github.com/rs/zerolog"
	"github.com/slavasuhoveev/shelf-auth/internal/service"
)

func LogoutHandler(auth *service.AuthService, logger zerolog.Logger, cookieCfg CookieCfg) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var raw string
		if c, err := r.Cookie("refresh_token"); err == nil {
			raw = c.Value
		}

		if err := auth.Logout(r.Context(), raw); err != nil {
			logger.Warn().Err(err).Msg("logout encountered error")
		}

		clearRefreshCookie(w, cookieCfg)

		w.WriteHeader(http.StatusNoContent)
	}
}
