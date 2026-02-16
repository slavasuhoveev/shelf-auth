// internal/httpserver/handlers/refresh.go
package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/service"
	"github.com/slavasuhoveev/shelf-auth/internal/util"
)

func RefreshHandler(auth *service.AuthService, logger zerolog.Logger, cookieCfg CookieCfg) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("refresh_token")
		if err != nil || strings.TrimSpace(c.Value) == "" {
			writeAPIError(w, http.StatusUnauthorized, "MISSING_REFRESH", "refresh token cookie is required")
			return
		}
		// Device can come from body/header; for MVP we accept optional header.
		deviceID := strings.TrimSpace(r.Header.Get("X-Device-ID"))
		if deviceID == "" {
			deviceID = "unknown"
		}
		ip := util.ClientIP(r)
		user_agent := r.UserAgent()

		res, svcErr := auth.Refresh(r.Context(), c.Value, deviceID, ip, user_agent)
		if svcErr != nil {
			logger.Warn().Err(svcErr).Str("device_id", deviceID).Msg("refresh failed")
			switch {
			case errors.Is(svcErr, domain.ErrMissingRefresh):
				writeAPIError(w, http.StatusUnauthorized, "MISSING_REFRESH", "refresh token missing")
				return
			case errors.Is(svcErr, domain.ErrInvalidRefresh),
				errors.Is(svcErr, domain.ErrExpiredRefresh),
				errors.Is(svcErr, domain.ErrRevokedRefresh):
				writeAPIError(w, http.StatusUnauthorized, "INVALID_REFRESH", "invalid or expired refresh")
				return
			case errors.Is(svcErr, domain.ErrReusedRefresh):
				// Reuse detected → revoke chain → require fresh login
				writeAPIError(w, http.StatusUnauthorized, "REUSED_REFRESH", "refresh reuse detected, please login again")
				return
			default:
				writeAPIError(w, http.StatusInternalServerError, "INTERNAL", "internal error")
				return
			}
		}

		setRefreshCookie(w, res.RefreshToken, res.RefreshExp, cookieCfg)

		writeJSON(w, http.StatusOK, LoginResponse{
			AccessToken:     res.AccessToken,
			AccessExpiresAt: res.AccessExp,
		})
	}
}
