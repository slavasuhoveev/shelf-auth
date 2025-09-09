// internal/httpserver/handlers/refresh.go
package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/service"
	"github.com/slavasuhoveev/shelf-auth/internal/util"
)

func RefreshHandler(auth *service.AuthService, logger zerolog.Logger) http.HandlerFunc {
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
		ua := r.UserAgent()

		res, svcErr := auth.Refresh(r.Context(), c.Value, deviceID, ip, ua)
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

		// Set rotated refresh cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    res.RefreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true, // set false only for local http testing if needed
			SameSite: http.SameSiteLaxMode,
			Expires:  res.RefreshExp,
			MaxAge:   int(time.Until(res.RefreshExp).Seconds()),
		})

		writeJSON(w, http.StatusOK, struct {
			AccessToken     string    `json:"access_token"`
			AccessExpiresAt time.Time `json:"access_expires_at"`
		}{
			AccessToken:     res.AccessToken,
			AccessExpiresAt: res.AccessExp,
		})
	}
}
