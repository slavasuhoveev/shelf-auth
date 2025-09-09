package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/service"
	"github.com/slavasuhoveev/shelf-auth/internal/util"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	DeviceID string `json:"device_id"`
}

type LoginResponse struct {
	AccessToken     string    `json:"access_token"`
	AccessExpiresAt time.Time `json:"access_expires_at"`
}

func LoginHandler(auth *service.AuthService, logger zerolog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON")
			return
		}
		req.Email = strings.TrimSpace(req.Email)
		req.DeviceID = strings.TrimSpace(req.DeviceID)
		if req.Email == "" || req.Password == "" || req.DeviceID == "" {
			writeAPIError(w, http.StatusBadRequest, "MISSING_FIELDS", "email, password and device_id are required")
			return
		}

		ip := util.ClientIP(r)
		ua := r.UserAgent()

		res, err := auth.Login(r.Context(), req.Email, req.Password, req.DeviceID, ip, ua)
		if err != nil {
			// log full error (with stack/context where)
			logger.Error().Err(err).Str("email", req.Email).Str("device_id", req.DeviceID).Msg("login failed")

			switch {
			case errors.Is(err, domain.ErrInvalidCredentials):
				writeAPIError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials")
				return
			case errors.Is(err, domain.ErrEmailNotVerified):
				writeAPIError(w, http.StatusForbidden, "EMAIL_NOT_VERIFIED", "email not verified")
				return
			default:
				writeAPIError(w, http.StatusInternalServerError,
					"INTERNAL", fmt.Sprintf("internal error: %v", err))
				return
			}
		}

		// HttpOnly refresh cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    res.RefreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Expires:  res.RefreshExp,
			MaxAge:   int(time.Until(res.RefreshExp).Seconds()),
		})

		writeJSON(w, http.StatusOK, LoginResponse{
			AccessToken:     res.AccessToken,
			AccessExpiresAt: res.AccessExp,
		})
	}
}
