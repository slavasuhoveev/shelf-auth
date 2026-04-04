package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/security"
	"github.com/slavasuhoveev/shelf-auth/internal/service"
)

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func RegisterHandler(auth *service.AuthService, logger zerolog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON")
			return
		}
		req.Email = strings.TrimSpace(req.Email)
		if req.Email == "" || req.Password == "" {
			writeAPIError(w, http.StatusBadRequest, "MISSING_FIELDS", "email and password are required")
			return
		}

		res, err := auth.Register(r.Context(), req.Email, req.Password, true)
		if err != nil {
			logger.Error().Err(err).Str("email", req.Email).Msg("register failed")
			switch {
			case errors.Is(err, domain.ErrInvalidEmail):
				writeAPIError(w, http.StatusBadRequest, "INVALID_EMAIL", "invalid email")
				return
			case errors.Is(err, security.ErrPasswordTooShort):
				writeAPIError(w, http.StatusBadRequest, "PASSWORD_TOO_SHORT", "password must be at least 8 characters long")
				return
			case errors.Is(err, security.ErrPasswordNoDigit):
				writeAPIError(w, http.StatusBadRequest, "PASSWORD_NO_DIGIT", "password must contain at least one digit")
				return
			case errors.Is(err, security.ErrPasswordNoUpper):
				writeAPIError(w, http.StatusBadRequest, "PASSWORD_NO_UPPERCASE", "password must contain at least one uppercase letter")
				return
			case errors.Is(err, security.ErrPasswordNoLower):
				writeAPIError(w, http.StatusBadRequest, "PASSWORD_NO_LOWERCASE", "password must contain at least one lowercase letter")
				return
			case errors.Is(err, security.ErrEmptyPassword):
				writeAPIError(w, http.StatusBadRequest, "PASSWORD_EMPTY", "password must not be empty")
				return
			case errors.Is(err, security.ErrEmptyPasswordHash):
				writeAPIError(w, http.StatusInternalServerError, "PASSWORD_HASH_ERROR", "internal error while hashing password")
				return
			case errors.Is(err, security.ErrPasswordNoSymbol):
				writeAPIError(w, http.StatusBadRequest, "PASSWORD_NO_SYMBOL", "password must contain at least one symbol")
				return
			case errors.Is(err, security.ErrPasswordHasSpace):
				writeAPIError(w, http.StatusBadRequest, "PASSWORD_HAS_SPACE", "password must not contain spaces")
				return
			case errors.Is(err, domain.ErrEmailAlreadyTaken):
				writeAPIError(w, http.StatusConflict, "EMAIL_TAKEN", "email already taken")
				return
			default:
				writeAPIError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
				return
			}
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(RegisterResponse{
			ID:    res.ID.String(),
			Email: res.Email,
		})
	}
}
