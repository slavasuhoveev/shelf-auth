package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/service"
)

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	ID    int64  `json:"id"`
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
			ID:    int64(res.ID),
			Email: res.Email,
		})
	}
}
