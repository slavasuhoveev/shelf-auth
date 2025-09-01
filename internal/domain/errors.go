package domain

import "errors"

// Domain-level errors that can be mapped to transport (HTTP/gRPC) later.
var (
	// Input / validation
	ErrInvalidEmail      = errors.New("invalid email")
	ErrEmptyPasswordHash = errors.New("empty password hash")
	ErrInvalidDeviceID   = errors.New("invalid device id")
	ErrInvalidJTI        = errors.New("invalid jti")

	// Auth / session
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrEmailAlreadyTaken    = errors.New("email already taken")
	ErrEmailNotVerified     = errors.New("email not verified")
	ErrSessionExpired       = errors.New("session expired")
	ErrSessionRevoked       = errors.New("session revoked")
	ErrRefreshReuseDetected = errors.New("refresh token reuse detected")
)
