package domain

import "errors"

// Domain-level errors that can be mapped to transport (HTTP/gRPC) later.
var (
	// Input / validation
	ErrInvalidEmail      = errors.New("invalid email")
	ErrEmptyPasswordHash = errors.New("empty password hash")
	ErrInvalidDeviceID   = errors.New("invalid device id")
	ErrInvalidJTI        = errors.New("invalid jti")

	// Generic not-found for repositories
	ErrNotFound = errors.New("not found")

	// Auth / session
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrEmailAlreadyTaken    = errors.New("email already taken")
	ErrEmailNotVerified     = errors.New("email not verified")
	ErrSessionExpired       = errors.New("session expired")
	ErrSessionRevoked       = errors.New("session revoked")
	ErrRefreshReuseDetected = errors.New("refresh token reuse detected")
	ErrMissingRefresh       = errors.New("refresh token missing")
	ErrInvalidRefresh       = errors.New("invalid refresh token")
	ErrExpiredRefresh       = errors.New("refresh token expired")
	ErrRevokedRefresh       = errors.New("refresh token revoked")
	ErrReusedRefresh        = errors.New("refresh token reuse detected")
	ErrInvalidAccessToken   = errors.New("invalid access token")
	ErrExpiredAccessToken   = errors.New("expired access token")
	ErrUserNotFound         = errors.New("user not found")
)
