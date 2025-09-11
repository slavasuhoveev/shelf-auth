package service

import (
	"context"
	"time"

	"github.com/slavasuhoveev/shelf-auth/internal/security"
)

func (s *AuthService) Logout(ctx context.Context, rawRefresh string) error {
	// Idempotent: nothing to do if cookie is empty
	if !nonEmpty(rawRefresh) {
		return nil
	}
	hash := security.HashSHA256Hex(rawRefresh)
	// Revoke if present; if not present — still ok (idempotent)
	_ = s.sessions.(SessionsWriter).RevokeByHash(ctx, hash, time.Now().UTC())
	return nil
}
