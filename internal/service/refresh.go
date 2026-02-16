package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/security"
	"github.com/slavasuhoveev/shelf-auth/internal/tokens"
)

// RefreshResult is returned to the handler.
type RefreshResult struct {
	AccessToken  string
	AccessExp    time.Time
	RefreshToken string
	RefreshExp   time.Time
}

func (s *AuthService) Refresh(ctx context.Context, rawRefresh, deviceID, ipStr, user_agent string) (*RefreshResult, error) {
	if !nonEmpty(rawRefresh) {
		return nil, domain.ErrMissingRefresh
	}

	// Find session by hash
	hash := security.HashSHA256Hex(rawRefresh)
	sess, err := s.sessions.(SessionsReader).FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrInvalidRefresh
		}
		return nil, err
	}

	now := time.Now().UTC()

	// Basic checks
	if sess.RevokedAt != nil {
		return nil, domain.ErrRevokedRefresh
	}
	if now.After(sess.ExpiresAt) {
		return nil, domain.ErrExpiredRefresh
	}

	// Reuse detection: the moment a refresh is rotated, old row gets replaced_by=newJTI.
	// If client still presents the old token -> REUSE → revoke all sessions for this user+device.
	if sess.ReplacedBy != nil {
		_ = s.sessions.(SessionsWriter).RevokeAllByUserAndDevice(ctx, sess.UserID, sess.DeviceID, now)
		return nil, domain.ErrReusedRefresh
	}

	// Sign new access
	acc, exp, err := s.signer.SignAccess(tokens.AccessClaims{
		UserID: sess.UserID.String(),
		Email:  "", // optional: load user or persist email in sessions if needed
	}, s.accessTTL)
	if err != nil {
		return nil, err
	}

	// Rotate refresh
	newRaw, err := security.GenerateOpaqueToken(32)
	if err != nil {
		return nil, err
	}
	newHash := security.HashSHA256Hex(newRaw)

	parsedIP, err := domain.ParseIP(ipStr)
	if err != nil {
		return nil, err
	}

	newSess := &domain.Session{
		UserID:      sess.UserID,
		JTI:         uuid.NewString(),
		RefreshHash: newHash,
		DeviceID:    deviceID,
		IP:          parsedIP,
		UserAgent:   user_agent,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.refreshTTL),
	}

	if err := s.sessions.(SessionsWriter).Rotate(ctx, sess.JTI, newSess); err != nil {
		return nil, err
	}

	return &RefreshResult{
		AccessToken:  acc,
		AccessExp:    exp,
		RefreshToken: newRaw,
		RefreshExp:   newSess.ExpiresAt,
	}, nil
}
