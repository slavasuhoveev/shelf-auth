//go:build unit

package service

import (
	"context"
	"testing"
	"time"

	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/security"
)

type memSessionsLogout struct {
	revokedHashes map[string]time.Time
}

func newMemSessionsLogout() *memSessionsLogout {
	return &memSessionsLogout{revokedHashes: map[string]time.Time{}}
}

func (m *memSessionsLogout) RevokeByHash(_ context.Context, h string, at time.Time) error {
	m.revokedHashes[h] = at
	return nil
}

// satisfy full SessionsWriter for compile (no-ops for others)
func (m *memSessionsLogout) Create(context.Context, *domain.Session) error         { return nil }
func (m *memSessionsLogout) Rotate(context.Context, string, *domain.Session) error { return nil }
func (m *memSessionsLogout) RevokeAllByUserAndDevice(context.Context, domain.ID, string, time.Time) error {
	return nil
}

func TestLogout_Idempotent_NoCookie(t *testing.T) {
	mem := newMemSessionsLogout()
	svc := &AuthService{sessions: mem}
	if err := svc.Logout(context.Background(), ""); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(mem.revokedHashes) != 0 {
		t.Fatalf("should not revoke when no cookie present")
	}
}

func TestLogout_RevokesHash(t *testing.T) {
	mem := newMemSessionsLogout()
	svc := &AuthService{sessions: mem}
	raw := "R-abc"
	if err := svc.Logout(context.Background(), raw); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	h := security.HashSHA256Hex(raw)
	if _, ok := mem.revokedHashes[h]; !ok {
		t.Fatalf("expected hash %s to be revoked", h)
	}
}
