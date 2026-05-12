//go:build unit

package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/security"
	"github.com/slavasuhoveev/shelf-auth/internal/tokens"
)

// ---- fakes ----

type fakeSigner struct{}

func (fakeSigner) SignAccess(_ tokens.AccessClaims, ttl time.Duration) (string, time.Time, error) {
	return "acc.token", time.Now().Add(ttl), nil
}

type memSessions struct {
	byHash  map[string]*domain.Session
	revoked map[string]bool // key: "<userID>|<deviceID>"
	nextID  int
}

func newMemSessions() *memSessions {
	return &memSessions{
		byHash:  make(map[string]*domain.Session),
		revoked: make(map[string]bool),
		nextID:  1,
	}
}

func key(u domain.ID, d string) string { return fmt.Sprintf("%s|%s", u, d) }

func (m *memSessions) FindByHash(_ context.Context, h string) (*domain.Session, error) {
	if s, ok := m.byHash[h]; ok {
		return s, nil
	}
	return nil, domain.ErrNotFound
}

func (m *memSessions) Create(_ context.Context, s *domain.Session) error {
	s.ID = domain.NewID()
	m.nextID++
	m.byHash[s.RefreshHash] = s
	return nil
}

func (m *memSessions) Rotate(_ context.Context, oldJTI string, ns *domain.Session) error {
	// give new session an ID
	ns.ID = domain.NewID()
	m.nextID++

	// mark old session as replaced_by = new ID
	for _, s := range m.byHash {
		if s.JTI == oldJTI {
			rb := ns.ID // *domain.ID expected
			s.ReplacedBy = &rb
			break
		}
	}
	m.byHash[ns.RefreshHash] = ns
	return nil
}

func (m *memSessions) RevokeAllByUserAndDevice(_ context.Context, userID domain.ID, deviceID string, at time.Time) error {
	m.revoked[key(userID, deviceID)] = true
	for _, s := range m.byHash {
		if s.UserID == userID && s.DeviceID == deviceID && s.RevokedAt == nil {
			s.RevokedAt = &at
		}
	}
	return nil
}

func (m *memSessions) RevokeByHash(_ context.Context, _ string, _ time.Time) error {
	return nil
}

// ---- helpers ----

func newSvc(t *testing.T) *AuthService {
	t.Helper()
	sess := newMemSessions()
	return &AuthService{
		users:      nil,
		sessions:   sess,
		signer:     fakeSigner{},
		accessTTL:  15 * time.Minute,
		refreshTTL: 30 * 24 * time.Hour,
		pwOptions:  security.DefaultOptions(),
	}
}

func seedSession(t *testing.T, svc *AuthService, raw string, userID domain.ID, deviceID string) *domain.Session {
	t.Helper()
	h := security.HashSHA256Hex(raw)
	now := time.Now().UTC()
	s := &domain.Session{
		UserID:      userID,
		JTI:         uuid.NewString(),
		RefreshHash: h,
		DeviceID:    deviceID,
		IP:          domain.NewIPFromNet(net.ParseIP("1.2.3.4")),
		CreatedAt:   now,
		ExpiresAt:   now.Add(30 * 24 * time.Hour),
	}
	if err := svc.sessions.(SessionsWriter).Create(context.Background(), s); err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	return s
}

// ---- tests ----

func TestRefresh_Success_Rotation(t *testing.T) {
	svc := newSvc(t)
	raw := "R1-token"
	s := seedSession(t, svc, raw, domain.NewID(), "dev-1")

	res, err := svc.Refresh(context.Background(), raw, "dev-1", "1.1.1.1", "UA")
	if err != nil {
		t.Fatalf("refresh err: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatalf("empty tokens: %+v", res)
	}
	// old session should be marked replaced
	if s.ReplacedBy == nil {
		t.Fatalf("expected replaced_by to be set")
	}
}

func TestRefresh_Reuse_Detected_RevokesDevice(t *testing.T) {
	svc := newSvc(t)
	raw := "R1"
	user := domain.NewID()
	dev := "dev-7"
	seed := seedSession(t, svc, raw, user, dev)

	// first refresh ok → rotation
	if _, err := svc.Refresh(context.Background(), raw, dev, "1.1.1.1", "UA"); err != nil {
		t.Fatalf("first refresh err: %v", err)
	}
	if seed.ReplacedBy == nil {
		t.Fatalf("expected replaced_by set after first refresh")
	}

	// reuse old R1 → should revoke device sessions and return ErrReusedRefresh
	_, err := svc.Refresh(context.Background(), raw, dev, "1.1.1.1", "UA")
	if !errors.Is(err, domain.ErrReusedRefresh) {
		t.Fatalf("expected ErrReusedRefresh, got %v", err)
	}
}

func TestRefresh_Expired(t *testing.T) {
	svc := newSvc(t)
	raw := "R1-expired"
	h := security.HashSHA256Hex(raw)
	now := time.Now().UTC().Add(-time.Hour)
	s := &domain.Session{
		UserID:      domain.NewID(),
		JTI:         uuid.NewString(),
		RefreshHash: h,
		DeviceID:    "dev",
		IP:          domain.NewIPFromNet(net.ParseIP("127.0.0.1")),
		CreatedAt:   now.Add(-30 * 24 * time.Hour),
		ExpiresAt:   now, // already expired
	}
	_ = svc.sessions.(SessionsWriter).Create(context.Background(), s)

	_, err := svc.Refresh(context.Background(), raw, "dev", "ip", "UA")
	if !errors.Is(err, domain.ErrExpiredRefresh) {
		t.Fatalf("expected ErrExpiredRefresh, got %v", err)
	}
}

func TestRefresh_Invalid(t *testing.T) {
	svc := newSvc(t)
	_, err := svc.Refresh(context.Background(), "does-not-exist", "dev", "ip", "UA")
	if !errors.Is(err, domain.ErrInvalidRefresh) {
		t.Fatalf("expected ErrInvalidRefresh, got %v", err)
	}
}
