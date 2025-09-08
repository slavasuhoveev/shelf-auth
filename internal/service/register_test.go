//go:build unit
// +build unit

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/security"
)

// ---- fakes/mocks ----

type fakeUsersRepo struct {
	inserted *domain.User
	forceErr error
	nextID   domain.ID
	byEmail  map[string]*domain.User
}

func (f *fakeUsersRepo) Insert(_ context.Context, u *domain.User) (domain.ID, error) {
	if f.forceErr != nil {
		return 0, f.forceErr
	}
	c := *u
	f.inserted = &c
	if f.nextID == 0 {
		f.nextID = 1
	}
	if f.byEmail == nil {
		f.byEmail = make(map[string]*domain.User)
	}
	f.byEmail[u.Email.String()] = &c
	return f.nextID, nil
}

// ---- helpers ----

func (f *fakeUsersRepo) FindByEmail(_ context.Context, email domain.Email) (*domain.User, error) {
	if f.byEmail != nil {
		if u, ok := f.byEmail[email.String()]; ok {
			return u, nil
		}
	}
	return nil, errors.New("not found")
}

func newTestService(t *testing.T, ur *fakeUsersRepo) *AuthService {
	t.Helper()

	// We only need users repo and password options for Register.
	// Other deps (sessions, signer) are not used by Register and can be nil.
	return &AuthService{
		users:      ur,
		sessions:   nil,
		signer:     nil,
		accessTTL:  15 * time.Minute,
		refreshTTL: 30 * 24 * time.Hour,
		pwOptions:  security.DefaultOptions(),
	}
}

// ---- tests ----

func TestRegister_Success(t *testing.T) {
	frepo := &fakeUsersRepo{nextID: 42}
	svc := newTestService(t, frepo)

	res, err := svc.Register(context.Background(), "new.user@example.com", "abc12345", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.ID != 42 || res.Email != "new.user@example.com" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if frepo.inserted == nil {
		t.Fatalf("expected user to be inserted")
	}
	if frepo.inserted.Email.String() != "new.user@example.com" {
		t.Errorf("stored email mismatch: %s", frepo.inserted.Email.String())
	}
	if frepo.inserted.PasswordHash == "" {
		t.Errorf("expected password hash to be set")
	}
	if !frepo.inserted.EmailVerified {
		t.Errorf("expected EmailVerified=true when verifyNow=true")
	}
}

func TestRegister_InvalidEmail(t *testing.T) {
	frepo := &fakeUsersRepo{}
	svc := newTestService(t, frepo)

	_, err := svc.Register(context.Background(), "not-an-email", "abc12345", true)
	if !errors.Is(err, domain.ErrInvalidEmail) {
		t.Fatalf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	frepo := &fakeUsersRepo{}
	svc := newTestService(t, frepo)

	// too short
	_, err := svc.Register(context.Background(), "ok@example.com", "123", true)
	if err == nil {
		t.Fatalf("expected password policy error, got nil")
	}
}

func TestRegister_EmailAlreadyTaken(t *testing.T) {
	frepo := &fakeUsersRepo{forceErr: domain.ErrEmailAlreadyTaken}
	svc := newTestService(t, frepo)

	_, err := svc.Register(context.Background(), "dupe@example.com", "abc12345", true)
	if !errors.Is(err, domain.ErrEmailAlreadyTaken) {
		t.Fatalf("expected ErrEmailAlreadyTaken, got %v", err)
	}
}
