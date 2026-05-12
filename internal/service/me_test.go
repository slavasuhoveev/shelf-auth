//go:build unit

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/slavasuhoveev/shelf-auth/internal/domain"
)

func TestMe_ReturnsUserProjection(t *testing.T) {
	userID := domain.NewID()
	email, _ := domain.ParseEmail("me@example.com")
	user := &domain.User{
		ID:            userID,
		Email:         email,
		EmailVerified: true,
	}
	repo := &fakeUsersRepo{
		byEmail: map[string]*domain.User{
			email.String(): user,
		},
	}
	svc := newTestService(t, repo)

	res, err := svc.Me(context.Background(), userID)
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if res.ID != userID || res.Email != email.String() || !res.EmailVerified {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestMe_PropagatesRepositoryError(t *testing.T) {
	svc := newTestService(t, &fakeUsersRepo{})

	_, err := svc.Me(context.Background(), domain.NewID())
	if !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}
