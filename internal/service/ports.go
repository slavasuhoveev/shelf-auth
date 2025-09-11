package service

import (
	"context"
	"time"

	"github.com/slavasuhoveev/shelf-auth/internal/domain"
)

// Users
type UsersReader interface {
	FindByEmail(ctx context.Context, email domain.Email) (*domain.User, error)
}
type UsersWriter interface {
	Insert(ctx context.Context, u *domain.User) (domain.ID, error)
}

// Sessions
type SessionsReader interface {
	FindByHash(ctx context.Context, hashHex string) (*domain.Session, error)
}
type SessionsWriter interface {
	Create(ctx context.Context, s *domain.Session) error
	Rotate(ctx context.Context, oldJTI string, newS *domain.Session) error
	RevokeAllByUserAndDevice(ctx context.Context, userID domain.ID, deviceID string, at time.Time) error
	RevokeByHash(ctx context.Context, hashHex string, at time.Time) error
}
