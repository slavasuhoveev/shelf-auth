package service

import (
	"context"
	"errors"
	"time"

	"github.com/slavasuhoveev/shelf-auth/internal/domain"
)

var ErrUnauthorized = errors.New("unauthorized")

type MeResult struct {
	ID            domain.ID
	Email         string
	EmailVerified bool
	CreatedAt     time.Time
}

func (s *AuthService) Me(ctx context.Context, userID domain.ID) (*MeResult, error) {
	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &MeResult{
		ID:            u.ID,
		Email:         u.Email.String(),
		EmailVerified: u.EmailVerified,
	}, nil
}
