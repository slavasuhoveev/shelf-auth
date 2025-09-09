package service

import (
	"context"

	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/security"
)

type RegisterResult struct {
	ID    domain.ID
	Email string
}

// Register creates a new user account.
// For MVP, verifyNow can be true to skip email confirmation.
func (s *AuthService) Register(ctx context.Context, emailRaw, password string, verifyNow bool) (*RegisterResult, error) {
	email, err := domain.ParseEmail(emailRaw)
	if err != nil {
		return nil, domain.ErrInvalidEmail
	}

	// Validate password with current policy.
	if err := security.ValidatePassword(security.DefaultPolicy(), password); err != nil {
		return nil, err
	}

	// Hash password.
	hash, err := security.HashPassword(password, s.pwOptions)
	if err != nil {
		return nil, err
	}

	// Build domain user.
	u, err := domain.NewUser(email, hash)
	if err != nil {
		return nil, err
	}
	u.EmailVerified = verifyNow // MVP: allow immediate verification if desired

	id, err := s.users.(UsersWriter).Insert(ctx, u)
	if err != nil {
		return nil, err
	}

	return &RegisterResult{
		ID:    id,
		Email: u.Email.String(),
	}, nil
}
