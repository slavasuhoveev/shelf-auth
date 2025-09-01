package domain

import "time"

// User is an aggregate root representing an authenticated principal.
type User struct {
	ID            ID
	Email         Email
	PasswordHash  string
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// NewUser constructs a new user with invariants enforced.
// PasswordHash must be a pre-hashed string (bcrypt or similar), never a raw password.
func NewUser(email Email, passwordHash string) (*User, error) {
	if email.IsZero() {
		return nil, ErrInvalidEmail
	}
	if !nonEmpty(passwordHash) {
		return nil, ErrEmptyPasswordHash
	}

	now := Now()
	return &User{
		Email:         email,
		PasswordHash:  passwordHash,
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}, nil
}

// Touch updates the UpdatedAt timestamp (call on updates).
func (u *User) Touch() { u.UpdatedAt = Now() }
