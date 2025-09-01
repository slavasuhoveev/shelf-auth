package domain

import (
	"net/mail"
	"strings"
)

// Email is a value object representing a normalized email address.
type Email struct {
	value string
}

// ParseEmail validates and normalizes an email string.
// Normalization: trim spaces, preserve case (DB uses CITEXT for case-insensitive ops).
func ParseEmail(raw string) (Email, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Email{}, ErrInvalidEmail
	}
	// Basic RFC5322 validation. This is permissive but good enough for domain-level check.
	// We rely on DB CITEXT for case-insensitive uniqueness.
	if _, err := mail.ParseAddress(s); err != nil {
		return Email{}, ErrInvalidEmail
	}
	return Email{value: s}, nil
}

// String returns the canonical string form.
func (e Email) String() string { return e.value }

// IsZero reports whether the email is unset.
func (e Email) IsZero() bool { return e.value == "" }
