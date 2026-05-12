//go:build unit
// +build unit

package domain

import (
	"testing"
	"time"
)

func TestNewUser_Success(t *testing.T) {
	email, _ := ParseEmail("a@b.com")
	u, err := NewUser(email, "hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !u.ID.IsZero() {
		t.Errorf("new user should not have ID yet, got %s", u.ID)
	}
	if u.Email.String() != "a@b.com" {
		t.Errorf("unexpected email: %s", u.Email.String())
	}
	if !u.CreatedAt.Equal(u.UpdatedAt) {
		t.Error("CreatedAt and UpdatedAt should be equal at creation")
	}
}

func TestNewUser_Invalid(t *testing.T) {
	if _, err := NewUser(Email{}, "hash"); err != ErrInvalidEmail {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
	email, _ := ParseEmail("a@b.com")
	if _, err := NewUser(email, ""); err != ErrEmptyPasswordHash {
		t.Errorf("expected ErrEmptyPasswordHash, got %v", err)
	}
}

func TestUser_Touch(t *testing.T) {
	email, _ := ParseEmail("a@b.com")
	u, _ := NewUser(email, "hash")
	oldUpdated := u.UpdatedAt
	time.Sleep(10 * time.Millisecond)
	u.Touch()
	if !u.UpdatedAt.After(oldUpdated) {
		t.Error("UpdatedAt should be updated by Touch()")
	}
}
