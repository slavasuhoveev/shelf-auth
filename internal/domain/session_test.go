//go:build unit
// +build unit

package domain

import (
	"errors"
	"testing"
	"time"
)

func TestNewSession_Success(t *testing.T) {
	userID := NewID()
	s, err := NewSession(userID, "device", "jti1", "hash", "127.0.0.1", "user_agent", time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.UserID != userID {
		t.Errorf("unexpected user ID: %s", s.UserID)
	}
	if !s.ExpiresAt.After(s.CreatedAt) {
		t.Error("ExpiresAt must be after CreatedAt")
	}
}

func TestNewSession_Invalid(t *testing.T) {
	userID := NewID()

	_, err := NewSession(ID{}, "device", "jti", "hash", "", "", time.Hour)
	if err == nil {
		t.Error("expected error for invalid userID")
	}
	_, err = NewSession(userID, "   ", "jti", "hash", "", "", time.Hour)
	if !errors.Is(err, ErrInvalidDeviceID) {
		t.Errorf("expected ErrInvalidDeviceID, got %v", err)
	}
	_, err = NewSession(userID, "device", "", "hash", "", "", time.Hour)
	if !errors.Is(err, ErrInvalidJTI) {
		t.Errorf("expected ErrInvalidJTI, got %v", err)
	}
}

func TestSession_Lifecycle(t *testing.T) {
	s, _ := NewSession(NewID(), "device", "jti1", "hash", "", "", time.Millisecond*10)

	// Not expired immediately
	if s.IsExpired(time.Now()) {
		t.Error("session should not be expired yet")
	}

	// Expired after TTL
	time.Sleep(20 * time.Millisecond)
	if !s.IsExpired(time.Now()) {
		t.Error("session should be expired")
	}

	// Revoke
	now := Now()
	s.Revoke(now)
	if !s.IsRevoked() {
		t.Error("session should be revoked")
	}

	// Rotation
	replacementID := NewID()
	s.MarkRotated(replacementID)
	if s.ReplacedBy == nil || *s.ReplacedBy != replacementID {
		t.Error("MarkRotated did not set ReplacedBy correctly")
	}
}
