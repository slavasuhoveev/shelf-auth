//go:build unit
// +build unit

package domain

import (
	"testing"
	"time"
)

func TestNewSession_Success(t *testing.T) {
	s, err := NewSession(1, "device", "jti1", "hash", "127.0.0.1", "ua", time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s.ExpiresAt.After(s.CreatedAt) {
		t.Error("ExpiresAt must be after CreatedAt")
	}
}

func TestNewSession_Invalid(t *testing.T) {
	_, err := NewSession(0, "device", "jti", "hash", "", "", time.Hour)
	if err == nil {
		t.Error("expected error for invalid userID")
	}
	_, err = NewSession(1, "", "jti", "hash", "", "", time.Hour)
	if err != ErrInvalidDeviceID {
		t.Errorf("expected ErrInvalidDeviceID, got %v", err)
	}
	_, err = NewSession(1, "device", "", "hash", "", "", time.Hour)
	if err != ErrInvalidJTI {
		t.Errorf("expected ErrInvalidJTI, got %v", err)
	}
}

func TestSession_Lifecycle(t *testing.T) {
	s, _ := NewSession(1, "device", "jti1", "hash", "", "", time.Millisecond*10)

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
	s.MarkRotated(42)
	if s.ReplacedBy == nil || *s.ReplacedBy != 42 {
		t.Error("MarkRotated did not set ReplacedBy correctly")
	}
}
