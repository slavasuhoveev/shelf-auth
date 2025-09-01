package domain

import "time"

// Session models a refresh session for a particular user/device.
// We store a hash of the opaque refresh token (never the raw token).
type Session struct {
	ID          ID
	UserID      ID
	DeviceID    string
	JTI         string // unique identifier per refresh token instance
	RefreshHash string // hash(opaque_refresh_token)
	IP          string // optional: remote IP for audit
	UserAgent   string // optional: UA for audit
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ReplacedBy  *ID        // points to the new session created during rotation
	RevokedAt   *time.Time // set when session is force-revoked
}

// NewSession creates a new refresh session with the given TTL.
// DeviceID and JTI must be non-empty. RefreshHash must be non-empty.
func NewSession(userID ID, deviceID, jti, refreshHash, ip, ua string, ttl time.Duration) (*Session, error) {
	if userID <= 0 {
		return nil, ErrInvalidCredentials // or a dedicated ErrInvalidUserID, if needed
	}
	if !nonEmpty(deviceID) {
		return nil, ErrInvalidDeviceID
	}
	if !nonEmpty(jti) {
		return nil, ErrInvalidJTI
	}
	if !nonEmpty(refreshHash) {
		return nil, ErrInvalidCredentials // keep generic; precise error can be added later
	}

	now := Now()
	return &Session{
		UserID:      userID,
		DeviceID:    deviceID,
		JTI:         jti,
		RefreshHash: refreshHash,
		IP:          ip,
		UserAgent:   ua,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}, nil
}

// IsExpired reports whether the session expired by time.
func (s *Session) IsExpired(at time.Time) bool {
	return !at.Before(s.ExpiresAt)
}

// IsRevoked reports whether the session was explicitly revoked.
func (s *Session) IsRevoked() bool { return s.RevokedAt != nil }

// IsActive reports whether the session can be used for refresh right now.
func (s *Session) IsActive(at time.Time) bool {
	return !s.IsRevoked() && !s.IsExpired(at)
}

// Revoke marks the session as revoked (e.g., on logout).
func (s *Session) Revoke(at time.Time) {
	if s.RevokedAt == nil {
		s.RevokedAt = ptrTime(at)
	}
}

// MarkRotated links this session to a new one created during token rotation.
// After rotation, old session should not be accepted again (reuse detection).
func (s *Session) MarkRotated(newSessionID ID) {
	s.ReplacedBy = &newSessionID
}
