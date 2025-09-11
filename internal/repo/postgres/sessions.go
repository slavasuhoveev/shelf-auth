package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/slavasuhoveev/shelf-auth/internal/domain"
)

type SessionsRepo struct {
	db *DB
}

func NewSessionsRepo(db *DB) *SessionsRepo { return &SessionsRepo{db: db} }

// Create inserts a new session and returns its ID.
func (r *SessionsRepo) Create(ctx context.Context, s *domain.Session) error {
	const q = `
INSERT INTO sessions (user_id, jti, refresh_hash, device_id, ip, ua, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);`
	_, err := r.db.Pool().Exec(ctx, q,
		s.UserID, s.JTI, s.RefreshHash, s.DeviceID, s.IP, s.UserAgent, s.CreatedAt, s.ExpiresAt,
	)
	return err
}

// FindByHash returns a session row by refresh hash.
func (r *SessionsRepo) FindByHash(ctx context.Context, hashHex string) (*domain.Session, error) {
	const q = `
SELECT id, user_id, jti, refresh_hash, device_id, ip, ua, created_at, expires_at, replaced_by, revoked_at
FROM sessions
WHERE refresh_hash = $1
LIMIT 1`
	row := r.db.Pool().QueryRow(ctx, q, hashHex)
	var s domain.Session
	if err := row.Scan(
		&s.ID, &s.UserID, &s.JTI, &s.RefreshHash, &s.DeviceID, &s.IP, &s.UserAgent,
		&s.CreatedAt, &s.ExpiresAt, &s.ReplacedBy, &s.RevokedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return &s, nil
}

// Rotate inserts a new session and marks the old one as replaced_by=new.JTI.
func (r *SessionsRepo) Rotate(ctx context.Context, oldJTI string, newS *domain.Session) error {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Insert new session
	const ins = `
INSERT INTO sessions (user_id, jti, refresh_hash, device_id, ip, ua, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);`
	if _, err := tx.Exec(ctx, ins,
		newS.UserID, newS.JTI, newS.RefreshHash, newS.DeviceID, newS.IP, newS.UserAgent,
		newS.CreatedAt, newS.ExpiresAt,
	); err != nil {
		return err
	}

	// Link old -> new via replaced_by
	const upd = `UPDATE sessions SET replaced_by = $2 WHERE jti = $1;`
	if _, err := tx.Exec(ctx, upd, oldJTI, newS.JTI); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// RevokeAllByUserAndDevice revokes all sessions for given user+device (reuse defense).
func (r *SessionsRepo) RevokeAllByUserAndDevice(ctx context.Context, userID domain.ID, deviceID string, at time.Time) error {
	const q = `
UPDATE sessions
SET revoked_at = $3
WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL;`
	_, err := r.db.Pool().Exec(ctx, q, userID, deviceID, at)
	return err
}

// RevokeByHash sets revoked_at for the session row with given refresh hash.
func (r *SessionsRepo) RevokeByHash(ctx context.Context, hashHex string, at time.Time) error {
	const q = `
UPDATE sessions
SET revoked_at = $2
WHERE refresh_hash = $1 AND revoked_at IS NULL;`
	_, err := r.db.Pool().Exec(ctx, q, hashHex, at)
	return err
}
