package postgres

import (
	"context"

	"github.com/slavasuhoveev/shelf-auth/internal/domain"
)

type SessionsRepo struct {
	db *DB
}

func NewSessionsRepo(db *DB) *SessionsRepo { return &SessionsRepo{db: db} }

// Create inserts a new session and returns its ID.
func (r *SessionsRepo) Create(ctx context.Context, s *domain.Session) (domain.ID, error) {
	const q = `
INSERT INTO sessions (user_id, device_id, jti, refresh_hash, ip, user_agent, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id
`
	var id domain.ID
	if err := r.db.Pool().QueryRow(ctx, q,
		s.UserID, s.DeviceID, s.JTI, s.RefreshHash, s.IP, s.UserAgent, s.CreatedAt, s.ExpiresAt,
	).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}
