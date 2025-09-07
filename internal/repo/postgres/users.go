package postgres

import (
	"context"
	"fmt"

	"github.com/slavasuhoveev/shelf-auth/internal/domain"
)

type UsersRepo struct {
	db *DB
}

func NewUsersRepo(db *DB) *UsersRepo { return &UsersRepo{db: db} }

// FindByEmail returns user by email or pgx.ErrNoRows.
func (r *UsersRepo) FindByEmail(ctx context.Context, email domain.Email) (*domain.User, error) {
	const q = `
SELECT id, email, password_hash, email_verified, created_at, updated_at
FROM users
WHERE email = $1
`
	row := r.db.Pool().QueryRow(ctx, q, email.String())

	var u domain.User
	var eml string
	if err := row.Scan(&u.ID, &eml, &u.PasswordHash, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	parsed, err := domain.ParseEmail(eml)
	if err != nil {
		return nil, fmt.Errorf("parse email from db: %w", err)
	}
	u.Email = parsed
	return &u, nil
}
