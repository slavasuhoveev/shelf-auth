package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
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

// Insert creates a new user and returns its ID.
// Maps unique violation (email) to domain.ErrEmailAlreadyTaken.
func (r *UsersRepo) Insert(ctx context.Context, u *domain.User) (domain.ID, error) {
	const q = `
INSERT INTO users (email, password_hash, email_verified, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id
`
	var id domain.ID
	err := r.db.Pool().QueryRow(ctx, q,
		u.Email.String(),
		u.PasswordHash,
		u.EmailVerified,
		u.CreatedAt,
		u.UpdatedAt,
	).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return 0, domain.ErrEmailAlreadyTaken
		}
		return 0, err
	}
	return id, nil
}
