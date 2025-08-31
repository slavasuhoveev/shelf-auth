package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps pgxpool.Pool to hide implementation details behind our package.
type DB struct {
	pool *pgxpool.Pool
}

// Open creates a connection pool to Postgres using the provided connection string.
// Example: postgres://user:pass@host:5432/dbname?sslmode=disable
func Open(connString string) (*DB, error) {
	if connString == "" {
		return nil, fmt.Errorf("postgres: empty connection string")
	}

	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse config: %w", err)
	}

	// Reasonable pool tuning defaults (tweak later via env if needed).
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.HealthCheckPeriod = 30 * time.Second
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.MaxConnLifetime = 60 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: new pool: %w", err)
	}

	// Quick ping with timeout to fail fast on startup.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	return &DB{pool: pool}, nil
}

// Close closes the underlying pool.
func (db *DB) Close() error {
	if db.pool != nil {
		db.pool.Close()
	}
	return nil
}

// Pool exposes the underlying pgx pool for repositories (optional).
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}
