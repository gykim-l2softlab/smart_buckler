package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
)

// Secret returns the named secret, generating and storing size random bytes
// on first use. Secrets are stable across restarts.
func (s *Store) Secret(ctx context.Context, name string, size int) ([]byte, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx, "SELECT value FROM secrets WHERE name = ?", name).Scan(&v)
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("read secret %s: %w", name, err)
	}
	v = make([]byte, size)
	if _, err := rand.Read(v); err != nil {
		return nil, fmt.Errorf("generate secret %s: %w", name, err)
	}
	// INSERT OR IGNORE then re-read keeps concurrent first uses consistent.
	if _, err := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO secrets (name, value) VALUES (?, ?)", name, v); err != nil {
		return nil, fmt.Errorf("store secret %s: %w", name, err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM secrets WHERE name = ?", name).Scan(&v); err != nil {
		return nil, fmt.Errorf("read secret %s: %w", name, err)
	}
	return v, nil
}
