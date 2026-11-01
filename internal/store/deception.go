package store

import (
	"context"
	"fmt"
	"time"
)

// Decoy is a generated trap path.
type Decoy struct {
	Path      string
	CreatedAt time.Time
}

// Block is a blocked session.
type Block struct {
	SessionID string
	Until     time.Time
	Reason    string
	CreatedAt time.Time
}

// Decoys returns all stored decoys ordered by path.
func (s *Store) Decoys(ctx context.Context) ([]Decoy, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT path, created_at FROM decoys ORDER BY path")
	if err != nil {
		return nil, fmt.Errorf("query decoys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Decoy
	for rows.Next() {
		var (
			d  Decoy
			ms int64
		)
		if err := rows.Scan(&d.Path, &ms); err != nil {
			return nil, fmt.Errorf("scan decoy: %w", err)
		}
		d.CreatedAt = time.UnixMilli(ms)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate decoys: %w", err)
	}
	return out, nil
}

// ReplaceDecoys atomically replaces the stored decoy set.
func (s *Store) ReplaceDecoys(ctx context.Context, decoys []Decoy) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "DELETE FROM decoys"); err != nil {
		return fmt.Errorf("delete decoys: %w", err)
	}
	for _, d := range decoys {
		if _, err := tx.ExecContext(ctx, "INSERT INTO decoys (path, created_at) VALUES (?, ?)",
			d.Path, d.CreatedAt.UnixMilli()); err != nil {
			return fmt.Errorf("insert decoy: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// SaveBlock inserts or extends a block.
func (s *Store) SaveBlock(ctx context.Context, b Block) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO blocks (session_id, until, reason, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (session_id) DO UPDATE SET until = excluded.until, reason = excluded.reason`,
		b.SessionID, b.Until.UnixMilli(), b.Reason, b.CreatedAt.UnixMilli())
	if err != nil {
		return fmt.Errorf("save block: %w", err)
	}
	return nil
}

// ActiveBlocks deletes blocks that expired before now and returns the rest.
func (s *Store) ActiveBlocks(ctx context.Context, now time.Time) ([]Block, error) {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM blocks WHERE until <= ?", now.UnixMilli()); err != nil {
		return nil, fmt.Errorf("delete expired blocks: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, "SELECT session_id, until, reason, created_at FROM blocks")
	if err != nil {
		return nil, fmt.Errorf("query blocks: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Block
	for rows.Next() {
		var (
			b                  Block
			untilMs, createdMs int64
		)
		if err := rows.Scan(&b.SessionID, &untilMs, &b.Reason, &createdMs); err != nil {
			return nil, fmt.Errorf("scan block: %w", err)
		}
		b.Until, b.CreatedAt = time.UnixMilli(untilMs), time.UnixMilli(createdMs)
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate blocks: %w", err)
	}
	return out, nil
}
