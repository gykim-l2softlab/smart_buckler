// Package store persists security events in SQLite.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver (pure Go, no cgo)
)

// Event actions.
const (
	// ActionBlocked: the request was denied.
	ActionBlocked = "blocked"
	// ActionWouldBlock: detect mode let the request through, block mode would deny it.
	ActionWouldBlock = "would_block"
	// ActionDetected: rules matched below the blocking threshold.
	ActionDetected = "detected"
	// ActionTrapHit: a decoy path was requested and the session was blocked.
	ActionTrapHit = "trap_hit"
	// ActionChallenged: the behavior score reached the threshold and a
	// proof-of-work challenge was served.
	ActionChallenged = "challenged"
	// ActionWouldChallenge: the score reached the threshold but the request
	// was let through (detect mode, or not a page navigation).
	ActionWouldChallenge = "would_challenge"
	// ActionChallengePassed: a challenge was solved.
	ActionChallengePassed = "challenge_passed"
	// ActionUnblocked: an administrator lifted a block. RequestID holds
	// "admin@" and the administrator's address.
	ActionUnblocked = "unblocked"
)

// Event is a security event. It never contains request bodies, query strings
// or matched request data; callers must redact Path before recording.
type Event struct {
	Time      time.Time
	RequestID string
	ClientIP  string
	Method    string
	Host      string
	Path      string
	Status    int
	Action    string
	Rules     []Rule
	// Score and Signals are set for behavior score events.
	Score   int
	Signals []string
}

// Rule is a matched WAF rule.
type Rule struct {
	ID       int    `json:"id"`
	Message  string `json:"msg"`
	Severity string `json:"severity"`
}

// Store is the SQLite access layer.
type Store struct {
	db *sql.DB
}

// migrations are applied in order; PRAGMA user_version records how many ran.
var migrations = []string{
	`CREATE TABLE events (
		id         INTEGER PRIMARY KEY,
		ts         INTEGER NOT NULL, -- unix milliseconds
		request_id TEXT    NOT NULL,
		client_ip  TEXT    NOT NULL,
		method     TEXT    NOT NULL,
		host       TEXT    NOT NULL,
		path       TEXT    NOT NULL,
		status     INTEGER NOT NULL,
		action     TEXT    NOT NULL,
		rules      TEXT    NOT NULL  -- JSON array of {id, msg, severity}
	);
	CREATE INDEX events_ts ON events (ts);`,
	`CREATE TABLE decoys (
		path       TEXT    PRIMARY KEY,
		created_at INTEGER NOT NULL -- unix milliseconds
	);
	CREATE TABLE blocks (
		session_id TEXT    PRIMARY KEY,
		until      INTEGER NOT NULL, -- unix milliseconds
		reason     TEXT    NOT NULL,
		created_at INTEGER NOT NULL
	);`,
	`ALTER TABLE events ADD COLUMN score INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE events ADD COLUMN signals TEXT NOT NULL DEFAULT '[]'; -- JSON array of signal names
	CREATE TABLE secrets (
		name  TEXT PRIMARY KEY,
		value BLOB NOT NULL
	);`,
	`CREATE TABLE reports (
		day        TEXT    PRIMARY KEY, -- YYYY-MM-DD in the report time zone
		created_at INTEGER NOT NULL,    -- unix milliseconds
		body       TEXT    NOT NULL,
		sent       INTEGER NOT NULL     -- number of channels that accepted it
	);`,
	`CREATE INDEX events_client_ts ON events (client_ip, ts);`,
}

// Open opens (creating if needed) the database at path and applies migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// A single connection serializes writes and avoids SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this binary supports (%d)", version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("set schema version %d: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", i+1, err)
		}
	}
	return nil
}

// InsertEvents writes events in a single transaction.
func (s *Store) InsertEvents(ctx context.Context, events []Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO events
		(ts, request_id, client_ip, method, host, path, status, action, rules, score, signals)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, e := range events {
		rules := e.Rules
		if rules == nil {
			rules = []Rule{}
		}
		rulesJSON, err := json.Marshal(rules)
		if err != nil {
			return fmt.Errorf("marshal rules: %w", err)
		}
		signals := e.Signals
		if signals == nil {
			signals = []string{}
		}
		signalsJSON, err := json.Marshal(signals)
		if err != nil {
			return fmt.Errorf("marshal signals: %w", err)
		}
		if _, err := stmt.ExecContext(ctx, e.Time.UnixMilli(), e.RequestID, e.ClientIP,
			e.Method, e.Host, e.Path, e.Status, e.Action, string(rulesJSON), e.Score, string(signalsJSON)); err != nil {
			return fmt.Errorf("insert event: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}
