package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Count is a value and how often it occurred.
type Count struct {
	Key string
	N   int
}

// RuleCount is a WAF rule and how often it matched.
type RuleCount struct {
	ID      int
	Message string
	N       int
}

// Summary aggregates the events of a time range for the daily report.
type Summary struct {
	// Events counts events per action.
	Events map[string]int
	// Clients counts distinct client IPs per action. Score events are
	// recorded at most once per client and window, so for them the number of
	// clients is meaningful and the number of events is not.
	Clients map[string]int
	// TopClients and TopPaths cover actions that indicate an attack or an
	// automated client; plain WAF warnings are left out as noise.
	TopClients []Count
	TopPaths   []Count
	TopRules   []RuleCount
	TopSignals []Count
}

// noteworthy are the actions that make a client or path worth listing.
var noteworthy = []string{ActionBlocked, ActionWouldBlock, ActionTrapHit, ActionChallenged, ActionWouldChallenge}

// Summarize aggregates events in [from, to), with at most limit entries per
// top list.
func (s *Store) Summarize(ctx context.Context, from, to time.Time, limit int) (Summary, error) {
	sum := Summary{Events: map[string]int{}, Clients: map[string]int{}}
	window := []any{from.UnixMilli(), to.UnixMilli()}

	rows, err := s.db.QueryContext(ctx, `SELECT action, COUNT(*), COUNT(DISTINCT client_ip)
		FROM events WHERE ts >= ? AND ts < ? GROUP BY action`, window...)
	if err != nil {
		return Summary{}, fmt.Errorf("count events: %w", err)
	}
	for rows.Next() {
		var action string
		var events, clients int
		if err := rows.Scan(&action, &events, &clients); err != nil {
			_ = rows.Close()
			return Summary{}, fmt.Errorf("scan counts: %w", err)
		}
		sum.Events[action], sum.Clients[action] = events, clients
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return Summary{}, fmt.Errorf("count events: %w", err)
	}

	in := "(" + strings.TrimSuffix(strings.Repeat("?,", len(noteworthy)), ",") + ")"
	args := append([]any{}, window...)
	for _, a := range noteworthy {
		args = append(args, a)
	}
	args = append(args, limit)

	if sum.TopClients, err = s.counts(ctx, `SELECT client_ip, COUNT(*) FROM events
		WHERE ts >= ? AND ts < ? AND action IN `+in+` GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT ?`, args...); err != nil {
		return Summary{}, fmt.Errorf("top clients: %w", err)
	}
	if sum.TopPaths, err = s.counts(ctx, `SELECT path, COUNT(*) FROM events
		WHERE ts >= ? AND ts < ? AND action IN `+in+` GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT ?`, args...); err != nil {
		return Summary{}, fmt.Errorf("top paths: %w", err)
	}
	if sum.TopSignals, err = s.counts(ctx, `SELECT j.value, COUNT(*) FROM events, json_each(events.signals) j
		WHERE ts >= ? AND ts < ? GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT ?`, from.UnixMilli(), to.UnixMilli(), limit); err != nil {
		return Summary{}, fmt.Errorf("top signals: %w", err)
	}

	// CRS anomaly evaluation rules (949xxx, 980xxx) repeat what the
	// attack rules already say.
	rows, err = s.db.QueryContext(ctx, `SELECT id, MAX(msg), COUNT(*) FROM (
			SELECT json_extract(j.value, '$.id') AS id, json_extract(j.value, '$.msg') AS msg
			FROM events, json_each(events.rules) j WHERE ts >= ? AND ts < ?)
		WHERE NOT (id BETWEEN 949000 AND 949999 OR id BETWEEN 980000 AND 980999)
		GROUP BY id ORDER BY 3 DESC, 1 LIMIT ?`, from.UnixMilli(), to.UnixMilli(), limit)
	if err != nil {
		return Summary{}, fmt.Errorf("top rules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r RuleCount
		if err := rows.Scan(&r.ID, &r.Message, &r.N); err != nil {
			return Summary{}, fmt.Errorf("scan rule: %w", err)
		}
		sum.TopRules = append(sum.TopRules, r)
	}
	if err := rows.Err(); err != nil {
		return Summary{}, fmt.Errorf("top rules: %w", err)
	}
	return sum, nil
}

func (s *Store) counts(ctx context.Context, query string, args ...any) ([]Count, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Count
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Key, &c.N); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ReportExists reports whether the report for day (YYYY-MM-DD) was produced.
func (s *Store) ReportExists(ctx context.Context, day string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, "SELECT 1 FROM reports WHERE day = ?", day).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read report: %w", err)
	}
	return true, nil
}

// SaveReport stores a produced report; sent is the number of channels that
// accepted it.
func (s *Store) SaveReport(ctx context.Context, day, body string, sent int, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO reports (day, created_at, body, sent) VALUES (?, ?, ?, ?)
		ON CONFLICT (day) DO UPDATE SET created_at = excluded.created_at, body = excluded.body, sent = excluded.sent`,
		day, at.UnixMilli(), body, sent)
	if err != nil {
		return fmt.Errorf("save report: %w", err)
	}
	return nil
}
