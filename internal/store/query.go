package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// StoredEvent is an Event read back with its row ID.
type StoredEvent struct {
	ID int64
	Event
}

// EventFilter selects events. Zero fields do not filter.
type EventFilter struct {
	From, To time.Time
	Actions  []string
	ClientIP string
	// PathContains matches a substring of the path.
	PathContains string
}

// Page is a keyset cursor over event IDs, newest first. Before returns
// events older than the ID; After returns events newer than it.
type Page struct {
	Before, After int64
	Limit         int
}

func (f EventFilter) where() (string, []any) {
	var (
		conds []string
		args  []any
	)
	if !f.From.IsZero() {
		conds, args = append(conds, "ts >= ?"), append(args, f.From.UnixMilli())
	}
	if !f.To.IsZero() {
		conds, args = append(conds, "ts < ?"), append(args, f.To.UnixMilli())
	}
	if len(f.Actions) > 0 {
		conds = append(conds, "action IN (?"+strings.Repeat(", ?", len(f.Actions)-1)+")")
		for _, a := range f.Actions {
			args = append(args, a)
		}
	}
	if f.ClientIP != "" {
		conds, args = append(conds, "client_ip = ?"), append(args, f.ClientIP)
	}
	if f.PathContains != "" {
		conds, args = append(conds, "instr(path, ?) > 0"), append(args, f.PathContains)
	}
	if len(conds) == 0 {
		return "1 = 1", args
	}
	return strings.Join(conds, " AND "), args
}

const eventColumns = "id, ts, request_id, client_ip, method, host, path, status, action, rules, score, signals"

// ListEvents returns one page of matching events, newest first.
func (s *Store) ListEvents(ctx context.Context, f EventFilter, p Page) ([]StoredEvent, error) {
	where, args := f.where()
	order := "DESC"
	switch {
	case p.Before > 0:
		where, args = where+" AND id < ?", append(args, p.Before)
	case p.After > 0:
		where, args, order = where+" AND id > ?", append(args, p.After), "ASC"
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+eventColumns+" FROM events WHERE "+where+
		" ORDER BY id "+order+" LIMIT ?", append(args, p.Limit)...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []StoredEvent
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}
	if order == "ASC" {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out, nil
}

// EventByID returns one event, or false if there is none.
func (s *Store) EventByID(ctx context.Context, id int64) (StoredEvent, bool, error) {
	e, err := scanEvent(s.db.QueryRowContext(ctx, "SELECT "+eventColumns+" FROM events WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return StoredEvent{}, false, nil
	}
	if err != nil {
		return StoredEvent{}, false, err
	}
	return e, true, nil
}

type scanner interface{ Scan(dest ...any) error }

func scanEvent(r scanner) (StoredEvent, error) {
	var (
		e              StoredEvent
		ms             int64
		rules, signals string
	)
	if err := r.Scan(&e.ID, &ms, &e.RequestID, &e.ClientIP, &e.Method, &e.Host, &e.Path,
		&e.Status, &e.Action, &rules, &e.Score, &signals); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return e, err
		}
		return e, fmt.Errorf("scan event: %w", err)
	}
	e.Time = time.UnixMilli(ms)
	_ = json.Unmarshal([]byte(rules), &e.Rules)
	_ = json.Unmarshal([]byte(signals), &e.Signals)
	return e, nil
}

// ActionCounts counts matching events per action.
func (s *Store) ActionCounts(ctx context.Context, f EventFilter) (map[string]int, error) {
	where, args := f.where()
	rows, err := s.db.QueryContext(ctx, "SELECT action, COUNT(*) FROM events WHERE "+where+" GROUP BY action", args...)
	if err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var (
			a string
			n int
		)
		if err := rows.Scan(&a, &n); err != nil {
			return nil, fmt.Errorf("scan count: %w", err)
		}
		out[a] = n
	}
	return out, rows.Err()
}

// HourCount is the number of events of one action in one hour.
type HourCount struct {
	Hour   time.Time // start of the hour
	Action string
	N      int
}

// HourlyCounts counts matching events per hour and action. Hours are whole
// UTC hours, which line up with local hours in whole-hour time zones.
func (s *Store) HourlyCounts(ctx context.Context, f EventFilter) ([]HourCount, error) {
	where, args := f.where()
	rows, err := s.db.QueryContext(ctx, "SELECT ts / 3600000, action, COUNT(*) FROM events WHERE "+where+
		" GROUP BY 1, 2 ORDER BY 1", args...)
	if err != nil {
		return nil, fmt.Errorf("count events by hour: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []HourCount
	for rows.Next() {
		var (
			h int64
			c HourCount
		)
		if err := rows.Scan(&h, &c.Action, &c.N); err != nil {
			return nil, fmt.Errorf("scan hourly count: %w", err)
		}
		c.Hour = time.UnixMilli(h * 3600000)
		out = append(out, c)
	}
	return out, rows.Err()
}

// PathCounts counts matching events per path.
func (s *Store) PathCounts(ctx context.Context, f EventFilter) (map[string]int, error) {
	where, args := f.where()
	rows, err := s.db.QueryContext(ctx, "SELECT path, COUNT(*) FROM events WHERE "+where+" GROUP BY path", args...)
	if err != nil {
		return nil, fmt.Errorf("count paths: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var (
			p string
			n int
		)
		if err := rows.Scan(&p, &n); err != nil {
			return nil, fmt.Errorf("scan path count: %w", err)
		}
		out[p] = n
	}
	return out, rows.Err()
}

// ReportInfo describes a stored daily report.
type ReportInfo struct {
	Day       string
	CreatedAt time.Time
	Sent      int
}

// Reports returns the most recent stored reports, newest first.
func (s *Store) Reports(ctx context.Context, limit int) ([]ReportInfo, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT day, created_at, sent FROM reports ORDER BY day DESC LIMIT ?", limit)
	if err != nil {
		return nil, fmt.Errorf("query reports: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ReportInfo
	for rows.Next() {
		var (
			r  ReportInfo
			ms int64
		)
		if err := rows.Scan(&r.Day, &ms, &r.Sent); err != nil {
			return nil, fmt.Errorf("scan report: %w", err)
		}
		r.CreatedAt = time.UnixMilli(ms)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Report returns a stored report body, or false if there is none.
func (s *Store) Report(ctx context.Context, day string) (string, bool, error) {
	var body string
	err := s.db.QueryRowContext(ctx, "SELECT body FROM reports WHERE day = ?", day).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read report: %w", err)
	}
	return body, true, nil
}
