package store

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func countEvents(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestInsertEvents(t *testing.T) {
	s := openTemp(t)
	now := time.UnixMilli(1_800_000_000_000)
	ev := Event{
		Time: now, RequestID: "tx1", ClientIP: "203.0.113.7", Method: "GET", Host: "example.com",
		Path: "/item", Status: 403, Action: ActionBlocked,
		Rules: []Rule{{ID: 942100, Message: "SQL Injection Attack Detected via libinjection", Severity: "critical"}},
	}
	if err := s.InsertEvents(context.Background(), []Event{ev, {Time: now, Action: ActionDetected}}); err != nil {
		t.Fatal(err)
	}

	var (
		ts            int64
		ip, action, r string
		status        int
	)
	err := s.db.QueryRow("SELECT ts, client_ip, status, action, rules FROM events WHERE request_id = 'tx1'").
		Scan(&ts, &ip, &status, &action, &r)
	if err != nil {
		t.Fatal(err)
	}
	if ts != now.UnixMilli() || ip != "203.0.113.7" || status != 403 || action != ActionBlocked {
		t.Errorf("unexpected row: ts=%d ip=%s status=%d action=%s", ts, ip, status, action)
	}
	var rules []Rule
	if err := json.Unmarshal([]byte(r), &rules); err != nil || len(rules) != 1 || rules[0].ID != 942100 {
		t.Errorf("rules = %s (err %v)", r, err)
	}

	var empty string
	if err := s.db.QueryRow("SELECT rules FROM events WHERE request_id = ''").Scan(&empty); err != nil || empty != "[]" {
		t.Errorf("nil rules stored as %q (err %v), want []", empty, err)
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	for i := 0; i < 2; i++ {
		s, err := Open(context.Background(), path)
		if err != nil {
			t.Fatalf("Open #%d: %v", i+1, err)
		}
		_ = s.Close()
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA user_version = 99"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := Open(context.Background(), path); err == nil {
		t.Fatal("expected error for newer schema")
	}
}

func TestRecorderFlushesOnClose(t *testing.T) {
	s := openTemp(t)
	r := newRecorder(s, discardLogger(), 1000, 10, time.Hour)

	var wg sync.WaitGroup
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				r.Record(Event{Time: time.Now(), Action: ActionDetected})
			}
		}()
	}
	wg.Wait()
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := countEvents(t, s); got != 100 {
		t.Errorf("stored %d events, want 100", got)
	}
	if r.Dropped() != 0 {
		t.Errorf("dropped %d", r.Dropped())
	}

	r.Record(Event{}) // after Close: dropped, must not panic
	if r.Dropped() != 1 {
		t.Errorf("Record after Close: dropped = %d, want 1", r.Dropped())
	}
}

func TestRecorderDropsWhenFull(t *testing.T) {
	s := openTemp(t)
	// Hold the only connection so the writer blocks on its first insert.
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := newRecorder(s, discardLogger(), 2, 1, time.Hour)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			r.Record(Event{Time: time.Now()})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked while the writer was stalled")
	}
	if r.Dropped() == 0 {
		t.Error("expected dropped events")
	}

	_ = conn.Close()
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestEventScoreAndSignals(t *testing.T) {
	s := openTemp(t)
	if err := s.InsertEvents(context.Background(), []Event{
		{Time: time.Now(), RequestID: "c1", Action: ActionChallenged, Score: 12, Signals: []string{"high_404", "path_enumeration"}},
	}); err != nil {
		t.Fatal(err)
	}
	var (
		score   int
		signals string
	)
	if err := s.db.QueryRow("SELECT score, signals FROM events WHERE request_id = 'c1'").Scan(&score, &signals); err != nil {
		t.Fatal(err)
	}
	if score != 12 || signals != `["high_404","path_enumeration"]` {
		t.Errorf("score=%d signals=%s", score, signals)
	}
}

func TestSecretIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	ctx := context.Background()
	s1, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s1.Secret(ctx, "challenge", 32)
	if err != nil || len(a) != 32 {
		t.Fatalf("secret: %v len %d", err, len(a))
	}
	b, _ := s1.Secret(ctx, "challenge", 32)
	other, _ := s1.Secret(ctx, "other", 32)
	_ = s1.Close()

	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	c, _ := s2.Secret(ctx, "challenge", 32)
	if string(a) != string(b) || string(a) != string(c) {
		t.Error("secret changed")
	}
	if string(a) == string(other) {
		t.Error("different names share a secret")
	}
}
