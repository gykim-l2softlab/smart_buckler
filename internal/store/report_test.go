package store

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestSummarize(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	day := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	at := day.Add(10 * time.Hour)
	sqli := Rule{ID: 942100, Message: "SQL Injection Attack Detected via libinjection"}
	anomaly := Rule{ID: 949110, Message: "Inbound Anomaly Score Exceeded"}
	events := []Event{
		{Time: at, ClientIP: "203.0.113.1", Path: "/backup-x/", Action: ActionTrapHit},
		{Time: at, ClientIP: "203.0.113.2", Path: "/board", Action: ActionChallenged, Signals: []string{"high_404", "fast_requests"}},
		{Time: at, ClientIP: "203.0.113.2", Path: "/board", Action: ActionChallengePassed},
		{Time: at, ClientIP: "203.0.113.3", Path: "/board", Action: ActionChallenged, Signals: []string{"high_404"}},
		{Time: at, ClientIP: "203.0.113.3", Path: "/item", Action: ActionWouldBlock, Rules: []Rule{sqli, anomaly}},
		{Time: at, ClientIP: "203.0.113.3", Path: "/item", Action: ActionWouldBlock, Rules: []Rule{sqli, anomaly}},
		{Time: at, ClientIP: "203.0.113.4", Path: "/", Action: ActionDetected, Rules: []Rule{{ID: 920350, Message: "Host header is a numeric IP address"}}},
		// Outside the day.
		{Time: day.Add(-time.Second), ClientIP: "203.0.113.9", Path: "/old", Action: ActionTrapHit},
		{Time: day.Add(24 * time.Hour), ClientIP: "203.0.113.9", Path: "/new", Action: ActionTrapHit},
	}
	if err := s.InsertEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	got, err := s.Summarize(ctx, day, day.Add(24*time.Hour), 5)
	if err != nil {
		t.Fatal(err)
	}
	want := Summary{
		Events:     map[string]int{ActionTrapHit: 1, ActionChallenged: 2, ActionChallengePassed: 1, ActionWouldBlock: 2, ActionDetected: 1},
		Clients:    map[string]int{ActionTrapHit: 1, ActionChallenged: 2, ActionChallengePassed: 1, ActionWouldBlock: 1, ActionDetected: 1},
		TopClients: []Count{{"203.0.113.3", 3}, {"203.0.113.1", 1}, {"203.0.113.2", 1}},
		TopPaths:   []Count{{"/board", 2}, {"/item", 2}, {"/backup-x/", 1}},
		TopRules:   []RuleCount{{942100, sqli.Message, 2}, {920350, "Host header is a numeric IP address", 1}},
		TopSignals: []Count{{"high_404", 2}, {"fast_requests", 1}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Summarize =\n%+v\nwant\n%+v", got, want)
	}

	empty, err := s.Summarize(ctx, day.Add(48*time.Hour), day.Add(72*time.Hour), 5)
	if err != nil || len(empty.Events) != 0 || empty.TopClients != nil {
		t.Errorf("empty day = %+v, %v", empty, err)
	}
}

func TestReports(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	if ok, err := s.ReportExists(ctx, "2026-10-31"); ok || err != nil {
		t.Fatalf("exists before save: %v %v", ok, err)
	}
	if err := s.SaveReport(ctx, "2026-10-31", "body", 2, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveReport(ctx, "2026-10-31", "body2", 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ReportExists(ctx, "2026-10-31"); !ok || err != nil {
		t.Fatalf("exists after save: %v %v", ok, err)
	}
	var body string
	if err := s.db.QueryRow("SELECT body FROM reports").Scan(&body); err != nil || body != "body2" {
		t.Errorf("body = %q, %v", body, err)
	}
}
