package store

import (
	"context"
	"testing"
	"time"
)

func TestListEventsFilterAndPaging(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	var evs []Event
	for i := range 10 {
		a, ip := ActionDetected, "198.51.100.1"
		if i%2 == 0 {
			a, ip = ActionTrapHit, "198.51.100.2"
		}
		evs = append(evs, Event{Time: base.Add(time.Duration(i) * time.Minute), ClientIP: ip, Method: "GET",
			Path: "/p" + string(rune('a'+i)), Action: a, Rules: []Rule{{ID: 942100, Message: "sqli"}}, Signals: []string{"high_404"}})
	}
	if err := s.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		f    EventFilter
		want int
	}{
		{"all", EventFilter{}, 10},
		{"action", EventFilter{Actions: []string{ActionTrapHit}}, 5},
		{"two actions", EventFilter{Actions: []string{ActionTrapHit, ActionDetected}}, 10},
		{"client", EventFilter{ClientIP: "198.51.100.1"}, 5},
		{"path", EventFilter{PathContains: "pc"}, 1},
		{"time", EventFilter{From: base.Add(3 * time.Minute), To: base.Add(6 * time.Minute)}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.ListEvents(ctx, tt.f, Page{Limit: 100})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tt.want {
				t.Errorf("got %d events, want %d", len(got), tt.want)
			}
		})
	}

	page1, _ := s.ListEvents(ctx, EventFilter{}, Page{Limit: 4})
	if len(page1) != 4 || page1[0].Path != "/pj" || page1[0].ID <= page1[3].ID {
		t.Fatalf("page1 = %+v", page1)
	}
	if page1[0].Rules[0].ID != 942100 || page1[0].Signals[0] != "high_404" || !page1[0].Time.Equal(base.Add(9*time.Minute)) {
		t.Errorf("decoded event = %+v", page1[0])
	}
	page2, _ := s.ListEvents(ctx, EventFilter{}, Page{Before: page1[3].ID, Limit: 4})
	if len(page2) != 4 || page2[0].ID != page1[3].ID-1 {
		t.Fatalf("page2 = %+v", page2)
	}
	back, _ := s.ListEvents(ctx, EventFilter{}, Page{After: page2[0].ID, Limit: 4})
	if len(back) != 4 || back[0].ID != page1[0].ID || back[3].ID != page1[3].ID {
		t.Errorf("after page = %v, want page1 order", back)
	}

	one, ok, err := s.EventByID(ctx, page1[0].ID)
	if err != nil || !ok || one.Path != "/pj" {
		t.Errorf("EventByID = %+v, %v, %v", one, ok, err)
	}
	if _, ok, err := s.EventByID(ctx, 9999); ok || err != nil {
		t.Errorf("missing EventByID = %v, %v", ok, err)
	}
}

func TestCounts(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	if err := s.InsertEvents(ctx, []Event{
		{Time: base, ClientIP: "a", Path: "/x", Action: ActionTrapHit},
		{Time: base.Add(30 * time.Minute), ClientIP: "a", Path: "/x", Action: ActionTrapHit},
		{Time: base.Add(90 * time.Minute), ClientIP: "b", Path: "/y", Action: ActionChallenged},
	}); err != nil {
		t.Fatal(err)
	}
	hc, err := s.HourlyCounts(ctx, EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(hc) != 2 || !hc[0].Hour.Equal(base) || hc[0].N != 2 || hc[1].Action != ActionChallenged {
		t.Errorf("HourlyCounts = %+v", hc)
	}
	ac, _ := s.ActionCounts(ctx, EventFilter{ClientIP: "a"})
	if ac[ActionTrapHit] != 2 || len(ac) != 1 {
		t.Errorf("ActionCounts = %v", ac)
	}
	pc, _ := s.PathCounts(ctx, EventFilter{Actions: []string{ActionTrapHit}})
	if pc["/x"] != 2 || len(pc) != 1 {
		t.Errorf("PathCounts = %v", pc)
	}
}

func TestReportsAndSecretsAndBlocks(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	for _, d := range []string{"2026-10-30", "2026-10-31"} {
		if err := s.SaveReport(ctx, d, "body "+d, 2, now); err != nil {
			t.Fatal(err)
		}
	}
	reps, _ := s.Reports(ctx, 7)
	if len(reps) != 2 || reps[0].Day != "2026-10-31" || reps[0].Sent != 2 {
		t.Errorf("Reports = %+v", reps)
	}
	if body, ok, _ := s.Report(ctx, "2026-10-30"); !ok || body != "body 2026-10-30" {
		t.Errorf("Report = %q, %v", body, ok)
	}
	if _, ok, _ := s.Report(ctx, "2026-01-01"); ok {
		t.Error("missing report found")
	}

	if v, err := s.GetSecret(ctx, "x"); v != nil || err != nil {
		t.Errorf("unset secret = %q, %v", v, err)
	}
	for _, v := range []string{"one", "two"} {
		if err := s.SetSecret(ctx, "x", []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	if v, _ := s.GetSecret(ctx, "x"); string(v) != "two" {
		t.Errorf("secret = %q", v)
	}

	if err := s.SaveBlock(ctx, Block{SessionID: "a", Until: now.Add(time.Hour), Reason: ActionTrapHit, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.DeleteBlock(ctx, "a"); !ok || err != nil {
		t.Errorf("DeleteBlock = %v, %v", ok, err)
	}
	if ok, _ := s.DeleteBlock(ctx, "a"); ok {
		t.Error("second DeleteBlock reported a row")
	}
}
