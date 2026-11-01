package score

import (
	"fmt"
	"testing"
	"time"
)

var t0 = time.Unix(1_800_000_000, 0)

// seq builds entries: each step advances time by gap and adds one entry.
type seq struct {
	at      time.Time
	entries []Entry
}

func newSeq() *seq { return &seq{at: t0} }

func (s *seq) add(gap time.Duration, e Entry) *seq {
	s.at = s.at.Add(gap)
	e.At = s.at
	s.entries = append(s.entries, e)
	return s
}

func (s *seq) pages(n int, gap time.Duration) *seq {
	for i := 0; i < n; i++ {
		s.add(gap, Entry{Kind: KindPage, Status: 200, PathHash: Hash(fmt.Sprintf("/p/%d", i))})
	}
	return s
}

func (s *seq) history() History { return History{Entries: s.entries, Now: s.at} }

func page(p string, status int) Entry {
	return Entry{Kind: KindPage, Status: status, PathHash: Hash(p)}
}

func asset(p string) Entry { return Entry{Kind: KindAsset, Status: 200, PathHash: Hash(p)} }

func withQuery(e Entry, q string) Entry {
	e.QueryHash, e.HasQuery = Hash(q), true
	return e
}

// humanGaps are irregular reading times between pages.
var humanGaps = []time.Duration{4 * time.Second, 11 * time.Second, 7 * time.Second, 25 * time.Second,
	3 * time.Second, 9 * time.Second, 14 * time.Second, 6 * time.Second, 19 * time.Second, 5 * time.Second}

func humanBrowsing() *seq {
	s := newSeq()
	for i, gap := range humanGaps {
		s.add(gap, page(fmt.Sprintf("/article/%d", i), 200))
		s.add(100*time.Millisecond, asset("/static/site.css"))
		s.add(10*time.Millisecond, asset(fmt.Sprintf("/img/%d.jpg", i)))
	}
	return s
}

func TestSignals(t *testing.T) {
	tests := []struct {
		signal Signal
		name   string
		hist   func() History
		want   bool
	}{
		{htmlOnly{}, "pages without assets", func() History { return newSeq().pages(5, 3*time.Second).history() }, true},
		{htmlOnly{}, "few pages", func() History { return newSeq().pages(4, 3*time.Second).history() }, false},
		{htmlOnly{}, "pages with an asset", func() History {
			return newSeq().pages(6, 3*time.Second).add(time.Second, asset("/a.css")).history()
		}, false},

		{high404{}, "scanner", func() History {
			s := newSeq()
			for i := 0; i < 10; i++ {
				s.add(200*time.Millisecond, page(fmt.Sprintf("/x%d.php", i), 404))
			}
			return s.history()
		}, true},
		{high404{}, "missing favicon on every page", func() History {
			s := newSeq()
			for i := 0; i < 10; i++ {
				s.add(5*time.Second, page(fmt.Sprintf("/p%d", i), 200))
				s.add(0, Entry{Kind: KindAsset, Status: 404, PathHash: Hash("/favicon.ico")})
			}
			return s.history()
		}, false},
		{high404{}, "few requests", func() History {
			s := newSeq()
			for i := 0; i < 5; i++ {
				s.add(time.Second, page(fmt.Sprintf("/x%d", i), 404))
			}
			return s.history()
		}, false},

		{pathEnumeration{}, "30 paths in a minute", func() History { return newSeq().pages(30, time.Second).history() }, true},
		{pathEnumeration{}, "30 paths over two minutes", func() History { return newSeq().pages(30, 4*time.Second).history() }, false},
		{pathEnumeration{}, "assets do not count", func() History {
			s := newSeq()
			for i := 0; i < 40; i++ {
				s.add(100*time.Millisecond, asset(fmt.Sprintf("/img/%d.png", i)))
			}
			return s.history()
		}, false},

		{fastRequests{}, "10 pages in 5s", func() History { return newSeq().pages(10, 500*time.Millisecond).history() }, true},
		{fastRequests{}, "9 pages in 5s", func() History { return newSeq().pages(9, 500*time.Millisecond).history() }, false},
		{fastRequests{}, "10 pages over 20s", func() History { return newSeq().pages(10, 2*time.Second).history() }, false},
		{fastRequests{}, "page load with many assets", func() History {
			s := newSeq().add(0, page("/", 200))
			for i := 0; i < 50; i++ {
				s.add(10*time.Millisecond, asset(fmt.Sprintf("/a/%d.js", i)))
			}
			return s.history()
		}, false},

		{regularInterval{}, "fixed 3s crawl delay", func() History { return newSeq().pages(9, 3*time.Second).history() }, true},
		{regularInterval{}, "human reading", func() History { return humanBrowsing().history() }, false},
		{regularInterval{}, "too few pages", func() History { return newSeq().pages(8, 3*time.Second).history() }, false},

		{robotsDisallowed{}, "robots read then disallowed path", func() History {
			h := newSeq().add(0, Entry{RobotsFetch: true}).add(time.Second, Entry{Kind: KindPage, RobotsDisallowed: true}).history()
			h.RobotsFetched = true
			return h
		}, true},
		{robotsDisallowed{}, "person visits disallowed /search", func() History {
			return newSeq().add(0, Entry{Kind: KindPage, RobotsDisallowed: true}).history()
		}, false},

		{errorRetry{}, "fuzzing parameters after 400", func() History {
			s := newSeq()
			for i := 0; i < 6; i++ {
				s.add(200*time.Millisecond, withQuery(page("/api/item", 400), fmt.Sprintf("id=%d'", i)))
			}
			return s.history()
		}, true},
		{errorRetry{}, "form corrected twice", func() History {
			s := newSeq()
			for i := 0; i < 3; i++ {
				s.add(10*time.Second, withQuery(page("/signup", 422), fmt.Sprintf("email=a%d", i)))
			}
			return s.history()
		}, false},
		{errorRetry{}, "same failing query repeated", func() History {
			s := newSeq()
			for i := 0; i < 10; i++ {
				s.add(time.Second, withQuery(page("/api/item", 500), "id=1"))
			}
			return s.history()
		}, false},
		{errorRetry{}, "different queries without errors", func() History {
			s := newSeq()
			for i := 0; i < 10; i++ {
				s.add(time.Second, withQuery(page("/search", 200), fmt.Sprintf("q=%d", i)))
			}
			return s.history()
		}, false},

		{wafAnomaly{}, "would block", func() History {
			return newSeq().add(0, Entry{Kind: KindPage, WAFWouldBlock: true}).history()
		}, true},
		{wafAnomaly{}, "clean", func() History { return newSeq().pages(3, time.Second).history() }, false},
	}
	for _, tt := range tests {
		t.Run(tt.signal.Name()+"/"+tt.name, func(t *testing.T) {
			if got := tt.signal.Fired(tt.hist()); got != tt.want {
				t.Errorf("Fired = %v, want %v", got, tt.want)
			}
		})
	}
}

// Human browsing must stay far below the threshold with default weights.
func TestHumanBrowsingScoresLow(t *testing.T) {
	h := humanBrowsing().history()
	score := 0
	for _, s := range Signals() {
		if s.Fired(h) {
			score += DefaultWeights()[s.Name()]
			t.Logf("fired: %s", s.Name())
		}
	}
	if score >= DefaultThreshold {
		t.Errorf("human browsing scored %d", score)
	}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTracker(t *testing.T, c *clock, maxSessions int) *Tracker {
	t.Helper()
	tr, err := NewTracker(Config{Weights: DefaultWeights(), Window: DefaultWindow, MaxEntries: DefaultMaxEntries, MaxSessions: maxSessions}, c.now)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestTrackerScoresAndExpires(t *testing.T) {
	c := &clock{t: t0}
	tr := newTracker(t, c, 100)

	for i := 0; i < 12; i++ {
		c.t = c.t.Add(200 * time.Millisecond)
		tr.Observe("bot", Entry{At: c.t, Kind: KindPage, Status: 404, PathHash: Hash(fmt.Sprintf("/x%d", i))})
	}
	r := tr.Evaluate("bot")
	if r.Score < DefaultThreshold {
		t.Fatalf("scanner scored %d (%v)", r.Score, r.Fired)
	}
	if got := tr.Evaluate("nobody"); got.Score != 0 {
		t.Errorf("unknown session scored %d", got.Score)
	}

	c.t = c.t.Add(DefaultWindow + time.Second)
	if r := tr.Evaluate("bot"); r.Score != 0 {
		t.Errorf("score after window = %d (%v)", r.Score, r.Fired)
	}
}

func TestTrackerRobotsFetchOutlivesWindow(t *testing.T) {
	c := &clock{t: t0}
	tr := newTracker(t, c, 100)
	tr.Observe("s", Entry{At: c.t, RobotsFetch: true})
	c.t = c.t.Add(10 * time.Minute)
	tr.Observe("s", Entry{At: c.t, Kind: KindPage, Status: 200, RobotsDisallowed: true})
	if r := tr.Evaluate("s"); r.Score < DefaultWeights()[SignalRobotsDisallowed] {
		t.Errorf("robots_disallowed not fired after window: %+v", r)
	}
}

func TestTrackerBounds(t *testing.T) {
	c := &clock{t: t0}
	tr := newTracker(t, c, 3)
	for i := 0; i < 5; i++ {
		tr.Observe(fmt.Sprintf("s%d", i), Entry{At: c.t})
	}
	if len(tr.sessions) != 3 || tr.lru.Len() != 3 {
		t.Errorf("sessions = %d", len(tr.sessions))
	}
	if _, ok := tr.sessions["s0"]; ok {
		t.Error("least recently seen session not evicted")
	}

	for i := 0; i < DefaultMaxEntries*2; i++ {
		tr.Observe("s4", Entry{At: c.t})
	}
	if n := len(tr.sessions["s4"].Value.(*session).entries); n != DefaultMaxEntries {
		t.Errorf("entries = %d, want %d", n, DefaultMaxEntries)
	}
}

func TestShouldReport(t *testing.T) {
	c := &clock{t: t0}
	tr := newTracker(t, c, 10)
	if !tr.ShouldReport("s", "a") || tr.ShouldReport("s", "a") {
		t.Fatal("expected one report per window")
	}
	if !tr.ShouldReport("s", "b") {
		t.Error("another kind suppressed")
	}
	c.t = c.t.Add(DefaultWindow)
	if !tr.ShouldReport("s", "a") {
		t.Error("no report after window")
	}
}

func TestNewTrackerRejectsUnknownSignal(t *testing.T) {
	if _, err := NewTracker(Config{Weights: map[string]int{"ua_mismatch": 3}}, time.Now); err == nil {
		t.Fatal("expected error")
	}
}

func TestWeightZeroDisables(t *testing.T) {
	w := DefaultWeights()
	w[SignalWAFAnomaly] = 0
	c := &clock{t: t0}
	tr, err := NewTracker(Config{Weights: w, Window: DefaultWindow, MaxEntries: 64, MaxSessions: 10}, c.now)
	if err != nil {
		t.Fatal(err)
	}
	tr.Observe("s", Entry{At: c.t, Kind: KindPage, WAFWouldBlock: true})
	if r := tr.Evaluate("s"); r.Score != 0 {
		t.Errorf("disabled signal scored: %+v", r)
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		path, ct string
		status   int
		want     Kind
	}{
		{"/", "text/html; charset=utf-8", 200, KindPage},
		{"/static/a.css", "", 200, KindAsset},
		{"/logo", "image/png", 200, KindAsset},
		{"/bundle", "text/javascript", 200, KindAsset},
		{"/api/items", "application/json", 200, KindOther},
		{"/wp-login.php", "text/plain", 404, KindPage},
		{"/favicon.ico", "text/html", 404, KindAsset},
		{"/report.pdf", "application/pdf", 200, KindOther},
	}
	for _, tt := range tests {
		if got := Classify(tt.path, tt.ct, tt.status); got != tt.want {
			t.Errorf("Classify(%q, %q, %d) = %d, want %d", tt.path, tt.ct, tt.status, got, tt.want)
		}
	}
}
