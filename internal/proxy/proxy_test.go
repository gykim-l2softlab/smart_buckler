package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gykim-l2softlab/smart_buckler/internal/deception"
	"github.com/gykim-l2softlab/smart_buckler/internal/redact"
	"github.com/gykim-l2softlab/smart_buckler/internal/response"
	"github.com/gykim-l2softlab/smart_buckler/internal/score"
	"github.com/gykim-l2softlab/smart_buckler/internal/session"
	"github.com/gykim-l2softlab/smart_buckler/internal/store"
	"github.com/gykim-l2softlab/smart_buckler/internal/waf"
)

type fakeRecorder struct {
	mu     sync.Mutex
	events []store.Event
}

func (f *fakeRecorder) Record(e store.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

func (f *fakeRecorder) all() []store.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.Event(nil), f.events...)
}

type fakeInspector struct {
	verdict waf.Verdict
	err     error
	panic   bool
	closed  bool
}

func (f *fakeInspector) Inspect(*http.Request) (waf.Verdict, func(), error) {
	if f.panic {
		panic("boom")
	}
	return f.verdict, func() { f.closed = true }, f.err
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// upstream echoes request details and counts hits.
type upstream struct {
	*httptest.Server
	mu   sync.Mutex
	hits int
	last *http.Request
	body string
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.hits++
		u.last = r
		u.body = string(b)
		u.mu.Unlock()
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "hello from upstream")
	}))
	t.Cleanup(u.Close)
	return u
}

func newHandler(t *testing.T, up *upstream, insp Inspector, rec Recorder) *Handler {
	t.Helper()
	return newHandlerWith(t, up, insp, rec, nil, nil)
}

// newHandlerWith builds a Handler with a fresh store. dec may be nil
// (deception disabled); trusted lists trusted proxies.
func newHandlerWith(t testing.TB, up *upstream, insp Inspector, rec Recorder, dec *deception.Deception, trusted []string) *Handler {
	t.Helper()
	o := testOptions(t, up, insp, rec)
	o.Deception = dec
	sessions, err := session.NewResolver(trusted)
	if err != nil {
		t.Fatal(err)
	}
	o.Sessions = sessions
	return New(o)
}

// testOptions returns working defaults: no deception, default score weights,
// challenge mode with a low difficulty.
func testOptions(t testing.TB, up *upstream, insp Inspector, rec Recorder) Options {
	t.Helper()
	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	sessions, _ := session.NewResolver(nil)
	bl, err := response.NewBlocklist(context.Background(), tempStore(t), discardLogger(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	tracker, err := score.NewTracker(score.Config{
		Weights: score.DefaultWeights(), Window: score.DefaultWindow,
		MaxEntries: score.DefaultMaxEntries, MaxSessions: score.DefaultMaxSessions,
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := response.NewChallenger([]byte(strings.Repeat("s", 32)), 8, time.Hour, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		Upstream: u, Sessions: sessions, Blocklist: bl, BlockDuration: time.Hour,
		Inspector: insp, Tracker: tracker, Threshold: score.DefaultThreshold, Challenger: ch, Challenge: true,
		Recorder: rec, Log: discardLogger(),
	}
}

func tempStore(t testing.TB) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestPassThrough(t *testing.T) {
	up := newUpstream(t)
	rec := &fakeRecorder{}
	insp := &fakeInspector{verdict: waf.Verdict{TxID: "t"}}
	h := newHandler(t, up, insp, rec)

	r := httptest.NewRequest(http.MethodPost, "http://app.example/submit?x=1", strings.NewReader("payload"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK || w.Body.String() != "hello from upstream" {
		t.Fatalf("response = %d %q", w.Code, w.Body.String())
	}
	if up.body != "payload" {
		t.Errorf("upstream body = %q", up.body)
	}
	if up.last.Host != "app.example" {
		t.Errorf("upstream Host = %q, want client Host preserved", up.last.Host)
	}
	if up.last.Header.Get("X-Forwarded-For") == "" {
		t.Error("X-Forwarded-For not set")
	}
	if len(rec.all()) != 0 {
		t.Errorf("events recorded for clean request: %+v", rec.all())
	}
	if !insp.closed {
		t.Error("inspector transaction not closed")
	}
}

func TestBlocked(t *testing.T) {
	up := newUpstream(t)
	rec := &fakeRecorder{}
	insp := &fakeInspector{verdict: waf.Verdict{
		TxID: "tx-block", Interrupted: true, Status: http.StatusForbidden,
		Matches: []waf.Match{{RuleID: 942100, Message: "SQL Injection", Severity: "critical"}},
	}}
	h := newHandler(t, up, insp, rec)

	r := httptest.NewRequest(http.MethodGet, "/users/010-1234-5678?id=1'", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "tx-block") {
		t.Fatalf("response = %d %q", w.Code, w.Body.String())
	}
	if up.hits != 0 {
		t.Error("blocked request reached upstream")
	}
	evs := rec.all()
	if len(evs) != 1 {
		t.Fatalf("events = %+v", evs)
	}
	e := evs[0]
	if e.Action != store.ActionBlocked || e.Status != 403 || e.ClientIP != "203.0.113.9" ||
		e.RequestID != "tx-block" || len(e.Rules) != 1 || e.Rules[0].ID != 942100 {
		t.Errorf("event = %+v", e)
	}
	if e.Path != "/users/"+redact.Mask {
		t.Errorf("path not redacted: %q", e.Path)
	}
}

func TestDetectedRecordsUpstreamStatus(t *testing.T) {
	tests := []struct {
		name       string
		matches    []waf.Match
		path       string
		wantAction string
		wantStatus int
	}{
		{
			name:       "would block",
			matches:    []waf.Match{{RuleID: 942100}, {RuleID: 949110}},
			path:       "/item",
			wantAction: store.ActionWouldBlock,
			wantStatus: 200,
		},
		{
			name:       "below threshold",
			matches:    []waf.Match{{RuleID: 920350}},
			path:       "/missing",
			wantAction: store.ActionDetected,
			wantStatus: 404,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := newUpstream(t)
			rec := &fakeRecorder{}
			h := newHandler(t, up, &fakeInspector{verdict: waf.Verdict{TxID: "t", Matches: tt.matches}}, rec)

			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if up.hits != 1 {
				t.Fatal("request did not reach upstream")
			}
			evs := rec.all()
			if len(evs) != 1 || evs[0].Action != tt.wantAction || evs[0].Status != tt.wantStatus {
				t.Errorf("events = %+v", evs)
			}
		})
	}
}

func TestFailOpen(t *testing.T) {
	tests := []struct {
		name string
		insp *fakeInspector
	}{
		{"error", &fakeInspector{err: errors.New("engine broke"), verdict: waf.Verdict{Interrupted: true, Status: 403}}},
		{"panic", &fakeInspector{panic: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := newUpstream(t)
			rec := &fakeRecorder{}
			h := newHandler(t, up, tt.insp, rec)

			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

			if w.Code != http.StatusOK || up.hits != 1 {
				t.Errorf("request not passed: code=%d hits=%d", w.Code, up.hits)
			}
			if len(rec.all()) != 0 {
				t.Errorf("events recorded on failure: %+v", rec.all())
			}
		})
	}
}

func TestUpstreamDown(t *testing.T) {
	up := newUpstream(t)
	up.Close()
	h := newHandler(t, up, &fakeInspector{}, &fakeRecorder{})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusBadGateway {
		t.Errorf("code = %d, want 502", w.Code)
	}
}

func TestRealWAFBlocksBeforeUpstream(t *testing.T) {
	up := newUpstream(t)
	rec := &fakeRecorder{}
	w, err := waf.New(waf.Config{Mode: waf.ModeBlock, RequestBodyLimit: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(t, up, w, rec)

	r := httptest.NewRequest(http.MethodGet, "/item?id="+url.QueryEscape("1' OR '1'='1"), nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "text/html")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, r)

	if resp.Code != http.StatusForbidden || up.hits != 0 {
		t.Fatalf("code=%d hits=%d", resp.Code, up.hits)
	}
	if evs := rec.all(); len(evs) != 1 || evs[0].Action != store.ActionBlocked {
		t.Errorf("events = %+v", evs)
	}
}
