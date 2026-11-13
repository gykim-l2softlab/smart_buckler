package report

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gykim-l2softlab/smart_buckler/internal/store"
)

var update = flag.Bool("update", false, "rewrite golden files")

var seoul = time.FixedZone("KST", 9*3600)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// seed records a busy day on 2026-10-31 (KST).
func seed(t *testing.T, s *store.Store) {
	t.Helper()
	at := time.Date(2026, 10, 31, 14, 0, 0, 0, seoul)
	sqli := store.Rule{ID: 942100, Message: "SQL Injection Attack Detected via libinjection"}
	var ev []store.Event
	for i := 0; i < 6; i++ {
		ip := fmt.Sprintf("203.0.113.%d", 10+i)
		ev = append(ev, store.Event{Time: at, ClientIP: ip, Path: "/board", Action: store.ActionChallenged, Signals: []string{"high_404", "html_only"}})
		if i < 4 {
			ev = append(ev, store.Event{Time: at, ClientIP: ip, Path: "/.l2b/pow", Action: store.ActionChallengePassed})
		}
	}
	ev = append(ev,
		store.Event{Time: at, ClientIP: "198.51.100.7", Path: "/db-export-x1y2z3/", Action: store.ActionTrapHit},
		store.Event{Time: at, ClientIP: "198.51.100.7", Path: "/item\x1b[31m", Action: store.ActionWouldBlock, Rules: []store.Rule{sqli}},
		store.Event{Time: at, ClientIP: "198.51.100.7", Path: "/" + strings.Repeat("a", 200), Action: store.ActionWouldBlock, Rules: []store.Rule{sqli}},
		store.Event{Time: at, ClientIP: "198.51.100.8", Path: "/", Action: store.ActionDetected, Rules: []store.Rule{{ID: 920350, Message: "Host header is a numeric IP address"}}},
	)
	if err := s.InsertEvents(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
}

func newGen(t *testing.T, st Store, o Options) *Generator {
	t.Helper()
	o.Store, o.Location, o.Log = st, seoul, discard()
	if o.Now == nil {
		o.Now = func() time.Time { return time.Date(2026, 11, 1, 9, 0, 0, 0, seoul) }
	}
	g, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if got != string(want) {
		t.Errorf("%s mismatch (run with -update to accept):\n%s", name, got)
	}
}

func TestBuildBusyDay(t *testing.T) {
	st := openStore(t)
	seed(t, st)
	rep, err := newGen(t, st, Options{}).Build(context.Background(), "2026-10-31")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Subject != "[smart_buckler] 2026년 10월 31일 보안 요약" {
		t.Errorf("subject = %q", rep.Subject)
	}
	if strings.ContainsAny(rep.Body, "\x1b—·") {
		t.Error("body has control characters, em dash or middle dot")
	}
	golden(t, "busy.golden", rep.Body)
}

func TestBuildQuietDay(t *testing.T) {
	st := openStore(t)
	seed(t, st)
	llm := &fakeLLM{out: "should not be called"}
	rep, err := newGen(t, st, Options{LLM: llm}).Build(context.Background(), "2026-10-30")
	if err != nil {
		t.Fatal(err)
	}
	if llm.calls != 0 {
		t.Error("llm called for a quiet day")
	}
	golden(t, "quiet.golden", rep.Body)
}

type fakeLLM struct {
	out    string
	err    error
	calls  int
	system string
	prompt string
}

func (f *fakeLLM) Generate(_ context.Context, system, prompt string) (string, error) {
	f.calls++
	f.system, f.prompt = system, prompt
	return f.out, f.err
}

func TestAISummary(t *testing.T) {
	st := openStore(t)
	seed(t, st)

	llm := &fakeLLM{out: "  어제는 자동화 도구 6곳이 확인 화면을 받았습니다 — 그중 4곳이 통과했습니다.\x07  "}
	rep, err := newGen(t, st, Options{LLM: llm}).Build(context.Background(), "2026-10-31")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.Body, "\n\n어제는 자동화 도구 6곳이 확인 화면을 받았습니다, 그중 4곳이 통과했습니다.\n(AI가") {
		t.Errorf("summary not placed or cleaned:\n%s", rep.Body)
	}
	// Attacker-controlled values never reach the model.
	for _, leak := range []string{"/db-export", "/item", "198.51.100.7", "/board"} {
		if strings.Contains(llm.system+llm.prompt, leak) {
			t.Errorf("prompt contains %q", leak)
		}
	}
	if !strings.Contains(llm.system, "되풀이하지 마라") {
		t.Errorf("system prompt = %q", llm.system)
	}
	if strings.Contains(llm.prompt, ": 0곳") || strings.Contains(llm.prompt, ": 0건") {
		t.Errorf("prompt lists zero counts:\n%s", llm.prompt)
	}
	if !strings.Contains(llm.prompt, "확인 화면을 보여 준 클라이언트: 6곳, 그중 통과: 4곳") {
		t.Errorf("prompt lacks counts:\n%s", llm.prompt)
	}

	failing := &fakeLLM{err: errors.New("connection refused")}
	rep2, err := newGen(t, st, Options{LLM: failing}).Build(context.Background(), "2026-10-31")
	if err != nil || strings.Contains(rep2.Body, "AI가 아래") {
		t.Errorf("failed llm should fall back: %v\n%s", err, rep2.Body)
	}
}

type fakeNotifier struct {
	name string
	err  error
	mu   sync.Mutex
	got  []string
}

func (f *fakeNotifier) Name() string { return f.name }
func (f *fakeNotifier) Send(_ context.Context, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, subject)
	return f.err
}

func TestDeliverOncePerDay(t *testing.T) {
	st := openStore(t)
	seed(t, st)
	ok := &fakeNotifier{name: "slack"}
	bad := &fakeNotifier{name: "email", err: errors.New("smtp down")}
	g := newGen(t, st, Options{Notifiers: []Notifier{bad, ok}})

	for i := 0; i < 2; i++ {
		if err := g.Deliver(context.Background(), "2026-10-31"); err != nil {
			t.Fatal(err)
		}
	}
	if len(ok.got) != 1 || len(bad.got) != 1 {
		t.Errorf("sends: ok=%d bad=%d, want 1 each", len(ok.got), len(bad.got))
	}
	if exists, _ := st.ReportExists(context.Background(), "2026-10-31"); !exists {
		t.Error("report not saved")
	}
}

func TestSchedule(t *testing.T) {
	g := newGen(t, openStore(t), Options{SendAt: 9 * time.Hour})
	tests := []struct {
		now  time.Time
		day  string
		due  bool
		next time.Time
	}{
		{time.Date(2026, 11, 1, 8, 59, 0, 0, seoul), "", false, time.Date(2026, 11, 1, 9, 0, 0, 0, seoul)},
		{time.Date(2026, 11, 1, 9, 0, 0, 0, seoul), "2026-10-31", true, time.Date(2026, 11, 2, 9, 0, 0, 0, seoul)},
		{time.Date(2026, 11, 1, 23, 0, 0, 0, seoul), "2026-10-31", true, time.Date(2026, 11, 2, 9, 0, 0, 0, seoul)},
		// The report time zone decides the day, not the host's.
		{time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC), "2026-10-31", true, time.Date(2026, 11, 2, 9, 0, 0, 0, seoul)},
		{time.Date(2026, 3, 1, 10, 0, 0, 0, seoul), "2026-02-28", true, time.Date(2026, 3, 2, 9, 0, 0, 0, seoul)},
	}
	for _, tt := range tests {
		day, due, next := g.schedule(tt.now)
		if day != tt.day || due != tt.due || !next.Equal(tt.next) {
			t.Errorf("schedule(%v) = %q %v %v, want %q %v %v", tt.now, day, due, next, tt.day, tt.due, tt.next)
		}
	}
}

func TestRunCatchesUp(t *testing.T) {
	st := openStore(t)
	seed(t, st)
	n := &fakeNotifier{name: "slack"}
	// 10:00 on Nov 1: yesterday's report is overdue.
	g := newGen(t, st, Options{Notifiers: []Notifier{n}, SendAt: 9 * time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n.mu.Lock()
		got := len(n.got)
		n.mu.Unlock()
		if got == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("overdue report not delivered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestChat(t *testing.T) {
	var req map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		auth = r.Header.Get("Authorization")
		req = nil
		_ = json.NewDecoder(r.Body).Decode(&req)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"요약입니다."}}]}`))
	}))
	defer srv.Close()

	c := &Chat{URL: srv.URL + "/v1/", Model: "qwen3:4b", Timeout: time.Second}
	out, err := c.Generate(context.Background(), "s", "p")
	if err != nil || out != "요약입니다." {
		t.Fatalf("Generate = %q, %v", out, err)
	}
	msgs, _ := json.Marshal(req["messages"])
	if req["model"] != "qwen3:4b" || string(msgs) != `[{"content":"s","role":"system"},{"content":"p","role":"user"}]` {
		t.Errorf("request = %v", req)
	}
	if _, ok := req["reasoning_effort"]; ok || auth != "" {
		t.Errorf("unset options sent: %v, auth %q", req, auth)
	}

	c.APIKey, c.ReasoningEffort = "sk-test", "none"
	if _, err := c.Generate(context.Background(), "s", "p"); err != nil {
		t.Fatal(err)
	}
	if req["reasoning_effort"] != "none" || auth != "Bearer sk-test" {
		t.Errorf("reasoning_effort = %v, auth %q", req["reasoning_effort"], auth)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"message":"model \"x\" not found"}}`))
	}))
	defer failing.Close()
	_, err = (&Chat{URL: failing.URL, Model: "x", APIKey: "sk-secret", Timeout: time.Second}).Generate(context.Background(), "s", "p")
	if err == nil || !strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "sk-secret") {
		t.Errorf("err = %v", err)
	}
}

func TestAnthropic(t *testing.T) {
	var req map[string]any
	var header http.Header
	reply := `{"content":[{"type":"thinking","thinking":""},{"type":"text","text":"요약"},{"type":"text","text":"입니다."}],"stop_reason":"end_turn"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.NotFound(w, r)
			return
		}
		header = r.Header.Clone()
		req = nil
		_ = json.NewDecoder(r.Body).Decode(&req)
		_, _ = w.Write([]byte(reply))
	}))
	defer srv.Close()

	a := &Anthropic{URL: srv.URL + "/v1", Model: "claude-opus-5-5", APIKey: "sk-ant-test", Timeout: time.Second}
	out, err := a.Generate(context.Background(), "s", "p")
	if err != nil || out != "요약입니다." {
		t.Fatalf("Generate = %q, %v", out, err)
	}
	if header.Get("x-api-key") != "sk-ant-test" || header.Get("anthropic-version") != anthropicVersion {
		t.Errorf("headers = %v", header)
	}
	msgs, _ := json.Marshal(req["messages"])
	if req["model"] != "claude-opus-5-5" || req["system"] != "s" || string(msgs) != `[{"content":"p","role":"user"}]` {
		t.Errorf("request = %v", req)
	}
	for _, k := range []string{"temperature", "output_config"} {
		if _, ok := req[k]; ok {
			t.Errorf("%s sent: %v", k, req)
		}
	}

	a.Effort = "low"
	if _, err := a.Generate(context.Background(), "s", "p"); err != nil {
		t.Fatal(err)
	}
	if oc, _ := req["output_config"].(map[string]any); oc["effort"] != "low" {
		t.Errorf("output_config = %v", req["output_config"])
	}

	reply = `{"content":[],"stop_reason":"refusal"}`
	if _, err := a.Generate(context.Background(), "s", "p"); err == nil || !strings.Contains(err.Error(), "declined") {
		t.Errorf("refusal err = %v", err)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`))
	}))
	defer failing.Close()
	_, err = (&Anthropic{URL: failing.URL, Model: "m", APIKey: "sk-ant-secret", Timeout: time.Second}).Generate(context.Background(), "s", "p")
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "sk-ant-secret") {
		t.Errorf("err = %v", err)
	}
}
