package admin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gykim-l2softlab/smart_buckler/internal/report"
	"github.com/gykim-l2softlab/smart_buckler/internal/response"
	"github.com/gykim-l2softlab/smart_buckler/internal/store"
)

const testPassword = "correct-horse-battery"

type fakeRecorder struct {
	mu     sync.Mutex
	events []store.Event
}

func (f *fakeRecorder) Record(e store.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

type fakeReporter struct{ sent int }

func (f *fakeReporter) Preview(_ context.Context, day string) (report.Report, error) {
	return report.Report{Day: day, Subject: "subject " + day, Body: "preview body"}, nil
}
func (f *fakeReporter) TestMessage() (report.Report, error) { return report.Report{Subject: "t"}, nil }
func (f *fakeReporter) SendEach(context.Context, report.Report) []report.SendResult {
	f.sent++
	return []report.SendResult{{Channel: "slack"}, {Channel: "email", Err: errors.New("smtp: secret-server-reply")}}
}
func (f *fakeReporter) Labels() map[string]string {
	return map[string]string{"high_404": "없는 페이지(404)를 많이 요청"}
}

type env struct {
	srv  *Server
	st   *store.Store
	bl   *response.Blocklist
	rec  *fakeRecorder
	rep  *fakeReporter
	now  time.Time
	jar  []*http.Cookie
	csrf string
}

func newEnv(t *testing.T, withPassword bool) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &env{st: st, rec: &fakeRecorder{}, rep: &fakeReporter{}, now: time.Date(2026, 11, 1, 10, 30, 0, 0, time.UTC)}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if e.bl, err = response.NewBlocklist(ctx, st, log, func() time.Time { return e.now }); err != nil {
		t.Fatal(err)
	}
	if withPassword {
		h, _ := HashPassword(testPassword)
		if err := st.SetSecret(ctx, PasswordSecret, []byte(h)); err != nil {
			t.Fatal(err)
		}
	}
	e.srv, err = New(Options{
		Store: st, Blocklist: e.bl, Recorder: e.rec, Reporter: e.rep,
		SessionKey: []byte(strings.Repeat("k", 32)), SessionDuration: time.Hour,
		Listen: "127.0.0.1:8081", Hosts: []string{"admin.example"}, Location: time.UTC,
		Info: Info{Version: "v-test", WAFMode: "detect", ScoreMode: "challenge", Config: "notify:\n  slack:\n    webhook_url: (set)\n"},
		Log:  log, Now: func() time.Time { return e.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) do(t *testing.T, method, target string, form url.Values, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:8081"+target, body)
	r.RemoteAddr = "192.0.2.10:5000"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(header); i += 2 {
		if header[i] == "Host" {
			r.Host = header[i+1]
			continue
		}
		r.Header.Set(header[i], header[i+1])
	}
	for _, c := range e.jar {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, r)
	return w
}

var hrefRE = regexp.MustCompile(`href="[^"]*"`)

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (e *env) login(t *testing.T) {
	t.Helper()
	w := e.do(t, "POST", "/login", url.Values{"password": {testPassword}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login status %d: %s", w.Code, w.Body)
	}
	e.jar = w.Result().Cookies()
	m := csrfRE.FindStringSubmatch(e.do(t, "GET", "/settings", nil).Body.String())
	if m == nil {
		t.Fatal("no CSRF token on settings page")
	}
	e.csrf = m[1]
}

func TestLoginRequired(t *testing.T) {
	e := newEnv(t, true)
	for _, p := range []string{"/", "/events", "/blocks", "/settings", "/clients/192.0.2.1"} {
		w := e.do(t, "GET", p, nil)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
			t.Errorf("GET %s = %d %s", p, w.Code, w.Header().Get("Location"))
		}
	}
	if w := e.do(t, "POST", "/blocks/192.0.2.1/unblock", url.Values{}); w.Code != http.StatusForbidden {
		t.Errorf("POST without session = %d", w.Code)
	}
}

func TestClosedWithoutPassword(t *testing.T) {
	e := newEnv(t, false)
	w := e.do(t, "GET", "/login", nil)
	if !strings.Contains(w.Body.String(), "admin-password") || strings.Contains(w.Body.String(), `type="password"`) {
		t.Error("login page without password should explain the CLI and show no form")
	}
	if w := e.do(t, "POST", "/login", url.Values{"password": {""}}); w.Code != http.StatusForbidden {
		t.Errorf("login without password set = %d", w.Code)
	}
}

func TestLoginAndLockout(t *testing.T) {
	e := newEnv(t, true)
	for i := range loginMaxFail {
		if w := e.do(t, "POST", "/login", url.Values{"password": {"wrong"}}); w.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d = %d", i, w.Code)
		}
	}
	if w := e.do(t, "POST", "/login", url.Values{"password": {testPassword}}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("locked login = %d", w.Code)
	}
	e.now = e.now.Add(loginWindow)
	e.login(t)
	c := e.jar[0]
	if c.Name != cookieName || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie = %+v", c)
	}
	if w := e.do(t, "GET", "/", nil); w.Code != http.StatusOK {
		t.Fatalf("overview = %d", w.Code)
	}
	// Changing the password ends the session.
	h, _ := HashPassword("another-long-password")
	_ = e.st.SetSecret(context.Background(), PasswordSecret, []byte(h))
	if w := e.do(t, "GET", "/", nil); w.Code != http.StatusSeeOther {
		t.Errorf("old session after password change = %d", w.Code)
	}
}

func TestRequestChecks(t *testing.T) {
	e := newEnv(t, true)
	e.login(t)
	tests := []struct {
		name   string
		method string
		form   url.Values
		header []string
		want   int
	}{
		{"loopback alias", "GET", nil, []string{"Host", "localhost:8081"}, http.StatusOK},
		{"configured host", "GET", nil, []string{"Host", "admin.example"}, http.StatusOK},
		{"rebinding host", "GET", nil, []string{"Host", "evil.example:8081"}, http.StatusMisdirectedRequest},
		{"post without csrf", "POST", url.Values{}, nil, http.StatusForbidden},
		{"post bad csrf", "POST", url.Values{"csrf": {"x"}}, nil, http.StatusForbidden},
		{"post cross origin", "POST", url.Values{"csrf": {e.csrf}}, []string{"Origin", "http://evil.example"}, http.StatusForbidden},
		{"post same origin", "POST", url.Values{"csrf": {e.csrf}}, []string{"Origin", "http://127.0.0.1:8081"}, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := "/settings"
			if tt.method == "POST" {
				target = "/settings/notify-test"
			}
			if w := e.do(t, tt.method, target, tt.form, tt.header...); w.Code != tt.want {
				t.Errorf("status %d, want %d", w.Code, tt.want)
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t, true)
	e.login(t)
	w := e.do(t, "GET", "/", nil)
	h := w.Header()
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP = %q", csp)
	}
	for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if h.Get(k) != v {
			t.Errorf("%s = %q", k, h.Get(k))
		}
	}
	nonce := regexp.MustCompile(`'nonce-([^']+)'`).FindStringSubmatch(csp)[1]
	body := w.Body.String()
	if !strings.Contains(body, `<style nonce="`+nonce+`">`) || strings.Contains(body, "<script") || strings.Contains(body, ` style="`) {
		t.Error("page must use the nonce stylesheet only, with no scripts or inline styles")
	}
}

func TestAttackerValuesAreEscaped(t *testing.T) {
	e := newEnv(t, true)
	e.login(t)
	evil := "/<script>alert(1)</script>\x1b[31m" + strings.Repeat("a", 300)
	if err := e.st.InsertEvents(context.Background(), []store.Event{{
		Time: e.now, ClientIP: "203.0.113.5", Method: "GET", Host: "<img src=x>", Path: evil, Action: store.ActionTrapHit,
		Rules: []store.Rule{{ID: 1, Message: "<b>m</b>"}},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/", "/events", "/events/1", "/clients/203.0.113.5"} {
		body := e.do(t, "GET", p, nil).Body.String()
		if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x>") || strings.Contains(body, "<b>m</b>") || strings.Contains(body, "\x1b") {
			t.Errorf("%s renders attacker markup", p)
		}
		// Links keep the full value; visible text is truncated.
		if strings.Contains(hrefRE.ReplaceAllString(body, ""), strings.Repeat("a", 250)) {
			t.Errorf("%s does not truncate long values", p)
		}
	}
}

func TestOverviewCounts(t *testing.T) {
	e := newEnv(t, true)
	e.login(t)
	ctx := context.Background()
	_ = e.st.InsertEvents(ctx, []store.Event{
		{Time: e.now.Add(-time.Hour), ClientIP: "203.0.113.1", Path: "/.env", Action: store.ActionTrapHit},
		{Time: e.now.Add(-time.Hour), ClientIP: "203.0.113.2", Path: "/", Action: store.ActionChallenged, Signals: []string{"high_404"}},
		{Time: e.now.Add(-48 * time.Hour), ClientIP: "203.0.113.3", Path: "/", Action: store.ActionWouldBlock},
	})
	e.bl.Block(ctx, "203.0.113.1", time.Hour, store.ActionTrapHit)
	body := e.do(t, "GET", "/", nil).Body.String()
	for _, want := range []string{
		"2026년 11월 1일", "10시 30분까지",
		`tile alert`, "<title>9시: 미끼 접근 차단 1, 확인 화면 1, WAF 차단 0</title>",
		"<title>10/30: 미끼 접근 차단 0, 확인 화면 0, WAF 차단 1</title>",
		"/clients/203.0.113.1", "없는 페이지(404)를 많이 요청", "탐지 모드",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("overview missing %q", want)
		}
	}
	if strings.Contains(body, "<title>11시") {
		t.Error("future hour has a tooltip")
	}
}

func TestEventsPaging(t *testing.T) {
	e := newEnv(t, true)
	e.login(t)
	var evs []store.Event
	for i := range pageSize + 5 {
		evs = append(evs, store.Event{Time: e.now.Add(time.Duration(-i) * time.Second), ClientIP: "203.0.113.9", Path: "/p", Action: store.ActionChallenged})
	}
	evs = append(evs, store.Event{Time: e.now, ClientIP: "203.0.113.9", Path: "/warn", Action: store.ActionDetected})
	_ = e.st.InsertEvents(context.Background(), evs)

	body := e.do(t, "GET", "/events", nil).Body.String()
	if strings.Contains(body, "/warn") {
		t.Error("default filter shows plain WAF warnings")
	}
	if strings.Count(body, `href="/events/`) != pageSize {
		t.Errorf("first page has %d rows", strings.Count(body, `href="/events/`))
	}
	older := regexp.MustCompile(`href="/events\?([^"]+)">더 이전`).FindStringSubmatch(body)
	if older == nil || strings.Contains(body, "더 최근") {
		t.Fatal("first page paging links wrong")
	}
	q := strings.ReplaceAll(older[1], "&amp;", "&")
	body2 := e.do(t, "GET", "/events?"+q, nil).Body.String()
	if n := strings.Count(body2, `href="/events/`); n != 5 || !strings.Contains(body2, "더 최근") || strings.Contains(body2, "더 이전") {
		t.Errorf("second page: %d rows", n)
	}
	if body := e.do(t, "GET", "/events?action=detected", nil).Body.String(); !strings.Contains(body, "/warn") {
		t.Error("detected filter misses the warning")
	}
	if w := e.do(t, "GET", "/events?ip=not-an-ip", nil); w.Code != http.StatusBadRequest {
		t.Errorf("bad ip = %d", w.Code)
	}
}

func TestUnblock(t *testing.T) {
	e := newEnv(t, true)
	e.login(t)
	ctx := context.Background()
	e.bl.Block(ctx, "203.0.113.7", time.Hour, store.ActionTrapHit)
	if body := e.do(t, "GET", "/blocks", nil).Body.String(); !strings.Contains(body, "203.0.113.7") || !strings.Contains(body, "1시간") {
		t.Error("blocks page does not list the block")
	}
	if w := e.do(t, "GET", "/blocks/203.0.113.7/unblock", nil); !strings.Contains(w.Body.String(), `method="post"`) || !e.bl.Blocked("203.0.113.7") {
		t.Fatal("GET must only show a confirmation")
	}
	w := e.do(t, "POST", "/blocks/203.0.113.7/unblock", url.Values{"csrf": {e.csrf}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/blocks?done=unblocked" {
		t.Fatalf("unblock = %d %s", w.Code, w.Header().Get("Location"))
	}
	if e.bl.Blocked("203.0.113.7") {
		t.Error("still blocked")
	}
	if len(e.rec.events) != 1 || e.rec.events[0].Action != store.ActionUnblocked || e.rec.events[0].RequestID != "admin@192.0.2.10" {
		t.Errorf("recorded = %+v", e.rec.events)
	}
	w = e.do(t, "POST", "/blocks/203.0.113.7/unblock", url.Values{"csrf": {e.csrf}})
	if w.Header().Get("Location") != "/blocks?done=notblocked" || len(e.rec.events) != 1 {
		t.Error("second unblock should report not blocked and record nothing")
	}
	if w := e.do(t, "POST", "/blocks/x/unblock", url.Values{"csrf": {e.csrf}}); w.Code != http.StatusNotFound {
		t.Errorf("bad address = %d", w.Code)
	}
}

func TestSettingsAndNotify(t *testing.T) {
	e := newEnv(t, true)
	e.login(t)
	body := e.do(t, "GET", "/settings", nil).Body.String()
	if !strings.Contains(body, "v-test") || !strings.Contains(body, "webhook_url: (set)") {
		t.Error("settings page missing info")
	}
	body = e.do(t, "POST", "/settings/notify-test", url.Values{"csrf": {e.csrf}}).Body.String()
	if e.rep.sent != 1 || !strings.Contains(body, "slack: 보냄") || !strings.Contains(body, "email: 실패") || strings.Contains(body, "secret-server-reply") {
		t.Errorf("notify result page wrong: %s", body)
	}
}

func TestDecoysAndReports(t *testing.T) {
	e := newEnv(t, true)
	e.login(t)
	ctx := context.Background()
	_ = e.st.ReplaceDecoys(ctx, []store.Decoy{{Path: "/old-backup-a1/", CreatedAt: e.now.Add(-48 * time.Hour)}, {Path: "/new-export-b2/", CreatedAt: e.now}})
	_ = e.st.InsertEvents(ctx, []store.Event{
		{Time: e.now, ClientIP: "203.0.113.1", Path: "/Old-Backup-A1/db.sql", Action: store.ActionTrapHit},
		{Time: e.now, ClientIP: "203.0.113.2", Path: "/old-backup-a1", Action: store.ActionTrapHit},
	})
	body := e.do(t, "GET", "/decoys", nil).Body.String()
	if !strings.Contains(body, "robots.txt와 숨김 링크") || !strings.Contains(body, "robots.txt에만") || !strings.Contains(body, ">2</a>") {
		t.Errorf("decoys page wrong")
	}
	_ = e.st.SaveReport(ctx, "2026-10-31", "어제 요약 본문", 1, e.now)
	if body := e.do(t, "GET", "/", nil).Body.String(); !strings.Contains(body, `href="/reports/2026-10-31"`) {
		t.Error("overview does not list the report")
	}
	if body := e.do(t, "GET", "/reports/2026-10-31", nil).Body.String(); !strings.Contains(body, "어제 요약 본문") {
		t.Error("report page missing body")
	}
	if body := e.do(t, "GET", "/reports/preview", nil).Body.String(); !strings.Contains(body, "subject 2026-11-01") {
		t.Error("preview missing")
	}
	if w := e.do(t, "GET", "/reports/2026-01-01", nil); w.Code != http.StatusNotFound {
		t.Errorf("missing report = %d", w.Code)
	}
}

func TestWidthAndRemaining(t *testing.T) {
	for _, tt := range []struct {
		n, max int
		want   string
	}{{0, 0, "w0"}, {1, 3, "w35"}, {3, 3, "w100"}, {1, 100, "w5"}} {
		if got := widthClass(tt.n, tt.max); got != tt.want {
			t.Errorf("widthClass(%d, %d) = %s", tt.n, tt.max, got)
		}
	}
	now := time.Unix(0, 0)
	for _, tt := range []struct {
		d    time.Duration
		want string
	}{{10 * time.Second, "1분 미만"}, {5 * time.Minute, "5분"}, {time.Hour, "1시간"}, {90 * time.Minute, "1시간 30분"}} {
		if got := remaining(now.Add(tt.d), now); got != tt.want {
			t.Errorf("remaining(%v) = %s", tt.d, got)
		}
	}
}
