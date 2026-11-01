package proxy

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gykim-l2softlab/smart_buckler/internal/score"
	"github.com/gykim-l2softlab/smart_buckler/internal/store"
)

// siteUpstream behaves like a small website: pages under known prefixes,
// assets by extension, 404 elsewhere, 400 for /api/item, and a robots.txt.
func siteUpstream(t testing.TB) *upstream {
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hits++
		u.mu.Unlock()
		p := r.URL.Path
		switch {
		case p == "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private/\n"))
		case strings.HasSuffix(p, ".css"):
			w.Header().Set("Content-Type", "text/css")
			_, _ = w.Write([]byte("body{}"))
		case strings.HasSuffix(p, ".js"):
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = w.Write([]byte(";"))
		case strings.HasSuffix(p, ".png"), strings.HasSuffix(p, ".ico"):
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte{0x89, 'P', 'N', 'G'})
		case p == "/api/item":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("<html><body>bad request</body></html>"))
		case strings.HasPrefix(p, "/api/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		case p == "/", strings.HasPrefix(p, "/board"), strings.HasPrefix(p, "/search"), strings.HasPrefix(p, "/login"),
			strings.HasPrefix(p, "/logout"), strings.HasPrefix(p, "/private/"), strings.HasPrefix(p, "/article"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<!doctype html><html><body><h1>page</h1></body></html>"))
		default:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><body>not found</body></html>"))
		}
	}))
	t.Cleanup(u.Close)
	return u
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// scoreHandler builds a handler with a fake clock driving both the tracker
// and recorded entries.
func scoreHandler(t testing.TB, up *upstream, rec Recorder, challenge bool) (*Handler, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Now()}
	o := testOptions(t, up, &fakeInspector{}, rec)
	tr, err := score.NewTracker(score.Config{
		Weights: score.DefaultWeights(), Window: score.DefaultWindow,
		MaxEntries: score.DefaultMaxEntries, MaxSessions: score.DefaultMaxSessions,
	}, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	o.Tracker, o.Now, o.Challenge = tr, clk.now, challenge
	o.Deception = loadDeception(t)
	return New(o), clk
}

const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

func nav(h http.Handler, path, ip string, extra ...string) *httptest.ResponseRecorder {
	return get(h, path, ip, append([]string{"Accept", browserAccept, "Sec-Fetch-Dest", "document", "Sec-Fetch-Mode", "navigate"}, extra...)...)
}

func isChallenge(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), `id="l2b"`)
}

// scan sends n requests for missing pages, gap apart, with the given Accept.
func scanWith(h http.Handler, clk *fakeClock, ip, accept string, n int, gap time.Duration) {
	for i := 0; i < n; i++ {
		clk.advance(gap)
		get(h, fmt.Sprintf("/nope/%d.php", i), ip, "Accept", accept)
	}
}

func scan(h http.Handler, clk *fakeClock, ip string, n int, gap time.Duration) {
	scanWith(h, clk, ip, "*/*", n, gap)
}

func TestScannerIsChallenged(t *testing.T) {
	up := siteUpstream(t)
	rec := &fakeRecorder{}
	h, clk := scoreHandler(t, up, rec, true)
	const ip = "198.51.100.30:1"

	if w := nav(h, "/", ip); isChallenge(w) {
		t.Fatal("challenged before any suspicious behavior")
	}
	scan(h, clk, ip, 12, 200*time.Millisecond)

	w := nav(h, "/board", ip)
	if !isChallenge(w) {
		t.Fatalf("scanner not challenged: %d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("challenge cacheable")
	}
	// Another client is unaffected.
	if w := nav(h, "/board", "198.51.100.31:1"); isChallenge(w) {
		t.Error("other client challenged")
	}

	var challenged []store.Event
	for _, e := range rec.all() {
		if e.Action == store.ActionChallenged {
			challenged = append(challenged, e)
		}
	}
	if len(challenged) != 1 || challenged[0].Score < score.DefaultThreshold || len(challenged[0].Signals) == 0 {
		t.Fatalf("challenged events = %+v", challenged)
	}
	// Repeated challenges within the window are not recorded again.
	nav(h, "/board", ip)
	nav(h, "/search", ip)
	n := 0
	for _, e := range rec.all() {
		if e.Action == store.ActionChallenged {
			n++
		}
	}
	if n != 1 {
		t.Errorf("challenged recorded %d times", n)
	}
}

func TestOverThresholdNonNavigationPasses(t *testing.T) {
	up := siteUpstream(t)
	rec := &fakeRecorder{}
	h, clk := scoreHandler(t, up, rec, true)
	const ip = "198.51.100.32:1"
	// Scan with API requests so the scan itself is never challenged.
	scanWith(h, clk, ip, "application/json", 12, 200*time.Millisecond)

	tests := []struct {
		name string
		do   func() *httptest.ResponseRecorder
	}{
		{"json api", func() *httptest.ResponseRecorder { return get(h, "/api/list", ip, "Accept", "application/json") }},
		{"fetch from page", func() *httptest.ResponseRecorder {
			return get(h, "/board", ip, "Accept", "*/*", "Sec-Fetch-Dest", "empty", "Sec-Fetch-Mode", "cors")
		}},
		{"image", func() *httptest.ResponseRecorder { return get(h, "/static/logo.png", ip, "Accept", "image/*") }},
		{"post", func() *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("a=b"))
			r.RemoteAddr = ip
			r.Header.Set("Accept", browserAccept)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			return w
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if w := tt.do(); isChallenge(w) || w.Code == http.StatusForbidden {
				t.Errorf("non-navigation challenged: %d", w.Code)
			}
		})
	}
	var would int
	for _, e := range rec.all() {
		if e.Action == store.ActionWouldChallenge {
			would++
		}
	}
	if would != 1 {
		t.Errorf("would_challenge events = %d, want 1", would)
	}
}

func TestDetectModeOnlyRecords(t *testing.T) {
	up := siteUpstream(t)
	rec := &fakeRecorder{}
	h, clk := scoreHandler(t, up, rec, false)
	const ip = "198.51.100.33:1"
	scan(h, clk, ip, 12, 200*time.Millisecond)

	if w := nav(h, "/board", ip); w.Code != http.StatusOK {
		t.Fatalf("detect mode blocked navigation: %d", w.Code)
	}
	var found bool
	for _, e := range rec.all() {
		if e.Action == store.ActionWouldChallenge && e.Score >= score.DefaultThreshold {
			found = true
		}
		if e.Action == store.ActionChallenged {
			t.Error("challenged in detect mode")
		}
	}
	if !found {
		t.Error("no would_challenge event")
	}
}

var dataC = regexp.MustCompile(`data-c="([^"]+)"`)

func solvePoW(token string, difficulty int) string {
	for n := 0; ; n++ {
		sum := sha256.Sum256([]byte(token + ":" + strconv.Itoa(n)))
		z := 0
		for _, b := range sum {
			if b != 0 {
				z += bits.LeadingZeros8(b)
				break
			}
			z += 8
		}
		if z >= difficulty {
			return strconv.Itoa(n)
		}
	}
}

func TestSolvingChallengeGrantsPass(t *testing.T) {
	up := siteUpstream(t)
	rec := &fakeRecorder{}
	h, clk := scoreHandler(t, up, rec, true)
	const ip = "198.51.100.34:1"
	scan(h, clk, ip, 12, 200*time.Millisecond)

	page := nav(h, "/board?page=3", ip)
	m := dataC.FindStringSubmatch(page.Body.String())
	if !isChallenge(page) || m == nil {
		t.Fatalf("expected challenge, got %d", page.Code)
	}
	q := url.Values{"c": {m[1]}, "n": {solvePoW(m[1], 8)}, "r": {"/board?page=3"}}
	res := get(h, "/.l2b/pow?"+q.Encode(), ip)
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/board?page=3" {
		t.Fatalf("verify: %d %v", res.Code, res.Header())
	}
	cookie := res.Result().Cookies()[0]

	hits := up.hits
	if w := nav(h, "/board?page=3", ip, "Cookie", cookie.Name+"="+cookie.Value); w.Code != http.StatusOK {
		t.Fatalf("with pass: %d", w.Code)
	}
	if up.hits != hits+1 {
		t.Error("request with pass not forwarded")
	}
	if w := nav(h, "/board", ip); !isChallenge(w) {
		t.Error("request without the cookie not challenged")
	}

	var passed bool
	for _, e := range rec.all() {
		passed = passed || e.Action == store.ActionChallengePassed
	}
	if !passed {
		t.Error("no challenge_passed event")
	}
}

func TestRobotsReaderVisitingDisallowedIsChallenged(t *testing.T) {
	up := siteUpstream(t)
	h, clk := scoreHandler(t, up, &fakeRecorder{}, true)
	const ip = "198.51.100.35:1"

	// A person visiting a disallowed path is fine.
	if w := nav(h, "/private/report", "198.51.100.36:1"); w.Code != http.StatusOK {
		t.Fatalf("person: %d", w.Code)
	}
	clk.advance(time.Second)
	if w := nav(h, "/board", "198.51.100.36:1"); isChallenge(w) {
		t.Error("person visiting disallowed path challenged")
	}

	get(h, "/robots.txt", ip, "Accept", "*/*")
	clk.advance(2 * time.Second)
	get(h, "/private/report", ip, "Accept", "*/*")
	clk.advance(2 * time.Second)
	if w := get(h, "/board", ip, "Accept", "*/*"); !isChallenge(w) {
		t.Errorf("robots reader not challenged: %d", w.Code)
	}
}

func TestHumanBrowsingNotChallenged(t *testing.T) {
	up := siteUpstream(t)
	rec := &fakeRecorder{}
	h, clk := scoreHandler(t, up, rec, true)
	const ip = "198.51.100.37:1"
	gaps := []time.Duration{3, 12, 7, 30, 5, 9, 16, 4, 22, 6, 11, 8}
	for i, g := range gaps {
		clk.advance(g * time.Second)
		w := nav(h, fmt.Sprintf("/article/%d", i), ip)
		if w.Code != http.StatusOK {
			t.Fatalf("page %d: %d", i, w.Code)
		}
		if i == 0 {
			// First visit loads assets; later pages come from cache.
			get(h, "/static/site.css", ip, "Accept", "text/css,*/*;q=0.1", "Sec-Fetch-Dest", "style")
			get(h, "/static/app.js", ip, "Accept", "*/*", "Sec-Fetch-Dest", "script")
		}
		get(h, "/api/notifications", ip, "Accept", "application/json", "Sec-Fetch-Dest", "empty")
	}
	for _, e := range rec.all() {
		t.Errorf("unexpected event: %+v", e)
	}
}

func TestIsNavigation(t *testing.T) {
	tests := []struct {
		method, path string
		hdr          []string
		want         bool
	}{
		{"GET", "/", []string{"Sec-Fetch-Dest", "document"}, true},
		{"GET", "/", []string{"Accept", browserAccept}, true},
		{"GET", "/", []string{"Accept", "*/*"}, true},
		{"GET", "/", nil, true},
		{"GET", "/", []string{"Accept", "application/json"}, false},
		{"GET", "/", []string{"Sec-Fetch-Dest", "empty", "Accept", "*/*"}, false},
		{"GET", "/", []string{"Sec-Fetch-Dest", "iframe"}, false},
		{"GET", "/app.js", []string{"Accept", "*/*"}, false},
		{"POST", "/", []string{"Sec-Fetch-Dest", "document"}, false},
	}
	for _, tt := range tests {
		r := httptest.NewRequest(tt.method, tt.path, nil)
		for i := 0; i+1 < len(tt.hdr); i += 2 {
			r.Header.Set(tt.hdr[i], tt.hdr[i+1])
		}
		if got := isNavigation(r); got != tt.want {
			t.Errorf("isNavigation(%s %s %v) = %v", tt.method, tt.path, tt.hdr, got)
		}
	}
}
