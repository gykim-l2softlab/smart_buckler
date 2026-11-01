package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/gykim-l2softlab/smart_buckler/internal/deception"
	"github.com/gykim-l2softlab/smart_buckler/internal/store"
	"github.com/gykim-l2softlab/smart_buckler/internal/waf"
)

// loadDeception seeds two decoys old enough for link injection; Load adds
// fresh ones that only appear in robots.txt.
func loadDeception(t testing.TB) *deception.Deception {
	t.Helper()
	st := tempStore(t)
	old := time.Now().Add(-deception.LinkGracePeriod - time.Minute)
	if err := st.ReplaceDecoys(context.Background(), []store.Decoy{
		{Path: "/admin-backup-abcdef/", CreatedAt: old},
		{Path: "/db-export-ghijkl/", CreatedAt: old},
	}); err != nil {
		t.Fatal(err)
	}
	d, err := deception.Load(context.Background(), st, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func get(h http.Handler, path, remote string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = remote
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Add(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestTrapBlocksSession(t *testing.T) {
	up := newUpstream(t)
	rec := &fakeRecorder{}
	dec := loadDeception(t)
	h := newHandlerWith(t, up, &fakeInspector{}, rec, dec, nil)
	decoy := dec.Decoys()[0].Base + "/"

	const attacker, bystander = "198.51.100.66:1000", "198.51.100.77:1000"
	if w := get(h, "/", attacker); w.Code != 200 {
		t.Fatalf("before trap: %d", w.Code)
	}
	if w := get(h, decoy, attacker); w.Code != http.StatusForbidden {
		t.Fatalf("trap response %d", w.Code)
	}
	if w := get(h, "/", attacker); w.Code != http.StatusForbidden {
		t.Errorf("attacker not blocked after trap: %d", w.Code)
	}
	if w := get(h, "/", bystander); w.Code != 200 {
		t.Errorf("other client blocked: %d", w.Code)
	}
	if up.hits != 2 {
		t.Errorf("upstream hits = %d, want 2 (trap and blocked requests must not be forwarded)", up.hits)
	}
	evs := rec.all()
	if len(evs) != 1 || evs[0].Action != store.ActionTrapHit || evs[0].ClientIP != "198.51.100.66" || evs[0].Path != decoy {
		t.Errorf("events = %+v", evs)
	}
}

func TestTrapPrefetchDoesNotBlock(t *testing.T) {
	up := newUpstream(t)
	dec := loadDeception(t)
	h := newHandlerWith(t, up, &fakeInspector{}, &fakeRecorder{}, dec, nil)

	const client = "198.51.100.5:1"
	if w := get(h, dec.Decoys()[0].Base+"/", client, "Sec-Purpose", "prefetch"); w.Code != http.StatusNotFound {
		t.Errorf("prefetch of decoy: %d, want 404", w.Code)
	}
	if w := get(h, "/", client); w.Code != 200 {
		t.Errorf("client blocked after prefetch: %d", w.Code)
	}
}

func TestTrapBehindTrustedProxy(t *testing.T) {
	up := newUpstream(t)
	dec := loadDeception(t)
	h := newHandlerWith(t, up, &fakeInspector{}, &fakeRecorder{}, dec, []string{"127.0.0.1"})
	decoy := dec.Decoys()[0].Base + "/"
	const proxy = "127.0.0.1:5000"

	// Client behind the proxy is identified and blocked; others behind the same proxy are not.
	get(h, decoy, proxy, "X-Forwarded-For", "203.0.113.10")
	if w := get(h, "/", proxy, "X-Forwarded-For", "203.0.113.10"); w.Code != http.StatusForbidden {
		t.Errorf("client behind proxy not blocked: %d", w.Code)
	}
	if w := get(h, "/", proxy, "X-Forwarded-For", "203.0.113.11"); w.Code != 200 {
		t.Errorf("other client behind proxy blocked: %d", w.Code)
	}
	if got := up.last.Header.Get("X-Forwarded-For"); got != "203.0.113.11, 127.0.0.1" {
		t.Errorf("upstream X-Forwarded-For = %q", got)
	}

	// Missing X-Forwarded-For resolves to the proxy itself, which must never be blocked.
	get(h, decoy, proxy)
	if w := get(h, "/", proxy, "X-Forwarded-For", "203.0.113.12"); w.Code != 200 {
		t.Errorf("proxy got blocked: %d", w.Code)
	}
}

func TestSpoofedForwardedForIgnored(t *testing.T) {
	up := newUpstream(t)
	dec := loadDeception(t)
	h := newHandlerWith(t, up, &fakeInspector{}, &fakeRecorder{}, dec, nil)

	// A direct client cannot frame someone else via X-Forwarded-For.
	get(h, dec.Decoys()[0].Base+"/", "198.51.100.9:1", "X-Forwarded-For", "203.0.113.50")
	if w := get(h, "/", "203.0.113.50:1"); w.Code != 200 {
		t.Errorf("spoofed address blocked: %d", w.Code)
	}
	if w := get(h, "/", "198.51.100.9:1"); w.Code != http.StatusForbidden {
		t.Errorf("real address not blocked: %d", w.Code)
	}
	// The spoofed header is not passed upstream either.
	get(h, "/", "198.51.100.10:1", "X-Forwarded-For", "203.0.113.50")
	if got := up.last.Header.Get("X-Forwarded-For"); got != "198.51.100.10" {
		t.Errorf("upstream X-Forwarded-For = %q, want only the connecting address", got)
	}
}

var linkRe = regexp.MustCompile(`<a href="(/[^"]+)" hidden`)

func TestHiddenLinkLeadsToTrap(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			http.NotFound(w, r)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><body><a href=\"/board\">board</a></body></html>"))
		}
	}))
	t.Cleanup(up.Close)
	dec := loadDeception(t)
	h := newHandlerWith(t, &upstream{Server: up}, &fakeInspector{}, &fakeRecorder{}, dec, nil)

	const crawler = "198.51.100.200:1"
	page := get(h, "/", crawler)
	m := linkRe.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("no hidden link in %q", page.Body.String())
	}
	robots := get(h, "/robots.txt", crawler)
	if robots.Code != 200 || !regexp.MustCompile(`Disallow: `+regexp.QuoteMeta(m[1])).MatchString(robots.Body.String()) {
		t.Errorf("robots.txt does not disallow %s: %d %q", m[1], robots.Code, robots.Body.String())
	}
	if w := get(h, m[1], crawler); w.Code != http.StatusForbidden {
		t.Fatalf("following hidden link: %d", w.Code)
	}
	if w := get(h, "/", crawler); w.Code != http.StatusForbidden {
		t.Errorf("crawler not blocked: %d", w.Code)
	}
}

func TestDeceptionDisabled(t *testing.T) {
	up := newUpstream(t)
	h := newHandlerWith(t, up, &fakeInspector{verdict: waf.Verdict{}}, &fakeRecorder{}, nil, nil)
	if w := get(h, "/admin-backup-aaaaaa/", "198.51.100.1:1"); w.Code != 200 || up.hits != 1 {
		t.Errorf("deception disabled but request not forwarded: %d", w.Code)
	}
}
