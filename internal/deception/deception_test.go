package deception

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/gykim-l2softlab/smart_buckler/internal/store"
)

var t0 = time.Unix(1_800_000_000, 0)

func fixed(t time.Time) func() time.Time { return func() time.Time { return t } }

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func openStore(t *testing.T, path string) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

var decoyPattern = regexp.MustCompile(`^/[a-z-]+-[a-z2-7]{6}$`)

func TestLoadGeneratesAndPersists(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "e.db")

	d1, err := Load(ctx, openStore(t, path), nil, fixed(t0))
	if err != nil {
		t.Fatal(err)
	}
	if len(d1.decoys) != decoyCount {
		t.Fatalf("got %d decoys", len(d1.decoys))
	}
	seen := map[string]bool{}
	for _, dc := range d1.decoys {
		if !decoyPattern.MatchString(dc.Base) || dc.Label == "" || !dc.CreatedAt.Equal(t0) {
			t.Errorf("bad decoy %+v", dc)
		}
		if seen[slugOf(dc.Base)] {
			t.Errorf("duplicate word in %s", dc.Base)
		}
		seen[slugOf(dc.Base)] = true
	}

	// Restart: same decoys, original creation time kept.
	d2, err := Load(ctx, openStore(t, path), nil, fixed(t0.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	for i := range d1.decoys {
		if d1.decoys[i].Base != d2.decoys[i].Base && !containsBase(d2.decoys, d1.decoys[i].Base) {
			t.Errorf("decoy %s changed after restart", d1.decoys[i].Base)
		}
	}
	for _, dc := range d2.decoys {
		if !dc.CreatedAt.Equal(t0) {
			t.Errorf("creation time reset: %+v", dc)
		}
	}
}

func containsBase(ds []Decoy, base string) bool {
	for _, d := range ds {
		if d.Base == base {
			return true
		}
	}
	return false
}

func TestLoadReplacesConflicts(t *testing.T) {
	ctx := context.Background()
	st := openStore(t, filepath.Join(t.TempDir(), "e.db"))
	if err := st.ReplaceDecoys(ctx, []store.Decoy{
		{Path: "/admin-backup-aaaaaa/", CreatedAt: t0},
		{Path: "/old-site-bbbbbb/", CreatedAt: t0},
	}); err != nil {
		t.Fatal(err)
	}

	d, err := Load(ctx, st, []string{"/Admin"}, fixed(t0))
	if err != nil {
		t.Fatal(err)
	}
	if containsBase(d.decoys, "/admin-backup-aaaaaa") {
		t.Error("conflicting decoy kept")
	}
	if !containsBase(d.decoys, "/old-site-bbbbbb") {
		t.Error("valid decoy dropped")
	}
	for _, dc := range d.decoys {
		if strings.HasPrefix(dc.Base, "/admin") {
			t.Errorf("new decoy %s conflicts with /admin", dc.Base)
		}
	}
	stored, _ := st.Decoys(ctx)
	if len(stored) != decoyCount {
		t.Errorf("stored %d decoys", len(stored))
	}
}

func TestLoadFailsWhenEverythingConflicts(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "e.db"))
	if _, err := Load(context.Background(), st, []string{"/"}, fixed(t0)); err == nil {
		t.Fatal("expected error")
	}
}

func testDeception(created time.Time, now time.Time) *Deception {
	return &Deception{
		decoys: []Decoy{
			{Base: "/admin-backup-k7f3q2", Label: "Admin backup", CreatedAt: created},
			{Base: "/db-export-x9w4ab", Label: "Database export", CreatedAt: created},
		},
		now: fixed(now),
	}
}

func TestIsTrap(t *testing.T) {
	d := testDeception(t0, t0)
	tests := []struct {
		path string
		want bool
	}{
		{"/admin-backup-k7f3q2", true},
		{"/admin-backup-k7f3q2/", true},
		{"/admin-backup-k7f3q2/files/db.sql", true},
		{"/ADMIN-BACKUP-K7F3Q2/", true},
		{"/static/../admin-backup-k7f3q2/", true},
		{"//db-export-x9w4ab", true},
		{"/admin-backup-k7f3q2x", false},
		{"/admin-backup", false},
		{"/", false},
		{"/board/1", false},
	}
	for _, tt := range tests {
		if got := d.IsTrap(tt.path); got != tt.want {
			t.Errorf("IsTrap(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsPrefetch(t *testing.T) {
	for _, h := range [][2]string{{"Sec-Purpose", "prefetch"}, {"Sec-Purpose", "prefetch;prerender"}, {"Purpose", "prefetch"}, {"X-Moz", "prefetch"}} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(h[0], h[1])
		if !IsPrefetch(r) {
			t.Errorf("%s: %s not detected", h[0], h[1])
		}
	}
	if IsPrefetch(httptest.NewRequest("GET", "/", nil)) {
		t.Error("plain request detected as prefetch")
	}
}

func TestRobots(t *testing.T) {
	d := testDeception(t0, t0)
	disallow := "Disallow: /admin-backup-k7f3q2/\nDisallow: /db-export-x9w4ab/\n"
	tests := []struct {
		name, in, want string
	}{
		{"no upstream", "", "User-agent: *\n" + disallow},
		{
			"wildcard group",
			"User-agent: *\nDisallow: /private/\n",
			"User-agent: *\n" + disallow + "Disallow: /private/\n",
		},
		{
			"specific groups get disallow too, wildcard added",
			"User-agent: Googlebot\nUser-agent: Bingbot\nAllow: /\n\nSitemap: https://a.example/s.xml",
			"User-agent: Googlebot\nUser-agent: Bingbot\n" + disallow + "Allow: /\n\nSitemap: https://a.example/s.xml\n\nUser-agent: *\n" + disallow,
		},
		{
			"crlf and comments",
			"# hi\r\nuser-agent : * # all\r\nDisallow: /tmp/\r\n",
			"# hi\nuser-agent : * # all\n" + disallow + "Disallow: /tmp/\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.Robots(tt.in); got != tt.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestAcceptsGzip(t *testing.T) {
	tests := []struct {
		in   []string
		want bool
	}{
		{[]string{"gzip, deflate, br, zstd"}, true},
		{[]string{"br", "GZIP;q=0.5"}, true},
		{[]string{"gzip;q=0"}, false},
		{[]string{"gzip; q=0.000"}, false},
		{[]string{"br"}, false},
		{nil, false},
	}
	for _, tt := range tests {
		if got := acceptsGzip(tt.in); got != tt.want {
			t.Errorf("acceptsGzip(%q) = %v", tt.in, got)
		}
	}
}

func TestPrepareUpstreamRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Encoding", "gzip, deflate, br")
	PrepareUpstreamRequest(r)
	if r.Header.Get("Accept-Encoding") != "gzip" {
		t.Errorf("got %q", r.Header.Get("Accept-Encoding"))
	}
	r = httptest.NewRequest("GET", "/robots.txt", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	PrepareUpstreamRequest(r)
	if r.Header.Get("Accept-Encoding") != "" {
		t.Error("robots.txt request still compressed")
	}
}

func TestInjector(t *testing.T) {
	const snip = `<a hidden>x</a>`
	tests := []struct {
		name, in, want string
	}{
		{"simple", "<html><body><p>hi</p></body></html>", "<html><body>" + snip + "<p>hi</p></body></html>"},
		{"attributes and case", `<HTML><BODY class="a b" data-x='1'>hi`, `<HTML><BODY class="a b" data-x='1'>` + snip + "hi"},
		{"no body tag", "<p>fragment</p>", "<p>fragment</p>"},
		{"bodyguard is not body", "<bodyguard>x</bodyguard><body>y", "<bodyguard>x</bodyguard><body>" + snip + "y"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// OneByteReader exercises tags split across reads.
			got, err := io.ReadAll(newInjector(iotest.OneByteReader(strings.NewReader(tt.in)), snip))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInjectorGivesUpAfterScanLimit(t *testing.T) {
	in := strings.Repeat("a", bodyScanLimit+100) + "<body>"
	got, err := io.ReadAll(newInjector(strings.NewReader(in), "X"))
	if err != nil || string(got) != in {
		t.Errorf("modified beyond scan limit (len %d, err %v)", len(got), err)
	}
}

func htmlResponse(t *testing.T, method, path string, body []byte, header http.Header) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if header == nil {
		header = http.Header{}
	}
	if header.Get("Content-Type") == "" {
		header.Set("Content-Type", "text/html; charset=utf-8")
	}
	return &http.Response{
		StatusCode: 200, Status: "200 OK", Header: header, Request: req,
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)),
	}
}

const page = "<!doctype html><html><head><title>t</title></head><body><h1>hello</h1></body></html>"

var hiddenLink = regexp.MustCompile(`<a href="(/[a-z-]+-[a-z0-9]{6}/)" hidden aria-hidden="true" tabindex="-1" rel="nofollow">[^<]+</a>`)

func TestModifyResponseInjectsAfterGracePeriod(t *testing.T) {
	before := testDeception(t0, t0.Add(LinkGracePeriod-time.Minute))
	after := testDeception(t0, t0.Add(LinkGracePeriod))

	resp := htmlResponse(t, "GET", "/", []byte(page), nil)
	_ = before.ModifyResponse(discard())(resp)
	if b, _ := io.ReadAll(resp.Body); string(b) != page {
		t.Errorf("injected during grace period: %s", b)
	}

	h := http.Header{"Etag": {`"abc"`}, "Content-Length": {"88"}}
	resp = htmlResponse(t, "GET", "/", []byte(page), h)
	_ = after.ModifyResponse(discard())(resp)
	b, _ := io.ReadAll(resp.Body)
	m := hiddenLink.FindStringSubmatch(string(b))
	if m == nil {
		t.Fatalf("no hidden link in %s", b)
	}
	if !after.IsTrap(m[1]) {
		t.Errorf("injected link %s is not a trap", m[1])
	}
	if resp.Header.Get("Content-Length") != "" || resp.ContentLength != -1 {
		t.Error("stale Content-Length kept")
	}
	if resp.Header.Get("ETag") != `W/"abc"` {
		t.Errorf("ETag = %q, want weak", resp.Header.Get("ETag"))
	}

	// Same page, same link.
	resp2 := htmlResponse(t, "GET", "/", []byte(page), nil)
	_ = after.ModifyResponse(discard())(resp2)
	b2, _ := io.ReadAll(resp2.Body)
	if string(b) != string(b2) {
		t.Error("injection is not deterministic per page")
	}
}

func TestModifyResponseGzip(t *testing.T) {
	d := testDeception(t0, t0.Add(LinkGracePeriod))
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(page))
	_ = zw.Close()

	resp := htmlResponse(t, "GET", "/", gz.Bytes(), http.Header{"Content-Encoding": {"gzip"}})
	_ = d.ModifyResponse(discard())(resp)
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if !hiddenLink.Match(b) || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("gzip page not injected: %s", b)
	}
	_ = resp.Body.Close()

	// Corrupt gzip is forwarded untouched.
	bad := []byte("not gzip at all")
	resp = htmlResponse(t, "GET", "/", bad, http.Header{"Content-Encoding": {"gzip"}})
	_ = d.ModifyResponse(discard())(resp)
	if b, _ := io.ReadAll(resp.Body); string(b) != string(bad) {
		t.Errorf("corrupt gzip modified: %q", b)
	}
}

func TestModifyResponseSkips(t *testing.T) {
	d := testDeception(t0, t0.Add(LinkGracePeriod))
	tests := []struct {
		name string
		resp func() *http.Response
	}{
		{"json", func() *http.Response {
			return htmlResponse(t, "GET", "/", []byte(page), http.Header{"Content-Type": {"application/json"}})
		}},
		{"head", func() *http.Response { return htmlResponse(t, "HEAD", "/", []byte(page), nil) }},
		{"404", func() *http.Response {
			r := htmlResponse(t, "GET", "/", []byte(page), nil)
			r.StatusCode = 404
			return r
		}},
		{"attachment", func() *http.Response {
			return htmlResponse(t, "GET", "/", []byte(page), http.Header{"Content-Disposition": {"attachment; filename=a.html"}})
		}},
		{"brotli", func() *http.Response {
			return htmlResponse(t, "GET", "/", []byte(page), http.Header{"Content-Encoding": {"br"}})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := tt.resp()
			_ = d.ModifyResponse(discard())(resp)
			if b, _ := io.ReadAll(resp.Body); string(b) != page {
				t.Errorf("modified: %s", b)
			}
		})
	}
}

func TestModifyResponseRobots(t *testing.T) {
	d := testDeception(t0, t0)
	for _, tt := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"upstream robots", 200, "User-agent: *\nDisallow: /tmp/\n", "Disallow: /tmp/"},
		{"upstream 404", 404, "not found", "User-agent: *"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp := htmlResponse(t, "GET", "/robots.txt", []byte(tt.body), http.Header{"Content-Type": {"text/plain"}})
			resp.StatusCode = tt.status
			_ = d.ModifyResponse(discard())(resp)
			b, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 || !strings.Contains(string(b), tt.want) ||
				!strings.Contains(string(b), "Disallow: /admin-backup-k7f3q2/") {
				t.Errorf("status %d body %q", resp.StatusCode, b)
			}
			if resp.ContentLength != int64(len(b)) {
				t.Errorf("ContentLength %d, body %d", resp.ContentLength, len(b))
			}
		})
	}
}

func TestUpstreamDisallows(t *testing.T) {
	robots := `User-agent: Googlebot
Disallow: /only-google/

User-agent: *
User-agent: Bingbot
Disallow: /search
Disallow: /cart$
Disallow: /*.pdf$
Disallow: /private/
Allow: /private/public/
Disallow: /tmp/*/cache
`
	r := parseRobotsRules(robots)
	tests := []struct {
		path string
		want bool
	}{
		{"/search", true},
		{"/search?q=x", true},
		{"/searching", true},
		{"/cart", true},
		{"/cart/items", false},
		{"/docs/a.pdf", true},
		{"/docs/a.pdf.html", false},
		{"/private/x", true},
		{"/private/public/x", false},
		{"/tmp/a/cache/1", true},
		{"/only-google/", false},
		{"/", false},
	}
	for _, tt := range tests {
		if got := r.disallows(tt.path); got != tt.want {
			t.Errorf("disallows(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}

	d := testDeception(t0, t0)
	if d.UpstreamDisallows("/search") {
		t.Error("disallowed before robots.txt was fetched")
	}
	resp := htmlResponse(t, "GET", "/robots.txt", []byte(robots), http.Header{"Content-Type": {"text/plain"}})
	_ = d.ModifyResponse(discard())(resp)
	if !d.UpstreamDisallows("/search") || d.UpstreamDisallows("/admin-backup-k7f3q2/") {
		t.Error("upstream rules not captured, or decoys mixed in")
	}
}
