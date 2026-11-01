package response

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var secret = []byte(strings.Repeat("k", 32))

func newChallenger(t *testing.T, difficulty int, now func() time.Time) *Challenger {
	t.Helper()
	c, err := NewChallenger(secret, difficulty, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var dataAttr = regexp.MustCompile(`data-(c|d|r|p)="([^"]*)"`)

// servePage returns the challenge page's data attributes.
func servePage(t *testing.T, c *Challenger, target, ip string) (*httptest.ResponseRecorder, map[string]string) {
	t.Helper()
	w := httptest.NewRecorder()
	c.Serve(w, httptest.NewRequest(http.MethodGet, target, nil), ip)
	attrs := map[string]string{}
	for _, m := range dataAttr.FindAllStringSubmatch(w.Body.String(), -1) {
		attrs[m[1]] = strings.ReplaceAll(m[2], "&amp;", "&")
	}
	return w, attrs
}

func solve(token string, difficulty int) string {
	for n := 0; ; n++ {
		sum := sha256.Sum256([]byte(token + ":" + strconv.Itoa(n)))
		if leadingZeroBits(sum[:]) >= difficulty {
			return strconv.Itoa(n)
		}
	}
}

func verify(c *Challenger, ip, token, nonce, redirect string) *httptest.ResponseRecorder {
	q := url.Values{"c": {token}, "n": {nonce}, "r": {redirect}}
	w := httptest.NewRecorder()
	c.Verify(w, httptest.NewRequest(http.MethodGet, PoWPath+"?"+q.Encode(), nil), ip)
	return w
}

func TestChallengeRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := newChallenger(t, 12, func() time.Time { return now })
	const ip = "203.0.113.1"

	w, attrs := servePage(t, c, "/board?page=2&sort=new", ip)
	if w.Code != http.StatusForbidden || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("serve: %d %v", w.Code, w.Header())
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'nonce-") {
		t.Error("missing CSP nonce")
	}
	if attrs["r"] != "/board?page=2&sort=new" || attrs["d"] != "12" || attrs["p"] != PoWPath {
		t.Fatalf("attrs = %v", attrs)
	}

	res := verify(c, ip, attrs["c"], solve(attrs["c"], 12), attrs["r"])
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/board?page=2&sort=new" {
		t.Fatalf("verify: %d %v", res.Code, res.Header())
	}
	cookies := res.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie = %+v", cookies)
	}

	withPass := func(ip string, at time.Time) bool {
		now = at
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(cookies[0])
		return c.HasPass(r, ip)
	}
	start := now
	if !withPass(ip, start) {
		t.Error("pass rejected")
	}
	if withPass("203.0.113.2", start) {
		t.Error("pass accepted from another IP")
	}
	if withPass(ip, start.Add(24*time.Hour+time.Second)) {
		t.Error("expired pass accepted")
	}
}

func TestVerifyRejects(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := newChallenger(t, 12, func() time.Time { return now })
	const ip = "203.0.113.1"
	_, attrs := servePage(t, c, "/", ip)
	token := attrs["c"]
	good := solve(token, 12)

	bad := "0"
	for n := 0; ; n++ {
		sum := sha256.Sum256([]byte(token + ":" + strconv.Itoa(n)))
		if leadingZeroBits(sum[:]) < 12 {
			bad = strconv.Itoa(n)
			break
		}
	}
	other := newChallenger(t, 12, func() time.Time { return now })
	other.secret = []byte(strings.Repeat("x", 32))
	passToken := c.signToken(tokenPass, ip, now.Add(time.Hour), "")

	tests := []struct {
		name, ip, token, nonce string
		c                      *Challenger
	}{
		{"insufficient work", ip, token, bad, c},
		{"other client", "203.0.113.9", token, good, c},
		{"tampered", ip, token[:len(token)-2] + "AA", good, c},
		{"other secret", ip, token, good, other},
		{"pass used as challenge", ip, passToken, solve(passToken, 12), c},
		{"non-numeric nonce", ip, token, "12a", c},
		{"empty", ip, "", "", c},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := verify(tt.c, tt.ip, tt.token, tt.nonce, "/")
			if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
				t.Errorf("accepted: %d", w.Code)
			}
		})
	}

	// Expired challenge.
	now = now.Add(challengeTTL + time.Second)
	if w := verify(c, ip, token, good, "/"); w.Code != http.StatusForbidden {
		t.Errorf("expired challenge accepted: %d", w.Code)
	}
}

func TestSafeRedirect(t *testing.T) {
	tests := map[string]string{
		"/board?x=1":           "/board?x=1",
		"//evil.example/":      "/",
		"/\\evil.example":      "/",
		"/\t/evil.example":     "/",
		"https://evil.example": "/",
		"javascript:alert(1)":  "/",
		"":                     "/",
		PoWPath + "?c=x":       "/",
	}
	for in, want := range tests {
		if got := safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewChallengerValidates(t *testing.T) {
	if _, err := NewChallenger([]byte("short"), 16, time.Hour, time.Now); err == nil {
		t.Error("short secret accepted")
	}
	if _, err := NewChallenger(secret, 0, time.Hour, time.Now); err == nil {
		t.Error("difficulty 0 accepted")
	}
}

// TestChallengeScriptInNode runs the page's own JavaScript in Node: its
// SHA-256 must match Go's, and a nonce it finds must pass Verify.
func TestChallengeScriptInNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	now := time.Unix(1_800_000_000, 0)
	c := newChallenger(t, 12, func() time.Time { return now })
	const ip = "203.0.113.1"
	w, attrs := servePage(t, c, "/after?x=1", ip)

	script := regexp.MustCompile(`(?s)<script nonce="[^"]+">(.*)</script>`).FindStringSubmatch(w.Body.String())
	if script == nil {
		t.Fatal("no script")
	}
	inputs := []string{"", "abc", strings.Repeat("a", 55), strings.Repeat("b", 56), strings.Repeat("c", 200)}
	harness := fmt.Sprintf(`
var module = {exports: {}};
var redirected = null;
var attrs = %q;
var location = {replace: function (u) { redirected = u; }};
var setTimeout = function (f) { f(); };
var document = {getElementById: function (id) {
  if (id === "l2b") return {getAttribute: function (n) { return JSON.parse(attrs)[n.slice(5)]; }};
  return {textContent: ""};
}};
%s
var hex = function (h) { return h.map(function (x) { return x.toString(16).padStart(8, "0"); }).join(""); };
console.log(JSON.stringify({hashes: %s.map(function (s) { return hex(module.exports.sha256(s)); }), redirected: redirected}));
`, mustJSON(attrs), script[1], mustJSON(inputs))

	path := filepath.Join(t.TempDir(), "harness.js")
	if err := os.WriteFile(path, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	var got struct {
		Hashes     []string `json:"hashes"`
		Redirected string   `json:"redirected"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("parse %s: %v", out, err)
	}
	for i, in := range inputs {
		want := sha256.Sum256([]byte(in))
		if got.Hashes[i] != hex.EncodeToString(want[:]) {
			t.Errorf("sha256(%d bytes): js %s, go %x", len(in), got.Hashes[i], want)
		}
	}

	u, err := url.Parse(got.Redirected)
	if err != nil || u.Path != PoWPath {
		t.Fatalf("script redirected to %q", got.Redirected)
	}
	res := httptest.NewRecorder()
	c.Verify(res, httptest.NewRequest(http.MethodGet, got.Redirected, nil), ip)
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/after?x=1" {
		t.Errorf("solution from script rejected: %d %v", res.Code, res.Header())
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
