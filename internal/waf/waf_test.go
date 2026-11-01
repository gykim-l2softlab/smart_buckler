package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

var (
	engines   = map[Mode]*WAF{}
	enginesMu sync.Mutex
)

func engine(t testing.TB, m Mode) *WAF {
	t.Helper()
	enginesMu.Lock()
	defer enginesMu.Unlock()
	if w, ok := engines[m]; ok {
		return w
	}
	w, err := New(Config{Mode: m, RequestBodyLimit: 1 << 20})
	if err != nil {
		t.Fatalf("New(%s): %v", m, err)
	}
	engines[m] = w
	return w
}

func browserRequest(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/605.1.15 Safari/605.1.15")
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("Accept-Language", "ko-KR,ko;q=0.9")
	return r
}

// formRequest sets Content-Length in the header map like net/http's server does;
// httptest.NewRequest only sets the ContentLength field (CRS rule 920180).
func formRequest(target string, form url.Values) *http.Request {
	body := form.Encode()
	r := browserRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return r
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	if _, err := New(Config{Mode: "off", RequestBodyLimit: 1}); err == nil {
		t.Error("expected error for unknown mode")
	}
	if _, err := New(Config{Mode: ModeDetect}); err == nil {
		t.Error("expected error for zero body limit")
	}
}

func TestInspect(t *testing.T) {
	tests := []struct {
		name       string
		req        func() *http.Request
		wantBlock  bool
		wantRuleID int
	}{
		{
			name: "plain page",
			req:  func() *http.Request { return browserRequest(http.MethodGet, "/", nil) },
		},
		{
			name: "search with korean text",
			req: func() *http.Request {
				return browserRequest(http.MethodGet, "/search?q="+url.QueryEscape("엘투소프트랩 리버스 프록시"), nil)
			},
		},
		{
			name: "login form",
			req: func() *http.Request {
				return formRequest("/login", url.Values{"username": {"alice"}, "password": {"correct horse battery"}})
			},
		},
		{
			name: "sqli in query",
			req: func() *http.Request {
				return browserRequest(http.MethodGet, "/item?id="+url.QueryEscape("1' OR '1'='1"), nil)
			},
			wantBlock:  true,
			wantRuleID: 942100,
		},
		{
			name: "xss in query",
			req: func() *http.Request {
				return browserRequest(http.MethodGet, "/search?q="+url.QueryEscape("<script>alert(document.cookie)</script>"), nil)
			},
			wantBlock:  true,
			wantRuleID: 941100,
		},
		{
			name: "sqli in form body",
			req: func() *http.Request {
				return formRequest("/login", url.Values{"username": {"admin' UNION SELECT password FROM users--"}, "password": {"x"}})
			},
			wantBlock:  true,
			wantRuleID: 942100,
		},
		{
			name: "path traversal",
			req: func() *http.Request {
				return browserRequest(http.MethodGet, "/download?file=../../../../etc/passwd", nil)
			},
			wantBlock:  true,
			wantRuleID: 930100,
		},
	}

	for _, mode := range []Mode{ModeDetect, ModeBlock} {
		for _, tt := range tests {
			t.Run(string(mode)+"/"+tt.name, func(t *testing.T) {
				v, closeTx, err := engine(t, mode).Inspect(tt.req())
				defer closeTx()
				if err != nil {
					t.Fatalf("Inspect: %v", err)
				}
				if v.TxID == "" {
					t.Error("empty TxID")
				}
				if got := v.WouldBlock(); got != tt.wantBlock {
					t.Fatalf("WouldBlock = %v, want %v (matches %+v)", got, tt.wantBlock, v.Matches)
				}
				if wantInterrupt := mode == ModeBlock && tt.wantBlock; v.Interrupted != wantInterrupt {
					t.Errorf("Interrupted = %v, want %v", v.Interrupted, wantInterrupt)
				}
				if v.Interrupted && v.Status != http.StatusForbidden {
					t.Errorf("Status = %d, want 403", v.Status)
				}
				if !tt.wantBlock && len(v.Matches) > 0 {
					t.Errorf("benign request has matches: %+v", v.Matches)
				}
				if tt.wantRuleID != 0 && !hasRule(v.Matches, tt.wantRuleID) {
					t.Errorf("rule %d not matched: %+v", tt.wantRuleID, v.Matches)
				}
			})
		}
	}
}

func hasRule(ms []Match, id int) bool {
	for _, m := range ms {
		if m.RuleID == id {
			return true
		}
	}
	return false
}

func TestInspectPreservesBody(t *testing.T) {
	body := strings.Repeat("a=b&", 100) + "end=1"
	r := browserRequest(http.MethodPost, "/submit", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, closeTx, err := engine(t, ModeDetect).Inspect(r)
	defer closeTx()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("body changed: got %d bytes, want %d", len(got), len(body))
	}
}

func TestInspectForwardsBodyBeyondLimit(t *testing.T) {
	w, err := New(Config{Mode: ModeBlock, RequestBodyLimit: 16})
	if err != nil {
		t.Fatal(err)
	}
	body := "note=" + strings.Repeat("x", 100)
	r := browserRequest(http.MethodPost, "/upload", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	v, closeTx, err := w.Inspect(r)
	defer closeTx()
	if err != nil {
		t.Fatal(err)
	}
	if v.Interrupted {
		t.Fatalf("oversized body was rejected: %+v", v.Matches)
	}
	got, _ := io.ReadAll(r.Body)
	if string(got) != body {
		t.Errorf("body truncated: got %d bytes, want %d", len(got), len(body))
	}
}

func BenchmarkInspectBenign(b *testing.B) {
	w := engine(b, ModeBlock)
	for b.Loop() {
		_, closeTx, err := w.Inspect(browserRequest(http.MethodGet, "/products?page=2&sort=price", nil))
		if err != nil {
			b.Fatal(err)
		}
		closeTx()
	}
}
