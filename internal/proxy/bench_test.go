package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gykim-l2softlab/smart_buckler/internal/waf"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

type nopRecorder struct{ fakeRecorder }

// BenchmarkPipeline measures the full handler with the real WAF against an
// in-process upstream. Compare against BenchmarkPassThrough to get the added
// latency per request.
func BenchmarkPipeline(b *testing.B) {
	engine, err := waf.New(waf.Config{Mode: waf.ModeBlock, RequestBodyLimit: 1 << 20})
	if err != nil {
		b.Fatal(err)
	}
	benchHandler(b, engine)
}

func BenchmarkPassThrough(b *testing.B) {
	benchHandler(b, &fakeInspector{})
}

func benchHandler(b *testing.B, insp Inspector) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	h := New(u, insp, &nopRecorder{}, discardLogger())

	b.ResetTimer()
	for b.Loop() {
		r := httptest.NewRequest(http.MethodGet, "/board?page=2&sort=recent", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		r.Header.Set("Accept", "text/html")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			b.Fatalf("status %d", w.Code)
		}
	}
}
