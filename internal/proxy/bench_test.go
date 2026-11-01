package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gykim-l2softlab/smart_buckler/internal/deception"
	"github.com/gykim-l2softlab/smart_buckler/internal/waf"
)

func benchDeception(b *testing.B) *deception.Deception {
	d, err := deception.Load(context.Background(), tempStore(b), nil, time.Now)
	if err != nil {
		b.Fatal(err)
	}
	return d
}

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
	up := &upstream{Server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))}
	defer up.Close()
	h := newHandlerWith(b, up, insp, &nopRecorder{}, benchDeception(b), nil)

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

// BenchmarkHTMLInjection measures hidden link injection on a 20 KB gzip page,
// with and without deception, using a no-op inspector.
func BenchmarkHTMLInjection(b *testing.B) {
	pageBody := []byte("<!doctype html><html><head><title>t</title></head><body>" +
		strings.Repeat("<p>lorem ipsum dolor sit amet</p>", 600) + "</body></html>")
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(pageBody)
	_ = zw.Close()

	up := &upstream{Server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gz.Bytes())
	}))}
	defer up.Close()

	for _, tc := range []struct {
		name string
		dec  func() *deception.Deception
	}{
		{"off", func() *deception.Deception { return nil }},
		{"on", func() *deception.Deception { return loadDeception(b) }},
	} {
		b.Run(tc.name, func(b *testing.B) {
			h := newHandlerWith(b, up, &fakeInspector{}, &nopRecorder{}, tc.dec(), nil)
			for b.Loop() {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Accept-Encoding", "gzip")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != http.StatusOK {
					b.Fatalf("status %d", w.Code)
				}
			}
		})
	}
}
