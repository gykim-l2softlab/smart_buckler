//go:build integration

package proxy

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gykim-l2softlab/smart_buckler/internal/store"
	"github.com/gykim-l2softlab/smart_buckler/internal/waf"
)

// readFixture parses a file of concatenated raw HTTP/1.1 requests.
func readFixture(t *testing.T, path string) []*http.Request {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var reqs []*http.Request
	br := bufio.NewReader(f)
	for {
		r, err := http.ReadRequest(br)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("%s: request %d: %v", path, len(reqs)+1, err)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("%s: request %d body: %v", path, len(reqs)+1, err)
		}
		// Rebuild as a server-side request so ServeHTTP sees what net/http would deliver.
		sr := httptest.NewRequest(r.Method, r.RequestURI, bytesReader(body))
		sr.Header = r.Header
		sr.Host = r.Host
		sr.RemoteAddr = "198.51.100.20:40000"
		reqs = append(reqs, sr)
	}
	if len(reqs) == 0 {
		t.Fatalf("%s: no requests", path)
	}
	return reqs
}

func fixtures(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", dir, "*.http"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures in testdata/%s: %v", dir, err)
	}
	return files
}

func blockingHandler(t *testing.T) (*Handler, *upstream, *fakeRecorder) {
	t.Helper()
	engine, err := waf.New(waf.Config{Mode: waf.ModeBlock, RequestBodyLimit: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	up := newUpstream(t)
	rec := &fakeRecorder{}
	return newHandler(t, up, engine, rec), up, rec
}

// Benign traffic must never be blocked, even in block mode.
func TestIntegrationBenignNotBlocked(t *testing.T) {
	for _, path := range fixtures(t, "benign") {
		t.Run(filepath.Base(path), func(t *testing.T) {
			h, up, rec := blockingHandler(t)
			reqs := readFixture(t, path)
			for i, r := range reqs {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code == http.StatusForbidden {
					t.Errorf("request %d %s %s blocked", i+1, r.Method, r.URL)
				}
			}
			if up.hits != len(reqs) {
				t.Errorf("upstream hits = %d, want %d", up.hits, len(reqs))
			}
			for _, e := range rec.all() {
				t.Errorf("unexpected event on benign traffic: %s %s %+v", e.Method, e.Path, e.Rules)
			}
		})
	}
}

// Every attack request must be blocked in block mode and recorded.
func TestIntegrationAttacksBlocked(t *testing.T) {
	for _, path := range fixtures(t, "attacks") {
		t.Run(filepath.Base(path), func(t *testing.T) {
			h, up, rec := blockingHandler(t)
			reqs := readFixture(t, path)
			for i, r := range reqs {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != http.StatusForbidden {
					t.Errorf("request %d %s %s not blocked (status %d)", i+1, r.Method, r.URL, w.Code)
				}
			}
			if up.hits != 0 {
				t.Errorf("%d attack requests reached upstream", up.hits)
			}
			evs := rec.all()
			if len(evs) != len(reqs) {
				t.Fatalf("events = %d, want %d", len(evs), len(reqs))
			}
			for _, e := range evs {
				if e.Action != store.ActionBlocked {
					t.Errorf("event action = %s, want blocked", e.Action)
				}
			}
		})
	}
}
