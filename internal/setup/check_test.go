package setup

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrompterAsk(t *testing.T) {
	var out strings.Builder
	p := NewPrompter(bufio.NewReader(strings.NewReader("bad\n\n")), &out)
	calls := 0
	got, err := p.Ask("포트", "8080", func(s string) (string, error) {
		calls++
		if s == "bad" {
			return "", errors.New("틀렸습니다")
		}
		return s, nil
	})
	if err != nil || got != "8080" {
		t.Fatalf("Ask = %q, %v; want default after a retry", got, err)
	}
	if calls != 2 || !strings.Contains(out.String(), "틀렸습니다") || !strings.Contains(out.String(), "[8080]") {
		t.Errorf("calls = %d, output = %q", calls, out.String())
	}
}

func TestPrompterAskGivesUp(t *testing.T) {
	p := NewPrompter(bufio.NewReader(strings.NewReader(strings.Repeat("x\n", maxAttempts+1))), &strings.Builder{})
	if _, err := p.Ask("q", "", func(string) (string, error) { return "", errors.New("no") }); err == nil {
		t.Fatal("Ask kept asking after maxAttempts")
	}
}

func TestPrompterEOF(t *testing.T) {
	p := NewPrompter(bufio.NewReader(strings.NewReader("")), &strings.Builder{})
	if _, err := p.Ask("q", "d", func(s string) (string, error) { return s, nil }); err == nil {
		t.Fatal("Ask on closed input returned no error")
	}
}

func TestPrompterConfirm(t *testing.T) {
	tests := []struct {
		in   string
		def  bool
		want bool
	}{
		{"\n", true, true},
		{"\n", false, false},
		{"y\n", false, true},
		{"예\n", false, true},
		{"N\n", true, false},
		{"maybe\nn\n", true, false},
	}
	for _, tt := range tests {
		p := NewPrompter(bufio.NewReader(strings.NewReader(tt.in)), &strings.Builder{})
		got, err := p.Confirm("q", tt.def)
		if err != nil || got != tt.want {
			t.Errorf("Confirm(%q, %v) = %v, %v; want %v", tt.in, tt.def, got, err, tt.want)
		}
	}
}

func TestCheckHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if status, err := CheckHTTP(context.Background(), srv.URL); err != nil || status != http.StatusInternalServerError {
		t.Errorf("CheckHTTP = %d, %v; any response counts as reachable", status, err)
	}
	if status, err := CheckHTTP(context.Background(), srv.URL+"/redirect"); err != nil || status != http.StatusFound {
		t.Errorf("CheckHTTP followed a redirect: %d, %v", status, err)
	}

	_, err := CheckHTTP(context.Background(), "http://"+closedAddr(t))
	if err == nil {
		t.Fatal("CheckHTTP to a closed port succeeded")
	}
	if got := Explain(err); !strings.Contains(got, "거부") {
		t.Errorf("Explain(refused) = %q", got)
	}
}

func TestPortFreeAndReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	addr := ln.Addr().String()
	err = PortFree(addr)
	if err == nil {
		t.Fatal("PortFree on a bound port succeeded")
	}
	if got := Explain(err); !strings.Contains(got, "이미") {
		t.Errorf("Explain(in use) = %q", got)
	}
	if err := Reachable(context.Background(), addr); err != nil {
		t.Errorf("Reachable(listening) = %v", err)
	}
	if err := Reachable(context.Background(), closedAddr(t)); err == nil {
		t.Error("Reachable(closed) succeeded")
	}
}

func TestDialAddr(t *testing.T) {
	tests := map[string]string{
		":8080":          "127.0.0.1:8080",
		"0.0.0.0:80":     "127.0.0.1:80",
		"[::]:80":        "127.0.0.1:80",
		"127.0.0.1:8081": "127.0.0.1:8081",
		"10.0.0.5:8080":  "10.0.0.5:8080",
	}
	for in, want := range tests {
		if got := DialAddr(in); got != want {
			t.Errorf("DialAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDetectTimezone(t *testing.T) {
	env := func(tz string) func(string) string {
		return func(k string) string {
			if k == "TZ" {
				return tz
			}
			return ""
		}
	}
	link := func(target string, err error) func(string) (string, error) {
		return func(string) (string, error) { return target, err }
	}
	noLink := link("", errors.New("no link"))
	tests := []struct {
		name     string
		getenv   func(string) string
		readlink func(string) (string, error)
		want     string
	}{
		{"TZ", env("Europe/Berlin"), noLink, "Europe/Berlin"},
		{"TZ with colon", env(":UTC"), noLink, "UTC"},
		{"localtime link", env(""), link("/usr/share/zoneinfo/America/New_York", nil), "America/New_York"},
		{"macOS link", env(""), link("/var/db/timezone/zoneinfo/Asia/Tokyo", nil), "Asia/Tokyo"},
		{"invalid TZ falls through", env("Not/AZone"), link("/usr/share/zoneinfo/UTC", nil), "UTC"},
		{"fallback", env(""), noLink, "Asia/Seoul"},
	}
	for _, tt := range tests {
		if got := DetectTimezone(tt.getenv, tt.readlink); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}

// closedAddr returns a loopback address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}
