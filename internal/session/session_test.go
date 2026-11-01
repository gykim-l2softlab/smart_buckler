package session

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	r, err := NewResolver([]string{"10.0.0.0/8", "127.0.0.1", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"direct client", "203.0.113.5:1234", nil, "203.0.113.5"},
		{"direct client spoofs xff", "203.0.113.5:1234", []string{"1.2.3.4"}, "203.0.113.5"},
		{"trusted proxy", "10.1.2.3:80", []string{"198.51.100.7"}, "198.51.100.7"},
		{"proxy chain", "10.1.2.3:80", []string{"1.2.3.4, 198.51.100.7, 10.9.9.9"}, "198.51.100.7"},
		{"spoofed left part ignored", "127.0.0.1:80", []string{"6.6.6.6", "198.51.100.7"}, "198.51.100.7"},
		{"trusted proxy without xff", "127.0.0.1:80", nil, "127.0.0.1"},
		{"all hops trusted", "10.1.2.3:80", []string{"10.4.4.4"}, "10.1.2.3"},
		{"ipv6 loopback proxy", "[::1]:80", []string{"2001:db8::1"}, "2001:db8::1"},
		{"ipv4-mapped remote", "[::ffff:203.0.113.5]:1", nil, "203.0.113.5"},
		{"garbage hop resets chain", "10.1.2.3:80", []string{"198.51.100.7, nonsense, 10.2.2.2"}, "10.1.2.3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			if got := r.ClientIP(req); got != tt.want {
				t.Errorf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsTrusted(t *testing.T) {
	r, _ := NewResolver([]string{"10.0.0.0/8"})
	if !r.IsTrusted("10.2.3.4") || r.IsTrusted("11.0.0.1") || r.IsTrusted("not-an-ip") {
		t.Error("IsTrusted mismatch")
	}
	none, _ := NewResolver(nil)
	if none.IsTrusted("127.0.0.1") {
		t.Error("empty resolver trusts loopback")
	}
}

func TestNewResolverRejectsInvalid(t *testing.T) {
	if _, err := NewResolver([]string{"10.0.0.0/33"}); err == nil {
		t.Error("expected error")
	}
	if _, err := NewResolver([]string{"proxy.local"}); err == nil {
		t.Error("expected error")
	}
}
