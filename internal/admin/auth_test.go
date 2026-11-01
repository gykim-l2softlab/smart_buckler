package admin

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHash(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("short password accepted")
	}
	h, err := HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "pbkdf2-sha256$600000$") {
		t.Errorf("hash = %q", h)
	}
	h2, _ := HashPassword("correct-horse-battery")
	if h == h2 {
		t.Error("same salt twice")
	}
	tests := []struct {
		hash, pw string
		want     bool
	}{
		{h, "correct-horse-battery", true},
		{h, "correct-horse-batter", false},
		{h, "", false},
		{"", "correct-horse-battery", false},
		{"md5$1$x$y", "correct-horse-battery", false},
		{"pbkdf2-sha256$x$AA$AA", "correct-horse-battery", false},
	}
	for _, tt := range tests {
		if got := VerifyPassword(tt.hash, tt.pw); got != tt.want {
			t.Errorf("VerifyPassword(%q, %q) = %v", tt.hash, tt.pw, got)
		}
	}
}

func TestSessions(t *testing.T) {
	s := sessions{key: []byte(strings.Repeat("k", 32)), ttl: time.Hour}
	now := time.Unix(1_800_000_000, 0)
	tok := s.issue("hash-1", now)
	tests := []struct {
		name  string
		token string
		hash  string
		at    time.Time
		want  bool
	}{
		{"valid", tok, "hash-1", now.Add(59 * time.Minute), true},
		{"expired", tok, "hash-1", now.Add(time.Hour), false},
		{"password changed", tok, "hash-2", now, false},
		{"no password", tok, "", now, false},
		{"tampered", tok[:len(tok)-2] + "AA", "hash-1", now, false},
		{"other key", sessions{key: []byte(strings.Repeat("x", 32)), ttl: time.Hour}.issue("hash-1", now), "hash-1", now, false},
		{"garbage", "abc", "hash-1", now, false},
	}
	for _, tt := range tests {
		if got := s.valid(tt.token, tt.hash, tt.at); got != tt.want {
			t.Errorf("%s: valid = %v", tt.name, got)
		}
	}
	if s.csrf(tok) == s.csrf(s.issue("hash-1", now.Add(time.Second))) {
		t.Error("CSRF token does not depend on the session")
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(3, 15*time.Minute)
	now := time.Unix(1_800_000_000, 0)
	for i := range 3 {
		if err := l.check("a", now); err != nil {
			t.Fatalf("locked after %d failures", i)
		}
		l.fail("a", now)
	}
	if l.check("a", now) == nil {
		t.Error("not locked after 3 failures")
	}
	if l.check("b", now) != nil {
		t.Error("other address locked")
	}
	if l.check("a", now.Add(15*time.Minute)) != nil {
		t.Error("still locked after the window")
	}
	l.fail("a", now)
	l.reset("a")
	if len(l.fails) != 0 {
		t.Errorf("fails = %v after reset", l.fails)
	}
}
