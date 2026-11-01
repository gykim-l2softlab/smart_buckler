package admin

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PasswordSecret is the store secret that holds the password hash.
const PasswordSecret = "admin_password"

// MinPasswordLength is the shortest accepted admin password.
const MinPasswordLength = 12

const (
	pbkdf2Iterations = 600_000 // OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
	pbkdf2KeyLen     = 32
	hashScheme       = "pbkdf2-sha256"
)

// HashPassword returns an encoded PBKDF2-HMAC-SHA256 hash of pw.
func HashPassword(pw string) (string, error) {
	if len([]rune(pw)) < MinPasswordLength {
		return "", fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	enc := base64.RawStdEncoding
	return strings.Join([]string{hashScheme, strconv.Itoa(pbkdf2Iterations), enc.EncodeToString(salt), enc.EncodeToString(key)}, "$"), nil
}

// VerifyPassword reports whether pw matches the encoded hash.
func VerifyPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// sessions signs stateless session tokens. A token embeds a tag of the
// current password hash, so changing the password ends every session.
type sessions struct {
	key []byte
	ttl time.Duration
}

const sessionKind = "a1"

func passwordTag(encoded string) string {
	sum := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(sum[:8])
}

func (s sessions) issue(passwordHash string, now time.Time) string {
	payload := strings.Join([]string{sessionKind, strconv.FormatInt(now.Add(s.ttl).Unix(), 10), passwordTag(passwordHash)}, "|")
	enc := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return enc + "." + base64.RawURLEncoding.EncodeToString(s.mac("session|"+enc))
}

func (s sessions) valid(token, passwordHash string, now time.Time) bool {
	enc, sig, ok := strings.Cut(token, ".")
	if !ok || passwordHash == "" {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac("session|"+enc)) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 || parts[0] != sessionKind || parts[2] != passwordTag(passwordHash) {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	return err == nil && now.Before(time.Unix(exp, 0))
}

// csrf derives the form token for a session token.
func (s sessions) csrf(token string) string {
	return hex.EncodeToString(s.mac("csrf|" + token)[:16])
}

func (s sessions) mac(data string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// limiter locks out an address after too many failed logins.
type limiter struct {
	max    int
	window time.Duration

	mu    sync.Mutex
	fails map[string][]time.Time
}

const maxTrackedAddrs = 10_000

var errLocked = errors.New("too many failed logins")

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, fails: map[string][]time.Time{}}
}

// check returns errLocked while addr is locked out.
func (l *limiter) check(addr string, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.recent(addr, now)) >= l.max {
		return errLocked
	}
	return nil
}

func (l *limiter) fail(addr string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.fails) >= maxTrackedAddrs {
		for a := range l.fails {
			if len(l.recent(a, now)) == 0 {
				delete(l.fails, a)
			}
		}
		if len(l.fails) >= maxTrackedAddrs {
			l.fails = map[string][]time.Time{}
		}
	}
	l.fails[addr] = append(l.recent(addr, now), now)
}

func (l *limiter) reset(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, addr)
}

// recent returns addr's failures inside the window. Callers hold l.mu.
func (l *limiter) recent(addr string, now time.Time) []time.Time {
	ts := l.fails[addr]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= l.window {
		i++
	}
	if i == len(ts) {
		delete(l.fails, addr)
		return nil
	}
	l.fails[addr] = ts[i:]
	return ts[i:]
}
