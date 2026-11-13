package response

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"math/bits"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// PoWPath receives challenge solutions. It is handled by smart_buckler and never
// forwarded upstream.
const PoWPath = "/.l2b/pow"

const (
	passCookie   = "l2b_pass"
	challengeTTL = 5 * time.Minute

	tokenChallenge = "c1"
	tokenPass      = "p1"
)

//go:embed challenge.html
var challengeHTML string

var challengePage = template.Must(template.New("challenge").Parse(challengeHTML))

// Challenger issues and verifies stateless proof-of-work challenges, modeled
// on Anubis: the browser finds a nonce such that SHA-256(challenge ":" nonce)
// starts with Difficulty zero bits, and receives a signed pass cookie.
// Challenges and passes are HMAC-signed and bound to the client IP, so no
// server state is kept.
type Challenger struct {
	secret     []byte
	difficulty int
	passTTL    time.Duration
	now        func() time.Time
}

// NewChallenger returns a Challenger. secret must be stable across restarts
// so passes stay valid.
func NewChallenger(secret []byte, difficulty int, passTTL time.Duration, now func() time.Time) (*Challenger, error) {
	if len(secret) < 32 {
		return nil, errors.New("challenge secret must be at least 32 bytes")
	}
	if difficulty < 1 || difficulty > 32 {
		return nil, fmt.Errorf("difficulty %d out of range 1..32", difficulty)
	}
	return &Challenger{secret: secret, difficulty: difficulty, passTTL: passTTL, now: now}, nil
}

// HasPass reports whether r carries a valid pass for clientIP.
func (c *Challenger) HasPass(r *http.Request, clientIP string) bool {
	ck, err := r.Cookie(passCookie)
	return err == nil && c.verifyToken(ck.Value, tokenPass, clientIP) == nil
}

// Serve writes the challenge page. After solving it, the browser returns to
// the current URL.
func (c *Challenger) Serve(w http.ResponseWriter, r *http.Request, clientIP string) {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	cspNonce := base64.RawStdEncoding.EncodeToString(nonce)

	var buf bytes.Buffer
	err := challengePage.Execute(&buf, map[string]any{
		"Challenge":  c.signToken(tokenChallenge, clientIP, c.now().Add(challengeTTL), hex.EncodeToString(nonce)),
		"Difficulty": c.difficulty,
		"Redirect":   safeRedirect(r.URL.RequestURI()),
		"PoWPath":    PoWPath,
		"CSPNonce":   cspNonce,
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
		cspNonce, cspNonce))
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(buf.Bytes())
}

// Verify handles a request to PoWPath. On a valid solution it sets the pass
// cookie, redirects to the original URL and returns true; otherwise it serves
// a fresh challenge and returns false.
func (c *Challenger) Verify(w http.ResponseWriter, r *http.Request, clientIP string) bool {
	q := r.URL.Query()
	token, nonce := q.Get("c"), q.Get("n")
	if err := c.verifyToken(token, tokenChallenge, clientIP); err != nil || !c.solved(token, nonce) {
		r2 := r.Clone(r.Context())
		u, err := url.ParseRequestURI(safeRedirect(q.Get("r")))
		if err != nil {
			u = &url.URL{Path: "/"}
		}
		r2.URL = u
		c.Serve(w, r2, clientIP)
		return false
	}

	http.SetCookie(w, &http.Cookie{
		Name:     passCookie,
		Value:    c.signToken(tokenPass, clientIP, c.now().Add(c.passTTL), ""),
		Path:     "/",
		MaxAge:   int(c.passTTL.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, safeRedirect(q.Get("r")), http.StatusSeeOther)
	return true
}

func (c *Challenger) solved(token, nonce string) bool {
	if nonce == "" || len(nonce) > 20 {
		return false
	}
	if _, err := strconv.ParseUint(nonce, 10, 64); err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(token + ":" + nonce))
	return leadingZeroBits(sum[:]) >= c.difficulty
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x != 0 {
			return n + bits.LeadingZeros8(x)
		}
		n += 8
	}
	return n
}

// signToken encodes kind|ip|expiry|extra with an HMAC. The kind prefix keeps
// a challenge from being usable as a pass.
func (c *Challenger) signToken(kind, ip string, expiry time.Time, extra string) string {
	payload := strings.Join([]string{kind, ip, strconv.FormatInt(expiry.Unix(), 10), extra}, "|")
	enc := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return enc + "." + base64.RawURLEncoding.EncodeToString(c.mac(enc))
}

func (c *Challenger) verifyToken(token, kind, ip string) error {
	enc, sig, ok := strings.Cut(token, ".")
	if !ok {
		return errors.New("malformed token")
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, c.mac(enc)) {
		return errors.New("bad signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return errors.New("malformed payload")
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 || parts[0] != kind || parts[1] != ip {
		return errors.New("token kind or client mismatch")
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || !c.now().Before(time.Unix(exp, 0)) {
		return errors.New("token expired")
	}
	return nil
}

func (c *Challenger) mac(data string) []byte {
	m := hmac.New(sha256.New, c.secret)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// safeRedirect keeps redirects on this site: only absolute paths, never
// scheme-relative ("//evil.example"), backslash tricks, or control
// characters (browsers drop tabs and newlines, turning "/\t/x" into "//x").
func safeRedirect(target string) string {
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") ||
		strings.HasPrefix(target, "/\\") || strings.HasPrefix(target, PoWPath) {
		return "/"
	}
	for _, r := range target {
		if r < 0x20 || r == 0x7f {
			return "/"
		}
	}
	return target
}
