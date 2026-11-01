// Package deception generates decoy paths, advertises them to automated
// clients (robots.txt and hidden links) and recognizes requests for them.
package deception

import (
	"context"
	crand "crypto/rand"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/gykim-l2softlab/smart_buckler/internal/store"
)

// DecoyStore persists the decoy set so it stays stable across restarts
// (crawlers cache robots.txt).
type DecoyStore interface {
	Decoys(ctx context.Context) ([]store.Decoy, error)
	ReplaceDecoys(ctx context.Context, decoys []store.Decoy) error
}

const (
	decoyCount = 4
	tokenLen   = 6

	// LinkGracePeriod delays hidden link injection after a decoy is created.
	// Search engines may cache robots.txt for up to 24 hours; injecting links
	// before they see the new Disallow lines would lead them into the trap.
	LinkGracePeriod = 24 * time.Hour
)

// decoyWords are names automated attackers look for. The random suffix keeps
// each installation's paths unique so they cannot be fingerprinted or skipped.
var decoyWords = []struct{ slug, label string }{
	{"admin-backup", "Admin backup"},
	{"internal-api", "Internal API"},
	{"db-export", "Database export"},
	{"staging-admin", "Staging admin"},
	{"config-backup", "Configuration backup"},
	{"private-files", "Private files"},
	{"debug-console", "Debug console"},
	{"user-export", "User data export"},
	{"old-site", "Old site"},
	{"api-keys", "API keys"},
}

// Decoy is an active trap path.
type Decoy struct {
	// Base is the cleaned path without a trailing slash, e.g. "/admin-backup-k7f3q2".
	Base      string
	Label     string
	CreatedAt time.Time
}

// Deception holds the active decoys. It is immutable after Load and safe for
// concurrent use.
type Deception struct {
	decoys []Decoy
	now    func() time.Time
}

// Load returns the stored decoys, replacing any that conflict with
// reservedPaths and generating new ones until there are decoyCount.
func Load(ctx context.Context, st DecoyStore, reservedPaths []string, now func() time.Time) (*Deception, error) {
	stored, err := st.Decoys(ctx)
	if err != nil {
		return nil, err
	}
	reserved := make([]string, len(reservedPaths))
	for i, p := range reservedPaths {
		reserved[i] = strings.ToLower(p)
	}

	var (
		decoys  []Decoy
		changed bool
		used    = map[string]bool{}
	)
	for _, s := range stored {
		base := strings.TrimSuffix(s.Path, "/")
		if conflicts(base, reserved) {
			changed = true
			continue
		}
		slug := slugOf(base)
		used[slug] = true
		decoys = append(decoys, Decoy{Base: base, Label: labelOf(slug), CreatedAt: s.CreatedAt})
	}

	for _, i := range rand.Perm(len(decoyWords)) {
		if len(decoys) >= decoyCount {
			break
		}
		w := decoyWords[i]
		if used[w.slug] {
			continue
		}
		base := "/" + w.slug + "-" + token()
		if conflicts(base, reserved) {
			continue
		}
		used[w.slug] = true
		decoys = append(decoys, Decoy{Base: base, Label: w.label, CreatedAt: now()})
		changed = true
	}
	if len(decoys) == 0 {
		return nil, fmt.Errorf("every decoy candidate conflicts with deception.reserved_paths")
	}

	if changed {
		out := make([]store.Decoy, len(decoys))
		for i, d := range decoys {
			out[i] = store.Decoy{Path: d.Base + "/", CreatedAt: d.CreatedAt}
		}
		if err := st.ReplaceDecoys(ctx, out); err != nil {
			return nil, err
		}
	}
	return &Deception{decoys: decoys, now: now}, nil
}

// conflicts uses plain string prefixes in both directions, so a reserved
// "/admin" also excludes "/admin-backup-..." (nginx "location /admin" matches it).
func conflicts(base string, reserved []string) bool {
	for _, r := range reserved {
		if strings.HasPrefix(base, r) || strings.HasPrefix(r, base) {
			return true
		}
	}
	return false
}

func token() string {
	return strings.ToLower(crand.Text()[:tokenLen])
}

// slugOf strips the random suffix: "/admin-backup-k7f3q2" -> "admin-backup".
func slugOf(base string) string {
	s := strings.TrimPrefix(base, "/")
	if i := strings.LastIndexByte(s, '-'); i > 0 {
		return s[:i]
	}
	return s
}

func labelOf(slug string) string {
	for _, w := range decoyWords {
		if w.slug == slug {
			return w.label
		}
	}
	return strings.ReplaceAll(slug, "-", " ")
}

// Decoys returns the active decoys.
func (d *Deception) Decoys() []Decoy {
	return append([]Decoy(nil), d.decoys...)
}

// IsTrap reports whether a request for urlPath hits a decoy. Matching is
// case-insensitive and on cleaned paths, so case-insensitive upstreams (IIS)
// and dot segments cannot bypass it.
func (d *Deception) IsTrap(urlPath string) bool {
	p := strings.ToLower(path.Clean("/" + urlPath))
	for _, dc := range d.decoys {
		if p == dc.Base || strings.HasPrefix(p, dc.Base+"/") {
			return true
		}
	}
	return false
}

// IsPrefetch reports whether r is a browser speculative fetch. Browsers may
// prefetch links a user never sees, so prefetches must not trigger a block.
func IsPrefetch(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Sec-Purpose"), "prefetch") ||
		r.Header.Get("Purpose") == "prefetch" ||
		r.Header.Get("X-Moz") == "prefetch"
}

// linkDecoy picks a decoy old enough for link injection, stable per page so
// the same page always renders the same bytes.
func (d *Deception) linkDecoy(pagePath string) (Decoy, bool) {
	var eligible []Decoy
	now := d.now()
	for _, dc := range d.decoys {
		if now.Sub(dc.CreatedAt) >= LinkGracePeriod {
			eligible = append(eligible, dc)
		}
	}
	if len(eligible) == 0 {
		return Decoy{}, false
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(pagePath))
	return eligible[h.Sum32()%uint32(len(eligible))], true
}
