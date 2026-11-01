// Package score extracts behavioral signals from each session's recent
// requests and turns them into a score.
package score

import (
	"container/list"
	"fmt"
	"hash/maphash"
	"sort"
	"sync"
	"time"
)

// Kind classifies a request by what it fetched.
type Kind uint8

// Kinds.
const (
	KindOther Kind = iota // API calls, downloads, anything else
	KindPage              // HTML pages and non-asset 404s
	KindAsset             // CSS, JS, images, fonts, media
)

// Entry is one observed request. Paths and queries are kept as hashes so a
// session costs a few kilobytes and no raw URL is held in memory.
type Entry struct {
	At        time.Time
	PathHash  uint64
	QueryHash uint64
	HasQuery  bool
	Kind      Kind
	Status    int
	// RobotsDisallowed: upstream robots.txt disallows the path.
	RobotsDisallowed bool
	// RobotsFetch: the request was for /robots.txt.
	RobotsFetch bool
	// WAFWouldBlock: the WAF anomaly score reached the blocking threshold.
	WAFWouldBlock bool
}

// History is a session's entries within the window, oldest first.
type History struct {
	Entries []Entry
	// Now is the evaluation time.
	Now time.Time
	// RobotsFetched: the session requested /robots.txt at some point, even
	// before the window. Browsers never do.
	RobotsFetched bool
}

// Signal is one behavioral rule. Implementations must be pure functions of
// the history so each can be tested on its own.
type Signal interface {
	Name() string
	Fired(h History) bool
}

// Result is a session's score and the signals behind it.
type Result struct {
	Score int
	Fired []string
}

type weighted struct {
	Signal
	weight int
}

// Tracker keeps recent history per session, bounded in both entries per
// session and number of sessions (least recently seen sessions are evicted).
type Tracker struct {
	signals     []weighted
	window      time.Duration
	maxEntries  int
	maxSessions int
	now         func() time.Time

	mu       sync.Mutex
	sessions map[string]*list.Element
	lru      *list.List // front = most recently seen
}

type session struct {
	id            string
	entries       []Entry
	reportedAt    map[string]time.Time
	robotsFetched bool
}

// Config configures a Tracker.
type Config struct {
	// Weights maps signal names to weights. Signals with weight 0 are disabled.
	Weights map[string]int
	// Window is how far back history is kept.
	Window      time.Duration
	MaxEntries  int
	MaxSessions int
}

// DefaultWindow, DefaultMaxEntries and DefaultMaxSessions bound memory to
// roughly MaxSessions * MaxEntries * 64 bytes (about 40 MB).
const (
	DefaultWindow      = 2 * time.Minute
	DefaultMaxEntries  = 64
	DefaultMaxSessions = 10000
)

// NewTracker builds a Tracker using the built-in signals.
func NewTracker(cfg Config, now func() time.Time) (*Tracker, error) {
	byName := map[string]Signal{}
	for _, s := range Signals() {
		byName[s.Name()] = s
	}
	t := &Tracker{
		window:      cfg.Window,
		maxEntries:  cfg.MaxEntries,
		maxSessions: cfg.MaxSessions,
		now:         now,
		sessions:    map[string]*list.Element{},
		lru:         list.New(),
	}
	names := make([]string, 0, len(cfg.Weights))
	for name := range cfg.Weights {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unknown signal %q", name)
		}
		if w := cfg.Weights[name]; w > 0 {
			t.signals = append(t.signals, weighted{Signal: s, weight: w})
		}
	}
	return t, nil
}

// Observe appends e to the session's history.
func (t *Tracker) Observe(id string, e Entry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.touch(id)
	s.entries = append(s.entries, e)
	s.robotsFetched = s.robotsFetched || e.RobotsFetch
	t.prune(s, e.At)
}

// Evaluate scores the session's history.
func (t *Tracker) Evaluate(id string) Result {
	now := t.now()
	t.mu.Lock()
	el, ok := t.sessions[id]
	if !ok {
		t.mu.Unlock()
		return Result{}
	}
	s := el.Value.(*session)
	t.prune(s, now)
	h := History{Entries: append([]Entry(nil), s.entries...), Now: now, RobotsFetched: s.robotsFetched}
	t.mu.Unlock()

	var r Result
	for _, sig := range t.signals {
		if sig.Fired(h) {
			r.Score += sig.weight
			r.Fired = append(r.Fired, sig.Name())
		}
	}
	return r
}

// ShouldReport reports whether an event of the given kind should be recorded
// for the session, at most once per kind and window, so a bot cannot flood
// the store.
func (t *Tracker) ShouldReport(id, kind string) bool {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.touch(id)
	if last, ok := s.reportedAt[kind]; ok && now.Sub(last) < t.window {
		return false
	}
	if s.reportedAt == nil {
		s.reportedAt = map[string]time.Time{}
	}
	s.reportedAt[kind] = now
	return true
}

// touch returns the session, creating it and evicting the least recently
// seen one when full. Callers hold t.mu.
func (t *Tracker) touch(id string) *session {
	if el, ok := t.sessions[id]; ok {
		t.lru.MoveToFront(el)
		return el.Value.(*session)
	}
	if t.lru.Len() >= t.maxSessions {
		oldest := t.lru.Back()
		delete(t.sessions, oldest.Value.(*session).id)
		t.lru.Remove(oldest)
	}
	s := &session{id: id}
	t.sessions[id] = t.lru.PushFront(s)
	return s
}

// prune drops entries outside the window and beyond maxEntries. Callers hold t.mu.
func (t *Tracker) prune(s *session, now time.Time) {
	cut := 0
	for cut < len(s.entries) && now.Sub(s.entries[cut].At) > t.window {
		cut++
	}
	if over := len(s.entries) - cut - t.maxEntries; over > 0 {
		cut += over
	}
	if cut > 0 {
		s.entries = append(s.entries[:0], s.entries[cut:]...)
	}
}

var hashSeed = maphash.MakeSeed()

// Hash hashes a path or query for an Entry.
func Hash(s string) uint64 {
	return maphash.String(hashSeed, s)
}
