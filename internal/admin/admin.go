// Package admin serves the administration web UI: today's summary, event
// search, per-client history, blocks and decoys. It listens apart from the
// proxy, renders HTML on the server and uses no JavaScript.
package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"go.yaml.in/yaml/v3"

	"github.com/gykim-l2softlab/smart_buckler/internal/report"
	"github.com/gykim-l2softlab/smart_buckler/internal/store"
)

//go:embed locales
var locales embed.FS

const (
	locale       = "ko"
	cookieName   = "l2b_admin"
	maxValueLen  = 200
	pageSize     = 50
	loginMaxFail = 5
	loginWindow  = 15 * time.Minute
	formLimit    = 4 << 10
)

// Store is what the admin UI reads from storage.
type Store interface {
	Summarize(ctx context.Context, from, to time.Time, limit int) (store.Summary, error)
	ListEvents(ctx context.Context, f store.EventFilter, p store.Page) ([]store.StoredEvent, error)
	EventByID(ctx context.Context, id int64) (store.StoredEvent, bool, error)
	ActionCounts(ctx context.Context, f store.EventFilter) (map[string]int, error)
	HourlyCounts(ctx context.Context, f store.EventFilter) ([]store.HourCount, error)
	PathCounts(ctx context.Context, f store.EventFilter) (map[string]int, error)
	ActiveBlocks(ctx context.Context, now time.Time) ([]store.Block, error)
	Decoys(ctx context.Context) ([]store.Decoy, error)
	Reports(ctx context.Context, limit int) ([]store.ReportInfo, error)
	Report(ctx context.Context, day string) (string, bool, error)
	GetSecret(ctx context.Context, name string) ([]byte, error)
}

// Unblocker lifts blocks.
type Unblocker interface {
	Unblock(ctx context.Context, id string) (bool, error)
}

// Recorder records events.
type Recorder interface {
	Record(e store.Event)
}

// Reporter builds report previews and sends test messages.
type Reporter interface {
	Preview(ctx context.Context, day string) (report.Report, error)
	TestMessage() (report.Report, error)
	SendEach(ctx context.Context, rep report.Report) []report.SendResult
	Labels() map[string]string
}

// Options configures the admin UI.
type Options struct {
	Store     Store
	Blocklist Unblocker
	Recorder  Recorder
	Reporter  Reporter
	// SessionKey signs session cookies. It must be stable across restarts.
	SessionKey      []byte
	SessionDuration time.Duration
	// Listen and Hosts decide which Host headers are accepted.
	Listen string
	Hosts  []string
	// Location is the report time zone; "today" starts at its midnight.
	Location *time.Location
	// Info is shown on the settings page.
	Info Info
	Log  *slog.Logger
	Now  func() time.Time
}

// Info describes the running instance.
type Info struct {
	Version   string
	Started   time.Time
	WAFMode   string
	ScoreMode string
	// Config is the redacted configuration as YAML.
	Config string
	// Dropped returns how many events the recorder has dropped.
	Dropped func() uint64
}

// Server is the admin UI handler.
type Server struct {
	Options
	sessions sessions
	limiter  *limiter
	hosts    map[string]bool
	pages    map[string]*template.Template
	text     texts
	mux      *http.ServeMux
}

// texts holds labels from the locale file.
type texts struct {
	Actions map[string]struct {
		Label string `yaml:"label"`
		Desc  string `yaml:"desc"`
	} `yaml:"actions"`
	Series []string `yaml:"series"`
}

// New returns the admin UI.
func New(o Options) (*Server, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Location == nil {
		o.Location = time.Local
	}
	if len(o.SessionKey) < 32 {
		return nil, fmt.Errorf("admin session key must be at least 32 bytes")
	}
	s := &Server{
		Options:  o,
		sessions: sessions{key: o.SessionKey, ttl: o.SessionDuration},
		limiter:  newLimiter(loginMaxFail, loginWindow),
		hosts:    allowedHosts(o.Listen, o.Hosts),
	}
	raw, err := locales.ReadFile("locales/" + locale + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("read admin texts: %w", err)
	}
	if err := yaml.Unmarshal(raw, &s.text); err != nil {
		return nil, fmt.Errorf("parse admin texts: %w", err)
	}
	if err := s.parsePages(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

// allowedHosts lists the Host headers the UI answers. Anything else is
// refused so a hostile page cannot reach the UI through DNS rebinding.
func allowedHosts(listen string, extra []string) map[string]bool {
	hosts := map[string]bool{listen: true}
	if _, port, err := net.SplitHostPort(listen); err == nil {
		for _, h := range []string{"localhost", "127.0.0.1", "[::1]"} {
			hosts[h+":"+port] = true
		}
	}
	for _, h := range extra {
		hosts[strings.ToLower(h)] = true
	}
	return hosts
}

func (s *Server) hostAllowed(host string) bool {
	host = strings.ToLower(host)
	if s.hosts[host] {
		return true
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return s.hosts[h]
	}
	return false
}

func (s *Server) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /login", s.loginPage)
	m.HandleFunc("POST /login", s.login)
	m.HandleFunc("POST /logout", s.logout)
	m.HandleFunc("GET /{$}", s.overview)
	m.HandleFunc("GET /events", s.events)
	m.HandleFunc("GET /events/{id}", s.event)
	m.HandleFunc("GET /clients/{ip}", s.client)
	m.HandleFunc("GET /blocks", s.blocks)
	m.HandleFunc("GET /blocks/{ip}/unblock", s.unblockPage)
	m.HandleFunc("POST /blocks/{ip}/unblock", s.unblock)
	m.HandleFunc("GET /decoys", s.decoys)
	m.HandleFunc("GET /settings", s.settings)
	m.HandleFunc("POST /settings/notify-test", s.notifyTest)
	m.HandleFunc("GET /reports/preview", s.reportPreview)
	m.HandleFunc("GET /reports/{day}", s.reportPage)
	s.mux = m
}

type ctxKey int

const sessionCtx ctxKey = 0

// ServeHTTP checks the Host header, the session and, for POST, the CSRF
// token before routing.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.hostAllowed(r.Host) {
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
		return
	}
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")

	if r.Method == http.MethodPost {
		if o := r.Header.Get("Origin"); o != "" && o != "null" {
			if u, err := url.Parse(o); err != nil || !strings.EqualFold(u.Host, r.Host) {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, formLimit)
	}
	if r.URL.Path == "/login" {
		s.mux.ServeHTTP(w, r)
		return
	}
	token, ok := s.session(r)
	if !ok {
		if r.Method == http.MethodGet {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Error(w, "login required", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPost && r.PostFormValue("csrf") != s.sessions.csrf(token) {
		http.Error(w, "invalid form token, reload the page and try again", http.StatusForbidden)
		return
	}
	s.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionCtx, token)))
}

// session returns the session token if r carries a valid one.
func (s *Server) session(r *http.Request) (string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	hash, err := s.passwordHash(r.Context())
	if err != nil {
		s.Log.Error("admin: read password", "err", err)
		return "", false
	}
	return c.Value, s.sessions.valid(c.Value, hash, s.Now())
}

func (s *Server) passwordHash(ctx context.Context) (string, error) {
	v, err := s.Store.GetSecret(ctx, PasswordSecret)
	return string(v), err
}

// PasswordSet reports whether an admin password has been set.
func (s *Server) PasswordSet(ctx context.Context) (bool, error) {
	h, err := s.passwordHash(ctx)
	return h != "", err
}

func remoteAddr(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// view is the data every page template receives.
type view struct {
	Nav   string
	CSRF  string
	Nonce string
	Flash string
	// Series names the overview chart series.
	Series []string
	Data   any
}

// tableArgs is the input of the "table" template.
type tableArgs struct {
	Head   string
	Series []string
	Rows   []tableRow
}

func (s *Server) parsePages() error {
	funcs := template.FuncMap{
		"action":     s.actionLabel,
		"actionDesc": s.actionDesc,
		"signal":     s.signalLabel,
		"inc":        func(i int) int { return i + 1 },
		"tableArgs":  func(head string, series []string, rows []tableRow) tableArgs { return tableArgs{head, series, rows} },
		"clock":      func(t time.Time) string { return t.In(s.Location).Format("15:04:05") },
		"datetime":   func(t time.Time) string { return t.In(s.Location).Format("2006-01-02 15:04:05") },
		"clip":       clip,
		"wclass":     widthClass,
		"remaining":  remaining,
		"pathEscape": url.PathEscape,
	}
	files, err := fs.Glob(locales, "locales/"+locale+"/*.html")
	if err != nil {
		return fmt.Errorf("list admin pages: %w", err)
	}
	s.pages = map[string]*template.Template{}
	for _, f := range files {
		name := strings.TrimSuffix(f[strings.LastIndex(f, "/")+1:], ".html")
		if name == "layout" {
			continue
		}
		t, err := template.New(name).Funcs(funcs).ParseFS(locales, "locales/"+locale+"/layout.html", f)
		if err != nil {
			return fmt.Errorf("parse admin page %s: %w", name, err)
		}
		s.pages[name] = t
	}
	return nil
}

// render writes a page. Every response gets a fresh CSP nonce for the one
// inline stylesheet; scripts are not allowed at all.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page, nav string, data any) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	v := view{Nav: nav, Nonce: base64.RawStdEncoding.EncodeToString(nonce), Flash: r.URL.Query().Get("done"), Series: s.text.Series, Data: data}
	if token, ok := r.Context().Value(sessionCtx).(string); ok {
		v.CSRF = s.sessions.csrf(token)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", v); err != nil {
		s.Log.Error("admin: render", "page", page, "err", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; style-src 'nonce-%s'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'", v.Nonce))
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.Log.Error("admin: request failed", "path", r.URL.Path, "err", err)
	s.render(w, r, http.StatusInternalServerError, "error", "", "데이터를 읽지 못했습니다. 잠시 뒤 다시 시도해 주세요.")
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusNotFound, "error", "", "찾는 항목이 없습니다.")
}

func (s *Server) actionLabel(a string) string {
	if t, ok := s.text.Actions[a]; ok {
		return t.Label
	}
	return a
}

func (s *Server) actionDesc(a string) string { return s.text.Actions[a].Desc }

func (s *Server) signalLabel(k string) string {
	if l, ok := s.Reporter.Labels()[k]; ok {
		return l
	}
	return k
}

// clip removes control characters and shortens attacker-controlled values.
func clip(v string) string {
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, v)
	if r := []rune(v); len(r) > maxValueLen {
		return string(r[:maxValueLen-1]) + "…"
	}
	return v
}

// widthClass maps n/max to a CSS class w0..w100 in steps of 5, since the
// CSP forbids inline style attributes.
func widthClass(n, max int) string {
	if max <= 0 {
		return "w0"
	}
	return fmt.Sprintf("w%d", (n*100/max+4)/5*5)
}

// remaining formats a positive duration in Korean.
func remaining(until, now time.Time) string {
	d := until.Sub(now).Round(time.Minute)
	if d < time.Minute {
		return "1분 미만"
	}
	h, m := int(d.Hours()), int(d.Minutes())%60
	switch {
	case h == 0:
		return fmt.Sprintf("%d분", m)
	case m == 0:
		return fmt.Sprintf("%d시간", h)
	}
	return fmt.Sprintf("%d시간 %d분", h, m)
}
