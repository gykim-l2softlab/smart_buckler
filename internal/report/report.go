// Package report builds the daily summary from recorded events and delivers
// it on a schedule.
package report

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"text/template"
	"time"
	"unicode"

	"go.yaml.in/yaml/v3"

	"github.com/gykim-l2softlab/smart_buckler/internal/store"
)

//go:embed locales
var locales embed.FS

const (
	locale    = "ko"
	topN      = 5
	dayLayout = "2006-01-02"
	// maxValueLen bounds request paths, which are attacker-controlled.
	maxValueLen  = 80
	sendTimeout  = time.Minute
	maxAISummary = 800
	highPassMin  = 5  // challenged clients needed before judging the pass rate
	highPassPct  = 50 // pass rate that suggests people are being challenged
)

// Store is what reports need from storage.
type Store interface {
	Summarize(ctx context.Context, from, to time.Time, limit int) (store.Summary, error)
	ReportExists(ctx context.Context, day string) (bool, error)
	SaveReport(ctx context.Context, day, body string, sent int, at time.Time) error
}

// Notifier delivers a report through one channel.
type Notifier interface {
	Name() string
	Send(ctx context.Context, subject, body string) error
}

// LLM writes text from a prompt, following the system instructions. Optional.
type LLM interface {
	Generate(ctx context.Context, system, prompt string) (string, error)
}

// Options configures a Generator.
type Options struct {
	Store     Store
	Notifiers []Notifier
	// LLM is nil unless a local model is configured.
	LLM LLM
	// Location and SendAt (hour and minute) set the daily schedule. Days are
	// counted in Location.
	Location *time.Location
	SendAt   time.Duration
	Log      *slog.Logger
	Now      func() time.Time
}

// Generator builds and delivers daily reports.
type Generator struct {
	Options
	tmpl   *template.Template
	labels map[string]string
}

// Report is a rendered daily report.
type Report struct {
	Day     string
	Subject string
	Body    string
}

// New returns a Generator.
func New(o Options) (*Generator, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Location == nil {
		o.Location = time.Local
	}
	raw, err := locales.ReadFile("locales/" + locale + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("read labels: %w", err)
	}
	var labels struct {
		Signals map[string]string `yaml:"signals"`
	}
	if err := yaml.Unmarshal(raw, &labels); err != nil {
		return nil, fmt.Errorf("parse labels: %w", err)
	}
	tmpl, err := template.New(locale).Funcs(template.FuncMap{
		"date": func(t time.Time) string { return fmt.Sprintf("%d년 %d월 %d일", t.Year(), t.Month(), t.Day()) },
	}).ParseFS(locales, "locales/"+locale+".tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &Generator{Options: o, tmpl: tmpl, labels: labels.Signals}, nil
}

// labeled is a top-list entry with a human-readable label.
type labeled struct {
	Label string
	N     int
}

type data struct {
	Day                   time.Time
	Quiet                 bool
	TrapClients           int
	ChallengedClients     int
	PassedClients         int
	WouldChallengeClients int
	Blocked               int
	WouldBlock            int
	Detected              int
	PassRate              int
	HighPassRate          bool
	TopClients            []store.Count
	TopPaths              []store.Count
	TopRules              []store.RuleCount
	TopSignals            []labeled
	AISummary             string
}

// Labels returns the human-readable labels for behavior signals.
func (g *Generator) Labels() map[string]string { return g.labels }

// Build renders the report for day (YYYY-MM-DD).
func (g *Generator) Build(ctx context.Context, day string) (Report, error) {
	return g.build(ctx, day, true)
}

// Preview renders the report for day without asking the LLM, so it is fast
// and sends nothing anywhere.
func (g *Generator) Preview(ctx context.Context, day string) (Report, error) {
	return g.build(ctx, day, false)
}

func (g *Generator) build(ctx context.Context, day string, useLLM bool) (Report, error) {
	from, err := time.ParseInLocation(dayLayout, day, g.Location)
	if err != nil {
		return Report{}, fmt.Errorf("parse day: %w", err)
	}
	sum, err := g.Store.Summarize(ctx, from, from.AddDate(0, 0, 1), topN)
	if err != nil {
		return Report{}, err
	}

	d := data{
		Day:                   from,
		TrapClients:           sum.Clients[store.ActionTrapHit],
		ChallengedClients:     sum.Clients[store.ActionChallenged],
		PassedClients:         sum.Clients[store.ActionChallengePassed],
		WouldChallengeClients: sum.Clients[store.ActionWouldChallenge],
		Blocked:               sum.Events[store.ActionBlocked],
		WouldBlock:            sum.Events[store.ActionWouldBlock],
		Detected:              sum.Events[store.ActionDetected],
		TopClients:            sum.TopClients,
		TopRules:              sum.TopRules,
	}
	d.Quiet = d.TrapClients+d.ChallengedClients+d.WouldChallengeClients+d.Blocked+d.WouldBlock == 0
	if d.ChallengedClients > 0 {
		d.PassRate = min(100, d.PassedClients*100/d.ChallengedClients)
		d.HighPassRate = d.ChallengedClients >= highPassMin && d.PassRate >= highPassPct
	}
	for _, p := range sum.TopPaths {
		d.TopPaths = append(d.TopPaths, store.Count{Key: clean(p.Key, maxValueLen), N: p.N})
	}
	for _, s := range sum.TopSignals {
		label, ok := g.labels[s.Key]
		if !ok {
			label = s.Key
		}
		d.TopSignals = append(d.TopSignals, labeled{Label: label, N: s.N})
	}
	if useLLM && g.LLM != nil && !d.Quiet {
		d.AISummary = g.summarize(ctx, d)
	}

	subject, err := g.render("subject", d)
	if err != nil {
		return Report{}, err
	}
	body, err := g.render("body", d)
	if err != nil {
		return Report{}, err
	}
	return Report{Day: day, Subject: subject, Body: body}, nil
}

// summarize asks the local model for a short summary. Only counts, signal
// labels and CRS rule messages go into the prompt, never request paths or
// other attacker-controlled text. Failures fall back to the plain report.
func (g *Generator) summarize(ctx context.Context, d data) string {
	system, err := g.render("system", d)
	if err != nil {
		g.Log.Warn("report: build llm prompt", "err", err)
		return ""
	}
	prompt, err := g.render("prompt", d)
	if err != nil {
		g.Log.Warn("report: build llm prompt", "err", err)
		return ""
	}
	out, err := g.LLM.Generate(ctx, system, prompt)
	if err != nil {
		g.Log.Warn("report: llm summary failed, sending without it", "err", err)
		return ""
	}
	out = dashes.ReplaceAllString(clean(out, maxAISummary), ", ")
	return strings.TrimSpace(out)
}

func (g *Generator) render(name string, d data) (string, error) {
	var b bytes.Buffer
	if err := g.tmpl.ExecuteTemplate(&b, name, d); err != nil {
		return "", fmt.Errorf("render %s: %w", name, err)
	}
	return b.String(), nil
}

// dashes matches em dashes and middle dots, which the style guide leaves out
// of user-facing text.
var dashes = regexp.MustCompile(`\s*[—·]\s*`)

// clean removes control characters (keeping newlines) and truncates to n runes.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r != '\n' && unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// Deliver builds the report for day and sends it through every channel,
// once: a day that already has a report is skipped, so restarts never send
// duplicates. One failing channel does not stop the others.
func (g *Generator) Deliver(ctx context.Context, day string) error {
	exists, err := g.Store.ReportExists(ctx, day)
	if err != nil || exists {
		return err
	}
	rep, err := g.Build(ctx, day)
	if err != nil {
		return err
	}
	sent := g.Send(ctx, rep)
	if err := g.Store.SaveReport(ctx, day, rep.Body, sent, g.Now()); err != nil {
		return err
	}
	g.Log.Info("daily report delivered", "day", day, "channels", len(g.Notifiers), "sent", sent)
	return nil
}

// Send sends rep through every channel and returns how many accepted it.
func (g *Generator) Send(ctx context.Context, rep Report) int {
	sent := 0
	for _, r := range g.SendEach(ctx, rep) {
		if r.Err == nil {
			sent++
		}
	}
	return sent
}

// SendResult is the outcome of sending through one channel.
type SendResult struct {
	Channel string
	Err     error
}

// SendEach sends rep through every channel and reports each outcome.
func (g *Generator) SendEach(ctx context.Context, rep Report) []SendResult {
	out := make([]SendResult, 0, len(g.Notifiers))
	for _, n := range g.Notifiers {
		sctx, cancel := context.WithTimeout(ctx, sendTimeout)
		err := n.Send(sctx, rep.Subject, rep.Body)
		cancel()
		if err != nil {
			g.Log.Error("report: send failed", "channel", n.Name(), "day", rep.Day, "err", err)
		}
		out = append(out, SendResult{Channel: n.Name(), Err: err})
	}
	return out
}

// TestMessage is the message notify-test sends.
func (g *Generator) TestMessage() (Report, error) {
	subject, err := g.render("test_subject", data{})
	if err != nil {
		return Report{}, err
	}
	body, err := g.render("test_body", data{})
	if err != nil {
		return Report{}, err
	}
	return Report{Day: "test", Subject: subject, Body: body}, nil
}

// Run delivers the previous day's report every day at SendAt until ctx is
// done. If the process starts after today's send time and yesterday's report
// is missing, it is delivered right away.
func (g *Generator) Run(ctx context.Context) {
	for {
		day, due, next := g.schedule(g.Now())
		if due {
			if err := g.Deliver(ctx, day); err != nil {
				g.Log.Error("report: deliver failed", "day", day, "err", err)
			}
		}
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// schedule returns the day whose report is due at now (if today's send time
// has passed) and the next send time.
func (g *Generator) schedule(now time.Time) (day string, due bool, next time.Time) {
	now = now.In(g.Location)
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, g.Location)
	at := midnight.Add(g.SendAt)
	if now.Before(at) {
		return "", false, at
	}
	return midnight.AddDate(0, 0, -1).Format(dayLayout), true, midnight.AddDate(0, 0, 1).Add(g.SendAt)
}

// Yesterday returns the day before now in the report time zone.
func (g *Generator) Yesterday() string {
	now := g.Now().In(g.Location)
	return time.Date(now.Year(), now.Month(), now.Day()-1, 0, 0, 0, 0, g.Location).Format(dayLayout)
}
