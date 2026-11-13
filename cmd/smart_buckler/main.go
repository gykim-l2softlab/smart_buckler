// Command smart_buckler runs the reverse proxy.
//
//	smart_buckler [-config FILE]                          run the proxy
//	smart_buckler report [-config FILE] [-date D] [-send] print (or send) a daily report
//	smart_buckler notify-test [-config FILE]              send a test message to every channel
//	smart_buckler admin-password [-config FILE]           set the admin UI password
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"
	_ "time/tzdata" // report.timezone works in minimal containers without zoneinfo

	"github.com/gykim-l2softlab/smart_buckler/internal/admin"
	"github.com/gykim-l2softlab/smart_buckler/internal/config"
	"github.com/gykim-l2softlab/smart_buckler/internal/deception"
	"github.com/gykim-l2softlab/smart_buckler/internal/notify"
	"github.com/gykim-l2softlab/smart_buckler/internal/proxy"
	"github.com/gykim-l2softlab/smart_buckler/internal/report"
	"github.com/gykim-l2softlab/smart_buckler/internal/response"
	"github.com/gykim-l2softlab/smart_buckler/internal/score"
	"github.com/gykim-l2softlab/smart_buckler/internal/session"
	"github.com/gykim-l2softlab/smart_buckler/internal/store"
	"github.com/gykim-l2softlab/smart_buckler/internal/waf"
)

const shutdownTimeout = 15 * time.Second

func main() {
	cmd, args := "serve", os.Args[1:]
	if len(args) > 0 && (args[0] == "report" || args[0] == "notify-test" || args[0] == "admin-password") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("smart_buckler "+cmd, flag.ExitOnError)
	configPath := fs.String("config", "smart_buckler.yaml", "path to the configuration file")
	date := fs.String("date", "", "report: day to report (YYYY-MM-DD, default yesterday)")
	send := fs.Bool("send", false, "report: send through the configured channels instead of printing")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "serve":
		err = run(ctx, *configPath)
	case "report":
		err = withReporter(ctx, *configPath, func(g *report.Generator) error {
			day := *date
			if day == "" {
				day = g.Yesterday()
			}
			rep, err := g.Build(ctx, day)
			if err != nil {
				return err
			}
			if !*send {
				fmt.Printf("%s\n\n%s", rep.Subject, rep.Body)
				return nil
			}
			return checkSent(g, g.Send(ctx, rep))
		})
	case "admin-password":
		err = setAdminPassword(ctx, *configPath)
	case "notify-test":
		err = withReporter(ctx, *configPath, func(g *report.Generator) error {
			msg, err := g.TestMessage()
			if err != nil {
				return err
			}
			return checkSent(g, g.Send(ctx, msg))
		})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "smart_buckler:", err)
		os.Exit(1)
	}
}

// withReporter runs fn with a report generator on the configured store.
func withReporter(ctx context.Context, configPath string, fn func(*report.Generator) error) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel()}))
	st, err := store.Open(ctx, cfg.Store.Path)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	g, err := newReporter(cfg, st, log)
	if err != nil {
		return err
	}
	return fn(g)
}

func checkSent(g *report.Generator, sent int) error {
	switch {
	case len(g.Notifiers) == 0:
		return errors.New("no notify channel is enabled")
	case sent < len(g.Notifiers):
		return fmt.Errorf("%d of %d channels failed (see log)", len(g.Notifiers)-sent, len(g.Notifiers))
	}
	return nil
}

// newReporter builds the report generator with the enabled channels.
func newReporter(cfg config.Config, st *store.Store, log *slog.Logger) (*report.Generator, error) {
	var notifiers []report.Notifier
	if e := cfg.Notify.Email; e.Enabled {
		notifiers = append(notifiers, &notify.Email{Host: e.Host, Port: e.Port, Username: e.Username, Password: e.Password, From: e.From, To: e.To})
	}
	if s := cfg.Notify.Slack; s.Enabled {
		notifiers = append(notifiers, &notify.Slack{WebhookURL: s.WebhookURL})
	}
	if t := cfg.Notify.Telegram; t.Enabled {
		notifiers = append(notifiers, &notify.Telegram{BotToken: t.BotToken, ChatID: t.ChatID})
	}
	o := report.Options{
		Store:     st,
		Notifiers: notifiers,
		Location:  cfg.ReportLocation(),
		SendAt:    cfg.ReportAt(),
		Log:       log,
	}
	if l := cfg.Report.LLM; l.Enabled {
		switch l.Provider {
		case "anthropic":
			o.LLM = &report.Anthropic{URL: l.URL, Model: l.Model, APIKey: l.APIKey, Effort: l.ReasoningEffort, Timeout: l.Timeout}
		default:
			o.LLM = &report.Chat{URL: l.URL, Model: l.Model, APIKey: l.APIKey, ReasoningEffort: l.ReasoningEffort, Timeout: l.Timeout}
		}
	}
	return report.New(o)
}

func run(ctx context.Context, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel()}))

	st, err := store.Open(ctx, cfg.Store.Path)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Error("close store", "err", err)
		}
	}()
	recorder := store.NewRecorder(st, log)

	engine, err := waf.New(waf.Config{Mode: waf.Mode(cfg.WAF.Mode), RequestBodyLimit: cfg.WAF.RequestBodyLimit})
	if err != nil {
		return err
	}
	sessions, err := session.NewResolver(cfg.TrustedProxies)
	if err != nil {
		return err
	}
	blocklist, err := response.NewBlocklist(ctx, st, log, time.Now)
	if err != nil {
		return err
	}
	var dec *deception.Deception
	if cfg.Deception.Enabled {
		if dec, err = deception.Load(ctx, st, cfg.Deception.ReservedPaths, time.Now); err != nil {
			return fmt.Errorf("load decoys: %w", err)
		}
		paths := make([]string, 0, len(dec.Decoys()))
		for _, d := range dec.Decoys() {
			paths = append(paths, d.Base+"/")
		}
		log.Info("decoys active", "paths", paths)
	}

	tracker, err := score.NewTracker(score.Config{
		Weights:     cfg.Score.Weights,
		Window:      score.DefaultWindow,
		MaxEntries:  score.DefaultMaxEntries,
		MaxSessions: score.DefaultMaxSessions,
	}, time.Now)
	if err != nil {
		return err
	}
	secret, err := st.Secret(ctx, "challenge", 32)
	if err != nil {
		return err
	}
	challenger, err := response.NewChallenger(secret, cfg.Challenge.Difficulty, cfg.Challenge.PassDuration, time.Now)
	if err != nil {
		return err
	}

	handler := proxy.New(proxy.Options{
		Upstream:      cfg.UpstreamURL(),
		Sessions:      sessions,
		Blocklist:     blocklist,
		Deception:     dec,
		BlockDuration: cfg.Deception.BlockDuration,
		Inspector:     engine,
		Tracker:       tracker,
		Threshold:     cfg.Score.Threshold,
		Challenger:    challenger,
		Challenge:     cfg.Score.Mode == config.ScoreModeChallenge,
		Recorder:      recorder,
		Log:           log,
	})

	reporter, err := newReporter(cfg, st, log)
	if err != nil {
		return err
	}
	reportDone := make(chan struct{})
	go func() { reporter.Run(ctx); close(reportDone) }()

	started := time.Now()
	var adminSrv *http.Server
	if cfg.Admin.Enabled {
		if adminSrv, err = startAdmin(ctx, cfg, st, blocklist, recorder, reporter, log, started); err != nil {
			return err
		}
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	// Bind before logging "started" so a busy port fails loudly at startup.
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	log.Info("smart_buckler started", "listen", cfg.Listen, "upstream", cfg.UpstreamURL().String(),
		"waf_mode", cfg.WAF.Mode, "score_mode", cfg.Score.Mode,
		"report_time", cfg.Report.Time, "report_timezone", cfg.ReportLocation().String(), "notify_channels", len(reporter.Notifiers))

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("http shutdown", "err", err)
	}
	if adminSrv != nil {
		if err := adminSrv.Shutdown(shutdownCtx); err != nil {
			log.Error("admin shutdown", "err", err)
		}
	}
	<-reportDone // Run returns once ctx is cancelled
	if err := recorder.Close(shutdownCtx); err != nil {
		log.Error("flush events", "err", err)
	}
	if d := recorder.Dropped(); d > 0 {
		log.Warn("events dropped during run", "dropped_total", d)
	}
	return nil
}

// startAdmin binds and serves the admin UI. A bind failure stops startup;
// later serve errors are logged and never take the proxy down.
func startAdmin(ctx context.Context, cfg config.Config, st *store.Store, bl *response.Blocklist,
	rec *store.Recorder, rep *report.Generator, log *slog.Logger, started time.Time) (*http.Server, error) {
	key, err := st.Secret(ctx, "admin_session", 32)
	if err != nil {
		return nil, err
	}
	redacted, err := cfg.Redacted()
	if err != nil {
		return nil, err
	}
	ui, err := admin.New(admin.Options{
		Store: st, Blocklist: bl, Recorder: rec, Reporter: rep,
		SessionKey: key, SessionDuration: cfg.Admin.SessionDuration,
		Listen: cfg.Admin.Listen, Hosts: cfg.Admin.Hosts, Location: cfg.ReportLocation(),
		Info: admin.Info{Version: version(), Started: started, WAFMode: cfg.WAF.Mode, ScoreMode: cfg.Score.Mode,
			Config: redacted, Dropped: rec.Dropped},
		Log: log,
	})
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", cfg.Admin.Listen)
	if err != nil {
		return nil, fmt.Errorf("admin listen: %w", err)
	}
	srv := &http.Server{
		Handler:           ui,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("admin serve", "err", err)
		}
	}()
	attrs := []any{"listen", cfg.Admin.Listen}
	if set, err := ui.PasswordSet(ctx); err == nil && !set {
		attrs = append(attrs, "note", "no password yet; run: smart_buckler admin-password")
	}
	log.Info("admin UI started", attrs...)
	if host, _, _ := net.SplitHostPort(cfg.Admin.Listen); !isLoopback(host) {
		log.Warn("admin UI listens beyond loopback without TLS; use an SSH tunnel or a TLS proxy", "listen", cfg.Admin.Listen)
	}
	return srv, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// version reports the module version stamped by the Go toolchain.
func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "unknown"
}
