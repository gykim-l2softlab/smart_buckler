// Command l2-buckler runs the reverse proxy.
//
//	l2-buckler [-config FILE]                          run the proxy
//	l2-buckler report [-config FILE] [-date D] [-send] print (or send) a daily report
//	l2-buckler notify-test [-config FILE]              send a test message to every channel
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
	"syscall"
	"time"
	_ "time/tzdata" // report.timezone works in minimal containers without zoneinfo

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
	if len(args) > 0 && (args[0] == "report" || args[0] == "notify-test") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("l2-buckler "+cmd, flag.ExitOnError)
	configPath := fs.String("config", "l2-buckler.yaml", "path to the configuration file")
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
	case "notify-test":
		err = withReporter(ctx, *configPath, func(g *report.Generator) error {
			return checkSent(g, g.Send(ctx, report.Report{
				Day:     "test",
				Subject: "[l2-buckler] 알림 테스트",
				Body:    "l2-buckler 알림 설정이 정상입니다. 매일 보안 요약을 이 채널로 보냅니다.\n",
			}))
		})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "l2-buckler:", err)
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
		o.LLM = &report.Ollama{URL: l.URL, Model: l.Model, Timeout: l.Timeout}
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
	log.Info("l2-buckler started", "listen", cfg.Listen, "upstream", cfg.UpstreamURL().String(),
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
	<-reportDone // Run returns once ctx is cancelled
	if err := recorder.Close(shutdownCtx); err != nil {
		log.Error("flush events", "err", err)
	}
	if d := recorder.Dropped(); d > 0 {
		log.Warn("events dropped during run", "dropped_total", d)
	}
	return nil
}
