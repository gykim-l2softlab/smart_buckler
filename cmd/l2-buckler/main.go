// Command l2-buckler runs the reverse proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gykim-l2softlab/smart_buckler/internal/config"
	"github.com/gykim-l2softlab/smart_buckler/internal/deception"
	"github.com/gykim-l2softlab/smart_buckler/internal/proxy"
	"github.com/gykim-l2softlab/smart_buckler/internal/response"
	"github.com/gykim-l2softlab/smart_buckler/internal/session"
	"github.com/gykim-l2softlab/smart_buckler/internal/store"
	"github.com/gykim-l2softlab/smart_buckler/internal/waf"
)

const shutdownTimeout = 15 * time.Second

func main() {
	configPath := flag.String("config", "l2-buckler.yaml", "path to the configuration file")
	flag.Parse()

	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "l2-buckler:", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel()}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	handler := proxy.New(proxy.Options{
		Upstream:      cfg.UpstreamURL(),
		Sessions:      sessions,
		Blocklist:     blocklist,
		Deception:     dec,
		BlockDuration: cfg.Deception.BlockDuration,
		Inspector:     engine,
		Recorder:      recorder,
		Log:           log,
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()
	log.Info("l2-buckler started", "listen", cfg.Listen, "upstream", cfg.UpstreamURL().String(), "waf_mode", cfg.WAF.Mode)

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
	if err := recorder.Close(shutdownCtx); err != nil {
		log.Error("flush events", "err", err)
	}
	if d := recorder.Dropped(); d > 0 {
		log.Warn("events dropped during run", "dropped_total", d)
	}
	return nil
}
