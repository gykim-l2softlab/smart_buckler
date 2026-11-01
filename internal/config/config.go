// Package config defines the configuration schema and its validation.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/gykim-l2softlab/smart_buckler/internal/score"
)

// WAF modes.
const (
	WAFModeDetect = "detect"
	WAFModeBlock  = "block"
)

// Score modes.
const (
	ScoreModeChallenge = "challenge"
	ScoreModeDetect    = "detect"
)

// Config is the root configuration.
type Config struct {
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`
	// TrustedProxies lists proxies (CIDR or IP) in front of l2-buckler whose
	// X-Forwarded-For header is trusted. Leave empty when clients connect directly.
	TrustedProxies []string  `yaml:"trusted_proxies"`
	WAF            WAF       `yaml:"waf"`
	Deception      Deception `yaml:"deception"`
	Score          Score     `yaml:"score"`
	Challenge      Challenge `yaml:"challenge"`
	Store          Store     `yaml:"store"`
	Log            Log       `yaml:"log"`

	upstreamURL *url.URL
	logLevel    slog.Level
}

// WAF configures the Coraza engine.
type WAF struct {
	// Mode is "detect" (log only) or "block" (deny requests over the CRS anomaly threshold).
	Mode string `yaml:"mode"`
	// RequestBodyLimit is the number of request body bytes inspected.
	// Bytes beyond the limit are forwarded without inspection.
	RequestBodyLimit int `yaml:"request_body_limit"`
}

// Deception configures decoy paths.
type Deception struct {
	Enabled bool `yaml:"enabled"`
	// BlockDuration is how long a session that requested a decoy stays blocked.
	BlockDuration time.Duration `yaml:"block_duration"`
	// ReservedPaths are real upstream path prefixes decoys must never overlap.
	ReservedPaths []string `yaml:"reserved_paths"`
}

// Score configures behavioral scoring.
type Score struct {
	// Mode is "challenge" (serve a proof-of-work challenge to page navigations
	// over the threshold) or "detect" (record only).
	Mode      string `yaml:"mode"`
	Threshold int    `yaml:"threshold"`
	// Weights per signal. Listed keys override the defaults; 0 disables a signal.
	Weights map[string]int `yaml:"weights"`
}

// Challenge configures the proof-of-work challenge.
type Challenge struct {
	// Difficulty is the number of leading zero bits required. Each extra bit
	// doubles the expected work.
	Difficulty int `yaml:"difficulty"`
	// PassDuration is how long a solved challenge exempts the client.
	PassDuration time.Duration `yaml:"pass_duration"`
}

// Store configures the SQLite event store.
type Store struct {
	Path string `yaml:"path"`
}

// Log configures application logging.
type Log struct {
	Level string `yaml:"level"`
}

// Default returns a configuration that is safe to run without tuning.
func Default() Config {
	return Config{
		Listen: ":8080",
		WAF: WAF{
			Mode:             WAFModeDetect,
			RequestBodyLimit: 1 << 20,
		},
		Deception: Deception{
			Enabled:       true,
			BlockDuration: time.Hour,
		},
		Score: Score{
			Mode:      ScoreModeChallenge,
			Threshold: score.DefaultThreshold,
			Weights:   score.DefaultWeights(),
		},
		Challenge: Challenge{
			Difficulty:   16,
			PassDuration: 24 * time.Hour,
		},
		Store: Store{Path: "l2-buckler.db"},
		Log:   Log{Level: "info"},
	}
}

// Load reads and validates the configuration file at path.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse decodes YAML on top of Default and validates the result.
// Unknown fields are rejected so typos do not silently fall back to defaults.
func Parse(data []byte) (Config, error) {
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if c.Upstream == "" {
		return errors.New("upstream is required")
	}
	u, err := url.Parse(c.Upstream)
	if err != nil {
		return fmt.Errorf("upstream: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("upstream must be an absolute http(s) URL, got %q", c.Upstream)
	}
	c.upstreamURL = u

	switch c.WAF.Mode {
	case WAFModeDetect, WAFModeBlock:
	default:
		return fmt.Errorf("waf.mode must be %q or %q, got %q", WAFModeDetect, WAFModeBlock, c.WAF.Mode)
	}
	if c.WAF.RequestBodyLimit <= 0 {
		return errors.New("waf.request_body_limit must be positive")
	}

	for _, p := range c.TrustedProxies {
		if err := validIPOrPrefix(p); err != nil {
			return fmt.Errorf("trusted_proxies: %q: %w", p, err)
		}
	}

	if c.Deception.BlockDuration <= 0 {
		return errors.New("deception.block_duration must be positive")
	}
	for _, p := range c.Deception.ReservedPaths {
		if !strings.HasPrefix(p, "/") || p == "/" {
			return fmt.Errorf("deception.reserved_paths: %q must start with / and not be / itself", p)
		}
	}

	switch c.Score.Mode {
	case ScoreModeChallenge, ScoreModeDetect:
	default:
		return fmt.Errorf("score.mode must be %q or %q, got %q", ScoreModeChallenge, ScoreModeDetect, c.Score.Mode)
	}
	if c.Score.Threshold <= 0 {
		return errors.New("score.threshold must be positive")
	}
	known := map[string]bool{}
	for _, s := range score.Signals() {
		known[s.Name()] = true
	}
	for name, w := range c.Score.Weights {
		if !known[name] {
			return fmt.Errorf("score.weights: unknown signal %q", name)
		}
		if w < 0 {
			return fmt.Errorf("score.weights.%s must not be negative", name)
		}
	}
	if c.Challenge.Difficulty < 8 || c.Challenge.Difficulty > 24 {
		return fmt.Errorf("challenge.difficulty must be between 8 and 24, got %d", c.Challenge.Difficulty)
	}
	if c.Challenge.PassDuration <= 0 {
		return errors.New("challenge.pass_duration must be positive")
	}

	if c.Store.Path == "" {
		return errors.New("store.path is required")
	}

	if err := c.logLevel.UnmarshalText([]byte(c.Log.Level)); err != nil {
		return fmt.Errorf("log.level: %w", err)
	}
	return nil
}

func validIPOrPrefix(s string) error {
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err
	}
	_, err := netip.ParseAddr(s)
	return err
}

// UpstreamURL returns the parsed upstream URL. Valid only after Parse succeeds.
func (c Config) UpstreamURL() *url.URL { return c.upstreamURL }

// LogLevel returns the parsed log level. Valid only after Parse succeeds.
func (c Config) LogLevel() slog.Level { return c.logLevel }
