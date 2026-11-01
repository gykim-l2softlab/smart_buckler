// Package config defines the configuration schema and its validation.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"

	"go.yaml.in/yaml/v3"
)

// WAF modes.
const (
	WAFModeDetect = "detect"
	WAFModeBlock  = "block"
)

// Config is the root configuration.
type Config struct {
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`
	WAF      WAF    `yaml:"waf"`
	Store    Store  `yaml:"store"`
	Log      Log    `yaml:"log"`

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

	if c.Store.Path == "" {
		return errors.New("store.path is required")
	}

	if err := c.logLevel.UnmarshalText([]byte(c.Log.Level)); err != nil {
		return fmt.Errorf("log.level: %w", err)
	}
	return nil
}

// UpstreamURL returns the parsed upstream URL. Valid only after Parse succeeds.
func (c Config) UpstreamURL() *url.URL { return c.upstreamURL }

// LogLevel returns the parsed log level. Valid only after Parse succeeds.
func (c Config) LogLevel() slog.Level { return c.logLevel }
