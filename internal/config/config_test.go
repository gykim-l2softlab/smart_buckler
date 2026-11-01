package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
		check   func(t *testing.T, c Config)
	}{
		{
			name: "minimal uses defaults",
			yaml: "upstream: http://127.0.0.1:3000\n",
			check: func(t *testing.T, c Config) {
				if c.Listen != ":8080" || c.WAF.Mode != WAFModeDetect || c.WAF.RequestBodyLimit != 1<<20 {
					t.Errorf("unexpected defaults: %+v", c)
				}
				if c.UpstreamURL().Host != "127.0.0.1:3000" {
					t.Errorf("upstream host = %q", c.UpstreamURL().Host)
				}
				if c.LogLevel() != slog.LevelInfo {
					t.Errorf("log level = %v", c.LogLevel())
				}
			},
		},
		{
			name: "full",
			yaml: `
listen: ":9000"
upstream: https://app.internal
waf:
  mode: block
  request_body_limit: 4096
store:
  path: /var/lib/l2-buckler/events.db
log:
  level: debug
`,
			check: func(t *testing.T, c Config) {
				if c.Listen != ":9000" || c.WAF.Mode != WAFModeBlock || c.WAF.RequestBodyLimit != 4096 ||
					c.Store.Path != "/var/lib/l2-buckler/events.db" || c.LogLevel() != slog.LevelDebug {
					t.Errorf("unexpected config: %+v", c)
				}
			},
		},
		{name: "empty document", yaml: "", wantErr: "upstream is required"},
		{name: "unknown field", yaml: "upstream: http://a\nupstreem: http://b\n", wantErr: "upstreem"},
		{name: "relative upstream", yaml: "upstream: localhost:3000\n", wantErr: "absolute http(s) URL"},
		{name: "bad mode", yaml: "upstream: http://a\nwaf:\n  mode: off\n", wantErr: "waf.mode"},
		{name: "bad body limit", yaml: "upstream: http://a\nwaf:\n  request_body_limit: 0\n", wantErr: "request_body_limit"},
		{name: "bad log level", yaml: "upstream: http://a\nlog:\n  level: loud\n", wantErr: "log.level"},
		{name: "empty store path", yaml: "upstream: http://a\nstore:\n  path: \"\"\n", wantErr: "store.path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Parse([]byte(tt.yaml))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tt.check(t, c)
		})
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte("upstream: http://127.0.0.1:3000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestDevConfigIsValid(t *testing.T) {
	if _, err := Load("../../configs/dev.yaml"); err != nil {
		t.Fatalf("configs/dev.yaml: %v", err)
	}
}
