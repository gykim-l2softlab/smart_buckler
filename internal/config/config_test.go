package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
				if !c.Deception.Enabled || c.Deception.BlockDuration != time.Hour || len(c.TrustedProxies) != 0 {
					t.Errorf("unexpected deception defaults: %+v", c.Deception)
				}
			},
		},
		{
			name: "full",
			yaml: `
listen: ":9000"
upstream: https://app.internal
trusted_proxies: ["127.0.0.1", "10.0.0.0/8"]
deception:
  enabled: false
  block_duration: 10m
  reserved_paths: ["/admin", "/api/"]
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
					c.Store.Path != "/var/lib/l2-buckler/events.db" || c.LogLevel() != slog.LevelDebug ||
					len(c.TrustedProxies) != 2 || c.Deception.Enabled || c.Deception.BlockDuration != 10*time.Minute ||
					len(c.Deception.ReservedPaths) != 2 {
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
		{name: "bad trusted proxy", yaml: "upstream: http://a\ntrusted_proxies: [proxy.local]\n", wantErr: "trusted_proxies"},
		{name: "bad block duration", yaml: "upstream: http://a\ndeception:\n  block_duration: 0s\n", wantErr: "block_duration"},
		{name: "unparsable duration", yaml: "upstream: http://a\ndeception:\n  block_duration: forever\n", wantErr: "parse config"},
		{name: "reserved root", yaml: "upstream: http://a\ndeception:\n  reserved_paths: [\"/\"]\n", wantErr: "reserved_paths"},
		{name: "reserved relative", yaml: "upstream: http://a\ndeception:\n  reserved_paths: [admin]\n", wantErr: "reserved_paths"},
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
