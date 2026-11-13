package setup

import (
	"slices"
	"testing"

	"github.com/gykim-l2softlab/smart_buckler/internal/config"
)

func TestNormalizeUpstream(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "3000", want: "http://127.0.0.1:3000"},
		{in: " 3000 ", want: "http://127.0.0.1:3000"},
		{in: "127.0.0.1:3000", want: "http://127.0.0.1:3000"},
		{in: "10.0.0.5:8000", want: "http://10.0.0.5:8000"},
		{in: "localhost:8080", want: "http://localhost:8080"},
		{in: "http://127.0.0.1:3000", want: "http://127.0.0.1:3000"},
		{in: "https://app.internal", want: "https://app.internal"},
		{in: "http://[::1]:3000", want: "http://[::1]:3000"},
		{in: "", wantErr: true},
		{in: "0", wantErr: true},
		{in: "70000", wantErr: true},
		{in: "127.0.0.1:99999", wantErr: true},
		{in: "ftp://host", wantErr: true},
		{in: "http://", wantErr: true},
	}
	for _, tt := range tests {
		got, err := NormalizeUpstream(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("NormalizeUpstream(%q) = %q, %v; want %q, err %v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestNormalizeListen(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "8080", want: ":8080"},
		{in: ":8080", want: ":8080"},
		{in: "127.0.0.1:8080", want: "127.0.0.1:8080"},
		{in: "[::1]:80", want: "[::1]:80"},
		{in: "", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "0", wantErr: true},
		{in: "127.0.0.1", wantErr: true},
		{in: ":65536", wantErr: true},
	}
	for _, tt := range tests {
		got, err := NormalizeListen(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("NormalizeListen(%q) = %q, %v; want %q, err %v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestRenderParses(t *testing.T) {
	tests := []struct {
		name string
		a    Answers
	}{
		{"direct", Answers{Upstream: "http://127.0.0.1:3000", Listen: ":80", Timezone: "Asia/Seoul", StorePath: "/var/lib/smart_buckler/smart_buckler.db"}},
		{"behind proxy", Answers{Upstream: "http://127.0.0.1:3000", Listen: "127.0.0.1:8080", BehindProxy: true, Timezone: "UTC", StorePath: "smart_buckler.db"}},
		{"windows path", Answers{Upstream: "http://127.0.0.1:5000", Listen: ":8080", Timezone: "Asia/Seoul", StorePath: `C:\ProgramData\smart_buckler\smart_buckler.db`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := config.Parse(Render(tt.a))
			if err != nil {
				t.Fatalf("Parse: %v\n%s", err, Render(tt.a))
			}
			if c.Listen != tt.a.Listen || c.Upstream != tt.a.Upstream || c.Store.Path != tt.a.StorePath ||
				c.Report.Timezone != tt.a.Timezone || !c.Admin.Enabled || c.Admin.Listen != AdminListen {
				t.Errorf("parsed config does not match answers: %+v", c)
			}
			wantProxies := []string(nil)
			if tt.a.BehindProxy {
				wantProxies = []string{"127.0.0.1", "::1"}
			}
			if !slices.Equal(c.TrustedProxies, wantProxies) {
				t.Errorf("trusted_proxies = %v, want %v", c.TrustedProxies, wantProxies)
			}
		})
	}
}

func TestDefaultPaths(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	tests := []struct {
		goos, programData string
		want              Paths
	}{
		{"linux", "", Paths{"/etc/smart_buckler/smart_buckler.yaml", "/var/lib/smart_buckler/smart_buckler.db"}},
		{"windows", `D:\Data\`, Paths{`D:\Data\smart_buckler\smart_buckler.yaml`, `D:\Data\smart_buckler\smart_buckler.db`}},
		{"windows", "", Paths{`C:\ProgramData\smart_buckler\smart_buckler.yaml`, `C:\ProgramData\smart_buckler\smart_buckler.db`}},
		{"darwin", "", Paths{"smart_buckler.yaml", "smart_buckler.db"}},
	}
	for _, tt := range tests {
		if got := DefaultPaths(tt.goos, env(tt.programData)); got != tt.want {
			t.Errorf("DefaultPaths(%s, %q) = %+v, want %+v", tt.goos, tt.programData, got, tt.want)
		}
	}
}

func TestResolveConfig(t *testing.T) {
	none := func(string) bool { return false }
	local := func(p string) bool { return p == ConfigName }
	getenv := func(string) string { return "" }
	tests := []struct {
		name   string
		flag   string
		set    bool
		exists func(string) bool
		want   string
	}{
		{"explicit flag wins", "x.yaml", true, local, "x.yaml"},
		{"current directory", ConfigName, false, local, ConfigName},
		{"installed location", ConfigName, false, none, "/etc/smart_buckler/smart_buckler.yaml"},
	}
	for _, tt := range tests {
		if got := ResolveConfig(tt.flag, tt.set, "linux", getenv, tt.exists); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}
