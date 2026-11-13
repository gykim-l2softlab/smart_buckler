package setup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/gykim-l2softlab/smart_buckler/internal/config"
)

// doctorHost fakes the checked system around a parsed configuration.
type doctorHost struct {
	yaml        string
	loadErr     error
	upstreamUp  bool
	proxyStatus int // 0: proxy not listening
	adminUp     bool
	service     *bool
	password    bool
	storeErr    error
}

func (h doctorHost) options() DoctorOptions {
	return DoctorOptions{
		ConfigPath: "/etc/smart_buckler/smart_buckler.yaml",
		Load: func(string) (config.Config, error) {
			if h.loadErr != nil {
				return config.Config{}, h.loadErr
			}
			return config.Parse([]byte(h.yaml))
		},
		CheckHTTP: func(_ context.Context, u string) (int, error) {
			if strings.HasPrefix(u, "http://127.0.0.1:3000") {
				if h.upstreamUp {
					return 200, nil
				}
				return 0, errors.New("connection refused")
			}
			if h.proxyStatus == 0 {
				return 0, errors.New("connection refused")
			}
			return h.proxyStatus, nil
		},
		Reachable: func(_ context.Context, addr string) error {
			if (addr == "127.0.0.1:8080" && h.proxyStatus != 0) || (addr == "127.0.0.1:8081" && h.adminUp) {
				return nil
			}
			return errors.New("connection refused")
		},
		Service: func(context.Context) (bool, bool) {
			if h.service == nil {
				return false, false
			}
			return *h.service, true
		},
		ServiceHint: "systemctl start",
		PasswordSet: func(context.Context, string) (bool, error) { return h.password, nil },
		StoreAccess: func(string) error { return h.storeErr },
	}
}

const doctorYAML = `listen: ":8080"
upstream: "http://127.0.0.1:3000"
admin:
  enabled: true
  listen: "127.0.0.1:8081"
`

func statuses(checks []Check) map[string]Status {
	m := map[string]Status{}
	for _, c := range checks {
		if prev, ok := m[c.Title]; !ok || c.Status > prev {
			m[c.Title] = c.Status
		}
	}
	return m
}

func TestDoctorHealthy(t *testing.T) {
	on := true
	h := doctorHost{yaml: doctorYAML, upstreamUp: true, proxyStatus: 200, adminUp: true, service: &on, password: true}
	checks := Doctor(context.Background(), h.options())
	for _, c := range checks {
		if c.Status != OK {
			t.Errorf("unexpected %v: %+v", c.Status, c)
		}
	}
	if len(checks) != 6 {
		t.Errorf("got %d checks, want 6: %+v", len(checks), checks)
	}
}

func TestDoctorFindings(t *testing.T) {
	off := false
	tests := []struct {
		name  string
		host  doctorHost
		title string
		want  Status
	}{
		{"missing config", doctorHost{loadErr: fmt.Errorf("read config: %w", fs.ErrNotExist)}, "설정 파일", Fail},
		{"invalid config", doctorHost{loadErr: errors.New("upstream is required")}, "설정 파일", Fail},
		{"service stopped", doctorHost{yaml: doctorYAML, upstreamUp: true, service: &off}, "서비스", Fail},
		{"upstream down", doctorHost{yaml: doctorYAML, proxyStatus: 502, adminUp: true, password: true}, "보호할 서비스", Fail},
		{"proxy bad gateway", doctorHost{yaml: doctorYAML, proxyStatus: 502, adminUp: true, password: true}, "요청 받기", Fail},
		{"proxy not listening", doctorHost{yaml: doctorYAML, upstreamUp: true, adminUp: true, password: true}, "요청 받기", Fail},
		{"proxy blocked check", doctorHost{yaml: doctorYAML, upstreamUp: true, proxyStatus: 403, adminUp: true, password: true}, "요청 받기", Warn},
		{"admin down", doctorHost{yaml: doctorYAML, upstreamUp: true, proxyStatus: 200, password: true}, "관리 화면", Fail},
		{"no password", doctorHost{yaml: doctorYAML, upstreamUp: true, proxyStatus: 200, adminUp: true}, "관리자 비밀번호", Warn},
		{"store owner", doctorHost{yaml: doctorYAML, upstreamUp: true, proxyStatus: 200, adminUp: true, password: true, storeErr: errors.New("owner")}, "DB 파일", Fail},
		{"admin exposed", doctorHost{yaml: strings.Replace(doctorYAML, "127.0.0.1:8081", "0.0.0.0:8081", 1), upstreamUp: true, proxyStatus: 200, adminUp: true, password: true}, "관리 화면 노출", Warn},
		{"loopback without trusted proxies", doctorHost{yaml: strings.Replace(doctorYAML, `":8080"`, `"127.0.0.1:8080"`, 1), upstreamUp: true, proxyStatus: 200, adminUp: true, password: true}, "앞단 웹 서버", Warn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checks := Doctor(context.Background(), tt.host.options())
			got, ok := statuses(checks)[tt.title]
			if !ok || got != tt.want {
				t.Errorf("%s = %v (present %v), want %v; checks: %+v", tt.title, got, ok, tt.want, checks)
			}
		})
	}
}

func TestDoctorBehindProxyIsFine(t *testing.T) {
	yaml := strings.Replace(doctorYAML, `":8080"`, `"127.0.0.1:8080"`, 1) + "trusted_proxies: [\"127.0.0.1\", \"::1\"]\n"
	h := doctorHost{yaml: yaml, upstreamUp: true, proxyStatus: 200, adminUp: true, password: true}
	if _, warned := statuses(Doctor(context.Background(), h.options()))["앞단 웹 서버"]; warned {
		t.Error("warned about trusted_proxies although they are set")
	}
}

func TestReport(t *testing.T) {
	var b strings.Builder
	fails := Report(&b, []Check{
		{Status: OK, Title: "a", Detail: "fine", Hint: "never shown"},
		{Status: Warn, Title: "b", Detail: "meh", Hint: "do b"},
		{Status: Fail, Title: "c", Detail: "broken", Hint: "do c"},
	})
	out := b.String()
	if fails != 1 {
		t.Errorf("fails = %d", fails)
	}
	for _, want := range []string{"[정상] a: fine", "[주의] b: meh", "→ do b", "[문제] c: broken", "→ do c", "정상 1, 주의 1, 문제 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "never shown") {
		t.Errorf("hint shown for an OK check:\n%s", out)
	}
}
