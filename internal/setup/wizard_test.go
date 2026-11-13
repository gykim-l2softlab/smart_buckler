package setup

import (
	"bufio"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gykim-l2softlab/smart_buckler/internal/config"
)

// fakeHost simulates the machine setup runs on.
type fakeHost struct {
	upstreamUp map[string]bool // upstream URL -> answers
	listening  map[string]bool // addresses something answers on
	busy       map[string]bool // addresses that cannot be bound
	passwords  []string        // successive ReadPassword results; "" fails

	written  []byte
	savedPW  string
	readPWAt int
}

func (h *fakeHost) wizard(input string) (*Wizard, *strings.Builder) {
	out := &strings.Builder{}
	return &Wizard{
		Prompt:   NewPrompter(bufio.NewReader(strings.NewReader(input)), out),
		Out:      out,
		Paths:    Paths{Config: "/etc/smart_buckler/smart_buckler.yaml", Store: "/var/lib/smart_buckler/smart_buckler.db"},
		Timezone: "Asia/Seoul",
		CheckHTTP: func(_ context.Context, u string) (int, error) {
			if h.upstreamUp[u] {
				return 200, nil
			}
			return 0, errors.New("connect: connection refused")
		},
		PortFree: func(addr string) error {
			if h.busy[addr] {
				return errors.New("bind: address already in use")
			}
			return nil
		},
		Reachable: func(_ context.Context, addr string) error {
			if h.listening[addr] {
				return nil
			}
			return errors.New("connection refused")
		},
		WriteConfig: func(_ string, data []byte) error { h.written = data; return nil },
		ReadPassword: func() (string, error) {
			pw := h.passwords[h.readPWAt]
			h.readPWAt++
			if pw == "" {
				return "", errors.New("두 비밀번호가 다릅니다")
			}
			return pw, nil
		},
		SavePassword: func(_ context.Context, _, pw string) error { h.savedPW = pw; return nil },
	}, out
}

const testPassword = "correct horse battery"

func TestWizardDirect(t *testing.T) {
	h := &fakeHost{upstreamUp: map[string]bool{"http://127.0.0.1:3000": true}, passwords: []string{testPassword}}
	w, out := h.wizard("3000\n\n\n")
	o, err := w.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, out)
	}
	c, err := config.Parse(h.written)
	if err != nil {
		t.Fatalf("written config does not parse: %v", err)
	}
	if c.Listen != ":80" || c.Upstream != "http://127.0.0.1:3000" || len(c.TrustedProxies) != 0 || c.Report.Timezone != "Asia/Seoul" {
		t.Errorf("config = listen %q upstream %q proxies %v tz %q", c.Listen, c.Upstream, c.TrustedProxies, c.Report.Timezone)
	}
	if !o.PasswordSet || h.savedPW != testPassword {
		t.Errorf("password set = %v, saved %q", o.PasswordSet, h.savedPW)
	}
}

func TestWizardBehindWebServer(t *testing.T) {
	h := &fakeHost{
		upstreamUp: map[string]bool{"http://127.0.0.1:3000": true},
		listening:  map[string]bool{"127.0.0.1:80": true, "127.0.0.1:443": true},
		busy:       map[string]bool{":80": true},
		passwords:  []string{testPassword},
	}
	w, out := h.wizard("3000\n\n\n\n") // upstream, accept front web server, default listen, default tz
	o, err := w.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, out)
	}
	c, err := config.Parse(h.written)
	if err != nil {
		t.Fatal(err)
	}
	if !o.BehindProxy || c.Listen != "127.0.0.1:8080" || !slices.Equal(c.TrustedProxies, []string{"127.0.0.1", "::1"}) {
		t.Errorf("behind = %v, listen %q, proxies %v", o.BehindProxy, c.Listen, c.TrustedProxies)
	}
	if !slices.Equal(o.WebPorts, []string{"80", "443"}) {
		t.Errorf("web ports = %v", o.WebPorts)
	}
}

func TestWizardUpstreamOnPort80IsNotAFrontServer(t *testing.T) {
	h := &fakeHost{
		upstreamUp: map[string]bool{"http://127.0.0.1:80": true},
		listening:  map[string]bool{"127.0.0.1:80": true},
		busy:       map[string]bool{":80": true},
		passwords:  []string{testPassword},
	}
	w, out := h.wizard("80\n\n\n")
	o, err := w.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, out)
	}
	if o.BehindProxy || len(o.WebPorts) != 0 || o.Listen != ":8080" {
		t.Errorf("behind %v, web ports %v, listen %q", o.BehindProxy, o.WebPorts, o.Listen)
	}
}

func TestWizardRetriesUnreachableUpstream(t *testing.T) {
	h := &fakeHost{upstreamUp: map[string]bool{"http://127.0.0.1:3001": true}, passwords: []string{testPassword}}
	// 3000 is down: decline to continue, then give 3001.
	w, out := h.wizard("3000\nn\n3001\n\n\n")
	o, err := w.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, out)
	}
	if o.Upstream != "http://127.0.0.1:3001" || !strings.Contains(out.String(), "거부") {
		t.Errorf("upstream %q, output:\n%s", o.Upstream, out)
	}
}

func TestWizardKeepsUnreachableUpstreamWhenConfirmed(t *testing.T) {
	h := &fakeHost{passwords: []string{testPassword}}
	w, out := h.wizard("3000\ny\n\n\n")
	o, err := w.Run(context.Background())
	if err != nil || o.Upstream != "http://127.0.0.1:3000" {
		t.Fatalf("Run = %+v, %v\n%s", o, err, out)
	}
}

func TestWizardRejectsBadListen(t *testing.T) {
	h := &fakeHost{
		upstreamUp: map[string]bool{"http://127.0.0.1:3000": true},
		busy:       map[string]bool{":80": true, ":9000": true},
		passwords:  []string{testPassword},
	}
	// admin port, upstream port, busy port, then a free one.
	w, out := h.wizard("3000\n8081\n3000\n9000\n8088\n\n")
	o, err := w.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, out)
	}
	if o.Listen != ":8088" {
		t.Errorf("listen = %q", o.Listen)
	}
	for _, want := range []string{"관리 화면이 씁니다", "같은 3000번", "이미"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestWizardPasswordGivesUpWithoutFailing(t *testing.T) {
	h := &fakeHost{upstreamUp: map[string]bool{"http://127.0.0.1:3000": true}, passwords: []string{"", "", ""}}
	w, out := h.wizard("3000\n\n\n")
	o, err := w.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if o.PasswordSet || h.written == nil || !strings.Contains(out.String(), "admin-password") {
		t.Errorf("password set %v, config written %v, output:\n%s", o.PasswordSet, h.written != nil, out)
	}
}

func TestNextSteps(t *testing.T) {
	behind := Outcome{Answers: Answers{Listen: "127.0.0.1:8080", BehindProxy: true}, PasswordSet: true, WebPorts: []string{"80", "443"}}
	got := NextSteps(behind, NextInfo{GOOS: "linux", ServiceInstalled: true, SSHUser: "kim", ServerIP: "203.0.113.7"})
	for _, want := range []string{
		"sudo systemctl restart smart_buckler",
		"proxy_pass http://127.0.0.1:8080;",
		"X-Forwarded-For $proxy_add_x_forwarded_for",
		"ssh -N -L 8081:127.0.0.1:8081 kim@203.0.113.7",
		"smart_buckler doctor",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("behind/linux lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "admin-password") {
		t.Errorf("asks for a password that is already set:\n%s", got)
	}

	direct := Outcome{Answers: Answers{Listen: ":8080"}, WebPorts: []string{"443"}}
	got = NextSteps(direct, NextInfo{GOOS: "windows", ConfigPath: `C:\ProgramData\smart_buckler\smart_buckler.yaml`})
	for _, want := range []string{
		`smart_buckler -config C:\ProgramData\smart_buckler\smart_buckler.yaml`,
		"http://서버주소:8080/",
		"HTTPS(443)",
		"원격 데스크톱",
		"smart_buckler admin-password",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("direct/windows lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ssh ") {
		t.Errorf("windows instructions mention ssh:\n%s", got)
	}
}
