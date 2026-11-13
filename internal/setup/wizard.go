package setup

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gykim-l2softlab/smart_buckler/internal/config"
)

// Wizard asks for the few values a first install needs, checks them against
// the running system, writes the configuration and sets the admin password.
type Wizard struct {
	Prompt    *Prompter
	Out       io.Writer
	Paths     Paths
	Timezone  string // suggested time zone
	CheckHTTP func(ctx context.Context, rawURL string) (int, error)
	PortFree  func(addr string) error
	Reachable func(ctx context.Context, addr string) error
	// WriteConfig stores the configuration file with restricted permissions.
	WriteConfig func(path string, data []byte) error
	// ReadPassword asks for the admin password (twice on a terminal).
	ReadPassword func() (string, error)
	// SavePassword hashes and stores the admin password in the database.
	SavePassword func(ctx context.Context, storePath, password string) error
}

// Outcome is what the wizard set up.
type Outcome struct {
	Answers
	PasswordSet bool
	// WebPorts are ports 80/443 answered by another web server.
	WebPorts []string
}

// passwordAttempts bounds retries for a mistyped password.
const passwordAttempts = 3

// Run asks the questions and writes the configuration.
func (w *Wizard) Run(ctx context.Context) (Outcome, error) {
	var out Outcome
	out.StorePath = w.Paths.Store

	fmt.Fprintln(w.Out, "smart_buckler 설정을 시작합니다. [ ] 안의 값은 Enter만 누르면 그대로 씁니다.")
	fmt.Fprintln(w.Out)

	up, err := w.askUpstream(ctx)
	if err != nil {
		return out, err
	}
	out.Upstream = up

	upHost, upPort := upstreamHostPort(up)
	for _, p := range WebServerRunning(ctx, w.Reachable) {
		// The protected service itself answering on 80/443 is not a front web server.
		if !(IsLoopbackHost(upHost) && p == upPort) {
			out.WebPorts = append(out.WebPorts, p)
		}
	}
	if len(out.WebPorts) > 0 {
		fmt.Fprintln(w.Out)
		fmt.Fprintf(w.Out, "이 서버의 %s번 포트를 다른 웹 서버(Nginx, Apache 등)가 쓰고 있습니다.\n", strings.Join(out.WebPorts, ", "))
		fmt.Fprintln(w.Out, "그 웹 서버가 요청을 smart_buckler로 넘기게 하면 지금 쓰는 도메인과 HTTPS를 그대로 쓸 수 있습니다.")
		if out.BehindProxy, err = w.Prompt.Confirm("이 방식으로 설치할까요? (권장)", true); err != nil {
			return out, err
		}
	}

	fmt.Fprintln(w.Out)
	if out.Listen, err = w.askListen(out.BehindProxy, upHost, upPort); err != nil {
		return out, err
	}

	fmt.Fprintln(w.Out)
	if out.Timezone, err = w.Prompt.Ask("일일 요약에 쓸 시간대", w.Timezone, checkTimezone); err != nil {
		return out, err
	}

	data := Render(out.Answers)
	if _, err := config.Parse(data); err != nil {
		return out, fmt.Errorf("만든 설정이 올바르지 않습니다 (버그입니다): %w", err)
	}
	if err := w.WriteConfig(w.Paths.Config, data); err != nil {
		return out, fmt.Errorf("설정 파일 저장: %w", err)
	}
	fmt.Fprintf(w.Out, "\n[완료] 설정 파일을 저장했습니다: %s\n\n", w.Paths.Config)

	fmt.Fprintln(w.Out, "관리 화면 비밀번호를 정합니다. 잊으면 smart_buckler admin-password로 다시 정할 수 있습니다.")
	for range passwordAttempts {
		pw, err := w.ReadPassword()
		if err != nil {
			fmt.Fprintf(w.Out, "  → %v\n", err)
			continue
		}
		if err := w.SavePassword(ctx, out.StorePath, pw); err != nil {
			return out, fmt.Errorf("비밀번호 저장: %w", err)
		}
		out.PasswordSet = true
		fmt.Fprintln(w.Out, "[완료] 비밀번호를 저장했습니다.")
		break
	}
	if !out.PasswordSet {
		fmt.Fprintln(w.Out, "[주의] 비밀번호를 정하지 못했습니다. 나중에 smart_buckler admin-password로 정하세요.")
	}
	return out, nil
}

func (w *Wizard) askUpstream(ctx context.Context) (string, error) {
	fmt.Fprintln(w.Out, "보호할 웹 서비스의 주소를 알려 주세요. 같은 서버에서 3000번 포트로 돌고 있다면 3000만 입력하면 됩니다.")
	for range maxAttempts {
		up, err := w.Prompt.Ask("보호할 서비스 주소 (예: 3000, 10.0.0.5:8000, http://127.0.0.1:3000)", "", NormalizeUpstream)
		if err != nil {
			return "", err
		}
		status, err := w.CheckHTTP(ctx, up)
		if err == nil {
			fmt.Fprintf(w.Out, "  [확인] %s 에서 응답을 받았습니다 (HTTP %d).\n", up, status)
			return up, nil
		}
		fmt.Fprintf(w.Out, "  [주의] %s 에 연결하지 못했습니다. %s\n", up, Explain(err))
		ok, err := w.Prompt.Confirm("서비스를 아직 켜지 않았다면 이 주소로 계속해도 됩니다. 계속할까요?", false)
		if err != nil {
			return "", err
		}
		if ok {
			return up, nil
		}
	}
	return "", fmt.Errorf("보호할 서비스 주소를 정하지 못해 중단합니다")
}

func (w *Wizard) askListen(behind bool, upHost, upPort string) (string, error) {
	def := "8080"
	switch {
	case behind:
		def = "127.0.0.1:8080"
		fmt.Fprintln(w.Out, "smart_buckler는 이 서버 안(127.0.0.1)에서만 요청을 받고, 앞의 웹 서버가 요청을 넘겨줍니다.")
	case w.PortFree(":80") == nil:
		def = "80"
		fmt.Fprintln(w.Out, "방문자가 접속할 포트를 정합니다. 80번이면 http://서버주소/ 로 바로 접속됩니다.")
	default:
		fmt.Fprintln(w.Out, "방문자가 접속할 포트를 정합니다.")
	}
	return w.Prompt.Ask("요청을 받을 포트", def, func(s string) (string, error) {
		l, err := NormalizeListen(s)
		if err != nil {
			return "", err
		}
		p := portOf(l)
		if p == portOf(AdminListen) {
			return "", fmt.Errorf("%s번은 관리 화면이 씁니다. 다른 포트를 고르세요", p)
		}
		if IsLoopbackHost(upHost) && p == upPort {
			return "", fmt.Errorf("보호할 서비스와 같은 %s번 포트는 쓸 수 없습니다", p)
		}
		if err := w.PortFree(l); err != nil {
			return "", fmt.Errorf("%s 를 열 수 없습니다. %s", l, Explain(err))
		}
		return l, nil
	})
}

func checkTimezone(s string) (string, error) {
	if s == "" || s == "Local" {
		return "", fmt.Errorf("Asia/Seoul 같은 시간대 이름을 입력하세요")
	}
	if _, err := time.LoadLocation(s); err != nil {
		return "", fmt.Errorf("알 수 없는 시간대입니다: %q (예: Asia/Seoul)", s)
	}
	return s, nil
}

// upstreamHostPort returns the host and port of an upstream URL, filling in
// the scheme's default port.
func upstreamHostPort(raw string) (string, string) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return u.Hostname(), port
}

// NextInfo describes the host for the closing instructions.
type NextInfo struct {
	GOOS             string
	ConfigPath       string
	ServiceInstalled bool
	SSHUser          string
	ServerIP         string
}

// NextSteps tells the operator what is left: start the service, send
// visitors through smart_buckler and open the admin UI.
func NextSteps(o Outcome, n NextInfo) string {
	var b strings.Builder
	step := 0
	head := func(s string) {
		step++
		fmt.Fprintf(&b, "\n%d. %s\n", step, s)
	}
	b.WriteString("설정을 마쳤습니다. 남은 일은 다음과 같습니다.\n")

	head("smart_buckler 시작")
	switch {
	case n.GOOS == "linux" && n.ServiceInstalled:
		b.WriteString("   sudo systemctl restart " + ServiceName + "\n")
	case n.GOOS == "windows" && n.ServiceInstalled:
		b.WriteString("   Restart-Service " + ServiceName + "   (관리자 PowerShell)\n")
	default:
		fmt.Fprintf(&b, "   smart_buckler -config %s\n", n.ConfigPath)
	}

	head("방문자 요청이 smart_buckler를 거치게 하기")
	server := n.ServerIP
	if server == "" {
		server = "서버주소"
	}
	port := portOf(o.Listen)
	switch {
	case o.BehindProxy:
		b.WriteString("   지금 쓰는 웹 서버가 요청을 smart_buckler로 넘기도록 바꿉니다.\n")
		b.WriteString("   Nginx: 사이트 설정의 location / 블록을 아래처럼 바꾼 뒤 sudo nginx -t && sudo systemctl reload nginx\n\n")
		fmt.Fprintf(&b, "       location / {\n           proxy_pass http://%s;\n", DialAddr(o.Listen))
		b.WriteString("           proxy_set_header Host $host;\n")
		b.WriteString("           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		b.WriteString("           proxy_set_header X-Forwarded-Proto $scheme;\n       }\n\n")
		fmt.Fprintf(&b, "   Apache: ProxyPreserveHost On 과 ProxyPass / http://%s/ 를 씁니다.\n", DialAddr(o.Listen))
	case port == "80":
		fmt.Fprintf(&b, "   방문자는 http://%s/ 로 접속하면 smart_buckler를 거칩니다.\n", server)
	default:
		fmt.Fprintf(&b, "   방문자는 http://%s:%s/ 로 접속해야 smart_buckler를 거칩니다.\n", server, port)
		b.WriteString("   원래 주소를 그대로 쓰려면 보호할 서비스를 다른 포트로 옮기고 listen을 80으로 바꾸세요.\n")
	}
	if slices.Contains(o.WebPorts, "443") && !o.BehindProxy {
		b.WriteString("   HTTPS(443) 요청은 지금 웹 서버로 바로 가므로 smart_buckler를 거치지 않습니다.\n")
	}

	head("관리 화면 열기")
	if !o.PasswordSet {
		b.WriteString("   먼저 비밀번호를 정하세요: smart_buckler admin-password\n")
	}
	if n.GOOS == "windows" {
		fmt.Fprintf(&b, "   서버에 원격 데스크톱으로 접속해 브라우저로 http://%s 를 엽니다.\n", AdminListen)
	} else {
		user := n.SSHUser
		if user == "" {
			user = "사용자"
		}
		_, adminPort, _ := net.SplitHostPort(AdminListen)
		b.WriteString("   관리 화면은 이 서버 안에서만 열립니다. 내 PC의 터미널에서 아래 명령을 실행해 둔 채로\n")
		fmt.Fprintf(&b, "   브라우저로 http://127.0.0.1:%s 를 엽니다.\n\n", adminPort)
		fmt.Fprintf(&b, "       ssh -N -L %s:%s %s@%s\n", adminPort, AdminListen, user, server)
	}

	head("문제가 있으면")
	b.WriteString("   smart_buckler doctor 로 상태를 점검하면 해결 방법을 알려 줍니다.\n")
	return b.String()
}
