package setup

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Answers are the values setup asks for.
type Answers struct {
	// Upstream is the protected service, an absolute http(s) URL.
	Upstream string
	// Listen is where visitors' requests arrive.
	Listen string
	// BehindProxy: a web server on this host (Nginx, Apache) forwards
	// requests to smart_buckler, so its X-Forwarded-For header is trusted.
	BehindProxy bool
	// Timezone is an IANA name for the daily report.
	Timezone  string
	StorePath string
}

// NormalizeUpstream accepts a port ("3000"), host:port ("10.0.0.5:3000") or
// a URL and returns an absolute http(s) URL.
func NormalizeUpstream(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("주소를 입력하세요")
	}
	if isPort(s) {
		if err := checkPort(s); err != nil {
			return "", err
		}
		return "http://127.0.0.1:" + s, nil
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("주소를 이해하지 못했습니다: %q", s)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("http 또는 https 주소만 쓸 수 있습니다: %q", s)
	}
	if p := u.Port(); p != "" {
		if err := checkPort(p); err != nil {
			return "", err
		}
	}
	return u.String(), nil
}

// NormalizeListen accepts a port ("8080") or host:port and returns host:port.
func NormalizeListen(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("포트를 입력하세요")
	}
	if isPort(s) {
		s = ":" + s
	}
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("포트 번호나 주소:포트 형태로 입력하세요: %q", s)
	}
	if err := checkPort(port); err != nil {
		return "", err
	}
	return s, nil
}

func isPort(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func checkPort(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("포트는 1에서 65535 사이여야 합니다: %q", s)
	}
	return nil
}

// Render writes the configuration file for a. Settings left out use the
// defaults documented in configs/dev.yaml.
func Render(a Answers) []byte {
	var b strings.Builder
	b.WriteString("# smart_buckler 설정 파일 (smart_buckler setup으로 만들었습니다)\n")
	b.WriteString("# 적지 않은 항목은 기본값을 씁니다. 전체 항목과 설명:\n")
	b.WriteString("# https://github.com/gykim-l2softlab/smart_buckler/blob/main/configs/dev.yaml\n")
	b.WriteString("# 고친 뒤에는 서비스를 다시 시작해야 적용됩니다.\n\n")
	fmt.Fprintf(&b, "listen: %s   # 방문자 요청을 받을 주소\n", strconv.Quote(a.Listen))
	fmt.Fprintf(&b, "upstream: %s   # 보호할 서비스\n", strconv.Quote(a.Upstream))
	if a.BehindProxy {
		b.WriteString("# 이 서버의 웹 서버(Nginx 등)가 요청을 넘겨줍니다. 방문자 주소는 X-Forwarded-For에서 읽습니다.\n")
		b.WriteString("trusted_proxies: [\"127.0.0.1\", \"::1\"]\n")
	}
	b.WriteString("\nstore:\n")
	fmt.Fprintf(&b, "  path: %s\n", strconv.Quote(a.StorePath))
	b.WriteString("\nreport:\n")
	fmt.Fprintf(&b, "  timezone: %s\n", strconv.Quote(a.Timezone))
	b.WriteString("\nadmin:\n")
	b.WriteString("  enabled: true\n")
	fmt.Fprintf(&b, "  listen: %s   # 관리 화면. 이 서버 안에서만 열립니다\n", strconv.Quote(AdminListen))
	return []byte(b.String())
}
