package setup

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

// CheckTimeout bounds each network check.
const CheckTimeout = 5 * time.Second

// CheckHTTP sends GET rawURL and succeeds on any HTTP response, even an
// error status: the point is that something answers. Redirects are not
// followed.
func CheckHTTP(ctx context.Context, rawURL string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "smart_buckler-check")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// PortFree reports whether addr (host:port) can be bound now.
func PortFree(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

// Reachable reports whether a TCP connection to addr succeeds.
func Reachable(ctx context.Context, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

// DialAddr turns a listen address into one this host can connect to: an
// empty or unspecified host becomes the loopback address.
func DialAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// IsLoopbackHost reports whether host is localhost or a loopback IP.
func IsLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Explain describes a network error in plain words.
func Explain(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(msg, "refused"):
		return "연결이 거부됐습니다. 서비스가 꺼져 있거나 포트 번호가 다릅니다."
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || strings.Contains(msg, "timeout"):
		return "응답이 없습니다. 주소가 맞는지, 방화벽이 막고 있지 않은지 확인하세요."
	case errors.As(err, &dnsErr):
		return "주소(호스트 이름)를 찾을 수 없습니다."
	case errors.Is(err, syscall.EADDRINUSE) || strings.Contains(msg, "address already in use") || strings.Contains(msg, "only one usage"):
		return "다른 프로그램이 이미 이 포트를 쓰고 있습니다."
	case errors.Is(err, syscall.EACCES) || strings.Contains(msg, "permission denied"):
		return "권한이 없습니다. 1024보다 작은 포트는 관리자 권한(sudo)이 필요합니다."
	}
	return err.Error()
}

// DetectTimezone guesses the host's IANA time zone from TZ or the
// /etc/localtime link and falls back to Asia/Seoul.
func DetectTimezone(getenv func(string) string, readlink func(string) (string, error)) string {
	valid := func(name string) bool {
		if name == "" || name == "Local" {
			return false
		}
		_, err := time.LoadLocation(name)
		return err == nil
	}
	if tz := strings.TrimPrefix(getenv("TZ"), ":"); valid(tz) {
		return tz
	}
	if target, err := readlink("/etc/localtime"); err == nil {
		if i := strings.Index(target, "zoneinfo/"); i >= 0 {
			if tz := target[i+len("zoneinfo/"):]; valid(tz) {
				return tz
			}
		}
	}
	return "Asia/Seoul"
}

// OutboundIP returns the address this host uses to reach the internet, for
// printing an SSH command. Connecting a UDP socket sends no packet.
func OutboundIP() string {
	c, err := net.Dial("udp", "192.0.2.1:9") // TEST-NET-1, never routed
	if err != nil {
		return ""
	}
	defer func() { _ = c.Close() }()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

// webServerPorts are where an existing web server would listen.
var webServerPorts = []string{"80", "443"}

// WebServerRunning reports which of ports 80 and 443 already answer on this host.
func WebServerRunning(ctx context.Context, reachable func(context.Context, string) error) []string {
	var busy []string
	for _, p := range webServerPorts {
		if reachable(ctx, net.JoinHostPort("127.0.0.1", p)) == nil {
			busy = append(busy, p)
		}
	}
	return busy
}

func portOf(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return p
}
