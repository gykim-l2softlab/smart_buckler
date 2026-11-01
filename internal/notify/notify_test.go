package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type captured struct {
	mu   sync.Mutex
	path string
	body map[string]any
}

func jsonServer(t *testing.T, status int) (*httptest.Server, *captured) {
	t.Helper()
	c := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &c.body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"ok":false,"description":"nope"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func TestSlackEscapesControlSequences(t *testing.T) {
	srv, got := jsonServer(t, http.StatusOK)
	s := &Slack{WebhookURL: srv.URL + "/services/T/B/secret"}
	if err := s.Send(context.Background(), "요약 <b>", "경로 /<!channel>&x"); err != nil {
		t.Fatal(err)
	}
	text := got.body["text"].(string)
	if strings.Contains(text, "<!channel>") || !strings.Contains(text, "&lt;!channel&gt;&amp;x") || !strings.HasPrefix(text, "*요약 &lt;b&gt;*\n") {
		t.Errorf("text = %q", text)
	}
}

func TestErrorsDoNotLeakSecrets(t *testing.T) {
	srv, _ := jsonServer(t, http.StatusUnauthorized)
	tg := &Telegram{BotToken: "123:SECRET", ChatID: "42", api: srv.URL}
	err := tg.Send(context.Background(), "s", "b")
	if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v", err)
	}

	// Connection failure: net/http's *url.Error would include the URL.
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	tg.api = closed.URL
	if err := tg.Send(context.Background(), "s", "b"); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("err = %v", err)
	}
	sl := &Slack{WebhookURL: closed.URL + "/services/T/B/SECRET"}
	if err := sl.Send(context.Background(), "s", "b"); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("err = %v", err)
	}
}

func TestTelegram(t *testing.T) {
	srv, got := jsonServer(t, http.StatusOK)
	tg := &Telegram{BotToken: "123:abc", ChatID: "-100", api: srv.URL}
	if err := tg.Send(context.Background(), "제목", strings.Repeat("가", 5000)); err != nil {
		t.Fatal(err)
	}
	text := got.body["text"].(string)
	if got.path != "/bot123:abc/sendMessage" || got.body["chat_id"] != "-100" || got.body["parse_mode"] != nil {
		t.Errorf("request = %s %v", got.path, got.body)
	}
	if n := len([]rune(text)); n != telegramMaxLen || !strings.HasPrefix(text, "제목\n\n가") {
		t.Errorf("text has %d runes", n)
	}
}

// fakeSMTP speaks just enough SMTP for net/smtp and records the session.
type fakeSMTP struct {
	addr string
	mu   sync.Mutex
	auth string
	from string
	rcpt []string
	data string
}

func startSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &fakeSMTP{addr: ln.Addr().String()}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		r := bufio.NewReader(conn)
		say := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		say("220 localhost ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
			f.mu.Lock()
			switch cmd {
			case "EHLO":
				say("250-localhost")
				say("250 AUTH PLAIN")
			case "AUTH":
				f.auth = line
				say("235 ok")
			case "MAIL":
				f.from = line
				say("250 ok")
			case "RCPT":
				f.rcpt = append(f.rcpt, line)
				say("250 ok")
			case "DATA":
				say("354 go")
				var b strings.Builder
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				f.data = b.String()
				say("250 queued")
			case "QUIT":
				say("221 bye")
				f.mu.Unlock()
				return
			default:
				say("502 unknown")
			}
			f.mu.Unlock()
		}
	}()
	return f
}

func TestEmail(t *testing.T) {
	srv := startSMTP(t)
	host, port, _ := net.SplitHostPort(srv.addr)
	p, _ := strconv.Atoi(port)
	e := &Email{
		Host: host, Port: p, Username: "bot", Password: "pw",
		From: "l2-buckler <bot@example.com>", To: []string{"ops@example.com", "Kim <kim@example.com>"},
	}
	body := strings.Repeat("어제 하루 동안의 요약입니다.\n", 10)
	if err := e.Send(context.Background(), "[l2-buckler] 2026년 10월 31일 보안 요약", body); err != nil {
		t.Fatal(err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.from != "MAIL FROM:<bot@example.com>" || len(srv.rcpt) != 2 || srv.rcpt[1] != "RCPT TO:<kim@example.com>" {
		t.Errorf("envelope = %q %q", srv.from, srv.rcpt)
	}
	cred, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(srv.auth, "AUTH PLAIN "))
	if string(cred) != "\x00bot\x00pw" {
		t.Errorf("auth = %q", cred)
	}
	msg, err := mail.ReadMessage(strings.NewReader(srv.data))
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if subject != "[l2-buckler] 2026년 10월 31일 보안 요약" {
		t.Errorf("subject = %q", subject)
	}
	raw, _ := io.ReadAll(base64.NewDecoder(base64.StdEncoding, msg.Body))
	if strings.ReplaceAll(string(raw), "\r\n", "\n") != body {
		t.Errorf("body = %q", raw)
	}
	head, rest, _ := strings.Cut(srv.data, "\r\n\r\n")
	if strings.Count(head, "=?utf-8?b?") < 2 {
		t.Error("long subject not split into folded encoded words")
	}
	for _, l := range strings.Split(rest, "\r\n") {
		if len(l) > 76 {
			t.Errorf("body line longer than 76: %d", len(l))
		}
	}
}

func TestEmailRejectsHeaderInjection(t *testing.T) {
	e := &Email{Host: "127.0.0.1", Port: 1, From: "a@example.com", To: []string{"b@example.com"}}
	if err := e.Send(context.Background(), "x\r\nBcc: evil@example.com", "b"); err == nil {
		t.Error("subject with CRLF accepted")
	}
}
