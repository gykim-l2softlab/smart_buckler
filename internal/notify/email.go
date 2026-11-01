package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Email sends through an SMTP server. Port 465 uses implicit TLS; any other
// port upgrades with STARTTLS when the server offers it. Credentials are only
// sent over TLS (or to localhost), as net/smtp's PLAIN auth enforces.
type Email struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string

	tlsConfig *tls.Config // overridden in tests
}

// Name implements report.Notifier.
func (e *Email) Name() string { return "email" }

// Send implements report.Notifier.
func (e *Email) Send(ctx context.Context, subject, body string) error {
	msg, err := e.message(subject, body, time.Now())
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	tlsConfig := e.tlsConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12}
	}

	var conn net.Conn
	dialer := &net.Dialer{Timeout: httpTimeout}
	if e.Port == 465 {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(httpTimeout)
	}
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp greeting: %w", err)
	}
	defer func() { _ = c.Close() }()
	if e.Port != 465 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		}
	}
	if e.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(e.envelope(e.From)); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, to := range e.To {
		if err := c.Rcpt(e.envelope(to)); err != nil {
			return fmt.Errorf("rcpt to: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("end message: %w", err)
	}
	return c.Quit()
}

// envelope returns the bare address of a configured address.
func (e *Email) envelope(s string) string {
	if a, err := mail.ParseAddress(s); err == nil {
		return a.Address
	}
	return s
}

// message builds a UTF-8 plain-text message with a base64 body, which keeps
// Korean text intact through any relay.
func (e *Email) message(subject, body string, now time.Time) ([]byte, error) {
	if strings.ContainsAny(subject, "\r\n") {
		return nil, errors.New("subject contains a line break")
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", e.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(e.To, ", "))
	// Go splits long subjects into encoded words of at most 75 characters;
	// fold between them to keep header lines short (RFC 2047, section 2).
	subj := mime.BEncoding.Encode("utf-8", subject)
	fmt.Fprintf(&b, "Subject: %s\r\n", strings.ReplaceAll(subj, "?= =?", "?=\r\n =?"))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.Bytes(), nil
}
