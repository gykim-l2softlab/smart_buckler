package notify

import (
	"context"
	"strings"
)

// Slack posts to an incoming webhook.
type Slack struct {
	WebhookURL string
}

// Name implements report.Notifier.
func (s *Slack) Name() string { return "slack" }

// slackEscaper escapes the characters Slack treats as control sequences, so
// attacker-controlled text such as request paths cannot produce mentions
// like <!channel> or links.
var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// Send implements report.Notifier.
func (s *Slack) Send(ctx context.Context, subject, body string) error {
	text := "*" + slackEscaper.Replace(subject) + "*\n" + slackEscaper.Replace(body)
	return postJSON(ctx, s.WebhookURL, map[string]any{"text": text, "unfurl_links": false, "unfurl_media": false})
}
