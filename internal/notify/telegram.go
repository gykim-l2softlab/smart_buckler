package notify

import "context"

const (
	telegramAPI = "https://api.telegram.org"
	// telegramMaxLen is the Bot API limit for one message.
	telegramMaxLen = 4096
)

// Telegram sends through the Bot API.
type Telegram struct {
	BotToken string
	ChatID   string

	api string // overridden in tests
}

// Name implements report.Notifier.
func (t *Telegram) Name() string { return "telegram" }

// Send implements report.Notifier. The message is plain text (no parse
// mode), so nothing in it is interpreted as markup.
func (t *Telegram) Send(ctx context.Context, subject, body string) error {
	api := t.api
	if api == "" {
		api = telegramAPI
	}
	return postJSON(ctx, api+"/bot"+t.BotToken+"/sendMessage", map[string]any{
		"chat_id":                  t.ChatID,
		"text":                     truncate(subject+"\n\n"+body, telegramMaxLen),
		"disable_web_page_preview": true,
	})
}
