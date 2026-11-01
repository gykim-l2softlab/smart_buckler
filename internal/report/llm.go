package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Chat generates text with any OpenAI-compatible chat completions API:
// local servers such as Ollama, LM Studio and vLLM, or hosted providers.
type Chat struct {
	// URL is the API base, e.g. "http://127.0.0.1:11434/v1".
	URL   string
	Model string
	// APIKey is sent as a bearer token when set.
	APIKey string
	// ReasoningEffort ("none", "low", ...) limits how long reasoning models
	// think before answering. Empty leaves the model default.
	ReasoningEffort string
	Timeout         time.Duration
}

// Generate implements LLM using the non-streaming /chat/completions endpoint.
func (c *Chat) Generate(ctx context.Context, system, prompt string) (string, error) {
	params := map[string]any{
		"model": c.Model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.2,
	}
	if c.ReasoningEffort != "" {
		params["reasoning_effort"] = c.ReasoningEffort
	}
	header := http.Header{}
	if c.APIKey != "" {
		header.Set("Authorization", "Bearer "+c.APIKey)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	status, err := post(ctx, c.Timeout, strings.TrimSuffix(c.URL, "/")+"/chat/completions", header, params, &out)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("llm: status %d: %s", status, clean(out.Error.Message, 200))
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", errors.New("llm: empty response")
	}
	return out.Choices[0].Message.Content, nil
}

// Anthropic generates text with the Claude Messages API.
type Anthropic struct {
	// URL is the API base, e.g. "https://api.anthropic.com/v1".
	URL    string
	Model  string
	APIKey string
	// Effort ("low" ... "max") is sent as output_config.effort. Empty leaves
	// the model default.
	Effort  string
	Timeout time.Duration
}

// anthropicVersion is the Messages API version. It rejects sampling
// parameters such as temperature, so none are sent.
const anthropicVersion = "2026-10-21"

// Generate implements LLM using the non-streaming /messages endpoint.
func (a *Anthropic) Generate(ctx context.Context, system, prompt string) (string, error) {
	params := map[string]any{
		"model":      a.Model,
		"max_tokens": 16000,
		"system":     system,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	}
	if a.Effort != "" {
		params["output_config"] = map[string]string{"effort": a.Effort}
	}
	header := http.Header{}
	header.Set("x-api-key", a.APIKey)
	header.Set("anthropic-version", anthropicVersion)
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Error      struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	status, err := post(ctx, a.Timeout, strings.TrimSuffix(a.URL, "/")+"/messages", header, params, &out)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("llm: status %d: %s", status, clean(out.Error.Message, 200))
	}
	if out.StopReason == "refusal" {
		return "", errors.New("llm: model declined the request")
	}
	var text strings.Builder
	for _, b := range out.Content {
		if b.Type == "text" {
			text.WriteString(b.Text)
		}
	}
	if strings.TrimSpace(text.String()) == "" {
		return "", errors.New("llm: empty response")
	}
	return text.String(), nil
}

// post sends params as JSON and decodes the response into out, returning the
// HTTP status. Transport errors drop the URL so nothing configured in it
// reaches logs.
func post(ctx context.Context, timeout time.Duration, endpoint string, header http.Header, params, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, err := json.Marshal(params)
	if err != nil {
		return 0, fmt.Errorf("llm: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("llm: build request: %w", err)
	}
	req.Header = header
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, fmt.Errorf("llm: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("llm: read: %w", err)
	}
	_ = json.Unmarshal(raw, out)
	return resp.StatusCode, nil
}
