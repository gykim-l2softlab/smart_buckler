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

// Ollama generates text with a local Ollama server.
type Ollama struct {
	URL     string
	Model   string
	Timeout time.Duration
}

// Generate implements LLM using the non-streaming /api/generate endpoint.
func (o *Ollama) Generate(ctx context.Context, prompt string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	body, err := json.Marshal(map[string]any{
		"model":   o.Model,
		"prompt":  prompt,
		"stream":  false,
		"options": map[string]any{"temperature": 0.2},
	})
	if err != nil {
		return "", fmt.Errorf("encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(o.URL, "/")+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", fmt.Errorf("ollama: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("ollama: read: %w", err)
	}
	var out struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama: status %d: %s", resp.StatusCode, out.Error)
	}
	if strings.TrimSpace(out.Response) == "" {
		return "", errors.New("ollama: empty response")
	}
	return out.Response, nil
}
