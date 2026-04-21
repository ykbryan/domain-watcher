package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	telegramMaxItems       = 10
	telegramTimeout        = 8 * time.Second
	telegramDefaultAPIBase = "https://api.telegram.org"
)

// Telegram posts to the Bot API sendMessage endpoint. Global bot token
// is set at construction; per-monitor chat_id comes from Target.
type Telegram struct {
	apiBase  string
	botToken string
	client   *http.Client
}

// NewTelegram returns nil when botToken is empty so the caller can skip
// registration. apiBase is overridable for tests.
func NewTelegram(botToken string) *Telegram {
	if botToken == "" {
		return nil
	}
	return NewTelegramWithBase(telegramDefaultAPIBase, botToken)
}

func NewTelegramWithBase(apiBase, botToken string) *Telegram {
	return &Telegram{apiBase: apiBase, botToken: botToken, client: &http.Client{Timeout: telegramTimeout}}
}

func (t *Telegram) Name() string { return "telegram" }

func (t *Telegram) Enabled(tg Target) bool { return strings.TrimSpace(tg.TelegramChatID) != "" }

type telegramRequest struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

func (t *Telegram) Send(ctx context.Context, b Batch, tg Target) error {
	msg := telegramRequest{
		ChatID:    tg.TelegramChatID,
		Text:      buildTelegramText(b),
		ParseMode: "Markdown",
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	url := fmt.Sprintf("%s/bot%s/sendMessage", t.apiBase, t.botToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("telegram status %d", resp.StatusCode)
	}
	return nil
}

// buildTelegramText produces the Markdown message body. Exported for testing.
func buildTelegramText(b Batch) string {
	items := b.Items
	truncated := 0
	if len(items) > telegramMaxItems {
		truncated = len(items) - telegramMaxItems
		items = items[:telegramMaxItems]
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "*Domain Threat Alert: %s*\n\n", escapeMarkdown(b.TargetDomain))
	fmt.Fprintf(&sb, "*%d new threat%s detected*\n\n", len(b.Items), pluralS(len(b.Items)))
	for _, it := range items {
		fmt.Fprintf(&sb, "• `%s` — %s (score %d)\n", it.Domain, it.RiskBand, it.RiskScore)
	}
	if truncated > 0 {
		fmt.Fprintf(&sb, "\n_…and %d more_", truncated)
	}
	fmt.Fprintf(&sb, "\n\nScan ID: `%s`", b.ScanID)
	return sb.String()
}

// escapeMarkdown only escapes chars that would break Telegram's Markdown
// mode for our content (domains + digits). We're conservative — backtick,
// asterisk, underscore, square bracket.
func escapeMarkdown(s string) string {
	for _, c := range []string{"\\", "`", "*", "_", "[", "]"} {
		s = strings.ReplaceAll(s, c, "\\"+c)
	}
	return s
}
