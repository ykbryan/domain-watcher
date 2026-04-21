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
	larkMaxItems = 10
	larkTimeout  = 8 * time.Second
)

// Lark posts an Interactive Card to a Lark webhook URL (per-monitor).
// No global config; Enabled fires only when the target has a webhook.
type Lark struct {
	client *http.Client
}

func NewLark() *Lark { return &Lark{client: &http.Client{Timeout: larkTimeout}} }

func (l *Lark) Name() string { return "lark" }

func (l *Lark) Enabled(t Target) bool { return strings.TrimSpace(t.LarkWebhook) != "" }

func (l *Lark) Send(ctx context.Context, b Batch, t Target) error {
	card := buildLarkCard(b)
	body, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.LarkWebhook, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("lark status %d", resp.StatusCode)
	}
	return nil
}

// buildLarkCard is exported to test the payload shape independently.
func buildLarkCard(b Batch) map[string]any {
	items := b.Items
	truncated := false
	if len(items) > larkMaxItems {
		items = items[:larkMaxItems]
		truncated = true
	}

	// Threat list as lark_md bullets.
	var bullets strings.Builder
	for _, it := range items {
		fmt.Fprintf(&bullets, "- **%s** — %s (score %d)\n", it.Domain, it.RiskBand, it.RiskScore)
	}
	if truncated {
		fmt.Fprintf(&bullets, "\n_…and %d more_", len(b.Items)-larkMaxItems)
	}

	summary := fmt.Sprintf("**%d new threat%s detected** for `%s`",
		len(b.Items), pluralS(len(b.Items)), b.TargetDomain)

	return map[string]any{
		"msg_type": "interactive",
		"card": map[string]any{
			"header": map[string]any{
				"title":    map[string]any{"tag": "plain_text", "content": "Domain Threat Alert: " + b.TargetDomain},
				"template": "red",
			},
			"elements": []any{
				map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": summary}},
				map[string]any{"tag": "hr"},
				map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": bullets.String()}},
				map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": fmt.Sprintf("Scan ID: `%s`", b.ScanID)}},
			},
		},
	}
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
