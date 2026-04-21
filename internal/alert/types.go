// Package alert dispatches diff-detected alerts to external channels
// (Lark, Telegram, email). Channels are registered conditionally at
// startup — if required config is absent the channel is not registered.
package alert

import (
	"context"

	"github.com/google/uuid"
)

// Item describes one alertable domain for message formatting.
type Item struct {
	Domain    string
	RiskScore int
	RiskBand  string
}

// Batch is what gets sent in a single notification — all the new
// HIGH/CRITICAL domains from one monitor's diff pass.
type Batch struct {
	MonitorID    uuid.UUID
	TargetDomain string    // e.g. "example.com"
	ScanID       uuid.UUID // the current scan that produced these
	Items        []Item
}

// Target is the per-monitor config parsed from monitored_domains.alert_channels
// plus the monitor's owner_email. Each channel reads only the fields it uses.
type Target struct {
	LarkWebhook    string
	TelegramChatID string
	Email          bool // when true, send to OwnerEmail
	OwnerEmail     string
}

// Channel is one external notification destination.
type Channel interface {
	Name() string
	// Enabled reports whether Send would do meaningful work given the
	// channel's own config + the per-monitor target. A disabled channel
	// is skipped silently.
	Enabled(target Target) bool
	Send(ctx context.Context, batch Batch, target Target) error
}
