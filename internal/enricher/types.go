// Package enricher defines the threat-intelligence source interface and a
// concurrent fan-out runner. Individual sources live under sources/<name>/
// and must implement Source.
package enricher

import (
	"context"
	"time"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// RiskSignal is a single interpreted indicator pulled from a source's raw
// response. The scorer (Sprint 5) aggregates these into a 0–100 score.
type RiskSignal struct {
	Label    string   `json:"label"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail,omitempty"`
}

// Finding is one source's output for one domain. RawData preserves the full
// upstream response for audit; RiskSignals is the interpreted view.
type Finding struct {
	SourceName  string       `json:"source_name"`
	RiskSignals []RiskSignal `json:"risk_signals,omitempty"`
	RawData     any          `json:"raw_data,omitempty"`
	FetchedAt   time.Time    `json:"fetched_at"`
	Error       string       `json:"error,omitempty"`
}

// Source is implemented by every threat-intel integration.
type Source interface {
	Name() string
	Enrich(ctx context.Context, domain string) (*Finding, error)
}
