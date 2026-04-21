// Package rdap queries rdap.org for domain registration metadata.
// New domains and suspicious registry statuses become risk signals.
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

const (
	sourceName      = "rdap"
	defaultEndpoint = "https://rdap.org/domain/"
	httpTimeout     = 8 * time.Second
)

type Source struct {
	endpoint string
	client   *http.Client
}

func New() *Source {
	return NewWithEndpoint(defaultEndpoint)
}

// NewWithEndpoint lets tests inject a fake base URL (trailing slash required).
func NewWithEndpoint(endpoint string) *Source {
	return &Source{endpoint: endpoint, client: &http.Client{Timeout: httpTimeout}}
}

func (s *Source) Name() string { return sourceName }

type rdapEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type rdapResponse struct {
	ObjectClassName string      `json:"objectClassName"`
	Events          []rdapEvent `json:"events"`
	Status          []string    `json:"status"`
	Entities        []struct {
		Roles  []string        `json:"roles"`
		Handle string          `json:"handle"`
		VCard  json.RawMessage `json:"vcardArray"`
	} `json:"entities"`
}

func (s *Source) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+domain, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return &enricher.Finding{SourceName: sourceName}, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("rdap status %d", resp.StatusCode)
	}
	var parsed rdapResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	f := &enricher.Finding{SourceName: sourceName, RawData: parsed}
	now := time.Now()
	for _, e := range parsed.Events {
		if !strings.EqualFold(e.EventAction, "registration") {
			continue
		}
		t, perr := time.Parse(time.RFC3339, e.EventDate)
		if perr != nil {
			continue
		}
		age := now.Sub(t)
		switch {
		case age < 7*24*time.Hour:
			f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
				Label:    "domain_age_under_7d",
				Severity: enricher.SeverityCritical,
				Detail:   fmt.Sprintf("registered %s ago", ageStr(age)),
			})
		case age < 30*24*time.Hour:
			f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
				Label:    "domain_age_under_30d",
				Severity: enricher.SeverityHigh,
				Detail:   fmt.Sprintf("registered %s ago", ageStr(age)),
			})
		}
	}
	for _, st := range parsed.Status {
		if strings.Contains(st, "clientHold") || strings.Contains(st, "pendingDelete") || strings.Contains(st, "serverHold") {
			f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
				Label:    "suspicious_domain_status",
				Severity: enricher.SeverityMedium,
				Detail:   st,
			})
		}
	}
	return f, nil
}

func ageStr(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days < 1 {
		return "<1 day"
	}
	return fmt.Sprintf("%d days", days)
}
