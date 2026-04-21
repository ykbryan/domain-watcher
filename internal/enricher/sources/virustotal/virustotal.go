// Package virustotal queries the VirusTotal v3 domain report.
// Free tier: 4 req/min, 500/day — enforced via the shared ratelimit registry.
package virustotal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ykbryan/domain-watcher/internal/enricher"
	"github.com/ykbryan/domain-watcher/internal/ratelimit"
)

const (
	sourceName      = "virustotal"
	defaultEndpoint = "https://www.virustotal.com/api/v3/domains/"
	httpTimeout     = 15 * time.Second
)

type Source struct {
	endpoint string
	apiKey   string
	limiter  ratelimit.Limiter
	client   *http.Client
}

// New returns nil if apiKey is empty — caller skips registration.
func New(apiKey string, limiter ratelimit.Limiter) *Source {
	if apiKey == "" {
		return nil
	}
	return NewWithEndpoint(defaultEndpoint, apiKey, limiter)
}

func NewWithEndpoint(endpoint, apiKey string, limiter ratelimit.Limiter) *Source {
	if limiter == nil {
		limiter = noopLimiter{}
	}
	return &Source{
		endpoint: endpoint,
		apiKey:   apiKey,
		limiter:  limiter,
		client:   &http.Client{Timeout: httpTimeout},
	}
}

func (s *Source) Name() string { return sourceName }

type vtStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
	Harmless   int `json:"harmless"`
	Timeout    int `json:"timeout"`
}

type vtAttributes struct {
	LastAnalysisStats vtStats           `json:"last_analysis_stats"`
	LastAnalysisDate  int64             `json:"last_analysis_date"`
	Reputation        int               `json:"reputation"`
	Categories        map[string]string `json:"categories"`
}

type vtResponse struct {
	Data struct {
		ID         string       `json:"id"`
		Attributes vtAttributes `json:"attributes"`
	} `json:"data"`
}

func (s *Source) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+domain, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("x-apikey", s.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return &enricher.Finding{SourceName: sourceName}, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("virustotal status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var parsed vtResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	stats := parsed.Data.Attributes.LastAnalysisStats
	f := &enricher.Finding{SourceName: sourceName, RawData: parsed}

	switch {
	case stats.Malicious > 0:
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "virustotal_malicious",
			Severity: enricher.SeverityCritical,
			Detail:   fmt.Sprintf("%d vendor(s) flagged as malicious", stats.Malicious),
		})
	case stats.Suspicious > 2:
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "virustotal_suspicious_multi",
			Severity: enricher.SeverityHigh,
			Detail:   fmt.Sprintf("%d vendor(s) flagged as suspicious", stats.Suspicious),
		})
	case stats.Suspicious > 0:
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "virustotal_suspicious",
			Severity: enricher.SeverityMedium,
			Detail:   fmt.Sprintf("%d vendor(s) flagged as suspicious", stats.Suspicious),
		})
	}

	if parsed.Data.Attributes.Reputation < -10 {
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "virustotal_low_reputation",
			Severity: enricher.SeverityMedium,
			Detail:   fmt.Sprintf("reputation score %d", parsed.Data.Attributes.Reputation),
		})
	}
	return f, nil
}

type noopLimiter struct{}

func (noopLimiter) Wait(context.Context) error { return nil }
