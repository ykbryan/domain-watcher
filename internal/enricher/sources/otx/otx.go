// Package otx queries AlienVault OTX for community IOC pulse counts.
package otx

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
	sourceName      = "otx"
	defaultEndpoint = "https://otx.alienvault.com/api/v1/indicators/domain/"
	httpTimeout     = 10 * time.Second
)

type Source struct {
	endpoint string
	apiKey   string
	limiter  ratelimit.Limiter
	client   *http.Client
}

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
	return &Source{endpoint: endpoint, apiKey: apiKey, limiter: limiter, client: &http.Client{Timeout: httpTimeout}}
}

func (s *Source) Name() string { return sourceName }

type otxResponse struct {
	PulseInfo struct {
		Count int `json:"count"`
	} `json:"pulse_info"`
	Validation []any  `json:"validation"`
	Alexa      string `json:"alexa"`
}

func (s *Source) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+domain+"/general", nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("X-OTX-API-KEY", s.apiKey)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return &enricher.Finding{SourceName: sourceName}, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("otx status %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var parsed otxResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	f := &enricher.Finding{SourceName: sourceName, RawData: parsed}
	switch {
	case parsed.PulseInfo.Count > 5:
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "otx_pulse_heavy",
			Severity: enricher.SeverityCritical,
			Detail:   fmt.Sprintf("%d OTX pulse matches", parsed.PulseInfo.Count),
		})
	case parsed.PulseInfo.Count > 0:
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "otx_pulse_match",
			Severity: enricher.SeverityHigh,
			Detail:   fmt.Sprintf("%d OTX pulse match(es)", parsed.PulseInfo.Count),
		})
	}
	return f, nil
}

type noopLimiter struct{}

func (noopLimiter) Wait(context.Context) error { return nil }
