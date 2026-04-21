// Package urlscan searches existing urlscan.io scans for a domain and
// surfaces malicious / suspicious verdicts. Submission (spec: "only for
// high-risk domains") is deferred — search works without a key and
// captures the bulk of the signal.
package urlscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ykbryan/domain-watcher/internal/enricher"
	"github.com/ykbryan/domain-watcher/internal/ratelimit"
)

const (
	sourceName      = "urlscan"
	defaultEndpoint = "https://urlscan.io/api/v1/search/"
	httpTimeout     = 12 * time.Second
)

type Source struct {
	endpoint string
	apiKey   string // optional; raises rate limits when present
	limiter  ratelimit.Limiter
	client   *http.Client
}

func New(apiKey string, limiter ratelimit.Limiter) *Source {
	return NewWithEndpoint(defaultEndpoint, apiKey, limiter)
}

func NewWithEndpoint(endpoint, apiKey string, limiter ratelimit.Limiter) *Source {
	if limiter == nil {
		limiter = noopLimiter{}
	}
	return &Source{endpoint: endpoint, apiKey: apiKey, limiter: limiter, client: &http.Client{Timeout: httpTimeout}}
}

func (s *Source) Name() string { return sourceName }

type usResult struct {
	Task struct {
		Time string `json:"time"`
		URL  string `json:"url"`
	} `json:"task"`
	Page struct {
		Title  string `json:"title"`
		Status string `json:"status"`
	} `json:"page"`
	Verdicts struct {
		Overall struct {
			Malicious  bool `json:"malicious"`
			Suspicious bool `json:"suspicious"`
		} `json:"overall"`
	} `json:"verdicts"`
}

type usResponse struct {
	Results []usResult `json:"results"`
	Total   int        `json:"total"`
}

func (s *Source) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit: %w", err)
	}
	q := url.Values{"q": {"domain:" + domain}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	if s.apiKey != "" {
		req.Header.Set("API-Key", s.apiKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("urlscan status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var parsed usResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	f := &enricher.Finding{SourceName: sourceName, RawData: parsed}
	var malicious, suspicious int
	for _, r := range parsed.Results {
		if r.Verdicts.Overall.Malicious {
			malicious++
		} else if r.Verdicts.Overall.Suspicious {
			suspicious++
		}
	}
	if malicious > 0 {
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "urlscan_malicious",
			Severity: enricher.SeverityCritical,
			Detail:   fmt.Sprintf("%d prior urlscan verdicts: malicious", malicious),
		})
	} else if suspicious > 0 {
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "urlscan_suspicious",
			Severity: enricher.SeverityHigh,
			Detail:   fmt.Sprintf("%d prior urlscan verdicts: suspicious", suspicious),
		})
	}
	return f, nil
}

type noopLimiter struct{}

func (noopLimiter) Wait(context.Context) error { return nil }
