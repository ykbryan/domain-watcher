// Package abuseipdb queries abuseipdb.com for reputation on each live A-record.
// Like ipinfo, resolves its own IPs to keep the Source interface simple.
package abuseipdb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ykbryan/domain-watcher/internal/enricher"
	"github.com/ykbryan/domain-watcher/internal/ratelimit"
)

const (
	sourceName      = "abuseipdb"
	defaultEndpoint = "https://api.abuseipdb.com/api/v2/check"
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

type aipCheck struct {
	IPAddress            string `json:"ipAddress"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	TotalReports         int    `json:"totalReports"`
	CountryCode          string `json:"countryCode"`
	ISP                  string `json:"isp"`
}

type aipResponse struct {
	Data aipCheck `json:"data"`
}

func (s *Source) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
	if err != nil || len(ips) == 0 {
		return &enricher.Finding{SourceName: sourceName}, nil
	}

	f := &enricher.Finding{SourceName: sourceName}
	checks := make([]aipCheck, 0, len(ips))

	for _, ip := range ips {
		c, err := s.check(ctx, ip.String())
		if err != nil {
			continue
		}
		checks = append(checks, c)
		switch {
		case c.AbuseConfidenceScore > 80:
			f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
				Label:    "abuseipdb_high_confidence",
				Severity: enricher.SeverityCritical,
				Detail:   fmt.Sprintf("%s: confidence %d, %d reports", c.IPAddress, c.AbuseConfidenceScore, c.TotalReports),
			})
		case c.AbuseConfidenceScore > 40:
			f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
				Label:    "abuseipdb_mid_confidence",
				Severity: enricher.SeverityHigh,
				Detail:   fmt.Sprintf("%s: confidence %d", c.IPAddress, c.AbuseConfidenceScore),
			})
		case c.AbuseConfidenceScore > 10:
			f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
				Label:    "abuseipdb_low_confidence",
				Severity: enricher.SeverityMedium,
				Detail:   fmt.Sprintf("%s: confidence %d", c.IPAddress, c.AbuseConfidenceScore),
			})
		}
	}
	f.RawData = checks
	return f, nil
}

func (s *Source) check(ctx context.Context, ip string) (aipCheck, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return aipCheck{}, fmt.Errorf("rate limit: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+"?ipAddress="+ip+"&maxAgeInDays=90", nil)
	if err != nil {
		return aipCheck{}, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Key", s.apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return aipCheck{}, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return aipCheck{}, fmt.Errorf("abuseipdb status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var parsed aipResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return aipCheck{}, fmt.Errorf("decode: %w", err)
	}
	return parsed.Data, nil
}

type noopLimiter struct{}

func (noopLimiter) Wait(context.Context) error { return nil }
