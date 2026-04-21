// Package ipinfo queries IPInfo for each A-record IP of a domain. Source
// does its own net.LookupIP to keep the enricher.Source interface simple —
// Go's resolver caches these lookups so the cost is negligible.
package ipinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ykbryan/domain-watcher/internal/enricher"
	"github.com/ykbryan/domain-watcher/internal/ratelimit"
)

const (
	sourceName      = "ipinfo"
	defaultEndpoint = "https://ipinfo.io/"
	httpTimeout     = 8 * time.Second
)

// bulletproofASNs is a small allowlist of known-bad hosting organizations.
// Extending this is cheap; removing noisy entries as we learn from scans.
var bulletproofASNs = map[string]string{
	"AS49870": "Alsycon / alleged bulletproof",
	"AS60781": "LeaseWeb (flagged ranges)",
}

type Source struct {
	endpoint string
	token    string
	limiter  ratelimit.Limiter
	client   *http.Client
}

func New(token string, limiter ratelimit.Limiter) *Source {
	if token == "" {
		return nil
	}
	return NewWithEndpoint(defaultEndpoint, token, limiter)
}

func NewWithEndpoint(endpoint, token string, limiter ratelimit.Limiter) *Source {
	if limiter == nil {
		limiter = noopLimiter{}
	}
	return &Source{endpoint: endpoint, token: token, limiter: limiter, client: &http.Client{Timeout: httpTimeout}}
}

func (s *Source) Name() string { return sourceName }

type ipInfo struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Org      string `json:"org"`
	Anycast  bool   `json:"anycast"`
}

func (s *Source) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
	if err != nil || len(ips) == 0 {
		return &enricher.Finding{SourceName: sourceName}, nil
	}

	f := &enricher.Finding{SourceName: sourceName}
	infos := make([]ipInfo, 0, len(ips))

	for _, ip := range ips {
		info, err := s.lookup(ctx, ip.String())
		if err != nil {
			continue
		}
		infos = append(infos, info)

		asn := asnOf(info.Org)
		if reason, ok := bulletproofASNs[asn]; ok {
			f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
				Label:    "hosted_on_bulletproof_asn",
				Severity: enricher.SeverityHigh,
				Detail:   fmt.Sprintf("%s on %s (%s)", info.IP, asn, reason),
			})
		}
		if isLikelyPrivacyHost(info.Org) {
			f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
				Label:    "hosted_on_privacy_service",
				Severity: enricher.SeverityMedium,
				Detail:   fmt.Sprintf("%s on %s", info.IP, info.Org),
			})
		}
	}
	f.RawData = infos
	return f, nil
}

func (s *Source) lookup(ctx context.Context, ip string) (ipInfo, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return ipInfo{}, fmt.Errorf("rate limit: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+ip+"/json?token="+s.token, nil)
	if err != nil {
		return ipInfo{}, fmt.Errorf("new request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return ipInfo{}, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return ipInfo{}, fmt.Errorf("ipinfo status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var out ipInfo
	if err := json.Unmarshal(body, &out); err != nil {
		return ipInfo{}, fmt.Errorf("decode: %w", err)
	}
	return out, nil
}

// asnOf extracts the leading ASNNN from an "AS15169 Google LLC"-style org string.
func asnOf(org string) string {
	fields := strings.Fields(org)
	if len(fields) == 0 {
		return ""
	}
	if strings.HasPrefix(fields[0], "AS") {
		return fields[0]
	}
	return ""
}

func isLikelyPrivacyHost(org string) bool {
	l := strings.ToLower(org)
	for _, kw := range []string{"privacy", "vpn", "proxy", "anon"} {
		if strings.Contains(l, kw) {
			return true
		}
	}
	return false
}

type noopLimiter struct{}

func (noopLimiter) Wait(context.Context) error { return nil }
