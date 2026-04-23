// Package pdns queries the CIRCL Passive DNS service for historical
// resolution data. Requires free credentials from https://www.circl.lu/
// services/passive-dns/. Without them, New returns nil and the caller
// declines to register the source.
//
// Signal intent: unlike every other source we consult — which looks at
// the current DNS snapshot or reputation — CIRCL PDNS tells us
// whether a domain has been seen resolving before, to how many distinct
// IPs, and how recently. That breadth-and-recency pair is a useful
// independent dimension against typosquat campaigns that churn IPs.
package pdns

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ykbryan/domain-watcher/internal/enricher"
	"github.com/ykbryan/domain-watcher/internal/ratelimit"
)

const (
	sourceName      = "pdns"
	defaultEndpoint = "https://www.circl.lu/pdns/query/"
	httpTimeout     = 12 * time.Second
)

type Source struct {
	endpoint string
	username string
	password string
	limiter  ratelimit.Limiter
	client   *http.Client
}

// New returns nil if either credential is empty — caller skips registration.
func New(username, password string, limiter ratelimit.Limiter) *Source {
	if username == "" || password == "" {
		return nil
	}
	if limiter == nil {
		limiter = noopLimiter{}
	}
	return &Source{
		endpoint: defaultEndpoint,
		username: username,
		password: password,
		limiter:  limiter,
		client:   &http.Client{Timeout: httpTimeout},
	}
}

func (s *Source) Name() string { return sourceName }

// record is one CIRCL PDNS NDJSON row. The service returns one JSON
// object per line, not a JSON array.
type record struct {
	RRType    string `json:"rrtype"`
	RRName    string `json:"rrname"`
	RData     string `json:"rdata"`
	TimeFirst int64  `json:"time_first"`
	TimeLast  int64  `json:"time_last"`
	Count     int    `json:"count"`
}

func (s *Source) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+domain, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.SetBasicAuth(s.username, s.password)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	// 404 = domain never observed. Legitimate silence, not an error.
	if resp.StatusCode == http.StatusNotFound {
		return &enricher.Finding{SourceName: sourceName}, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("circl pdns unauthorized (check CIRCL_PDNS_USERNAME/PASSWORD)")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("circl pdns status %d", resp.StatusCode)
	}

	// Parse NDJSON (one JSON object per line).
	var records []record
	distinctRData := map[string]struct{}{}
	var firstSeen, lastSeen time.Time
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var r record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue // skip malformed row, don't abort
		}
		records = append(records, r)
		if r.RRType == "A" || r.RRType == "AAAA" {
			distinctRData[r.RData] = struct{}{}
		}
		t := time.Unix(r.TimeFirst, 0)
		if firstSeen.IsZero() || t.Before(firstSeen) {
			firstSeen = t
		}
		t2 := time.Unix(r.TimeLast, 0)
		if t2.After(lastSeen) {
			lastSeen = t2
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan pdns response: %w", err)
	}

	f := &enricher.Finding{SourceName: sourceName}
	if len(records) == 0 {
		return f, nil
	}

	age := time.Since(firstSeen)
	distinctIPs := len(distinctRData)

	// History is the primary signal. An old domain with lots of distinct
	// historical IPs is more likely legitimate; a freshly-resolving
	// domain with a handful of IPs is more likely staging infrastructure.
	switch {
	case age < 30*24*time.Hour && distinctIPs >= 5:
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "pdns_fresh_flapping",
			Severity: enricher.SeverityHigh,
			Detail:   fmt.Sprintf("first seen %s ago across %d distinct IPs", shortAge(age), distinctIPs),
		})
	case age < 30*24*time.Hour:
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "pdns_fresh",
			Severity: enricher.SeverityMedium,
			Detail:   fmt.Sprintf("first seen %s ago (pdns)", shortAge(age)),
		})
	case distinctIPs >= 10:
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "pdns_infra_breadth",
			Severity: enricher.SeverityInfo,
			Detail:   fmt.Sprintf("resolved to %d distinct IPs historically", distinctIPs),
		})
	default:
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "pdns_seen",
			Severity: enricher.SeverityInfo,
			Detail:   fmt.Sprintf("%d pdns records, first seen %s ago", len(records), shortAge(age)),
		})
	}

	return f, nil
}

func shortAge(d time.Duration) string {
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	days := int(d / (24 * time.Hour))
	if days < 30 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dmo", days/30)
}

type noopLimiter struct{}

func (noopLimiter) Wait(context.Context) error { return nil }
