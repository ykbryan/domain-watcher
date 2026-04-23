// Package censys queries the Censys Search v2 API to surface the
// hosting footprint of a domain — observed services, TLS signatures,
// and the count of related names.
//
// Two things to know:
//
//  1. Free tier is ~250 queries/month. The source is rate-limited hard
//     (1 req / 30 s, burst 1) and returns gracefully when the limiter
//     or the upstream signals 429. Do not drive every live permutation
//     against Censys in production without a paid plan.
//
//  2. We query the "names" index rather than "hosts". "names" lets us
//     pass the domain directly; "hosts" would require resolving to an
//     IP first which duplicates work done in the resolver stage.
package censys

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ykbryan/domain-watcher/internal/enricher"
	"github.com/ykbryan/domain-watcher/internal/ratelimit"
)

const (
	sourceName      = "censys"
	defaultEndpoint = "https://search.censys.io/api/v2/hosts/search"
	httpTimeout     = 15 * time.Second
)

type Source struct {
	endpoint  string
	apiID     string
	apiSecret string
	limiter   ratelimit.Limiter
	client    *http.Client
}

// New returns nil unless both credentials are present.
func New(apiID, apiSecret string, limiter ratelimit.Limiter) *Source {
	if apiID == "" || apiSecret == "" {
		return nil
	}
	if limiter == nil {
		limiter = noopLimiter{}
	}
	return &Source{
		endpoint:  defaultEndpoint,
		apiID:     apiID,
		apiSecret: apiSecret,
		limiter:   limiter,
		client:    &http.Client{Timeout: httpTimeout},
	}
}

func (s *Source) Name() string { return sourceName }

// censysHit is the subset of the Censys v2 hosts-search response we use.
// The real payload is much larger; we deliberately ignore fields we're
// not acting on to keep the dependency surface tight.
type censysHit struct {
	IP       string `json:"ip"`
	LastSeen string `json:"last_updated_at"`
	Services []struct {
		Port     int    `json:"port"`
		Protocol string `json:"service_name"`
	} `json:"services"`
}

type censysResp struct {
	Result struct {
		Total int         `json:"total"`
		Hits  []censysHit `json:"hits"`
	} `json:"result"`
}

func (s *Source) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit: %w", err)
	}

	// `q=names: <domain>` searches host records whose certificate
	// subject-alt-names include the domain. Cheap and informative.
	q := url.Values{}
	q.Set("q", fmt.Sprintf("names: %s", domain))
	q.Set("per_page", "5")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.SetBasicAuth(s.apiID, s.apiSecret)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return &enricher.Finding{SourceName: sourceName}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("censys auth failed (check CENSYS_API_ID / CENSYS_API_SECRET)")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("censys rate limited (free tier is 250/mo)")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("censys status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var parsed censysResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	f := &enricher.Finding{SourceName: sourceName, RawData: parsed}
	total := parsed.Result.Total
	hits := parsed.Result.Hits

	if total == 0 {
		// No observed infrastructure for this name. Silent.
		return f, nil
	}

	// Fresh infrastructure serving a typosquat name is higher-signal
	// than long-established infrastructure — catches campaign staging.
	freshHost := false
	for _, h := range hits {
		if t, err := time.Parse(time.RFC3339, h.LastSeen); err == nil {
			if time.Since(t) < 7*24*time.Hour {
				freshHost = true
				break
			}
		}
	}

	if freshHost {
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "censys_fresh_infrastructure",
			Severity: enricher.SeverityHigh,
			Detail:   fmt.Sprintf("%d host(s) observed serving this name; one seen within 7 days", total),
		})
	} else {
		// Service footprint summary (collect unique protocols from top hits).
		protos := map[string]struct{}{}
		for _, h := range hits {
			for _, svc := range h.Services {
				if svc.Protocol != "" {
					protos[svc.Protocol] = struct{}{}
				}
			}
		}
		names := make([]string, 0, len(protos))
		for p := range protos {
			names = append(names, p)
		}
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "censys_observed_infrastructure",
			Severity: enricher.SeverityInfo,
			Detail:   fmt.Sprintf("%d host(s), services: %s", total, joinOrNone(names)),
		})
	}

	return f, nil
}

func joinOrNone(parts []string) string {
	if len(parts) == 0 {
		return "(none observed)"
	}
	return strings.Join(parts, ", ")
}

type noopLimiter struct{}

func (noopLimiter) Wait(context.Context) error { return nil }
