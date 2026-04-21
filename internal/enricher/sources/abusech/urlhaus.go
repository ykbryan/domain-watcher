// Package abusech wraps the abuse.ch URLhaus and ThreatFox lookups — two
// independent Source implementations that share HTTP boilerplate.
package abusech

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
)

const (
	urlhausName            = "urlhaus"
	urlhausDefaultEndpoint = "https://urlhaus-api.abuse.ch/v1/host/"
	httpTimeout            = 10 * time.Second
)

// URLhaus requires an abuse.ch Auth-Key (free, register at
// https://auth.abuse.ch) as of 2024-11. Without it, the API returns 401 and
// the source records the error in the Finding but does not fail the scan.
type URLhaus struct {
	endpoint string
	authKey  string
	client   *http.Client
}

func NewURLhaus(authKey string) *URLhaus {
	return &URLhaus{endpoint: urlhausDefaultEndpoint, authKey: authKey, client: &http.Client{Timeout: httpTimeout}}
}

func NewURLhausWithEndpoint(endpoint string) *URLhaus {
	return &URLhaus{endpoint: endpoint, client: &http.Client{Timeout: httpTimeout}}
}

func (s *URLhaus) Name() string { return urlhausName }

type urlhausURL struct {
	URL       string `json:"url"`
	URLStatus string `json:"url_status"`
	DateAdded string `json:"date_added"`
	Threat    string `json:"threat"`
	Tags      any    `json:"tags"`
}

type urlhausResponse struct {
	QueryStatus string       `json:"query_status"`
	URLs        []urlhausURL `json:"urls"`
}

func (s *URLhaus) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	form := url.Values{"host": {domain}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s.authKey != "" {
		req.Header.Set("Auth-Key", s.authKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("urlhaus status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var parsed urlhausResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	f := &enricher.Finding{SourceName: urlhausName, RawData: parsed}
	if parsed.QueryStatus == "no_results" || len(parsed.URLs) == 0 {
		return f, nil
	}

	var online, offline int
	for _, u := range parsed.URLs {
		switch strings.ToLower(u.URLStatus) {
		case "online":
			online++
		case "offline":
			offline++
		}
	}
	if online > 0 {
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "urlhaus_online",
			Severity: enricher.SeverityCritical,
			Detail:   fmt.Sprintf("%d online malicious URL(s)", online),
		})
	} else if offline > 0 {
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "urlhaus_offline",
			Severity: enricher.SeverityMedium,
			Detail:   fmt.Sprintf("%d previously-seen malicious URL(s)", offline),
		})
	}
	return f, nil
}
