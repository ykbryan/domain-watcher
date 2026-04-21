// Package safebrowsing queries Google Safe Browsing v4 threatMatches:find.
// One domain per call (no batching for now — typical scan volumes are well
// below rate limits).
package safebrowsing

import (
	"bytes"
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
	sourceName      = "safebrowsing"
	defaultEndpoint = "https://safebrowsingapis.googleapis.com/v4/threatMatches:find"
	httpTimeout     = 10 * time.Second
	clientID        = "domainwatch"
	clientVersion   = "0.1"
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

type sbRequest struct {
	Client     sbClient   `json:"client"`
	ThreatInfo sbThreatIn `json:"threatInfo"`
}

type sbClient struct {
	ClientID      string `json:"clientId"`
	ClientVersion string `json:"clientVersion"`
}

type sbThreatIn struct {
	ThreatTypes      []string  `json:"threatTypes"`
	PlatformTypes    []string  `json:"platformTypes"`
	ThreatEntryTypes []string  `json:"threatEntryTypes"`
	ThreatEntries    []sbEntry `json:"threatEntries"`
}

type sbEntry struct {
	URL string `json:"url"`
}

type sbResponse struct {
	Matches []struct {
		ThreatType      string  `json:"threatType"`
		PlatformType    string  `json:"platformType"`
		ThreatEntryType string  `json:"threatEntryType"`
		Threat          sbEntry `json:"threat"`
	} `json:"matches"`
}

func (s *Source) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit: %w", err)
	}
	body, _ := json.Marshal(sbRequest{
		Client: sbClient{ClientID: clientID, ClientVersion: clientVersion},
		ThreatInfo: sbThreatIn{
			ThreatTypes:      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
			PlatformTypes:    []string{"ANY_PLATFORM"},
			ThreatEntryTypes: []string{"URL"},
			ThreatEntries:    []sbEntry{{URL: "http://" + domain + "/"}, {URL: "https://" + domain + "/"}},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"?key="+s.apiKey, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("safebrowsing status %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var parsed sbResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	f := &enricher.Finding{SourceName: sourceName, RawData: parsed}
	if len(parsed.Matches) > 0 {
		threats := make([]string, 0, len(parsed.Matches))
		for _, m := range parsed.Matches {
			threats = append(threats, m.ThreatType)
		}
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "safebrowsing_match",
			Severity: enricher.SeverityCritical,
			Detail:   fmt.Sprintf("Google Safe Browsing flagged: %v", threats),
		})
	}
	return f, nil
}

type noopLimiter struct{}

func (noopLimiter) Wait(context.Context) error { return nil }
