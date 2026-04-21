package abusech

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

const (
	threatfoxName            = "threatfox"
	threatfoxDefaultEndpoint = "https://threatfox-api.abuse.ch/api/v1/"
)

// ThreatFox requires an abuse.ch Auth-Key (free, register at
// https://auth.abuse.ch) as of 2024-11. See URLhaus for the full note.
type ThreatFox struct {
	endpoint string
	authKey  string
	client   *http.Client
}

func NewThreatFox(authKey string) *ThreatFox {
	return &ThreatFox{endpoint: threatfoxDefaultEndpoint, authKey: authKey, client: &http.Client{Timeout: httpTimeout}}
}

func NewThreatFoxWithEndpoint(endpoint string) *ThreatFox {
	return &ThreatFox{endpoint: endpoint, client: &http.Client{Timeout: httpTimeout}}
}

func (s *ThreatFox) Name() string { return threatfoxName }

type threatfoxIOC struct {
	IOC            string `json:"ioc"`
	IOCType        string `json:"ioc_type"`
	ThreatType     string `json:"threat_type"`
	MalwarePrintable string `json:"malware_printable"`
	Confidence     int    `json:"confidence_level"`
	FirstSeen      string `json:"first_seen"`
	LastSeen       string `json:"last_seen"`
}

type threatfoxResponse struct {
	QueryStatus string         `json:"query_status"`
	Data        []threatfoxIOC `json:"data"`
}

func (s *ThreatFox) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	body, _ := json.Marshal(map[string]string{"query": "search_ioc", "search_term": domain})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.authKey != "" {
		req.Header.Set("Auth-Key", s.authKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("threatfox status %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var parsed threatfoxResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	f := &enricher.Finding{SourceName: threatfoxName, RawData: parsed}
	if parsed.QueryStatus != "ok" || len(parsed.Data) == 0 {
		return f, nil
	}
	f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
		Label:    "threatfox_ioc",
		Severity: enricher.SeverityHigh,
		Detail:   fmt.Sprintf("%d IOC match(es), latest threat: %s", len(parsed.Data), threatSummary(parsed.Data)),
	})
	return f, nil
}

func threatSummary(iocs []threatfoxIOC) string {
	if len(iocs) == 0 {
		return ""
	}
	latest := iocs[0]
	for _, i := range iocs {
		if t1, err1 := time.Parse("2006-01-02 15:04:05", i.LastSeen); err1 == nil {
			if t2, err2 := time.Parse("2006-01-02 15:04:05", latest.LastSeen); err2 != nil || t1.After(t2) {
				latest = i
			}
		}
	}
	if latest.MalwarePrintable != "" {
		return latest.MalwarePrintable
	}
	return latest.ThreatType
}
