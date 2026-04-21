// Package certwatch queries crt.sh's certificate transparency JSON API and
// surfaces signals for recently-issued certs (likely-live phishing setups).
package certwatch

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
	sourceName      = "certwatch"
	defaultEndpoint = "https://crt.sh/"
	httpTimeout     = 15 * time.Second
)

type Source struct {
	endpoint string
	client   *http.Client
}

func New() *Source {
	return NewWithEndpoint(defaultEndpoint)
}

func NewWithEndpoint(endpoint string) *Source {
	return &Source{endpoint: endpoint, client: &http.Client{Timeout: httpTimeout}}
}

func (s *Source) Name() string { return sourceName }

type certEntry struct {
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

func (s *Source) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	q := url.Values{"q": {domain}, "output": {"json"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("User-Agent", "domainwatch/0.1 (+https://github.com/ykbryan/domain-watcher)")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("crt.sh status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	// crt.sh returns `[]` (valid JSON) for zero matches; empty body is rare but handled.
	if len(body) == 0 {
		return &enricher.Finding{SourceName: sourceName}, nil
	}
	var entries []certEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	f := &enricher.Finding{SourceName: sourceName, RawData: entries}
	now := time.Now()

	var mostRecent time.Time
	var letsEncryptCount, totalCount int
	for _, e := range entries {
		totalCount++
		if strings.Contains(strings.ToLower(e.IssuerName), "let's encrypt") {
			letsEncryptCount++
		}
		t, err := parseCertTime(e.NotBefore)
		if err != nil {
			continue
		}
		if t.After(mostRecent) {
			mostRecent = t
		}
	}

	if !mostRecent.IsZero() {
		age := now.Sub(mostRecent)
		switch {
		case age < 24*time.Hour:
			f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
				Label:    "cert_issued_under_24h",
				Severity: enricher.SeverityCritical,
				Detail:   fmt.Sprintf("most recent cert issued %s ago", ageStr(age)),
			})
		case age < 7*24*time.Hour:
			f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
				Label:    "cert_issued_under_7d",
				Severity: enricher.SeverityHigh,
				Detail:   fmt.Sprintf("most recent cert issued %s ago", ageStr(age)),
			})
		}
	}
	// Let's Encrypt alone is not inherently suspicious for the original brand,
	// but for a typosquat-target domain it's cheap-phishing territory. Flag it.
	if letsEncryptCount > 0 {
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "lets_encrypt_cert",
			Severity: enricher.SeverityHigh,
			Detail:   fmt.Sprintf("%d of %d certs issued by Let's Encrypt", letsEncryptCount, totalCount),
		})
	}
	// Rapid cert issuance velocity — a common domain shadowing pattern.
	if totalCount >= 10 && !mostRecent.IsZero() && now.Sub(mostRecent) < 30*24*time.Hour {
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "rapid_cert_issuance",
			Severity: enricher.SeverityHigh,
			Detail:   fmt.Sprintf("%d certs, latest within 30d", totalCount),
		})
	}
	return f, nil
}

func parseCertTime(s string) (time.Time, error) {
	// crt.sh timestamps lack TZ; examples: 2024-07-18T13:23:14 or with fractional seconds.
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04:05.999", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable time %q", s)
}

func ageStr(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%d min", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%d hr", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}
