package urlscan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

func TestUS_AllowsNoKey(t *testing.T) {
	// urlscan search works without a key — New() should return a usable source.
	if s := New("", nil); s == nil {
		t.Error("expected usable source without key (search is free)")
	}
}

func TestUS_Malicious_Critical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{"verdicts": map[string]any{"overall": map[string]bool{"malicious": true}}},
			},
		})
	}))
	defer srv.Close()
	s := NewWithEndpoint(srv.URL, "", nil)
	f, err := s.Enrich(context.Background(), "bad.test")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !hasSignal(f, "urlscan_malicious", enricher.SeverityCritical) {
		t.Errorf("expected CRITICAL, got %+v", f.RiskSignals)
	}
}

func TestUS_SuspiciousOnly_High(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{"verdicts": map[string]any{"overall": map[string]bool{"suspicious": true}}},
			},
		})
	}))
	defer srv.Close()
	s := NewWithEndpoint(srv.URL, "", nil)
	f, _ := s.Enrich(context.Background(), "susp.test")
	if !hasSignal(f, "urlscan_suspicious", enricher.SeverityHigh) {
		t.Errorf("expected HIGH, got %+v", f.RiskSignals)
	}
}

func TestUS_ApiKeyHeaderSet(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("API-Key")
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
	}))
	defer srv.Close()
	s := NewWithEndpoint(srv.URL, "my-key", nil)
	_, _ = s.Enrich(context.Background(), "d.test")
	if seen != "my-key" {
		t.Errorf("API-Key header mismatch: %q", seen)
	}
}

func TestUS_NoResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
	}))
	defer srv.Close()
	s := NewWithEndpoint(srv.URL, "", nil)
	f, _ := s.Enrich(context.Background(), "clean.test")
	if len(f.RiskSignals) != 0 {
		t.Errorf("expected no signals, got %+v", f.RiskSignals)
	}
}

func hasSignal(f *enricher.Finding, label string, sev enricher.Severity) bool {
	for _, s := range f.RiskSignals {
		if s.Label == label && s.Severity == sev {
			return true
		}
	}
	return false
}

var _ enricher.Source = (*Source)(nil)
