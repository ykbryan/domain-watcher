package abuseipdb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

func TestAIP_NilWithoutKey(t *testing.T) {
	if s := New("", nil); s != nil {
		t.Error("expected nil without key")
	}
}

func server(t *testing.T, score int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "k" {
			t.Errorf("missing Key header: %q", r.Header.Get("Key"))
		}
		_ = json.NewEncoder(w).Encode(aipResponse{
			Data: aipCheck{IPAddress: "127.0.0.1", AbuseConfidenceScore: score, TotalReports: 5, CountryCode: "US"},
		})
	}))
}

func TestAIP_HighConfidence_Critical(t *testing.T) {
	srv := server(t, 90)
	defer srv.Close()
	s := NewWithEndpoint(srv.URL, "k", nil)
	f, err := s.Enrich(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !hasSignal(f, "abuseipdb_high_confidence", enricher.SeverityCritical) {
		t.Errorf("expected CRITICAL, got %+v", f.RiskSignals)
	}
}

func TestAIP_MidConfidence_High(t *testing.T) {
	srv := server(t, 50)
	defer srv.Close()
	s := NewWithEndpoint(srv.URL, "k", nil)
	f, _ := s.Enrich(context.Background(), "localhost")
	if !hasSignal(f, "abuseipdb_mid_confidence", enricher.SeverityHigh) {
		t.Errorf("expected HIGH, got %+v", f.RiskSignals)
	}
}

func TestAIP_LowConfidence_Medium(t *testing.T) {
	srv := server(t, 15)
	defer srv.Close()
	s := NewWithEndpoint(srv.URL, "k", nil)
	f, _ := s.Enrich(context.Background(), "localhost")
	if !hasSignal(f, "abuseipdb_low_confidence", enricher.SeverityMedium) {
		t.Errorf("expected MEDIUM, got %+v", f.RiskSignals)
	}
}

func TestAIP_Clean(t *testing.T) {
	srv := server(t, 0)
	defer srv.Close()
	s := NewWithEndpoint(srv.URL, "k", nil)
	f, _ := s.Enrich(context.Background(), "localhost")
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
