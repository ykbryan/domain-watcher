package otx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

func TestOTX_NilWithoutKey(t *testing.T) {
	if s := New("", nil); s != nil {
		t.Error("expected nil without key")
	}
}

func server(t *testing.T, count int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") != "k" {
			t.Errorf("missing API key header: %q", r.Header.Get("X-OTX-API-KEY"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"pulse_info": map[string]int{"count": count}})
	}))
}

func TestOTX_HeavyPulse_Critical(t *testing.T) {
	srv := server(t, 8)
	defer srv.Close()
	s := NewWithEndpoint(srv.URL+"/", "k", nil)
	f, err := s.Enrich(context.Background(), "bad.test")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !hasSignal(f, "otx_pulse_heavy", enricher.SeverityCritical) {
		t.Errorf("expected CRITICAL, got %+v", f.RiskSignals)
	}
}

func TestOTX_SomePulse_High(t *testing.T) {
	srv := server(t, 2)
	defer srv.Close()
	s := NewWithEndpoint(srv.URL+"/", "k", nil)
	f, _ := s.Enrich(context.Background(), "d.test")
	if !hasSignal(f, "otx_pulse_match", enricher.SeverityHigh) {
		t.Errorf("expected HIGH, got %+v", f.RiskSignals)
	}
}

func TestOTX_NoPulse(t *testing.T) {
	srv := server(t, 0)
	defer srv.Close()
	s := NewWithEndpoint(srv.URL+"/", "k", nil)
	f, _ := s.Enrich(context.Background(), "d.test")
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
