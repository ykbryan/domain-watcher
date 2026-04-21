package virustotal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

func fixture(mal, susp int, rep int) map[string]any {
	return map[string]any{
		"data": map[string]any{
			"id": "test.example",
			"attributes": map[string]any{
				"last_analysis_stats": map[string]int{
					"malicious": mal, "suspicious": susp, "undetected": 50, "harmless": 30,
				},
				"reputation": rep,
			},
		},
	}
}

func server(t *testing.T, body any, wantAPIKey string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != wantAPIKey {
			t.Errorf("wrong x-apikey header: %q", r.Header.Get("x-apikey"))
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func TestVT_NewReturnsNilWithoutKey(t *testing.T) {
	if s := New("", nil); s != nil {
		t.Error("expected nil source when apiKey is empty")
	}
}

func TestVT_Malicious_Critical(t *testing.T) {
	srv := server(t, fixture(3, 0, 0), "key")
	defer srv.Close()
	s := NewWithEndpoint(srv.URL+"/", "key", nil)
	f, err := s.Enrich(context.Background(), "bad.test")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !hasSignal(f, "virustotal_malicious", enricher.SeverityCritical) {
		t.Errorf("expected CRITICAL malicious signal, got %+v", f.RiskSignals)
	}
}

func TestVT_SuspiciousOver2_High(t *testing.T) {
	srv := server(t, fixture(0, 3, 0), "key")
	defer srv.Close()
	s := NewWithEndpoint(srv.URL+"/", "key", nil)
	f, _ := s.Enrich(context.Background(), "susp.test")
	if !hasSignal(f, "virustotal_suspicious_multi", enricher.SeverityHigh) {
		t.Errorf("expected HIGH signal for >2 suspicious, got %+v", f.RiskSignals)
	}
}

func TestVT_Suspicious1_Medium(t *testing.T) {
	srv := server(t, fixture(0, 1, 0), "key")
	defer srv.Close()
	s := NewWithEndpoint(srv.URL+"/", "key", nil)
	f, _ := s.Enrich(context.Background(), "susp1.test")
	if !hasSignal(f, "virustotal_suspicious", enricher.SeverityMedium) {
		t.Errorf("expected MEDIUM signal, got %+v", f.RiskSignals)
	}
}

func TestVT_LowReputation(t *testing.T) {
	srv := server(t, fixture(0, 0, -50), "key")
	defer srv.Close()
	s := NewWithEndpoint(srv.URL+"/", "key", nil)
	f, _ := s.Enrich(context.Background(), "rep.test")
	if !hasSignal(f, "virustotal_low_reputation", enricher.SeverityMedium) {
		t.Errorf("expected low-reputation signal, got %+v", f.RiskSignals)
	}
}

func TestVT_Clean(t *testing.T) {
	srv := server(t, fixture(0, 0, 0), "key")
	defer srv.Close()
	s := NewWithEndpoint(srv.URL+"/", "key", nil)
	f, _ := s.Enrich(context.Background(), "clean.test")
	if len(f.RiskSignals) != 0 {
		t.Errorf("expected no signals, got %+v", f.RiskSignals)
	}
}

func TestVT_NotFound_Benign(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	s := NewWithEndpoint(srv.URL+"/", "key", nil)
	f, err := s.Enrich(context.Background(), "missing.test")
	if err != nil {
		t.Errorf("404 should not error: %v", err)
	}
	if len(f.RiskSignals) != 0 {
		t.Errorf("no signals on 404")
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
