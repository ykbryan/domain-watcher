package safebrowsing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

func TestSB_NilWithoutKey(t *testing.T) {
	if s := New("", nil); s != nil {
		t.Error("expected nil source without key")
	}
}

func TestSB_Match_Critical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "mykey" {
			t.Errorf("missing key query: %q", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"matches": []map[string]any{
				{"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM", "threatEntryType": "URL"},
			},
		})
	}))
	defer srv.Close()
	s := NewWithEndpoint(srv.URL, "mykey", nil)
	f, err := s.Enrich(context.Background(), "phish.test")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !hasSignal(f, "safebrowsing_match", enricher.SeverityCritical) {
		t.Errorf("expected CRITICAL, got %+v", f.RiskSignals)
	}
}

func TestSB_NoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{}")
	}))
	defer srv.Close()
	s := NewWithEndpoint(srv.URL, "mykey", nil)
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
