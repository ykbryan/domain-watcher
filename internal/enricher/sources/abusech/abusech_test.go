package abusech

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

// URLhaus

func TestURLhaus_OnlineThreat_Critical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "host=bad.test") {
			t.Errorf("expected form host=bad.test, got %q", string(body))
		}
		_ = json.NewEncoder(w).Encode(urlhausResponse{
			QueryStatus: "ok",
			URLs: []urlhausURL{
				{URL: "http://bad.test/login", URLStatus: "online"},
			},
		})
	}))
	defer srv.Close()
	s := NewURLhausWithEndpoint(srv.URL + "/")
	f, err := s.Enrich(context.Background(), "bad.test")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !hasSignal(f, "urlhaus_online", enricher.SeverityCritical) {
		t.Errorf("expected CRITICAL online signal, got %+v", f.RiskSignals)
	}
}

func TestURLhaus_OfflineOnly_Medium(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(urlhausResponse{
			QueryStatus: "ok",
			URLs:        []urlhausURL{{URL: "http://old.test", URLStatus: "offline"}},
		})
	}))
	defer srv.Close()
	s := NewURLhausWithEndpoint(srv.URL + "/")
	f, _ := s.Enrich(context.Background(), "old.test")
	if !hasSignal(f, "urlhaus_offline", enricher.SeverityMedium) {
		t.Errorf("expected MEDIUM offline signal, got %+v", f.RiskSignals)
	}
}

func TestURLhaus_NoResults_Benign(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(urlhausResponse{QueryStatus: "no_results"})
	}))
	defer srv.Close()
	s := NewURLhausWithEndpoint(srv.URL + "/")
	f, err := s.Enrich(context.Background(), "clean.test")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if len(f.RiskSignals) != 0 {
		t.Errorf("expected no signals, got %+v", f.RiskSignals)
	}
}

// ThreatFox

func TestThreatFox_Match_High(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(threatfoxResponse{
			QueryStatus: "ok",
			Data: []threatfoxIOC{
				{IOC: "evil.test", ThreatType: "payload_delivery", MalwarePrintable: "Emotet", LastSeen: "2026-04-01 10:00:00"},
			},
		})
	}))
	defer srv.Close()
	s := NewThreatFoxWithEndpoint(srv.URL + "/")
	f, err := s.Enrich(context.Background(), "evil.test")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !hasSignal(f, "threatfox_ioc", enricher.SeverityHigh) {
		t.Errorf("expected HIGH signal, got %+v", f.RiskSignals)
	}
}

func TestThreatFox_NoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(threatfoxResponse{QueryStatus: "no_result"})
	}))
	defer srv.Close()
	s := NewThreatFoxWithEndpoint(srv.URL + "/")
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

var (
	_ enricher.Source = (*URLhaus)(nil)
	_ enricher.Source = (*ThreatFox)(nil)
)
