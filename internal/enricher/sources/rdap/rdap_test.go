package rdap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

func fixtureServer(t *testing.T, status int, body any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func rdapFixture(regAgo time.Duration, statuses []string) map[string]any {
	return map[string]any{
		"objectClassName": "domain",
		"events": []map[string]string{
			{"eventAction": "registration", "eventDate": time.Now().Add(-regAgo).Format(time.RFC3339)},
		},
		"status": statuses,
	}
}

func TestRDAP_NewDomain_Critical(t *testing.T) {
	srv := fixtureServer(t, 200, rdapFixture(2*24*time.Hour, nil))
	defer srv.Close()

	s := NewWithEndpoint(srv.URL + "/")
	f, err := s.Enrich(context.Background(), "new.test")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !hasSignal(f, "domain_age_under_7d", enricher.SeverityCritical) {
		t.Errorf("expected CRITICAL for <7d domain; got %+v", f.RiskSignals)
	}
}

func TestRDAP_RecentDomain_High(t *testing.T) {
	srv := fixtureServer(t, 200, rdapFixture(15*24*time.Hour, nil))
	defer srv.Close()

	s := NewWithEndpoint(srv.URL + "/")
	f, _ := s.Enrich(context.Background(), "recent.test")
	if !hasSignal(f, "domain_age_under_30d", enricher.SeverityHigh) {
		t.Errorf("expected HIGH for <30d domain; got %+v", f.RiskSignals)
	}
}

func TestRDAP_OldDomain_NoSignal(t *testing.T) {
	srv := fixtureServer(t, 200, rdapFixture(365*24*time.Hour, nil))
	defer srv.Close()

	s := NewWithEndpoint(srv.URL + "/")
	f, _ := s.Enrich(context.Background(), "old.test")
	if len(f.RiskSignals) != 0 {
		t.Errorf("old domain should have no signals; got %+v", f.RiskSignals)
	}
}

func TestRDAP_SuspiciousStatus(t *testing.T) {
	srv := fixtureServer(t, 200, rdapFixture(365*24*time.Hour, []string{"clientHold"}))
	defer srv.Close()

	s := NewWithEndpoint(srv.URL + "/")
	f, _ := s.Enrich(context.Background(), "held.test")
	if !hasSignal(f, "suspicious_domain_status", enricher.SeverityMedium) {
		t.Errorf("expected status signal; got %+v", f.RiskSignals)
	}
}

func TestRDAP_NotFound_Benign(t *testing.T) {
	srv := fixtureServer(t, 404, nil)
	defer srv.Close()

	s := NewWithEndpoint(srv.URL + "/")
	f, err := s.Enrich(context.Background(), "missing.test")
	if err != nil {
		t.Fatalf("404 should not error, got: %v", err)
	}
	if len(f.RiskSignals) != 0 {
		t.Errorf("404 should produce no signals; got %+v", f.RiskSignals)
	}
}

func TestRDAP_5xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	s := NewWithEndpoint(srv.URL + "/")
	_, err := s.Enrich(context.Background(), "d.test")
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Errorf("want 502 error, got %v", err)
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

// compile-time check that Source satisfies enricher.Source
var _ enricher.Source = (*Source)(nil)
