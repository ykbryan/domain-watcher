package certwatch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

func fixtureServer(t *testing.T, body []certEntry) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func cert(hoursAgo int, issuer string) certEntry {
	return certEntry{
		IssuerName:     issuer,
		CommonName:     "test.example",
		NotBefore:      time.Now().Add(-time.Duration(hoursAgo) * time.Hour).Format("2006-01-02T15:04:05"),
		EntryTimestamp: time.Now().Format("2006-01-02T15:04:05.000"),
	}
}

func TestCertwatch_FreshCert_Critical(t *testing.T) {
	srv := fixtureServer(t, []certEntry{cert(2, "DigiCert Inc")})
	defer srv.Close()

	s := NewWithEndpoint(srv.URL + "/")
	f, err := s.Enrich(context.Background(), "x.test")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !hasSignal(f, "cert_issued_under_24h", enricher.SeverityCritical) {
		t.Errorf("expected CRITICAL for <24h cert; got %+v", f.RiskSignals)
	}
}

func TestCertwatch_RecentCert_High(t *testing.T) {
	srv := fixtureServer(t, []certEntry{cert(48, "DigiCert Inc")})
	defer srv.Close()

	s := NewWithEndpoint(srv.URL + "/")
	f, _ := s.Enrich(context.Background(), "x.test")
	if !hasSignal(f, "cert_issued_under_7d", enricher.SeverityHigh) {
		t.Errorf("expected HIGH for <7d cert; got %+v", f.RiskSignals)
	}
}

func TestCertwatch_LetsEncrypt_High(t *testing.T) {
	srv := fixtureServer(t, []certEntry{cert(240, "C=US, O=Let's Encrypt, CN=R10")})
	defer srv.Close()
	s := NewWithEndpoint(srv.URL + "/")
	f, _ := s.Enrich(context.Background(), "x.test")
	if !hasSignal(f, "lets_encrypt_cert", enricher.SeverityHigh) {
		t.Errorf("expected Let's Encrypt signal; got %+v", f.RiskSignals)
	}
}

func TestCertwatch_RapidIssuance(t *testing.T) {
	var certs []certEntry
	for i := 0; i < 12; i++ {
		certs = append(certs, cert(5*24+i, "DigiCert Inc"))
	}
	srv := fixtureServer(t, certs)
	defer srv.Close()
	s := NewWithEndpoint(srv.URL + "/")
	f, _ := s.Enrich(context.Background(), "x.test")
	if !hasSignal(f, "rapid_cert_issuance", enricher.SeverityHigh) {
		t.Errorf("expected rapid issuance signal; got %+v", f.RiskSignals)
	}
}

func TestCertwatch_NoCerts(t *testing.T) {
	srv := fixtureServer(t, []certEntry{})
	defer srv.Close()
	s := NewWithEndpoint(srv.URL + "/")
	f, err := s.Enrich(context.Background(), "x.test")
	if err != nil {
		t.Fatalf("empty array should not error: %v", err)
	}
	if len(f.RiskSignals) != 0 {
		t.Errorf("no certs should produce no signals; got %+v", f.RiskSignals)
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
