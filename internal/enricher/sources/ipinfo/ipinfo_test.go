package ipinfo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

func TestIPInfo_NilWithoutToken(t *testing.T) {
	if s := New("", nil); s != nil {
		t.Error("expected nil without token")
	}
}

func fixtureServer(t *testing.T, info ipInfo) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "tok" {
			t.Errorf("missing token: %q", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(info)
	}))
}

// Uses "localhost" which reliably resolves to 127.0.0.1 — avoids mocking net.LookupIP.
func TestIPInfo_BulletproofASN_High(t *testing.T) {
	srv := fixtureServer(t, ipInfo{IP: "127.0.0.1", Org: "AS49870 Alsycon BV"})
	defer srv.Close()
	s := NewWithEndpoint(srv.URL+"/", "tok", nil)
	f, err := s.Enrich(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !hasSignal(f, "hosted_on_bulletproof_asn", enricher.SeverityHigh) {
		t.Errorf("expected HIGH bulletproof signal, got %+v", f.RiskSignals)
	}
}

func TestIPInfo_PrivacyHost_Medium(t *testing.T) {
	srv := fixtureServer(t, ipInfo{IP: "127.0.0.1", Org: "AS12345 Anonymous VPN Services"})
	defer srv.Close()
	s := NewWithEndpoint(srv.URL+"/", "tok", nil)
	f, _ := s.Enrich(context.Background(), "localhost")
	if !hasSignal(f, "hosted_on_privacy_service", enricher.SeverityMedium) {
		t.Errorf("expected MEDIUM privacy signal, got %+v", f.RiskSignals)
	}
}

func TestIPInfo_Clean(t *testing.T) {
	srv := fixtureServer(t, ipInfo{IP: "127.0.0.1", Org: "AS15169 Google LLC"})
	defer srv.Close()
	s := NewWithEndpoint(srv.URL+"/", "tok", nil)
	f, _ := s.Enrich(context.Background(), "localhost")
	if len(f.RiskSignals) != 0 {
		t.Errorf("expected no signals, got %+v", f.RiskSignals)
	}
}

func TestIPInfo_UnresolvableDomain(t *testing.T) {
	srv := fixtureServer(t, ipInfo{})
	defer srv.Close()
	s := NewWithEndpoint(srv.URL+"/", "tok", nil)
	f, err := s.Enrich(context.Background(), "this-domain-will-never-resolve.invalid")
	if err != nil {
		t.Fatalf("should not error on NXDOMAIN, got: %v", err)
	}
	if len(f.RiskSignals) != 0 {
		t.Errorf("no signals expected for unresolvable domain")
	}
}

func TestAsnOf(t *testing.T) {
	cases := map[string]string{
		"AS15169 Google LLC":    "AS15169",
		"Hetzner Online GmbH":   "",
		"":                      "",
		"AS49870 Alsycon BV":    "AS49870",
	}
	for in, want := range cases {
		if got := asnOf(in); got != want {
			t.Errorf("asnOf(%q) = %q; want %q", in, got, want)
		}
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
var _ = strings.Contains
