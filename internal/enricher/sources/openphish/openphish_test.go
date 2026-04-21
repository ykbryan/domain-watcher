package openphish

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

func feedServer(t *testing.T, urls []string, fetchCount *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fetchCount != nil {
			fetchCount.Add(1)
		}
		_, _ = io.WriteString(w, strings.Join(urls, "\n")+"\n")
	}))
}

func TestOpenPhish_Hit(t *testing.T) {
	srv := feedServer(t, []string{"http://evil.test/login.php", "https://bad.example/index"}, nil)
	defer srv.Close()
	s := NewWithConfig(srv.URL, time.Hour)

	f, err := s.Enrich(context.Background(), "evil.test")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !hasSignal(f, "openphish_match", enricher.SeverityCritical) {
		t.Errorf("expected CRITICAL match, got %+v", f.RiskSignals)
	}
}

func TestOpenPhish_Miss(t *testing.T) {
	srv := feedServer(t, []string{"http://evil.test/login.php"}, nil)
	defer srv.Close()
	s := NewWithConfig(srv.URL, time.Hour)

	f, _ := s.Enrich(context.Background(), "clean.test")
	if len(f.RiskSignals) != 0 {
		t.Errorf("expected no signals, got %+v", f.RiskSignals)
	}
}

func TestOpenPhish_CachesBetweenCalls(t *testing.T) {
	var fetches atomic.Int32
	srv := feedServer(t, []string{"http://evil.test/"}, &fetches)
	defer srv.Close()
	s := NewWithConfig(srv.URL, time.Hour)

	for i := 0; i < 5; i++ {
		_, err := s.Enrich(context.Background(), fmt.Sprintf("d%d.test", i))
		if err != nil {
			t.Fatalf("enrich %d: %v", i, err)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Errorf("expected 1 feed fetch across 5 calls, got %d", got)
	}
}

func TestOpenPhish_RefetchAfterTTL(t *testing.T) {
	var fetches atomic.Int32
	srv := feedServer(t, []string{"http://evil.test/"}, &fetches)
	defer srv.Close()
	s := NewWithConfig(srv.URL, 50*time.Millisecond)

	_, _ = s.Enrich(context.Background(), "a.test")
	time.Sleep(80 * time.Millisecond)
	_, _ = s.Enrich(context.Background(), "b.test")
	if got := fetches.Load(); got != 2 {
		t.Errorf("expected 2 fetches after TTL expiry, got %d", got)
	}
}

func TestOpenPhish_FeedHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := NewWithConfig(srv.URL, time.Hour)
	_, err := s.Enrich(context.Background(), "a.test")
	if err == nil {
		t.Error("expected error from 500 feed")
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
