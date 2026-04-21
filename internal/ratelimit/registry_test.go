package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestRegistry_KnownSourcesHaveLimiters(t *testing.T) {
	r := NewSpecRegistry()
	for _, name := range []string{"virustotal", "safebrowsing", "otx", "ipinfo", "abuseipdb", "urlscan"} {
		if _, ok := r[name]; !ok {
			t.Errorf("missing limiter for %q", name)
		}
	}
}

func TestRegistry_UnknownReturnsNoop(t *testing.T) {
	r := NewSpecRegistry()
	l := r.Get("does-not-exist")
	if err := l.Wait(context.Background()); err != nil {
		t.Errorf("noop Wait should not error: %v", err)
	}
}

func TestRegistry_Throttles(t *testing.T) {
	r := NewSpecRegistry()
	l := r.Get("virustotal") // 1 every 15s, burst 1
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	// First call should be instant (token available).
	if err := l.Wait(ctx); err != nil {
		t.Fatalf("first wait: %v", err)
	}
	// Second call should exceed the 100ms ctx because refill is 15s.
	if err := l.Wait(ctx); err == nil {
		t.Error("expected second wait to hit ctx deadline under VT's 15s refill")
	}
}
