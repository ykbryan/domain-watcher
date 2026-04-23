// Package ratelimit holds one token-bucket per enricher source so that
// all goroutines enriching the same source share a budget.
package ratelimit

import (
	"context"
	"time"

	"golang.org/x/time/rate"
)

// Limiter blocks until a token is available or ctx cancels.
type Limiter interface {
	Wait(ctx context.Context) error
}

// Registry is a fixed lookup of limiters by source name. It's a tiny wrapper
// rather than an abstraction — main.go constructs it once at startup and
// each source reads its own limiter in its HTTP client.
type Registry map[string]Limiter

// NewSpecRegistry returns limiters sized to the per-source caps documented
// in the spec. Sources whose keys are absent at startup simply won't ask
// their limiter — there's no harm in leaving unused entries.
func NewSpecRegistry() Registry {
	return Registry{
		"virustotal":   rate.NewLimiter(rate.Every(15*time.Second), 1), // 4/min
		"safebrowsing": rate.NewLimiter(rate.Every(100*time.Millisecond), 5),
		"otx":          rate.NewLimiter(rate.Every(100*time.Millisecond), 1),
		"ipinfo":       rate.NewLimiter(rate.Every(50*time.Millisecond), 10), // 50K/mo
		"abuseipdb":    rate.NewLimiter(rate.Every(time.Second), 1),          // 1K/day via ~60/min cap
		"urlscan":      rate.NewLimiter(rate.Every(2*time.Second), 1),        // 100/day search-only
		"pdns":         rate.NewLimiter(rate.Every(time.Second), 1),          // CIRCL PDNS, polite default
		"censys":       rate.NewLimiter(rate.Every(30*time.Second), 1),       // free tier is 250/mo
	}
}

// Get returns a no-op limiter for unknown sources so callers don't have to
// branch on "is this source rate-limited?".
func (r Registry) Get(name string) Limiter {
	if l, ok := r[name]; ok {
		return l
	}
	return noop{}
}

type noop struct{}

func (noop) Wait(context.Context) error { return nil }
