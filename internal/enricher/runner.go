package enricher

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Runner fans sources out across a worker pool. Every (domain, source) pair
// produces exactly one Finding — errors become Finding.Error rather than
// aborting the batch.
type Runner struct {
	sources []Source
	workers int
	timeout time.Duration
}

func NewRunner(sources []Source, workers int, perSourceTimeout time.Duration) *Runner {
	if workers <= 0 {
		workers = 10
	}
	if perSourceTimeout <= 0 {
		perSourceTimeout = 10 * time.Second
	}
	return &Runner{sources: sources, workers: workers, timeout: perSourceTimeout}
}

// FanOut enriches every domain with every source and returns findings grouped
// by input index: out[i] is the slice of Findings (one per source) for domains[i].
func (r *Runner) FanOut(ctx context.Context, domains []string) [][]Finding {
	out := make([][]Finding, len(domains))
	for i := range out {
		out[i] = make([]Finding, 0, len(r.sources))
	}
	if len(r.sources) == 0 || len(domains) == 0 {
		return out
	}

	var mu sync.Mutex
	sem := make(chan struct{}, r.workers)
	var wg sync.WaitGroup

	for i, domain := range domains {
		for _, src := range r.sources {
			wg.Add(1)
			sem <- struct{}{}
			go func(idx int, domain string, src Source) {
				defer wg.Done()
				defer func() { <-sem }()
				srcCtx, cancel := context.WithTimeout(ctx, r.timeout)
				defer cancel()
				f := r.runOne(srcCtx, src, domain)
				mu.Lock()
				out[idx] = append(out[idx], *f)
				mu.Unlock()
			}(i, domain, src)
		}
	}
	wg.Wait()
	return out
}

func (r *Runner) runOne(ctx context.Context, src Source, domain string) *Finding {
	started := time.Now()
	f, err := src.Enrich(ctx, domain)
	if err != nil {
		if f == nil {
			f = &Finding{}
		}
		f.Error = err.Error()
		slog.Warn("enrichment error", "source", src.Name(), "domain", domain, "err", err)
	}
	if f == nil {
		f = &Finding{}
	}
	if f.SourceName == "" {
		f.SourceName = src.Name()
	}
	if f.FetchedAt.IsZero() {
		f.FetchedAt = started
	}
	return f
}
