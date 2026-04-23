// Package metrics records per-provider enrichment counters. Values are
// in-memory only — they reset on process restart — and are exposed via
// the /api/v1/providers endpoint for operational transparency.
//
// Concurrency: every public method is safe to call from multiple
// goroutines. Write paths take a per-provider lock; Snapshot takes the
// registry's read lock and each provider's lock in turn.
package metrics

import (
	"sort"
	"sync"
	"time"
)

// Info is the public snapshot of one provider's metadata + counters.
type Info struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Category       string    `json:"category"`
	KeyConfigured  bool      `json:"key_configured"`
	CallCount      int64     `json:"call_count"`
	ErrorCount     int64     `json:"error_count"`
	LastCallAt     time.Time `json:"last_call_at,omitempty"`
	LastErrorAt    time.Time `json:"last_error_at,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	LastDurationMs int64     `json:"last_duration_ms"`
}

type entry struct {
	mu   sync.Mutex
	info Info
}

// Registry is a process-wide in-memory metrics store keyed on the
// slug that each enricher.Source returns from Name(). The slug is the
// stable identifier; Info.Name is the human-readable display label.
type Registry struct {
	mu   sync.RWMutex
	byID map[string]*entry
}

// NewRegistry returns an empty registry. Providers must be registered
// via Register before Record will track them.
func NewRegistry() *Registry {
	return &Registry{byID: make(map[string]*entry)}
}

// Register adds or updates a provider's static metadata keyed on ID.
// Counters for an existing entry are preserved.
func (r *Registry) Register(info Info) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byID[info.ID]
	if !ok {
		r.byID[info.ID] = &entry{info: info}
		return
	}
	e.mu.Lock()
	e.info.Name = info.Name
	e.info.Category = info.Category
	e.info.KeyConfigured = info.KeyConfigured
	e.mu.Unlock()
}

// Record matches the enricher.MetricsRecorder interface. The first
// argument is the slug from Source.Name() — identical to the Info.ID
// the provider was registered under. Unknown slugs are a no-op.
func (r *Registry) Record(id string, durationMs int64, err error) {
	r.mu.RLock()
	e, ok := r.byID[id]
	r.mu.RUnlock()
	if !ok {
		return
	}
	now := time.Now().UTC()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.info.CallCount++
	e.info.LastCallAt = now
	e.info.LastDurationMs = durationMs
	if err != nil {
		e.info.ErrorCount++
		e.info.LastErrorAt = now
		msg := err.Error()
		const cap = 240
		if len(msg) > cap {
			msg = msg[:cap] + "…"
		}
		e.info.LastError = msg
	}
}

// Snapshot returns a copy of all provider stats, ordered by Name.
func (r *Registry) Snapshot() []Info {
	r.mu.RLock()
	entries := make([]*entry, 0, len(r.byID))
	for _, e := range r.byID {
		entries = append(entries, e)
	}
	r.mu.RUnlock()

	out := make([]Info, 0, len(entries))
	for _, e := range entries {
		e.mu.Lock()
		out = append(out, e.info)
		e.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
