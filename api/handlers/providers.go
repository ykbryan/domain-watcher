package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ykbryan/domain-watcher/internal/metrics"
)

// Providers returns a handler that renders the current provider snapshot
// as JSON. The response shape mirrors metrics.Info and is documented in
// openapi.yaml under /api/v1/providers.
func Providers(reg *metrics.Registry, startedAt time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := reg.Snapshot()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"providers":    snap,
			"counters_since": startedAt.UTC().Format(time.RFC3339),
		})
	}
}
