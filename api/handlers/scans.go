package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ykbryan/domain-watcher/internal/enricher"
	"github.com/ykbryan/domain-watcher/internal/pipeline"
	"github.com/ykbryan/domain-watcher/internal/resolver"
	"github.com/ykbryan/domain-watcher/internal/store"
)

// ScanStore is the subset of scan_job operations the handler needs.
type ScanStore interface {
	Create(ctx context.Context, target, triggeredBy string) (uuid.UUID, error)
	MarkCompleted(ctx context.Context, id uuid.UUID) error
	MarkFailed(ctx context.Context, id uuid.UUID, msg string) error
}

// ScansConfig tunes quick-scan behavior. Defaults apply when zero.
type ScansConfig struct {
	QuickMaxPerms    int           // cap on permutations for /scans/quick (default 1000)
	QuickTimeout     time.Duration // total budget for /scans/quick (default 30s)
	QuickEnrichTopN  int           // enrich top-N live in /scans/quick (default 20)
	TopInResponse    int           // rows in response.top_live_domains (default 20)
	Resolver         resolver.Config
	EnricherSources  []enricher.Source
	EnricherWorkers  int
	EnricherTimeout  time.Duration
}

type Scans struct {
	cfg      ScansConfig
	jobs     ScanStore
	perms    pipeline.PermStore
	findings pipeline.FindingStore
}

func NewScans(jobs ScanStore, perms pipeline.PermStore, findings pipeline.FindingStore, cfg ScansConfig) *Scans {
	if cfg.QuickMaxPerms <= 0 {
		cfg.QuickMaxPerms = 1000
	}
	if cfg.QuickTimeout <= 0 {
		cfg.QuickTimeout = 30 * time.Second
	}
	if cfg.QuickEnrichTopN <= 0 {
		cfg.QuickEnrichTopN = 20
	}
	if cfg.TopInResponse <= 0 {
		cfg.TopInResponse = 20
	}
	if cfg.EnricherWorkers <= 0 {
		cfg.EnricherWorkers = 10
	}
	if cfg.EnricherTimeout <= 0 {
		cfg.EnricherTimeout = 8 * time.Second
	}
	return &Scans{cfg: cfg, jobs: jobs, perms: perms, findings: findings}
}

type quickRequest struct {
	Domain string `json:"domain"`
}

type quickResponse struct {
	ScanID       string `json:"scan_id"`
	TargetDomain string `json:"target_domain"`
	ElapsedMs    int64  `json:"elapsed_ms"`
	*pipeline.Result
}

// PostQuick handles POST /api/v1/scans/quick. Synchronous; hard-capped
// by QuickTimeout.
func (s *Scans) PostQuick(w http.ResponseWriter, r *http.Request) {
	var req quickRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" || !strings.Contains(domain, ".") {
		writeErr(w, http.StatusBadRequest, "domain required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.QuickTimeout)
	defer cancel()

	jobID, err := s.jobs.Create(ctx, domain, store.TriggeredByAPI)
	if err != nil {
		slog.Error("scan job create failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "could not create scan")
		return
	}

	start := time.Now()
	result, err := pipeline.Run(ctx, jobID, domain, pipeline.Options{
		MaxPerms:          s.cfg.QuickMaxPerms,
		IncludeDictionary: true,
		EnrichTopN:        s.cfg.QuickEnrichTopN,
		TopInResponse:     s.cfg.TopInResponse,
		ResolverCfg:       s.cfg.Resolver,
		Sources:           s.cfg.EnricherSources,
		EnricherWorkers:   s.cfg.EnricherWorkers,
		EnricherTimeout:   s.cfg.EnricherTimeout,
	}, s.perms, s.findings)
	if err != nil {
		_ = s.jobs.MarkFailed(context.Background(), jobID, err.Error())
		slog.Error("quick scan failed", "scan_id", jobID, "err", err)
		status := http.StatusInternalServerError
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		writeErr(w, status, "scan failed")
		return
	}

	if err := s.jobs.MarkCompleted(context.Background(), jobID); err != nil {
		slog.Warn("mark completed failed", "scan_id", jobID, "err", err)
	}

	resp := quickResponse{
		ScanID:       jobID.String(),
		TargetDomain: domain,
		ElapsedMs:    time.Since(start).Milliseconds(),
		Result:       result,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
