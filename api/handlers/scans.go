package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ykbryan/domain-watcher/internal/permutation"
	"github.com/ykbryan/domain-watcher/internal/resolver"
	"github.com/ykbryan/domain-watcher/internal/store"
)

// ScanStore is the subset of store operations the quick-scan handler needs.
// It exists so tests can fake persistence without a real Postgres.
type ScanStore interface {
	Create(ctx context.Context, target, triggeredBy string) (uuid.UUID, error)
	MarkCompleted(ctx context.Context, id uuid.UUID) error
	MarkFailed(ctx context.Context, id uuid.UUID, msg string) error
}

type PermStore interface {
	BulkInsert(ctx context.Context, scanJobID uuid.UUID, rows []store.PermutationRow) error
}

// ScansConfig tunes quick-scan behavior.
type ScansConfig struct {
	QuickMaxPerms int            // cap on permutations fed through resolver (default 1000)
	QuickTimeout  time.Duration  // total budget for /scans/quick (default 30s)
	TopN          int            // how many live domains to return in response (default 20)
	Resolver      resolver.Config // passed to resolver.New for each scan
}

type Scans struct {
	cfg   ScansConfig
	jobs  ScanStore
	perms PermStore
}

func NewScans(jobs ScanStore, perms PermStore, cfg ScansConfig) *Scans {
	if cfg.QuickMaxPerms <= 0 {
		cfg.QuickMaxPerms = 1000
	}
	if cfg.QuickTimeout <= 0 {
		cfg.QuickTimeout = 30 * time.Second
	}
	if cfg.TopN <= 0 {
		cfg.TopN = 20
	}
	return &Scans{cfg: cfg, jobs: jobs, perms: perms}
}

type quickRequest struct {
	Domain string `json:"domain"`
}

type liveDomainDTO struct {
	Domain string   `json:"domain"`
	A      []string `json:"a,omitempty"`
	MX     []string `json:"mx,omitempty"`
	NS     []string `json:"ns,omitempty"`
}

type quickResponse struct {
	ScanID           string          `json:"scan_id"`
	TargetDomain     string          `json:"target_domain"`
	PermutationCount int             `json:"permutation_count"`
	LiveCount        int             `json:"live_count"`
	TopLiveDomains   []liveDomainDTO `json:"top_live_domains"`
	ElapsedMs        int64           `json:"elapsed_ms"`
}

// PostQuick handles POST /api/v1/scans/quick.
// Synchronous: generate → resolve → persist → respond, all within the timeout.
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
	resp, err := s.runQuick(ctx, jobID, domain)
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
	resp.ElapsedMs = time.Since(start).Milliseconds()

	if err := s.jobs.MarkCompleted(context.Background(), jobID); err != nil {
		slog.Warn("mark completed failed", "scan_id", jobID, "err", err)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Scans) runQuick(ctx context.Context, jobID uuid.UUID, domain string) (*quickResponse, error) {
	perms, err := permutation.Generate(ctx, domain, permutation.Options{
		Max:               s.cfg.QuickMaxPerms,
		IncludeDictionary: true,
	})
	if err != nil {
		return nil, err
	}

	r := resolver.New(s.cfg.Resolver)
	results := r.Resolve(ctx, perms)

	rows := make([]store.PermutationRow, 0, len(results))
	for _, res := range results {
		rows = append(rows, store.PermutationRow{
			Domain: res.Domain,
			DNSA:   ipsToStrings(res.A),
			DNSMX:  res.MX,
			DNSNS:  res.NS,
			IsLive: res.IsLive,
		})
	}
	if err := s.perms.BulkInsert(ctx, jobID, rows); err != nil {
		return nil, err
	}

	live := resolver.LiveOnly(results)
	top := live
	if len(top) > s.cfg.TopN {
		top = top[:s.cfg.TopN]
	}
	topDTO := make([]liveDomainDTO, 0, len(top))
	for _, t := range top {
		topDTO = append(topDTO, liveDomainDTO{
			Domain: t.Domain,
			A:      ipsToStrings(t.A),
			MX:     t.MX,
			NS:     t.NS,
		})
	}

	return &quickResponse{
		ScanID:           jobID.String(),
		TargetDomain:     domain,
		PermutationCount: len(perms),
		LiveCount:        len(live),
		TopLiveDomains:   topDTO,
	}, nil
}

func ipsToStrings(ips []net.IP) []string {
	if len(ips) == 0 {
		return nil
	}
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
