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

	"github.com/ykbryan/domain-watcher/internal/enricher"
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
	BulkInsert(ctx context.Context, scanJobID uuid.UUID, rows []store.PermutationRow) ([]uuid.UUID, error)
}

type FindingStore interface {
	BulkInsert(ctx context.Context, rows []store.FindingRow) error
}

// ScansConfig tunes quick-scan behavior.
type ScansConfig struct {
	QuickMaxPerms int             // cap on permutations fed through resolver (default 1000)
	QuickTimeout  time.Duration   // total budget for /scans/quick (default 30s)
	TopN          int             // how many live domains to return AND enrich (default 20)
	Resolver      resolver.Config // passed to resolver.New for each scan
	Enricher      EnricherConfig  // enrichment options; if nil Sources, skipped
}

// EnricherConfig configures the enrichment fan-out step.
type EnricherConfig struct {
	Sources          []enricher.Source
	Workers          int
	PerSourceTimeout time.Duration
}

type Scans struct {
	cfg      ScansConfig
	jobs     ScanStore
	perms    PermStore
	findings FindingStore
}

func NewScans(jobs ScanStore, perms PermStore, findings FindingStore, cfg ScansConfig) *Scans {
	if cfg.QuickMaxPerms <= 0 {
		cfg.QuickMaxPerms = 1000
	}
	if cfg.QuickTimeout <= 0 {
		cfg.QuickTimeout = 30 * time.Second
	}
	if cfg.TopN <= 0 {
		cfg.TopN = 20
	}
	if cfg.Enricher.Workers <= 0 {
		cfg.Enricher.Workers = 10
	}
	if cfg.Enricher.PerSourceTimeout <= 0 {
		cfg.Enricher.PerSourceTimeout = 8 * time.Second
	}
	return &Scans{cfg: cfg, jobs: jobs, perms: perms, findings: findings}
}

type quickRequest struct {
	Domain string `json:"domain"`
}

type liveDomainDTO struct {
	Domain      string                `json:"domain"`
	A           []string              `json:"a,omitempty"`
	MX          []string              `json:"mx,omitempty"`
	NS          []string              `json:"ns,omitempty"`
	RiskSignals []enricher.RiskSignal `json:"risk_signals,omitempty"`
}

type quickResponse struct {
	ScanID              string          `json:"scan_id"`
	TargetDomain        string          `json:"target_domain"`
	PermutationCount    int             `json:"permutation_count"`
	LiveCount           int             `json:"live_count"`
	EnrichedCount       int             `json:"enriched_count"`
	FindingsBySeverity  map[string]int  `json:"findings_by_severity"`
	TopLiveDomains      []liveDomainDTO `json:"top_live_domains"`
	ElapsedMs           int64           `json:"elapsed_ms"`
}

// PostQuick handles POST /api/v1/scans/quick.
// Pipeline: generate → resolve → persist perms → enrich top-N live → persist
// findings → respond. All within QuickTimeout.
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

	rv := resolver.New(s.cfg.Resolver)
	results := rv.Resolve(ctx, perms)

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
	permIDs, err := s.perms.BulkInsert(ctx, jobID, rows)
	if err != nil {
		return nil, err
	}

	// live indices (into results / permIDs)
	var liveIdx []int
	for i, res := range results {
		if res.IsLive {
			liveIdx = append(liveIdx, i)
		}
	}

	topIdx := liveIdx
	if len(topIdx) > s.cfg.TopN {
		topIdx = topIdx[:s.cfg.TopN]
	}

	// Enrich top-N live domains.
	findingsByDomain := map[string][]enricher.Finding{}
	severityCounts := map[string]int{}
	if len(s.cfg.Enricher.Sources) > 0 && len(topIdx) > 0 {
		runner := enricher.NewRunner(s.cfg.Enricher.Sources, s.cfg.Enricher.Workers, s.cfg.Enricher.PerSourceTimeout)
		topDomains := make([]string, len(topIdx))
		for i, idx := range topIdx {
			topDomains[i] = results[idx].Domain
		}
		batch := runner.FanOut(ctx, topDomains)

		findingRows := make([]store.FindingRow, 0, len(batch)*len(s.cfg.Enricher.Sources))
		for i, findings := range batch {
			permID := permIDs[topIdx[i]]
			findingsByDomain[topDomains[i]] = findings
			for _, f := range findings {
				for _, sig := range f.RiskSignals {
					severityCounts[string(sig.Severity)]++
				}
				row, err := toFindingRow(permID, f)
				if err != nil {
					slog.Warn("skipping finding encode", "err", err)
					continue
				}
				findingRows = append(findingRows, row)
			}
		}
		if err := s.findings.BulkInsert(ctx, findingRows); err != nil {
			return nil, err
		}
	}

	topDTO := make([]liveDomainDTO, 0, len(topIdx))
	for _, idx := range topIdx {
		res := results[idx]
		dto := liveDomainDTO{
			Domain: res.Domain,
			A:      ipsToStrings(res.A),
			MX:     res.MX,
			NS:     res.NS,
		}
		for _, f := range findingsByDomain[res.Domain] {
			dto.RiskSignals = append(dto.RiskSignals, f.RiskSignals...)
		}
		topDTO = append(topDTO, dto)
	}

	return &quickResponse{
		ScanID:             jobID.String(),
		TargetDomain:       domain,
		PermutationCount:   len(perms),
		LiveCount:          len(liveIdx),
		EnrichedCount:      len(topIdx),
		FindingsBySeverity: severityCounts,
		TopLiveDomains:     topDTO,
	}, nil
}

func toFindingRow(permID uuid.UUID, f enricher.Finding) (store.FindingRow, error) {
	signals, err := json.Marshal(f.RiskSignals)
	if err != nil {
		return store.FindingRow{}, err
	}
	var raw json.RawMessage
	if f.RawData != nil {
		b, err := json.Marshal(f.RawData)
		if err != nil {
			return store.FindingRow{}, err
		}
		raw = b
	}
	return store.FindingRow{
		PermutationID: permID,
		SourceName:    f.SourceName,
		RiskSignals:   signals,
		RawData:       raw,
		FetchedAt:     f.FetchedAt,
		Error:         f.Error,
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
