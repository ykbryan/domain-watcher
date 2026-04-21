// Package pipeline runs the core scan pipeline (generate → resolve →
// persist → enrich → score → persist findings → update scores).
//
// It is shared by the synchronous /scans/quick handler and the async
// worker pool so the two paths never diverge.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/ykbryan/domain-watcher/internal/enricher"
	"github.com/ykbryan/domain-watcher/internal/permutation"
	"github.com/ykbryan/domain-watcher/internal/resolver"
	"github.com/ykbryan/domain-watcher/internal/scorer"
	"github.com/ykbryan/domain-watcher/internal/store"
)

// PermStore is the subset of store operations the pipeline needs for
// permutation rows. store.Permutations satisfies this.
type PermStore interface {
	BulkInsert(ctx context.Context, scanJobID uuid.UUID, rows []store.PermutationRow) ([]uuid.UUID, error)
	UpdateScores(ctx context.Context, updates []store.ScoreUpdate) error
}

// FindingStore is the subset of store operations for findings.
// store.Findings satisfies this.
type FindingStore interface {
	BulkInsert(ctx context.Context, rows []store.FindingRow) error
}

// Options controls pipeline behavior.
type Options struct {
	MaxPerms          int             // cap on permutations; 0 = no cap
	IncludeDictionary bool            // pass-through to permutation.Generate
	EnrichTopN        int             // 0 = enrich every live domain
	TopInResponse     int             // size of Result.TopLiveDomains; 0 = 20
	ResolverCfg       resolver.Config // for resolver.New
	Sources           []enricher.Source
	EnricherWorkers   int           // 0 = 10
	EnricherTimeout   time.Duration // 0 = 8s
}

// LiveDomain is one live permutation in the Result, with scoring if enriched.
type LiveDomain struct {
	Domain      string                `json:"domain"`
	A           []string              `json:"a,omitempty"`
	MX          []string              `json:"mx,omitempty"`
	NS          []string              `json:"ns,omitempty"`
	RiskScore   int                   `json:"risk_score"`
	RiskBand    string                `json:"risk_band"`
	RiskSignals []enricher.RiskSignal `json:"risk_signals,omitempty"`
}

// Result is what Run returns; handlers shape it into HTTP responses.
type Result struct {
	PermutationCount   int            `json:"permutation_count"`
	LiveCount          int            `json:"live_count"`
	EnrichedCount      int            `json:"enriched_count"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	AggregateScore     int            `json:"aggregate_score"`
	AggregateBand      string         `json:"aggregate_band"`
	TopLiveDomains     []LiveDomain   `json:"top_live_domains"`
}

// Run executes the full scan pipeline for one domain against one scan job.
// The caller is responsible for marking the scan_job as running/completed/failed.
func Run(ctx context.Context, jobID uuid.UUID, domain string, opts Options, perms PermStore, findings FindingStore) (*Result, error) {
	if opts.TopInResponse <= 0 {
		opts.TopInResponse = 20
	}

	list, err := permutation.Generate(ctx, domain, permutation.Options{
		Max:               opts.MaxPerms,
		IncludeDictionary: opts.IncludeDictionary,
	})
	if err != nil {
		return nil, fmt.Errorf("generate: %w", err)
	}

	rv := resolver.New(opts.ResolverCfg)
	results := rv.Resolve(ctx, list)

	rows := make([]store.PermutationRow, len(results))
	for i, res := range results {
		rows[i] = store.PermutationRow{
			Domain: res.Domain,
			DNSA:   ipsToStrings(res.A),
			DNSMX:  res.MX,
			DNSNS:  res.NS,
			IsLive: res.IsLive,
		}
	}
	permIDs, err := perms.BulkInsert(ctx, jobID, rows)
	if err != nil {
		return nil, fmt.Errorf("persist permutations: %w", err)
	}

	// Build index of live domains in result order.
	var liveIdx []int
	for i, res := range results {
		if res.IsLive {
			liveIdx = append(liveIdx, i)
		}
	}

	enrichIdx := liveIdx
	if opts.EnrichTopN > 0 && len(enrichIdx) > opts.EnrichTopN {
		enrichIdx = enrichIdx[:opts.EnrichTopN]
	}

	findingsByIdx := make(map[int][]enricher.Finding, len(enrichIdx))
	severityCounts := map[string]int{}

	if len(opts.Sources) > 0 && len(enrichIdx) > 0 {
		runner := enricher.NewRunner(opts.Sources, opts.EnricherWorkers, opts.EnricherTimeout)
		domains := make([]string, len(enrichIdx))
		for i, idx := range enrichIdx {
			domains[i] = results[idx].Domain
		}
		batch := runner.FanOut(ctx, domains)

		findingRows := make([]store.FindingRow, 0, len(batch)*len(opts.Sources))
		for i, fs := range batch {
			findingsByIdx[enrichIdx[i]] = fs
			for _, f := range fs {
				for _, sig := range f.RiskSignals {
					severityCounts[string(sig.Severity)]++
				}
				row, err := toFindingRow(permIDs[enrichIdx[i]], f)
				if err != nil {
					slog.Warn("skipping finding encode", "err", err)
					continue
				}
				findingRows = append(findingRows, row)
			}
		}
		if err := findings.BulkInsert(ctx, findingRows); err != nil {
			return nil, fmt.Errorf("persist findings: %w", err)
		}
	}

	// Score each enriched domain, collect score updates for DB.
	type scoredDomain struct {
		idx   int
		score int
		band  scorer.Band
	}
	scored := make([]scoredDomain, 0, len(enrichIdx))
	updates := make([]store.ScoreUpdate, 0, len(enrichIdx))
	aggregate := 0

	for _, idx := range enrichIdx {
		res := results[idx]
		s, band := scorer.Score(scorer.Inputs{
			Findings: findingsByIdx[idx],
			HasMX:    len(res.MX) > 0,
			IsLive:   res.IsLive,
		})
		scored = append(scored, scoredDomain{idx: idx, score: s, band: band})
		updates = append(updates, store.ScoreUpdate{ID: permIDs[idx], Score: s, Band: string(band)})
		if s > aggregate {
			aggregate = s
		}
	}
	if len(updates) > 0 {
		if err := perms.UpdateScores(ctx, updates); err != nil {
			return nil, fmt.Errorf("update scores: %w", err)
		}
	}

	// TopLiveDomains: sort scored by score DESC, take opts.TopInResponse.
	sort.Slice(scored, func(i, j int) bool { return scored[i].score > scored[j].score })
	topN := opts.TopInResponse
	if topN > len(scored) {
		topN = len(scored)
	}
	top := make([]LiveDomain, 0, topN)
	for _, sd := range scored[:topN] {
		res := results[sd.idx]
		ld := LiveDomain{
			Domain:    res.Domain,
			A:         ipsToStrings(res.A),
			MX:        res.MX,
			NS:        res.NS,
			RiskScore: sd.score,
			RiskBand:  string(sd.band),
		}
		for _, f := range findingsByIdx[sd.idx] {
			ld.RiskSignals = append(ld.RiskSignals, f.RiskSignals...)
		}
		top = append(top, ld)
	}

	return &Result{
		PermutationCount:   len(list),
		LiveCount:          len(liveIdx),
		EnrichedCount:      len(enrichIdx),
		FindingsBySeverity: severityCounts,
		AggregateScore:     aggregate,
		AggregateBand:      string(scorer.BandFor(aggregate)),
		TopLiveDomains:     top,
	}, nil
}

func toFindingRow(permID uuid.UUID, f enricher.Finding) (store.FindingRow, error) {
	// Force an empty JSON array rather than null — the findings.risk_signals
	// column is NOT NULL with DEFAULT '[]'::jsonb, and report queries do
	// jsonb_array_elements() over it, which fails on null/scalar.
	signalsSlice := f.RiskSignals
	if signalsSlice == nil {
		signalsSlice = []enricher.RiskSignal{}
	}
	signals, err := json.Marshal(signalsSlice)
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
