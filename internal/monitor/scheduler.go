package monitor

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ykbryan/domain-watcher/internal/store"
)

// MonitorStore is the scheduler's view of monitored_domains.
type MonitorStore interface {
	DueForScan(ctx context.Context) ([]store.MonitoredDomain, error)
	DueForDiff(ctx context.Context) ([]store.MonitoredDomain, error)
	MarkScanning(ctx context.Context, id, scanID uuid.UUID) error
	PromoteScan(ctx context.Context, id uuid.UUID) error
}

// ScanJobStore is what the scheduler needs from scan_jobs.
type ScanJobStore interface {
	CreateQueued(ctx context.Context, target, triggeredBy string) (uuid.UUID, error)
}

// PermReader fetches per-scan permutation results so the differ can compare.
type PermReader interface {
	ListByScan(ctx context.Context, scanJobID uuid.UUID, opts store.ListOptions) ([]store.PermutationResult, int, error)
}

// AlertStore is the sink for new alerts.
type AlertStore interface {
	Insert(ctx context.Context, rows []store.AlertRow) error
}

// Enqueuer hands a scan_id to the worker pool.
type Enqueuer interface {
	Enqueue(scanID uuid.UUID) error
}

type Config struct {
	Tick time.Duration // default 60s
}

type Scheduler struct {
	cfg      Config
	monitors MonitorStore
	jobs     ScanJobStore
	perms    PermReader
	alerts   AlertStore
	pool     Enqueuer

	wg   sync.WaitGroup
	stop chan struct{}
	once sync.Once
}

func New(cfg Config, monitors MonitorStore, jobs ScanJobStore, perms PermReader, alerts AlertStore, pool Enqueuer) *Scheduler {
	if cfg.Tick <= 0 {
		cfg.Tick = 60 * time.Second
	}
	return &Scheduler{
		cfg:      cfg,
		monitors: monitors,
		jobs:     jobs,
		perms:    perms,
		alerts:   alerts,
		pool:     pool,
		stop:     make(chan struct{}),
	}
}

// Start spawns the ticker goroutine. Safe to call once.
func (s *Scheduler) Start(ctx context.Context) {
	s.wg.Add(1)
	go s.loop(ctx)
}

// Shutdown signals the loop to exit and waits up to ctx deadline.
func (s *Scheduler) Shutdown(ctx context.Context) error {
	s.once.Do(func() { close(s.stop) })
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Scheduler) loop(ctx context.Context) {
	defer s.wg.Done()
	t := time.NewTicker(s.cfg.Tick)
	defer t.Stop()
	slog.Info("monitor scheduler started", "tick", s.cfg.Tick.String())

	// Run once immediately so a freshly-started server doesn't wait a full tick.
	s.Pass(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case <-t.C:
			s.Pass(ctx)
		}
	}
}

// Pass runs one scheduler iteration: diff completed scans, then enqueue due scans.
// Exported so tests can drive it directly without a ticker.
func (s *Scheduler) Pass(ctx context.Context) {
	s.diffCompleted(ctx)
	s.enqueueDue(ctx)
}

func (s *Scheduler) diffCompleted(ctx context.Context) {
	monitors, err := s.monitors.DueForDiff(ctx)
	if err != nil {
		slog.Warn("due for diff query failed", "err", err)
		return
	}
	for _, m := range monitors {
		s.diffOne(ctx, m)
	}
}

func (s *Scheduler) diffOne(ctx context.Context, m store.MonitoredDomain) {
	// Always promote at the end so we don't re-diff the same pair.
	defer func() {
		if err := s.monitors.PromoteScan(ctx, m.ID); err != nil {
			slog.Warn("promote scan failed", "monitor", m.ID, "err", err)
		}
	}()

	if m.CurrentScanID == nil {
		return
	}
	current, _, err := s.perms.ListByScan(ctx, *m.CurrentScanID, store.ListOptions{Limit: 200})
	if err != nil {
		slog.Warn("list current scan failed", "monitor", m.ID, "err", err)
		return
	}
	var previous []store.PermutationResult
	if m.LastScanID != nil {
		prev, _, err := s.perms.ListByScan(ctx, *m.LastScanID, store.ListOptions{Limit: 200})
		if err != nil {
			slog.Warn("list previous scan failed", "monitor", m.ID, "err", err)
			return
		}
		previous = prev
	}

	newAlerts := Diff(previous, current)
	if len(newAlerts) == 0 {
		return
	}

	rows := make([]store.AlertRow, 0, len(newAlerts))
	for _, a := range newAlerts {
		summary, _ := json.Marshal(map[string]any{
			"a":  a.DNSA,
			"mx": a.DNSMX,
			"ns": a.DNSNS,
		})
		score := 0
		band := ""
		if a.RiskScore != nil {
			score = *a.RiskScore
		}
		if a.RiskBand != nil {
			band = *a.RiskBand
		}
		rows = append(rows, store.AlertRow{
			MonitoredDomainID: m.ID,
			PermutationDomain: a.Domain,
			RiskScore:         score,
			RiskBand:          band,
			FindingsSummary:   summary,
		})
	}
	if err := s.alerts.Insert(ctx, rows); err != nil {
		slog.Warn("insert alerts failed", "monitor", m.ID, "err", err)
		return
	}
	slog.Info("alerts emitted", "monitor", m.ID, "count", len(rows))
}

func (s *Scheduler) enqueueDue(ctx context.Context) {
	monitors, err := s.monitors.DueForScan(ctx)
	if err != nil {
		slog.Warn("due for scan query failed", "err", err)
		return
	}
	for _, m := range monitors {
		scanID, err := s.jobs.CreateQueued(ctx, m.Domain, store.TriggeredByMonitor)
		if err != nil {
			slog.Warn("create queued scan failed", "monitor", m.ID, "err", err)
			continue
		}
		if err := s.pool.Enqueue(scanID); err != nil {
			slog.Warn("enqueue failed; monitor will retry next tick", "monitor", m.ID, "err", err)
			continue
		}
		if err := s.monitors.MarkScanning(ctx, m.ID, scanID); err != nil {
			slog.Warn("mark scanning failed", "monitor", m.ID, "err", err)
		}
	}
}
