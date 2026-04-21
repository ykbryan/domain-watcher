// Package worker runs queued scan jobs on an in-process goroutine pool.
// Enqueue returns immediately; workers drain the queue and invoke the
// shared pipeline to generate→resolve→enrich→score each job.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ykbryan/domain-watcher/internal/pipeline"
	"github.com/ykbryan/domain-watcher/internal/store"
)

// ErrQueueFull is returned by Enqueue when the buffered queue has no capacity.
var ErrQueueFull = errors.New("scan queue full")

// JobStore is the subset of scan_jobs operations workers need.
// store.ScanJobs satisfies this.
type JobStore interface {
	MarkRunning(ctx context.Context, id uuid.UUID) error
	MarkCompleted(ctx context.Context, id uuid.UUID) error
	MarkFailed(ctx context.Context, id uuid.UUID, msg string) error
	Get(ctx context.Context, id uuid.UUID) (*store.ScanJob, error)
}

// Config tunes pool behavior.
type Config struct {
	Workers   int           // default 3
	QueueSize int           // default 100
	JobBudget time.Duration // per-scan timeout (default 120s, i.e. SCAN_TIMEOUT_SECONDS)
}

// Pool is a fixed-size worker pool that runs pipeline.Run per job.
type Pool struct {
	cfg          Config
	jobs         JobStore
	perms        pipeline.PermStore
	findings     pipeline.FindingStore
	pipelineOpts pipeline.Options

	queue chan uuid.UUID
	wg    sync.WaitGroup
	once  sync.Once
	done  chan struct{}
}

func New(cfg Config, jobs JobStore, perms pipeline.PermStore, findings pipeline.FindingStore, opts pipeline.Options) *Pool {
	if cfg.Workers <= 0 {
		cfg.Workers = 3
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 100
	}
	if cfg.JobBudget <= 0 {
		cfg.JobBudget = 120 * time.Second
	}
	return &Pool{
		cfg:          cfg,
		jobs:         jobs,
		perms:        perms,
		findings:     findings,
		pipelineOpts: opts,
		queue:        make(chan uuid.UUID, cfg.QueueSize),
		done:         make(chan struct{}),
	}
}

// Start spawns Workers goroutines. Safe to call once. Workers exit when the
// queue closes (via Shutdown).
func (p *Pool) Start(ctx context.Context) {
	for i := 0; i < p.cfg.Workers; i++ {
		p.wg.Add(1)
		go p.worker(ctx, i)
	}
}

// Enqueue non-blockingly submits a scan_job for processing. Returns
// ErrQueueFull if the channel is saturated.
func (p *Pool) Enqueue(scanID uuid.UUID) error {
	select {
	case p.queue <- scanID:
		return nil
	default:
		return ErrQueueFull
	}
}

// Shutdown closes the queue and waits for workers to finish their current
// job, up to ctx deadline. Further Enqueue calls after Shutdown will panic.
func (p *Pool) Shutdown(ctx context.Context) error {
	p.once.Do(func() {
		close(p.queue)
	})
	waited := make(chan struct{})
	go func() { p.wg.Wait(); close(waited) }()
	select {
	case <-waited:
		close(p.done)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Pool) worker(parentCtx context.Context, n int) {
	defer p.wg.Done()
	log := slog.With("worker", n)
	log.Info("worker started")
	for scanID := range p.queue {
		p.runJob(parentCtx, scanID, log)
	}
	log.Info("worker stopped")
}

func (p *Pool) runJob(parentCtx context.Context, scanID uuid.UUID, log *slog.Logger) {
	// Look up the domain under a short ctx so we never block forever here.
	lookupCtx, lookupCancel := context.WithTimeout(parentCtx, 5*time.Second)
	job, err := p.jobs.Get(lookupCtx, scanID)
	lookupCancel()
	if err != nil {
		log.Error("job lookup failed", "scan_id", scanID, "err", err)
		return
	}
	if job.Status == store.ScanStatusCompleted || job.Status == store.ScanStatusFailed {
		log.Info("job already terminal; skipping", "scan_id", scanID, "status", job.Status)
		return
	}

	if err := p.jobs.MarkRunning(parentCtx, scanID); err != nil {
		log.Warn("mark running failed", "scan_id", scanID, "err", err)
	}

	jobCtx, cancel := context.WithTimeout(parentCtx, p.cfg.JobBudget)
	defer cancel()

	log.Info("scan started", "scan_id", scanID, "domain", job.TargetDomain)
	start := time.Now()
	_, err = pipeline.Run(jobCtx, scanID, job.TargetDomain, p.pipelineOpts, p.perms, p.findings)
	elapsed := time.Since(start)
	if err != nil {
		log.Error("scan failed", "scan_id", scanID, "err", err, "elapsed_ms", elapsed.Milliseconds())
		_ = p.jobs.MarkFailed(context.Background(), scanID, err.Error())
		return
	}
	if err := p.jobs.MarkCompleted(context.Background(), scanID); err != nil {
		log.Warn("mark completed failed", "scan_id", scanID, "err", err)
	}
	log.Info("scan completed", "scan_id", scanID, "elapsed_ms", elapsed.Milliseconds())
}
