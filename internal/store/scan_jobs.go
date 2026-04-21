package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ScanJob struct {
	ID           uuid.UUID
	TargetDomain string
	Status       string
	TriggeredBy  string
	CreatedAt    time.Time
	CompletedAt  *time.Time
	Error        *string
}

const (
	ScanStatusQueued    = "queued"
	ScanStatusRunning   = "running"
	ScanStatusCompleted = "completed"
	ScanStatusFailed    = "failed"

	TriggeredByAPI     = "api"
	TriggeredByMonitor = "monitor"
	TriggeredByCLI     = "cli"
)

type ScanJobs struct {
	pool *pgxpool.Pool
}

func NewScanJobs(p *pgxpool.Pool) *ScanJobs { return &ScanJobs{pool: p} }

// Create inserts a new scan_jobs row in 'running' state and returns its ID.
// Used by synchronous scans where work begins immediately.
func (s *ScanJobs) Create(ctx context.Context, target, triggeredBy string) (uuid.UUID, error) {
	return s.insert(ctx, target, ScanStatusRunning, triggeredBy)
}

// CreateQueued inserts a new scan_jobs row in 'queued' state and returns its ID.
// Used by async scans; the worker calls MarkRunning when it picks the job up.
func (s *ScanJobs) CreateQueued(ctx context.Context, target, triggeredBy string) (uuid.UUID, error) {
	return s.insert(ctx, target, ScanStatusQueued, triggeredBy)
}

func (s *ScanJobs) insert(ctx context.Context, target, status, triggeredBy string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO scan_jobs (target_domain, status, triggered_by)
		VALUES ($1, $2, $3)
		RETURNING id
	`, target, status, triggeredBy).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert scan_job: %w", err)
	}
	return id, nil
}

func (s *ScanJobs) MarkRunning(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scan_jobs SET status = $1 WHERE id = $2
	`, ScanStatusRunning, id)
	if err != nil {
		return fmt.Errorf("mark running: %w", err)
	}
	return nil
}

func (s *ScanJobs) MarkCompleted(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scan_jobs SET status = $1, completed_at = now() WHERE id = $2
	`, ScanStatusCompleted, id)
	if err != nil {
		return fmt.Errorf("mark completed: %w", err)
	}
	return nil
}

func (s *ScanJobs) MarkFailed(ctx context.Context, id uuid.UUID, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scan_jobs SET status = $1, completed_at = now(), error = $2 WHERE id = $3
	`, ScanStatusFailed, errMsg, id)
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	return nil
}

func (s *ScanJobs) Get(ctx context.Context, id uuid.UUID) (*ScanJob, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, target_domain, status, triggered_by, created_at, completed_at, error
		FROM scan_jobs WHERE id = $1
	`, id)
	var j ScanJob
	if err := row.Scan(&j.ID, &j.TargetDomain, &j.Status, &j.TriggeredBy, &j.CreatedAt, &j.CompletedAt, &j.Error); err != nil {
		return nil, fmt.Errorf("get scan_job: %w", err)
	}
	return &j, nil
}
