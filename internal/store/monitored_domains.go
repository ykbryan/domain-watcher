package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type MonitoredDomain struct {
	ID                   uuid.UUID
	Domain               string
	OwnerEmail           *string
	AlertChannels        json.RawMessage // JSONB passthrough
	CheckIntervalMinutes int
	LastCheckedAt        *time.Time
	LastScanID           *uuid.UUID
	CurrentScanID        *uuid.UUID
	CreatedAt            time.Time
}

type MonitoredDomains struct {
	pool *pgxpool.Pool
}

func NewMonitoredDomains(p *pgxpool.Pool) *MonitoredDomains { return &MonitoredDomains{pool: p} }

// Create inserts a new monitored domain. alertChannels must be valid JSON or nil (→ {}).
func (m *MonitoredDomains) Create(ctx context.Context, domain string, ownerEmail string, alertChannels json.RawMessage, intervalMinutes int) (uuid.UUID, error) {
	if len(alertChannels) == 0 {
		alertChannels = json.RawMessage(`{}`)
	}
	var id uuid.UUID
	err := m.pool.QueryRow(ctx, `
		INSERT INTO monitored_domains (domain, owner_email, alert_channels, check_interval_minutes)
		VALUES ($1, NULLIF($2, ''), $3, $4)
		RETURNING id
	`, domain, ownerEmail, []byte(alertChannels), intervalMinutes).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert monitored_domain: %w", err)
	}
	return id, nil
}

func (m *MonitoredDomains) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := m.pool.Exec(ctx, `DELETE FROM monitored_domains WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete monitored_domain: %w", err)
	}
	return nil
}

func (m *MonitoredDomains) Get(ctx context.Context, id uuid.UUID) (*MonitoredDomain, error) {
	row := m.pool.QueryRow(ctx, `
		SELECT id, domain, owner_email, alert_channels, check_interval_minutes,
		       last_checked_at, last_scan_id, current_scan_id, created_at
		FROM monitored_domains WHERE id = $1
	`, id)
	return scanMonitoredDomain(row)
}

func (m *MonitoredDomains) List(ctx context.Context) ([]MonitoredDomain, error) {
	rows, err := m.pool.Query(ctx, `
		SELECT id, domain, owner_email, alert_channels, check_interval_minutes,
		       last_checked_at, last_scan_id, current_scan_id, created_at
		FROM monitored_domains ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	defer rows.Close()
	var out []MonitoredDomain
	for rows.Next() {
		md, err := scanMonitoredDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *md)
	}
	return out, rows.Err()
}

// DueForScan returns monitors whose current_scan_id is NULL and whose
// last_checked_at is either NULL or older than check_interval_minutes.
func (m *MonitoredDomains) DueForScan(ctx context.Context) ([]MonitoredDomain, error) {
	rows, err := m.pool.Query(ctx, `
		SELECT id, domain, owner_email, alert_channels, check_interval_minutes,
		       last_checked_at, last_scan_id, current_scan_id, created_at
		FROM monitored_domains
		WHERE current_scan_id IS NULL
		  AND (last_checked_at IS NULL
		       OR last_checked_at < now() - (check_interval_minutes || ' minutes')::interval)
	`)
	if err != nil {
		return nil, fmt.Errorf("due for scan: %w", err)
	}
	defer rows.Close()
	var out []MonitoredDomain
	for rows.Next() {
		md, err := scanMonitoredDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *md)
	}
	return out, rows.Err()
}

// DueForDiff returns monitors whose current_scan_id points to a completed
// or failed scan — i.e. the scheduler should run the differ and promote.
func (m *MonitoredDomains) DueForDiff(ctx context.Context) ([]MonitoredDomain, error) {
	rows, err := m.pool.Query(ctx, `
		SELECT m.id, m.domain, m.owner_email, m.alert_channels, m.check_interval_minutes,
		       m.last_checked_at, m.last_scan_id, m.current_scan_id, m.created_at
		FROM monitored_domains m
		JOIN scan_jobs s ON s.id = m.current_scan_id
		WHERE s.status IN ('completed', 'failed')
	`)
	if err != nil {
		return nil, fmt.Errorf("due for diff: %w", err)
	}
	defer rows.Close()
	var out []MonitoredDomain
	for rows.Next() {
		md, err := scanMonitoredDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *md)
	}
	return out, rows.Err()
}

// MarkScanning links a monitor to an in-flight scan_job and updates last_checked_at.
func (m *MonitoredDomains) MarkScanning(ctx context.Context, id, scanID uuid.UUID) error {
	_, err := m.pool.Exec(ctx, `
		UPDATE monitored_domains
		SET current_scan_id = $1, last_checked_at = now()
		WHERE id = $2
	`, scanID, id)
	if err != nil {
		return fmt.Errorf("mark scanning: %w", err)
	}
	return nil
}

// PromoteScan moves current_scan_id → last_scan_id. Called after the differ
// has run against this pair.
func (m *MonitoredDomains) PromoteScan(ctx context.Context, id uuid.UUID) error {
	_, err := m.pool.Exec(ctx, `
		UPDATE monitored_domains
		SET last_scan_id = current_scan_id, current_scan_id = NULL
		WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("promote scan: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanMonitoredDomain(r rowScanner) (*MonitoredDomain, error) {
	var md MonitoredDomain
	var raw []byte
	if err := r.Scan(&md.ID, &md.Domain, &md.OwnerEmail, &raw, &md.CheckIntervalMinutes,
		&md.LastCheckedAt, &md.LastScanID, &md.CurrentScanID, &md.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	md.AlertChannels = json.RawMessage(raw)
	return &md, nil
}
