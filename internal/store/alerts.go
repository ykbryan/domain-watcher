package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Alert struct {
	ID                  uuid.UUID
	MonitoredDomainID   uuid.UUID
	PermutationDomain   string
	RiskScore           int
	RiskBand            string
	FindingsSummary     json.RawMessage
	AlertCreatedAt      time.Time
	AlertSentAt         *time.Time
}

type AlertRow struct {
	MonitoredDomainID uuid.UUID
	PermutationDomain string
	RiskScore         int
	RiskBand          string
	FindingsSummary   json.RawMessage
}

type Alerts struct {
	pool *pgxpool.Pool
}

func NewAlerts(p *pgxpool.Pool) *Alerts { return &Alerts{pool: p} }

func (a *Alerts) Insert(ctx context.Context, rows []AlertRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, r := range rows {
		summary := r.FindingsSummary
		if len(summary) == 0 {
			summary = json.RawMessage(`{}`)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO alerts (monitored_domain_id, permutation_domain, risk_score, risk_band, findings_summary)
			VALUES ($1, $2, $3, $4, $5)
		`, r.MonitoredDomainID, r.PermutationDomain, r.RiskScore, r.RiskBand, []byte(summary)); err != nil {
			return fmt.Errorf("insert alert: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// ListByMonitor returns alerts for one monitor, newest first.
func (a *Alerts) ListByMonitor(ctx context.Context, monitorID uuid.UUID, limit int) ([]Alert, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := a.pool.Query(ctx, `
		SELECT id, monitored_domain_id, permutation_domain, risk_score, risk_band,
		       findings_summary, alert_created_at, alert_sent_at
		FROM alerts
		WHERE monitored_domain_id = $1
		ORDER BY alert_created_at DESC
		LIMIT $2
	`, monitorID, limit)
	if err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var al Alert
		var raw []byte
		if err := rows.Scan(&al.ID, &al.MonitoredDomainID, &al.PermutationDomain,
			&al.RiskScore, &al.RiskBand, &raw, &al.AlertCreatedAt, &al.AlertSentAt); err != nil {
			return nil, err
		}
		al.FindingsSummary = json.RawMessage(raw)
		out = append(out, al)
	}
	return out, rows.Err()
}
