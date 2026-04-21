package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FindingRow is the store's input shape for bulk inserting enricher findings.
// Handler marshals enricher.Finding into these rows (JSON encoding happens here
// so the store stays free of enricher imports).
type FindingRow struct {
	PermutationID uuid.UUID
	SourceName    string
	RiskSignals   json.RawMessage // pre-encoded JSON array
	RawData       json.RawMessage // pre-encoded JSON, may be nil
	FetchedAt     time.Time
	Error         string
}

type Findings struct {
	pool *pgxpool.Pool
}

func NewFindings(p *pgxpool.Pool) *Findings { return &Findings{pool: p} }

func (f *Findings) BulkInsert(ctx context.Context, rows []FindingRow) error {
	if len(rows) == 0 {
		return nil
	}
	source := pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
		r := rows[i]
		return []any{
			r.PermutationID,
			r.SourceName,
			nonNilJSON(r.RiskSignals, []byte("[]")),
			nullableJSON(r.RawData),
			r.FetchedAt,
			nullableString(r.Error),
		}, nil
	})
	_, err := f.pool.CopyFrom(ctx, pgx.Identifier{"findings"},
		[]string{"permutation_id", "source_name", "risk_signals", "raw_data", "fetched_at", "error"},
		source)
	if err != nil {
		return fmt.Errorf("copy findings: %w", err)
	}
	return nil
}

// CountBySeverity returns a {severity: count} map across all findings for a
// scan, inspecting the risk_signals JSONB array. Used by /scans/quick summary.
func (f *Findings) CountBySeverity(ctx context.Context, scanJobID uuid.UUID) (map[string]int, error) {
	rows, err := f.pool.Query(ctx, `
		SELECT sig->>'severity' AS severity, COUNT(*)
		FROM findings fi
		JOIN permutations p ON p.id = fi.permutation_id
		CROSS JOIN LATERAL jsonb_array_elements(
			CASE WHEN jsonb_typeof(fi.risk_signals) = 'array'
			     THEN fi.risk_signals
			     ELSE '[]'::jsonb
			END
		) sig
		WHERE p.scan_job_id = $1
		GROUP BY severity
	`, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("count by severity: %w", err)
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		out[sev] = n
	}
	return out, rows.Err()
}

func nonNilJSON(b json.RawMessage, def []byte) []byte {
	if len(b) == 0 {
		return def
	}
	return b
}

func nullableJSON(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return []byte(b)
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
