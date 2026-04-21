package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PermutationRow is the store's input shape — handler translates resolver.Result
// into these rows to keep the store free of resolver imports.
type PermutationRow struct {
	Domain string
	DNSA   []string
	DNSMX  []string
	DNSNS  []string
	IsLive bool
}

type Permutations struct {
	pool *pgxpool.Pool
}

func NewPermutations(p *pgxpool.Pool) *Permutations { return &Permutations{pool: p} }

// BulkInsert writes all rows for a scan in one COPY batch.
func (p *Permutations) BulkInsert(ctx context.Context, scanJobID uuid.UUID, rows []PermutationRow) error {
	if len(rows) == 0 {
		return nil
	}
	source := pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
		r := rows[i]
		return []any{scanJobID, r.Domain, nilToEmpty(r.DNSA), nilToEmpty(r.DNSMX), nilToEmpty(r.DNSNS), r.IsLive}, nil
	})
	_, err := p.pool.CopyFrom(ctx, pgx.Identifier{"permutations"},
		[]string{"scan_job_id", "domain", "dns_a", "dns_mx", "dns_ns", "is_live"},
		source)
	if err != nil {
		return fmt.Errorf("copy permutations: %w", err)
	}
	return nil
}

// nilToEmpty converts a nil slice to an empty slice so COPY FROM populates
// the column with {} rather than NULL (which would violate NOT NULL).
func nilToEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// CountByScan returns (total, live) permutation counts for a scan.
func (p *Permutations) CountByScan(ctx context.Context, scanJobID uuid.UUID) (total, live int, err error) {
	row := p.pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE is_live = TRUE)
		FROM permutations WHERE scan_job_id = $1
	`, scanJobID)
	if err := row.Scan(&total, &live); err != nil {
		return 0, 0, fmt.Errorf("count permutations: %w", err)
	}
	return total, live, nil
}
