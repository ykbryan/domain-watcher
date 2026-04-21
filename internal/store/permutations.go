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

// BulkInsert writes all rows for a scan in one COPY batch and returns the
// generated UUIDs in the same order as input. Callers need these IDs to
// attach subsequent findings.
func (p *Permutations) BulkInsert(ctx context.Context, scanJobID uuid.UUID, rows []PermutationRow) ([]uuid.UUID, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	ids := make([]uuid.UUID, len(rows))
	for i := range ids {
		ids[i] = uuid.New()
	}
	source := pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
		r := rows[i]
		return []any{ids[i], scanJobID, r.Domain, nilToEmpty(r.DNSA), nilToEmpty(r.DNSMX), nilToEmpty(r.DNSNS), r.IsLive}, nil
	})
	_, err := p.pool.CopyFrom(ctx, pgx.Identifier{"permutations"},
		[]string{"id", "scan_job_id", "domain", "dns_a", "dns_mx", "dns_ns", "is_live"},
		source)
	if err != nil {
		return nil, fmt.Errorf("copy permutations: %w", err)
	}
	return ids, nil
}

// nilToEmpty converts a nil slice to an empty slice so COPY FROM populates
// the column with {} rather than NULL (which would violate NOT NULL).
func nilToEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ScoreUpdate carries a post-scoring risk_score / risk_band for one permutation.
type ScoreUpdate struct {
	ID    uuid.UUID
	Score int
	Band  string
}

// UpdateScores writes risk_score and risk_band for each update in a single
// transaction. Uses an unnest-based bulk UPDATE rather than N round-trips.
func (p *Permutations) UpdateScores(ctx context.Context, updates []ScoreUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, len(updates))
	scores := make([]int32, len(updates))
	bands := make([]string, len(updates))
	for i, u := range updates {
		ids[i] = u.ID
		scores[i] = int32(u.Score)
		bands[i] = u.Band
	}
	_, err := p.pool.Exec(ctx, `
		UPDATE permutations AS p
		SET risk_score = v.score, risk_band = v.band
		FROM (SELECT UNNEST($1::uuid[]) AS id, UNNEST($2::int[]) AS score, UNNEST($3::text[]) AS band) AS v
		WHERE p.id = v.id
	`, ids, scores, bands)
	if err != nil {
		return fmt.Errorf("update scores: %w", err)
	}
	return nil
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

// PermutationResult is one row for GET /scans/{id}/results.
type PermutationResult struct {
	ID        uuid.UUID
	Domain    string
	DNSA      []string
	DNSMX     []string
	DNSNS     []string
	IsLive    bool
	RiskScore *int
	RiskBand  *string
}

// ListOptions parameterizes ListByScan.
type ListOptions struct {
	RiskBands []string // filter (empty = any)
	Limit     int      // default 50, cap 200
	Offset    int
}

// ListByScan returns permutations for a scan, ordered by risk_score DESC NULLS LAST.
// Total is the unfiltered count for pagination.
func (p *Permutations) ListByScan(ctx context.Context, scanJobID uuid.UUID, opts ListOptions) ([]PermutationResult, int, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 200 {
		opts.Limit = 200
	}

	// Single count for pagination regardless of filter.
	var total int
	if err := p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM permutations WHERE scan_job_id = $1`, scanJobID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count: %w", err)
	}

	// Build filtered query.
	args := []any{scanJobID, opts.Limit, opts.Offset}
	q := `
		SELECT id, domain, dns_a, dns_mx, dns_ns, is_live, risk_score, risk_band
		FROM permutations
		WHERE scan_job_id = $1
	`
	if len(opts.RiskBands) > 0 {
		q += ` AND risk_band = ANY($4::text[])`
		args = append(args, opts.RiskBands)
	}
	q += ` ORDER BY risk_score DESC NULLS LAST, domain ASC LIMIT $2 OFFSET $3`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	var out []PermutationResult
	for rows.Next() {
		var r PermutationResult
		if err := rows.Scan(&r.ID, &r.Domain, &r.DNSA, &r.DNSMX, &r.DNSNS, &r.IsLive, &r.RiskScore, &r.RiskBand); err != nil {
			return nil, 0, fmt.Errorf("scan: %w", err)
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// BandCounts returns {band: count} across all permutations for a scan.
type BandCounts map[string]int

func (p *Permutations) BandCounts(ctx context.Context, scanJobID uuid.UUID) (BandCounts, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT COALESCE(risk_band, 'UNSCORED'), COUNT(*)
		FROM permutations WHERE scan_job_id = $1
		GROUP BY risk_band
	`, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("band counts: %w", err)
	}
	defer rows.Close()
	out := BandCounts{}
	for rows.Next() {
		var band string
		var n int
		if err := rows.Scan(&band, &n); err != nil {
			return nil, err
		}
		out[band] = n
	}
	return out, rows.Err()
}
