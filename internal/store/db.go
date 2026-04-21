package store

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultSchema is where all domainwatch tables live. Keeping the app
// out of 'public' makes the code safe to run on a shared Postgres
// instance (e.g. self-hosted Supabase) without colliding with other apps.
const DefaultSchema = "domainwatcher"

// SchemaFromEnv returns the schema name the app should use. Env var
// DB_SCHEMA overrides the default.
func SchemaFromEnv() string {
	if s := os.Getenv("DB_SCHEMA"); s != "" {
		return s
	}
	return DefaultSchema
}

func NewPool(ctx context.Context, dbURL string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	// Scope every connection to the app schema so unqualified table names
	// in queries resolve without the caller having to qualify them.
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = SchemaFromEnv() + ",public"

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return pool, nil
}
