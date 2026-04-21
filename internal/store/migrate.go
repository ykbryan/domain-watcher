package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate applies all pending migrations against the given database URL.
// All DDL lands in the schema named by DB_SCHEMA (default "domainwatcher"),
// including golang-migrate's own schema_migrations bookkeeping table.
// dbURL must be a postgres:// or postgresql:// URL understood by pgx.
func Migrate(dbURL string) error {
	schema := SchemaFromEnv()
	if !validSchemaName(schema) {
		return fmt.Errorf("invalid DB_SCHEMA %q (use lowercase letters, digits, underscores)", schema)
	}
	if err := ensureSchema(dbURL, schema); err != nil {
		return fmt.Errorf("ensure schema %q: %w", schema, err)
	}

	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("migrations source: %w", err)
	}
	// golang-migrate's pgx/v5 driver registers under the "pgx5" scheme.
	// Any connection it opens inherits the role-in-db default search_path
	// set by ensureSchema above, so tables + schema_migrations land in schema.
	mURL := "pgx5://" + stripScheme(dbURL)

	m, err := migrate.NewWithSourceInstance("iofs", src, mURL)
	if err != nil {
		return fmt.Errorf("migrate init: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	if _, err := m.Close(); err != nil {
		return fmt.Errorf("migrate close: %w", err)
	}
	return nil
}

// ensureSchema opens a bare connection and (1) creates the target schema
// if it doesn't exist, (2) persists the schema as the default search_path
// for the current role-in-database.
//
// Why ALTER ROLE: some Postgres-flavored proxies (notably Supabase's
// Supavisor pooler) silently drop non-standard startup parameters, so
// pgx's RuntimeParams["search_path"] and URL ?search_path=… don't reach
// the server. Role-in-database defaults are stored in the catalog and
// apply to every new connection regardless of the pooler's behavior.
func ensureSchema(dbURL, schema string) error {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)

	// Check first: Postgres evaluates privileges on CREATE SCHEMA even when
	// `IF NOT EXISTS` would short-circuit, so a restricted role like
	// domainwatcher_rw (no CREATE on database) fails on a pre-existing
	// schema. Reading pg_namespace requires no special privilege.
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname = $1)", schema).Scan(&exists); err != nil {
		return fmt.Errorf("check schema exists: %w", err)
	}
	if !exists {
		// schema name validated — safe to inline.
		if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
			return fmt.Errorf("create schema: %w", err)
		}
	}

	var user, dbname string
	if err := conn.QueryRow(ctx, "SELECT current_user, current_database()").Scan(&user, &dbname); err != nil {
		return fmt.Errorf("identify role/db: %w", err)
	}
	stmt := fmt.Sprintf(
		"ALTER ROLE %s IN DATABASE %s SET search_path = %s, public",
		quoteIdent(user), quoteIdent(dbname), schema,
	)
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("set default search_path: %w", err)
	}
	return nil
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func stripScheme(u string) string {
	for _, p := range []string{"postgres://", "postgresql://"} {
		if len(u) > len(p) && u[:len(p)] == p {
			return u[len(p):]
		}
	}
	return u
}

// validSchemaName restricts DB_SCHEMA to safe SQL identifiers so we can
// inline it into CREATE SCHEMA without needing to quote-escape.
func validSchemaName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
		if !ok {
			return false
		}
	}
	return true
}
