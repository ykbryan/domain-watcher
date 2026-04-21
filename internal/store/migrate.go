package store

import (
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate applies all pending migrations against the given database URL.
// dbURL must be a postgres:// or postgresql:// URL understood by pgx.
func Migrate(dbURL string) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("migrations source: %w", err)
	}
	// golang-migrate's pgx/v5 driver registers under the "pgx5" scheme.
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

func stripScheme(u string) string {
	for _, p := range []string{"postgres://", "postgresql://"} {
		if len(u) > len(p) && u[:len(p)] == p {
			return u[len(p):]
		}
	}
	return u
}
