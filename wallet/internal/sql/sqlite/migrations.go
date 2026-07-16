package sqlite

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"

	gomigrate "github.com/golang-migrate/migrate/v4"
	migrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// ErrIrreversibleMigration is returned when a rollback would discard data the
// target schema cannot represent, such as competing same-height blocks.
var ErrIrreversibleMigration = errors.New("irreversible migration")

// IsIrreversibleMigration reports whether a migration error is the block
// identity rollback guard rejecting a fork of competing same-height blocks.
func IsIrreversibleMigration(err error) bool {
	return err != nil &&
		strings.Contains(err.Error(), "no_competing_same_height_blocks")
}

func newMigrationInstance(db *sql.DB) (*gomigrate.Migrate, error) {
	sourceDriver, err := iofs.New(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("create migration source: %w", err)
	}

	driver, err := migrate.WithInstance(db, &migrate.Config{})
	if err != nil {
		return nil, fmt.Errorf("create sqlite migration driver: %w", err)
	}

	m, err := gomigrate.NewWithInstance(
		"iofs", sourceDriver, "sqlite", driver,
	)
	if err != nil {
		return nil, fmt.Errorf("create sqlite migration: %w", err)
	}

	return m, nil
}

// ApplyMigrations applies all embedded SQLite migrations.
func ApplyMigrations(db *sql.DB) error {
	m, err := newMigrationInstance(db)
	if err != nil {
		return err
	}

	err = m.Up()
	if err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		return fmt.Errorf("apply sqlite migrations: %w", err)
	}

	return nil
}

// RollbackMigrations rolls back all embedded SQLite migrations.
func RollbackMigrations(db *sql.DB) error {
	m, err := newMigrationInstance(db)
	if err != nil {
		return err
	}

	err = m.Down()
	if err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		if IsIrreversibleMigration(err) {
			return fmt.Errorf("%w: %v", ErrIrreversibleMigration, err)
		}

		return fmt.Errorf("rollback sqlite migrations: %w", err)
	}

	return nil
}
