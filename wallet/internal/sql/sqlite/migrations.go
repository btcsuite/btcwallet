package sqlite

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"

	gomigrate "github.com/golang-migrate/migrate/v4"
	migrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// newMigrationInstance creates a migrate instance from embedded sqlite
// migrations.
func newMigrationInstance(db *sql.DB) (*gomigrate.Migrate, error) {
	sourceDriver, err := iofs.New(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("create source driver: %w", err)
	}

	driver, err := migrate.WithInstance(db, &migrate.Config{})
	if err != nil {
		return nil, fmt.Errorf("create sqlite driver: %w", err)
	}

	m, err := gomigrate.NewWithInstance("iofs", sourceDriver, "sqlite", driver)
	if err != nil {
		return nil, fmt.Errorf("create migrate instance: %w", err)
	}

	return m, nil
}

// ApplyMigrations applies all SQLite migrations to the database.
func ApplyMigrations(db *sql.DB) error {
	m, err := newMigrationInstance(db)
	if err != nil {
		return err
	}

	err = m.Up()
	if err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		return fmt.Errorf("run migrations: %w", err)
	}

	return nil
}

// RollbackMigrations rolls back all SQLite migrations from the database.
func RollbackMigrations(db *sql.DB) error {
	m, err := newMigrationInstance(db)
	if err != nil {
		return err
	}

	err = m.Down()
	if err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		return fmt.Errorf("rollback migrations: %w", err)
	}

	return nil
}
