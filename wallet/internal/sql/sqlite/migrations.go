package sqlite

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	migrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type driverFactory func(*sql.DB) (database.Driver, error)

// applyMigrations applies all embedded sqlite migrations to one database.
func applyMigrations(db *sql.DB, newDriver driverFactory) error {
	sourceDriver, err := iofs.New(migrationFS, "migrations")
	if err != nil {
		return fmt.Errorf("create source driver: %w", err)
	}

	driver, err := newDriver(db)
	if err != nil {
		return fmt.Errorf("create sqlite driver: %w", err)
	}

	m, err := gomigrate.NewWithInstance("iofs", sourceDriver, "sqlite", driver)
	if err != nil {
		return fmt.Errorf("create migrate instance: %w", err)
	}

	err = m.Up()
	if err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		return fmt.Errorf("run migrations: %w", err)
	}

	return nil
}

// ApplyMigrations applies all SQLite migrations to the database.
func ApplyMigrations(db *sql.DB) error {
	return applyMigrations(db, func(db *sql.DB) (database.Driver, error) {
		return migrate.WithInstance(db, &migrate.Config{})
	})
}
