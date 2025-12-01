package db

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/sqlite/*.sql
var sqliteFS embed.FS

//go:embed migrations/postgres/*.sql
var postgresFS embed.FS

type driverFactory func(*sql.DB) (database.Driver, error)

// applyMigrations is a simple function that applies all migrations found in the
// given migrationFS at the given path to the provided database using the given
// driver factory.
//
// TODO(gustavostingelin): enhance migrations to be like sqldb/v2 before
// production use. This is a simplified migration system suitable for
// integration tests but lacks features required for production:
//   - No migration version tracking or status checks
//   - No migration history table or audit trail
//   - No protection against concurrent migrations
//
// For production use, this should be enhanced to match the patterns in
// lnd/sqldb/v2, which provides a more robust migration framework.
func applyMigrations(db *sql.DB, migrationFS fs.FS, path string, dbName string,
	newDriver driverFactory) error {

	sourceDriver, err := iofs.New(migrationFS, path)
	if err != nil {
		return fmt.Errorf("create source driver: %w", err)
	}

	driver, err := newDriver(db)
	if err != nil {
		return fmt.Errorf("create %s driver: %w", dbName, err)
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, dbName, driver)
	if err != nil {
		return fmt.Errorf("create migrate instance: %w", err)
	}

	err = m.Up()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("run migrations: %w", err)
	}

	return nil
}

// ApplySQLiteMigrations applies all SQLite migrations to the database.
//
// NOTE: not ready for production use.
func ApplySQLiteMigrations(db *sql.DB) error {
	return applyMigrations(db, sqliteFS, "migrations/sqlite", "sqlite",
		func(db *sql.DB) (database.Driver, error) {
			return sqlite.WithInstance(db, &sqlite.Config{})
		},
	)
}

// ApplyPostgresMigrations applies all PostgreSQL migrations to the database.
//
// NOTE: not ready for production use.
func ApplyPostgresMigrations(db *sql.DB) error {
	return applyMigrations(db, postgresFS, "migrations/postgres",
		"postgres", func(db *sql.DB) (database.Driver, error) {
			return postgres.WithInstance(db, &postgres.Config{})
		},
	)
}
