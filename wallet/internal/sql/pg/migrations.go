package pg

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"

	gomigrate "github.com/golang-migrate/migrate/v4"
	migrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

func newMigrationInstance(db *sql.DB) (*gomigrate.Migrate, error) {
	migrationDB, err := cloneDatabase(db)
	if err != nil {
		return nil, fmt.Errorf("clone postgres database: %w", err)
	}

	sourceDriver, err := iofs.New(migrationFS, "migrations")
	if err != nil {
		_ = migrationDB.Close()

		return nil, fmt.Errorf("create migration source: %w", err)
	}

	driver, err := migrate.WithInstance(migrationDB, &migrate.Config{})
	if err != nil {
		_ = sourceDriver.Close()
		_ = migrationDB.Close()

		return nil, fmt.Errorf("create postgres migration driver: %w", err)
	}

	m, err := gomigrate.NewWithInstance("iofs", sourceDriver, "pgx", driver)
	if err != nil {
		_ = sourceDriver.Close()
		_ = driver.Close()

		return nil, fmt.Errorf("create postgres migration: %w", err)
	}

	return m, nil
}

func cloneDatabase(db *sql.DB) (*sql.DB, error) {
	conn, err := db.Conn(context.Background())
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = conn.Close()
	}()

	var config *pgx.ConnConfig

	err = conn.Raw(func(driverConn any) error {
		pgxConn, ok := driverConn.(*stdlib.Conn)
		if !ok {
			return fmt.Errorf("unexpected postgres driver %T", driverConn)
		}

		config = pgxConn.Conn().Config()

		return nil
	})
	if err != nil {
		return nil, err
	}

	return stdlib.OpenDB(*config), nil
}

func runMigrations(db *sql.DB, operation string,
	migrateFunc func(*gomigrate.Migrate) error) (err error) {

	m, err := newMigrationInstance(db)
	if err != nil {
		return err
	}

	defer func() {
		sourceErr, databaseErr := m.Close()

		closeErr := errors.Join(sourceErr, databaseErr)
		if closeErr != nil {
			err = errors.Join(
				err, fmt.Errorf("close postgres migration: %w", closeErr),
			)
		}
	}()

	err = migrateFunc(m)
	if err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		return fmt.Errorf("%s postgres migrations: %w", operation, err)
	}

	return nil
}

// ApplyMigrations applies all embedded PostgreSQL migrations.
func ApplyMigrations(db *sql.DB) error {
	return runMigrations(db, "apply", (*gomigrate.Migrate).Up)
}

// RollbackMigrations rolls back all embedded PostgreSQL migrations.
func RollbackMigrations(db *sql.DB) error {
	return runMigrations(db, "rollback", (*gomigrate.Migrate).Down)
}
