package pg

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"

	gomigrate "github.com/golang-migrate/migrate/v4"
	migrate "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// newMigrationInstance pins metadata to btcwallet and owns one dedicated
// connection, releasing it explicitly if driver construction fails.
func newMigrationInstance(ctx context.Context,
	db *sql.DB) (*gomigrate.Migrate, error) {

	sourceDriver, err := iofs.New(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("create source driver: %w", err)
	}

	// Acquire the connection ourselves: WithInstance does not release it
	// when PostgreSQL metadata initialization fails after acquisition.
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire migration connection: %w",
			errors.Join(err, sourceDriver.Close()))
	}

	driver, err := migrate.WithConnection(ctx, conn, &migrate.Config{
		SchemaName: WalletSchemaName,
	})
	if err != nil {
		return nil, fmt.Errorf("create postgres driver: %w",
			errors.Join(err, conn.Close(), sourceDriver.Close()))
	}

	m, err := gomigrate.NewWithInstance(
		"iofs", sourceDriver, "postgres", driver,
	)
	if err != nil {
		return nil, fmt.Errorf("create migrate instance: %w",
			errors.Join(err, driver.Close(), sourceDriver.Close()))
	}

	return m, nil
}

// closeMigration returns the borrowed connection and closes the embedded source
// without discarding either cleanup failure or closing the caller's pool.
func closeMigration(m *gomigrate.Migrate) error {
	sourceErr, databaseErr := m.Close()

	err := errors.Join(sourceErr, databaseErr)
	if err != nil {
		return fmt.Errorf("close migration resources: %w", err)
	}

	return nil
}

// ApplyMigrations applies all PostgreSQL migrations, releasing the dedicated
// migration connection on success and failure so a one-slot pool remains
// usable.
func ApplyMigrations(ctx context.Context, db *sql.DB) (resultErr error) {
	m, err := newMigrationInstance(ctx, db)
	if err != nil {
		return err
	}

	// Keep the original migration result while also reporting cleanup
	// errors.
	defer func() {
		resultErr = errors.Join(resultErr, closeMigration(m))
	}()

	err = m.Up()
	if err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		return fmt.Errorf("run migrations: %w", err)
	}

	return nil
}

// RollbackMigrations rolls back all PostgreSQL migrations and releases the
// dedicated connection without taking ownership of the caller's pool.
func RollbackMigrations(ctx context.Context, db *sql.DB) (resultErr error) {
	m, err := newMigrationInstance(ctx, db)
	if err != nil {
		return err
	}

	// Match Up's ownership rule even when Down rejects the migration state.
	defer func() {
		resultErr = errors.Join(resultErr, closeMigration(m))
	}()

	err = m.Down()
	if err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		return fmt.Errorf("rollback migrations: %w", err)
	}

	return nil
}
