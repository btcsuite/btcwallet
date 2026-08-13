package pg

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"time"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	migrate "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

const (
	// migrationLockTimeout is the PostgreSQL statement timeout applied while
	// golang-migrate acquires its advisory lock. It terminates the server-side
	// lock query so the driver goroutine cannot outlive the caller timeout.
	migrationLockTimeout = 15 * time.Second

	// migrationLockGrace gives the server-side statement timeout time to
	// reach the driver before golang-migrate's outer LockTimeout expires.
	migrationLockGrace = time.Second

	// setStatementTimeout applies migrationLockTimeout to the dedicated
	// migration session without changing the database configuration.
	setStatementTimeout = `SELECT set_config('statement_timeout', $1, false)`

	// resetStatementTimeout restores the session's configured default before
	// migration statements run or the connection returns to the pool.
	resetStatementTimeout = `RESET statement_timeout`
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrationSession changes settings on the dedicated migration connection.
type migrationSession interface {
	ExecContext(ctx context.Context, query string,
		args ...any) (sql.Result, error)
}

// migrationLockDriver bounds the PostgreSQL driver's advisory lock query.
type migrationLockDriver struct {
	database.Driver

	session migrationSession
}

var _ database.Driver = (*migrationLockDriver)(nil)

// Lock acquires the migration lock with a server-enforced statement timeout.
func (d *migrationLockDriver) Lock() error {
	return withMigrationLockTimeout(
		context.Background(), d.session, d.Driver.Lock,
	)
}

// withMigrationLockTimeout runs an operation with a server-enforced statement
// timeout, restoring the configured session default afterward.
func withMigrationLockTimeout(ctx context.Context,
	session migrationSession, operation func() error) (resultErr error) {

	_, err := session.ExecContext(
		ctx, setStatementTimeout, migrationLockTimeout.String(),
	)
	if err != nil {
		return fmt.Errorf("set migration lock timeout: %w", err)
	}

	defer func() {
		_, err := session.ExecContext(
			ctx, resetStatementTimeout,
		)
		if err != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("reset migration lock timeout: %w", err),
			)
		}
	}()

	return operation()
}

// newMigrationInstance creates a migrate instance from embedded postgres
// migrations.
func newMigrationInstance(ctx context.Context,
	db *sql.DB) (*gomigrate.Migrate, error) {

	sourceDriver, err := iofs.New(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("create source driver: %w", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		_ = sourceDriver.Close()

		return nil, fmt.Errorf("acquire migration connection: %w", err)
	}

	var postgresDriver *migrate.Postgres

	err = withMigrationLockTimeout(ctx, conn, func() error {
		postgresDriver, err = migrate.WithConnection(
			ctx, conn, &migrate.Config{},
		)

		return err
	})
	if err != nil {
		_ = conn.Close()
		_ = sourceDriver.Close()

		return nil, fmt.Errorf("create postgres driver: %w", err)
	}

	driver := &migrationLockDriver{
		Driver:  postgresDriver,
		session: conn,
	}

	m, err := gomigrate.NewWithInstance(
		"iofs", sourceDriver, "postgres", driver,
	)
	if err != nil {
		_ = driver.Close()
		_ = sourceDriver.Close()

		return nil, fmt.Errorf("create migrate instance: %w", err)
	}

	m.LockTimeout = migrationLockTimeout + migrationLockGrace

	return m, nil
}

// closeMigration closes the migrate source and database drivers, returning all
// cleanup failures without discarding either one.
func closeMigration(m *gomigrate.Migrate) error {
	sourceErr, databaseErr := m.Close()

	var errs []error
	if sourceErr != nil {
		errs = append(errs, fmt.Errorf("close migration source: %w", sourceErr))
	}

	if databaseErr != nil {
		errs = append(
			errs, fmt.Errorf("close migration database: %w", databaseErr),
		)
	}

	return errors.Join(errs...)
}

// joinMigrationCloseError preserves the primary migration result while also
// reporting a cleanup failure.
func joinMigrationCloseError(operationErr, closeErr error) error {
	if operationErr == nil {
		return closeErr
	}

	if closeErr == nil {
		return operationErr
	}

	return errors.Join(operationErr, closeErr)
}

// ApplyMigrations applies all PostgreSQL migrations to the database.
func ApplyMigrations(ctx context.Context,
	db *sql.DB) (resultErr error) {

	m, err := newMigrationInstance(ctx, db)
	if err != nil {
		return err
	}

	defer func() {
		resultErr = joinMigrationCloseError(resultErr, closeMigration(m))
	}()

	err = m.Up()
	if err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		return fmt.Errorf("run migrations: %w", err)
	}

	return nil
}

// RollbackMigrations rolls back all PostgreSQL migrations from the database.
func RollbackMigrations(ctx context.Context,
	db *sql.DB) (resultErr error) {

	m, err := newMigrationInstance(ctx, db)
	if err != nil {
		return err
	}

	defer func() {
		resultErr = joinMigrationCloseError(resultErr, closeMigration(m))
	}()

	err = m.Down()
	if err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		return fmt.Errorf("rollback migrations: %w", err)
	}

	return nil
}
