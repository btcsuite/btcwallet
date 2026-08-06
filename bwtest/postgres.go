package bwtest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib" // Register the pgx SQL driver.
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// postgresTestImage is the PostgreSQL image used by the harness.
	postgresTestImage = "postgres:18-alpine"

	// postgresAdminDatabase is the administrative database used by the
	// harness.
	postgresAdminDatabase = "postgres"

	// postgresTestUsername and postgresTestPassword are credentials scoped
	// to the disposable PostgreSQL container.
	postgresTestUsername = "postgres"
	postgresTestPassword = "postgres"

	// postgresStartupTimeout includes the time needed to pull and start the
	// PostgreSQL image.
	postgresStartupTimeout = 2 * time.Minute

	// postgresShutdownTimeout bounds container teardown after the test
	// context has been canceled.
	postgresShutdownTimeout = time.Minute

	// postgresDatabaseHashBytes keeps database identifiers short while
	// retaining enough entropy to isolate test names.
	postgresDatabaseHashBytes = 12
)

// postgresTestServer owns the process-scoped PostgreSQL test container and
// its administrative connection.
type postgresTestServer struct {
	container *postgres.PostgresContainer
	adminDB   *sql.DB
	adminDSN  string
}

// postgresTestDatabase is one per-subtest database in the shared PostgreSQL
// server.
type postgresTestDatabase struct {
	server *postgresTestServer
	name   string
	dsn    string
}

// newPostgresTestServer starts PostgreSQL and opens its administrative
// connection after a successful SQL readiness probe.
func newPostgresTestServer(ctx context.Context) (*postgresTestServer, error) {
	cleanupCtx := context.WithoutCancel(ctx)

	waitForSQL := wait.ForSQL(
		"5432/tcp", "pgx", func(host string, port nat.Port) string {
			hostPort := net.JoinHostPort(host, port.Port())

			return fmt.Sprintf(
				"postgres://%s:%s@%s/%s?sslmode=disable",
				postgresTestUsername, postgresTestPassword, hostPort,
				postgresAdminDatabase,
			)
		},
	).WithStartupTimeout(postgresStartupTimeout)

	container, err := postgres.Run(
		ctx, postgresTestImage,
		postgres.WithDatabase(postgresAdminDatabase),
		postgres.WithUsername(postgresTestUsername),
		postgres.WithPassword(postgresTestPassword),
		testcontainers.WithWaitStrategyAndDeadline(
			postgresStartupTimeout, waitForSQL,
		),
	)
	if err != nil {
		var cleanupErr error
		if container != nil {
			cleanupErr = (&postgresTestServer{
				container: container,
			}).close(cleanupCtx)
		}

		return nil, errors.Join(
			fmt.Errorf("start postgres test server: %w", err),
			cleanupErr,
		)
	}

	server := &postgresTestServer{container: container}

	server.adminDSN, err = container.ConnectionString(
		ctx, "sslmode=disable",
	)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("get postgres admin DSN: %w", err),
			server.close(cleanupCtx),
		)
	}

	server.adminDB, err = sql.Open("pgx", server.adminDSN)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("open postgres admin connection: %w", err),
			server.close(cleanupCtx),
		)
	}

	pingCtx, cancel := context.WithTimeout(ctx, defaultTestTimeout)
	defer cancel()

	err = server.adminDB.PingContext(pingCtx)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("ping postgres admin connection: %w", err),
			server.close(cleanupCtx),
		)
	}

	return server, nil
}

// newDatabase creates an isolated database and returns its rewritten DSN.
func (s *postgresTestServer) newDatabase(ctx context.Context,
	testName string) (*postgresTestDatabase, error) {

	database := &postgresTestDatabase{
		server: s,
		name:   postgresDatabaseName(testName),
	}
	identifier := pgx.Identifier{database.name}.Sanitize()

	createCtx, cancel := context.WithTimeout(ctx, defaultTestTimeout)
	defer cancel()

	_, err := s.adminDB.ExecContext(
		createCtx, "CREATE DATABASE "+identifier,
	)
	if err != nil {
		return nil, fmt.Errorf("create postgres database %q: %w",
			database.name, err)
	}

	database.dsn, err = postgresDatabaseDSN(s.adminDSN, database.name)
	if err != nil {
		return nil, errors.Join(err, database.close(ctx))
	}

	return database, nil
}

// close drops the isolated database after its Managers have closed.
func (d *postgresTestDatabase) close(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(
		ctx, defaultTestTimeout,
	)
	defer cancel()

	identifier := pgx.Identifier{d.name}.Sanitize()

	// Managers close before this cleanup. WITH (FORCE) also releases the
	// auxiliary advisory-lock session retained by the migration driver.
	_, err := d.server.adminDB.ExecContext(
		ctx, "DROP DATABASE IF EXISTS "+identifier+" WITH (FORCE)",
	)
	if err != nil {
		return fmt.Errorf("drop postgres database %q: %w", d.name, err)
	}

	return nil
}

// postgresDatabaseName returns a short, deterministic SQL identifier for a
// subtest name.
func postgresDatabaseName(testName string) string {
	hash := sha256.Sum256([]byte(testName))

	return fmt.Sprintf(
		"bwtest_%x", hash[:postgresDatabaseHashBytes],
	)
}

// postgresDatabaseDSN rewrites an administrative DSN to select database.
func postgresDatabaseDSN(adminDSN, database string) (string, error) {
	dsn, err := url.Parse(adminDSN)
	if err != nil {
		return "", fmt.Errorf("parse postgres admin DSN: %w", err)
	}

	if dsn.Scheme == "" || dsn.Host == "" {
		return "", errors.New("parse postgres admin DSN: missing endpoint")
	}

	dsn.Path = "/" + database
	dsn.RawPath = ""

	return dsn.String(), nil
}

// validatePostgresSchema verifies that the PostgreSQL data source is reachable
// and contains the migrated wallet schema.
func validatePostgresSchema(dsn string) (err error) {
	dbConn, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open postgres schema probe: %w", err)
	}

	defer func() {
		err = errors.Join(err, dbConn.Close())
	}()

	ctx, cancel := context.WithTimeout(
		context.Background(), defaultTestTimeout,
	)
	defer cancel()

	var exists bool

	err = dbConn.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'wallets'
		)
	`).Scan(&exists)
	if err != nil {
		return fmt.Errorf("query postgres wallet schema: %w", err)
	}

	if !exists {
		return errors.New("postgres wallet schema is missing")
	}

	return nil
}

// close releases the administrative connection and immediately terminates
// the disposable PostgreSQL container.
func (s *postgresTestServer) close(ctx context.Context) error {
	var err error
	if s.adminDB != nil {
		err = s.adminDB.Close()
	}

	if s.container == nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, postgresShutdownTimeout)
	defer cancel()

	terminateErr := s.container.Terminate(
		ctx, testcontainers.StopTimeout(0),
	)

	return errors.Join(err, terminateErr)
}
