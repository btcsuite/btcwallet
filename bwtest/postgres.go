package bwtest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/docker/go-connections/nat"
	_ "github.com/jackc/pgx/v5/stdlib" // Register the pgx SQL driver.
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// postgresTestImage is the PostgreSQL image used by the harness.
	postgresTestImage = "postgres:18-alpine"

	// postgresTestDatabase is the administrative database used by the
	// harness.
	postgresTestDatabase = "postgres"

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
)

// postgresTestServer owns the process-scoped PostgreSQL test container and
// its administrative connection.
type postgresTestServer struct {
	container *postgres.PostgresContainer
	adminDB   *sql.DB
	adminDSN  string
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
				postgresTestDatabase,
			)
		},
	).WithStartupTimeout(postgresStartupTimeout)

	container, err := postgres.Run(
		ctx, postgresTestImage,
		postgres.WithDatabase(postgresTestDatabase),
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
