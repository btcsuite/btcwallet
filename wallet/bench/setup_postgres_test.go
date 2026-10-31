//go:build test_db_postgres

package bench

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// benchmarkPostgresImage fixes the server build across measurements and keeps
// its pg_dump/pg_restore tools matched to the database being measured.
const benchmarkPostgresImage = "postgres:18-alpine@sha256:" +
	"9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"

// setupBenchmarkPostgres provisions the pinned server and owns its cleanup.
// Return its DSN so Wallet startup and snapshot commands share this container.
func setupBenchmarkPostgres(tb testing.TB) (*postgres.PostgresContainer,
	string) {

	tb.Helper()

	// SQL readiness waits through the image's bootstrap server.
	readiness := wait.ForSQL(
		"5432/tcp", "pgx",
		func(host string, port nat.Port) string {
			return fmt.Sprintf(
				"postgres://postgres:postgres@%s/postgres?sslmode=disable",
				net.JoinHostPort(host, port.Port()),
			)
		},
	)

	container, err := postgres.Run(
		tb.Context(), benchmarkPostgresImage,
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),

		// Retain native durability instead of the module's fsync=off default.
		testcontainers.WithCmd("postgres", "-c", "fsync=on"),
		testcontainers.WithWaitStrategyAndDeadline(
			2*time.Minute, readiness,
		),
		testcontainers.WithHostConfigModifier(
			func(config *dockercontainer.HostConfig) {
				config.NanoCPUs = 1_000_000_000
				config.Memory = 1 << 30
			},
		),
	)

	// Early failures can return nil; startup/readiness failures can return a
	// partial container. Register cleanup before the fatal error check so a
	// partially started server is terminated when setup fails.
	if container != nil {
		tb.Cleanup(func() {
			ctx, cancel := context.WithTimeout(
				context.WithoutCancel(tb.Context()), time.Minute,
			)
			defer cancel()

			require.NoError(tb, container.Terminate(
				ctx, testcontainers.StopTimeout(0),
			))
		})
	}

	require.NoError(tb, err)
	dsn, err := container.ConnectionString(
		tb.Context(), "sslmode=disable",
	)
	require.NoError(tb, err)

	return container, dsn
}

// sqlBenchmarkFixture keeps the native container with the Manager configuration
// used for preparation, archive restore and measured reads in this invocation.
type sqlBenchmarkFixture struct {
	config    wallet.ManagerConfig
	container *postgres.PostgresContainer
}

// newSQLBenchmarkFixture provisions the native server before Wallet startup.
// Register the chain mock first so Manager and container cleanup finish before
// its expectations are checked.
func newSQLBenchmarkFixture(tb testing.TB) *sqlBenchmarkFixture {
	tb.Helper()

	chain := bwmock.NewGenesisChain(tb, false)
	container, dsn := setupBenchmarkPostgres(tb)

	return &sqlBenchmarkFixture{
		config: wallet.ManagerConfig{
			Backend:     wallet.DBBackendPostgres,
			DataSource:  dsn,
			ChainParams: chaincfg.RegressionNetParams,
			ChainSource: chain,
		},
		container: container,
	}
}

// openStore gives the common seeder normal database writes. Its caller closes
// this pool before stopping Manager and taking the database archive.
func (f *sqlBenchmarkFixture) openStore(tb testing.TB) (db.Store,
	func() error) {

	tb.Helper()

	identity, err := db.NewDatabaseIdentity(&f.config.ChainParams, nil)
	require.NoError(tb, err)

	store, err := pg.NewStore(tb.Context(), pg.Config{
		Dsn:      f.config.DataSource,
		Identity: identity,
	})
	require.NoError(tb, err)

	return store, store.Close
}

// snapshot dumps inside the pinned server image so client and server versions
// match. The common publisher owns closing the custom archive reader.
func (f *sqlBenchmarkFixture) snapshot(tb testing.TB) io.ReadCloser {
	tb.Helper()

	code, output, err := f.container.Exec(tb.Context(), []string{
		"pg_dump", "-U", "postgres", "-d", "postgres", "-Fc",
		"--no-owner", "--no-acl", "-f", "/tmp/benchmark.dump",
	})
	require.NoError(tb, err)
	diagnostic, err := io.ReadAll(output)
	require.NoError(tb, err)
	require.Zero(tb, code, "pg_dump: %s", diagnostic)
	source, err := f.container.CopyFileFromContainer(
		tb.Context(), "/tmp/benchmark.dump",
	)
	require.NoError(tb, err)

	return source
}

// restore replaces this invocation's database before Manager startup. Clean
// handles the first run's seeded database as well as a later cache hit.
func (f *sqlBenchmarkFixture) restore(tb testing.TB, fixture string) {
	tb.Helper()

	require.NoError(tb, f.container.CopyFileToContainer(
		tb.Context(), fixture, "/tmp/benchmark.dump", 0o600,
	))
	code, output, err := f.container.Exec(tb.Context(), []string{
		"pg_restore", "-U", "postgres", "-d", "postgres",
		"--exit-on-error", "--clean", "--if-exists", "--no-owner",
		"--no-acl", "/tmp/benchmark.dump",
	})
	require.NoError(tb, err)
	diagnostic, err := io.ReadAll(output)
	require.NoError(tb, err)
	require.Zero(tb, code, "pg_restore: %s", diagnostic)

	// Archives omit planner statistics. Analyze the private restore so timed
	// reads use data-aware plans without rebuilding saved data.
	code, output, err = f.container.Exec(tb.Context(), []string{
		"psql", "-X", "-U", "postgres", "-d", "postgres",
		"-v", "ON_ERROR_STOP=1", "-c", "ANALYZE",
	})
	require.NoError(tb, err)
	diagnostic, err = io.ReadAll(output)
	require.NoError(tb, err)
	require.Zero(tb, code, "ANALYZE: %s", diagnostic)
}
