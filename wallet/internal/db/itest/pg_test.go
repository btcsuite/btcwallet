//go:build itest && test_db_postgres

package itest

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// pgMaxIdentifierLen is the PostgreSQL maximum identifier length
	// (NAMEDATALEN - 1).
	pgMaxIdentifierLen = 63

	// pgHashSuffixLen is the length of the deterministic hash suffix
	// appended to truncated database names (8 hex chars from CRC32).
	pgHashSuffixLen = 8

	// pgHashSeparator is the separator between the truncated prefix and
	// the hash suffix.
	pgHashSeparator = "_"
)

var (
	// Shared container instance, reused across tests for performance.
	// This is safe to use concurrently because we only share the container
	// and not the database inside it. Each test gets its own database.
	pgContainer *postgres.PostgresContainer

	// Ensure the container is created only once.
	pgContainerOnce sync.Once

	// Error returned by the container creation operation. We need to store
	// it to return when the error already occurred during test setup.
	errPGContainer error

	// Timeout for waiting for the postgres container to start. Needs to
	// consider container image download time.
	pgInitTimeout = 2 * time.Minute

	// Timeout for terminating the postgres container after the test suite.
	pgTerminateTimeout = 1 * time.Minute
)

// testParallelism returns the effective test parallelism level. It reads the
// -test.parallel flag when set, falling back to GOMAXPROCS (the default used by
// the Go test runner).
func testParallelism() int {
	f := flag.Lookup("test.parallel")
	if f == nil {
		return runtime.GOMAXPROCS(0)
	}

	n, err := strconv.Atoi(f.Value.String())
	if err != nil || n <= 0 {
		return runtime.GOMAXPROCS(0)
	}

	return n
}

// TestMain ensures the shared postgres container is terminated after the
// integration test suite completes to avoid leaking docker resources.
func TestMain(m *testing.M) {
	code := m.Run()

	// Terminate the container after the test suite completes.
	if pgContainer != nil {
		ctx, cancel := context.WithTimeout(
			context.Background(), pgTerminateTimeout,
		)
		// As the tests already completed, we can stop the container
		// immediately.
		err := pgContainer.Terminate(
			ctx, testcontainers.StopTimeout(0),
		)

		cancel()

		if err != nil {
			_, _ = fmt.Fprintf(
				os.Stderr, "failed to terminate postgres container: %v\n",
				err,
			)
		}
	}

	os.Exit(code)
}

// PostgresConfig holds configuration for the test PostgreSQL database.
type PostgresConfig struct {
	// Image is the Docker image to use.
	Image string

	// Database is the database name.
	Database string

	// Username is the database user.
	Username string

	// Password is the database password.
	Password string
}

// DefaultPostgresConfig returns the default PostgreSQL test configuration.
func DefaultPostgresConfig() PostgresConfig {
	return PostgresConfig{
		Image:    "postgres:18-alpine",
		Database: "postgres",
		Username: "postgres",
		Password: "postgres",
	}
}

// GetPostgresContainer returns the shared PostgreSQL container instance.
// The container is created once and reused across all tests for performance.
func GetPostgresContainer(ctx context.Context) (*postgres.PostgresContainer,
	error) {

	pgContainerOnce.Do(func() {
		cfg := DefaultPostgresConfig()

		// PostgreSQL 18 can begin listening on the TCP port before it is
		// ready to handle client queries, so wait for a successful SQL round
		// trip instead of only waiting for the port to open.
		waitForSQL := wait.ForSQL(
			"5432/tcp", "pgx", func(host string, port nat.Port) string {
				hostPort := net.JoinHostPort(host, port.Port())

				return fmt.Sprintf(
					"postgres://%s:%s@%s/%s?sslmode=disable",
					cfg.Username, cfg.Password, hostPort, cfg.Database,
				)
			},
		).WithStartupTimeout(pgInitTimeout)

		p := testParallelism()
		m := db.DefaultMaxConnections

		// pgMaxConns is the Postgres max_connections budget for the
		// test container. We budget 4x the steady-state pool size to
		// absorb connection lifecycle overlap during parallel test
		// teardown and startup without trying to model each transient
		// connection source separately. The 2x multiplier proved too
		// tight on CI runs that produce many concurrent
		// CreateWallet/CreateDB subtests, so the budget is widened
		// here to avoid spurious "too many clients" failures.
		pgMaxConns := 4 * p * m

		pgContainer, errPGContainer = postgres.Run(ctx,
			cfg.Image,
			postgres.WithDatabase(cfg.Database),
			postgres.WithUsername(cfg.Username),
			postgres.WithPassword(cfg.Password),
			testcontainers.WithCmd(
				"-c", fmt.Sprintf("max_connections=%d", pgMaxConns),
			),
			testcontainers.WithWaitStrategyAndDeadline(
				pgInitTimeout, waitForSQL,
			),
		)
	})

	return pgContainer, errPGContainer
}

// sanitizePgDBNameString converts a database name string to a valid PostgreSQL
// database name. It converts to lowercase and replaces special characters with
// underscores. If the resulting name exceeds PostgreSQL's 63-byte identifier
// limit, it is truncated with a deterministic CRC32 hash suffix to prevent
// collisions from long subtest names that share the same prefix.
func sanitizePgDBNameString(dbName string) string {
	// Convert to lowercase.
	dbName = strings.ToLower(dbName)

	// Replace slashes and other special chars with underscores.
	reg := regexp.MustCompile(`[^a-z0-9_]`)
	dbName = reg.ReplaceAllString(dbName, "_")

	// PostgreSQL database names are limited to 63 characters.
	// If truncation is needed, append a deterministic hash suffix to prevent
	// collisions from long subtest names with identical prefixes.
	if len(dbName) > pgMaxIdentifierLen {
		// Reserve space for separator and hash suffix.
		suffixLen := len(pgHashSeparator) + pgHashSuffixLen
		prefixLen := pgMaxIdentifierLen - suffixLen

		// Compute deterministic CRC32 hash of the full sanitized name.
		checksum := crc32.ChecksumIEEE([]byte(dbName))
		hashSuffix := fmt.Sprintf("%08x", checksum)

		// Truncate prefix and append hash suffix.
		dbName = dbName[:prefixLen] + pgHashSeparator + hashSuffix
	}

	return dbName
}

// sanitizedPgDBName converts a test name to a valid PostgreSQL database name.
// It converts to lowercase and replaces special characters with underscores.
// If the resulting name exceeds PostgreSQL's 63-byte identifier limit, it is
// truncated with a deterministic CRC32 hash suffix to prevent collisions from
// long subtest names that share the same prefix.
func sanitizedPgDBName(t *testing.T) string {
	t.Helper()

	dbName := sanitizePgDBNameString(t.Name())

	if len(t.Name()) > pgMaxIdentifierLen {
		t.Logf("database name truncated to %d characters with hash suffix: %s",
			pgMaxIdentifierLen, dbName)
	}

	return dbName
}

// NewTestStore creates a new PostgreSQL database connection with migrations
// applied. Each parallel subtest must call NewTestStore itself rather than
// sharing a store created by the parent test. When a parent test creates the
// store and its subtests call t.Parallel(), the parent finishes and releases
// its parallel slot while the subtests are still running. A new parent test
// fills that slot and opens another store, but the original subtests still
// hold their connections. This leads to more open connections than the parallel
// limit allows, exhausting the PostgreSQL connection pool. Avoid this by
// creating NewTestStore inside each parallel subtest so its lifecycle is tied
// to the subtest's parallel slot.
func NewTestStore(t *testing.T) *pg.Store {
	t.Helper()

	return NewTestStoreWithDerive(t, mockDeriveFunc())
}

// NewTestStoreWithDerive creates a new PostgreSQL database for testing with the
// provided address derivation function.
func NewTestStoreWithDerive(t *testing.T,
	deriveAddress db.AddressDerivationFunc) *pg.Store {

	t.Helper()
	ctx := t.Context()

	container, err := GetPostgresContainer(ctx)
	require.NoError(t, err, "failed to get postgres container")

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "failed to get connection string")

	// Connect to the default database to create our test database.
	adminDB, err := sql.Open("pgx", connStr)
	require.NoError(t, err, "failed to open admin connection")
	require.NotNil(t, adminDB, "admin connection is nil")

	// Create a database name based on the test name.
	dbName := sanitizedPgDBName(t)

	// Create the test database.
	createDBStmt := "CREATE DATABASE " + dbName
	_, err = adminDB.ExecContext(ctx, createDBStmt)
	require.NoError(t, err, "failed to create test database")

	// Close the connection to avoid leaking an idle connection during tests.
	// The container is reused across all tests, so we explicitly clean this up.
	_ = adminDB.Close()

	// Build the connection string for the test database.
	testConnStr := strings.Replace(connStr, "/postgres?", "/"+dbName+"?", 1)

	cfg := pg.Config{
		Dsn:            testConnStr,
		MaxConnections: 0,
		DeriveAddress:  deriveAddress,
	}

	store, err := pg.NewStore(t.Context(), cfg)
	require.NoError(t, err, "failed to create postgres store")

	t.Cleanup(func() {
		_ = store.Close()
	})

	return store
}

// childSpendingTxIDs returns the direct child transaction IDs recorded for the
// provided parent transaction hash.
func childSpendingTxIDs(t *testing.T, store *pg.Store,
	walletID uint32,
	txHash chainhash.Hash) []int64 {

	t.Helper()

	meta, err := store.Queries().GetTransactionMetaByHash(
		t.Context(), sqlc.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	require.NoError(t, err)

	childIDs, err := store.Queries().ListSpendingTxIDsByParentTxID(
		t.Context(), sqlc.ListSpendingTxIDsByParentTxIDParams{
			WalletID: int64(walletID),
			TxID:     meta.ID,
		},
	)
	require.NoError(t, err)

	ids := make([]int64, 0, len(childIDs))
	for _, childID := range childIDs {
		require.True(t, childID.Valid)
		ids = append(ids, childID.Int64)
	}

	return ids
}

// txIDByHash returns the database row ID for the given wallet-scoped
// transaction hash and reports whether the row exists.
func txIDByHash(t *testing.T, store *pg.Store, walletID uint32,
	txHash chainhash.Hash) (int64, bool) {

	t.Helper()

	meta, err := store.Queries().GetTransactionMetaByHash(
		t.Context(), sqlc.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false
		}

		require.NoError(t, err)
	}

	return meta.ID, true
}

// setTxStatus rewrites one wallet-scoped transaction row to the provided
// status using the internal status-update query.
func setTxStatus(t *testing.T, store *pg.Store, walletID uint32,
	txHash chainhash.Hash, status db.TxStatus) {

	t.Helper()

	txID, ok := txIDByHash(t, store, walletID, txHash)
	require.True(t, ok)

	rows, err := store.Queries().UpdateTransactionStatusByIDs(
		t.Context(), sqlc.UpdateTransactionStatusByIDsParams{
			WalletID: int64(walletID),
			Status:   int16(status),
			TxIds:    []int64{txID},
		},
	)
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

// walletUtxoExists reports whether one wallet-scoped outpoint is currently
// present in the UTXO set.
func walletUtxoExists(t *testing.T, store *pg.Store,
	walletID uint32,
	outPoint wire.OutPoint) bool {

	t.Helper()

	_, err := store.Queries().GetUtxoIDByOutpoint(
		t.Context(), sqlc.GetUtxoIDByOutpointParams{
			WalletID:    int64(walletID),
			TxHash:      outPoint.Hash[:],
			OutputIndex: int32(outPoint.Index),
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false
		}

		require.NoError(t, err)
	}

	return true
}
