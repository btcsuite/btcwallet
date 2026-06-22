package bwtest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb" // Register bdb driver.
	"github.com/docker/go-connections/nat"
	_ "github.com/jackc/pgx/v5/stdlib" // Register pgx for PostgreSQL setup.
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	// ErrUnknownDBBackend is returned when an unknown db backend is requested.
	ErrUnknownDBBackend = errors.New("unknown db backend")
)

const (
	// dbNameKvdb is the identifier used for the kvdb wallet backend.
	dbNameKvdb = "kvdb"

	// dbNameSQLite is the identifier used for the SQLite wallet backend.
	dbNameSQLite = "sqlite"

	// dbNamePostgres is the identifier used for the PostgreSQL wallet backend.
	dbNamePostgres = "postgres"

	// kvdbDriver is the walletdb driver name used for kvdb.
	kvdbDriver = "bdb"

	// walletDBFilename is the default wallet database filename.
	walletDBFilename = "wallet.db"

	// sqliteDBFilename is the default SQLite runtime database filename.
	sqliteDBFilename = "wallet.sqlite"

	// pgImage is the PostgreSQL Docker image used by integration tests.
	pgImage = "postgres:18-alpine"

	// pgDatabase is the default database name created by the image.
	pgDatabase = "postgres"

	// pgUsername is the PostgreSQL test user.
	pgUsername = "postgres"

	// pgPassword is the PostgreSQL test password.
	pgPassword = "postgres"

	// pgMaxIdentifierLen is PostgreSQL's maximum identifier length.
	pgMaxIdentifierLen = 63

	// pgHashSeparator separates truncated names from their hash suffix.
	pgHashSeparator = "_"

	// pgHashSuffixLen is the hex CRC32 suffix length.
	pgHashSuffixLen = 8

	// pgInitTimeout allows enough time to pull and start the Docker image.
	pgInitTimeout = 3 * time.Minute
)

// postgresHarness is a shared PostgreSQL container and admin connection string.
type postgresHarness struct {
	container  *tcpostgres.PostgresContainer
	connString string
}

// normalizeDBType applies the default wallet backend when dbType is empty.
func normalizeDBType(dbType string) string {
	if dbType == "" {
		return dbNameKvdb
	}

	return dbType
}

// validateDBType fails the test for an unknown wallet backend name.
func validateDBType(tb testing.TB, dbType string) {
	tb.Helper()

	switch dbType {
	case dbNameKvdb, dbNameSQLite, dbNamePostgres:
		return

	default:
		tb.Fatalf("unknown wallet database backend %q", dbType)
	}
}

// WalletDBConfig returns the wallet database config for the current subtest.
func (h *HarnessTest) WalletDBConfig() wallet.DBConfig {
	h.Helper()

	kvdbCfg := wallet.KVDBConfig{
		DBPath: h.WalletDBPath,
	}

	switch h.dbType {
	case dbNameKvdb:
		return wallet.DBConfig{
			Backend: wallet.DBBackendKVDB,
			KVDB:    kvdbCfg,
		}

	case dbNameSQLite:
		return wallet.DBConfig{
			Backend: wallet.DBBackendSQLite,
			KVDB:    kvdbCfg,
			SQLite: wallet.SQLiteDBConfig{
				DBPath: h.walletSQLitePath,
			},
		}

	case dbNamePostgres:
		return wallet.DBConfig{
			Backend: wallet.DBBackendPostgres,
			KVDB:    kvdbCfg,
			Postgres: wallet.PostgresDBConfig{
				DSN: h.walletPostgresDSN,
			},
		}

	default:
		h.Fatalf("unknown wallet database backend %q", h.dbType)
		return wallet.DBConfig{}
	}
}

// setUpSharedWalletDB prepares any run-scoped database infrastructure.
func (h *HarnessTest) setUpSharedWalletDB() {
	h.Helper()

	if h.dbType != dbNamePostgres {
		return
	}

	h.postgres = newPostgresHarness(h)
}

// stopSharedWalletDB tears down any run-scoped database infrastructure.
func (h *HarnessTest) stopSharedWalletDB() {
	if h.postgres == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTestTimeout)
	defer cancel()

	err := h.postgres.container.Terminate(
		ctx, testcontainers.StopTimeout(0),
	)
	if err != nil {
		h.Logf("failed to terminate postgres container: %v", err)
	}

	h.postgres = nil
}

// newPostgresHarness starts the shared PostgreSQL integration-test container.
func newPostgresHarness(t *HarnessTest) *postgresHarness {
	t.Helper()

	ctx := t.Context()
	waitForSQL := wait.ForSQL(
		"5432/tcp", "pgx", func(host string, port nat.Port) string {
			hostPort := net.JoinHostPort(host, port.Port())

			return fmt.Sprintf(
				"postgres://%s:%s@%s/%s?sslmode=disable",
				pgUsername, pgPassword, hostPort, pgDatabase,
			)
		},
	).WithStartupTimeout(pgInitTimeout)

	container, err := tcpostgres.Run(
		ctx, pgImage,
		tcpostgres.WithDatabase(pgDatabase),
		tcpostgres.WithUsername(pgUsername),
		tcpostgres.WithPassword(pgPassword),
		testcontainers.WithCmd("-c", "max_connections=128"),
		testcontainers.WithWaitStrategyAndDeadline(
			pgInitTimeout, waitForSQL,
		),
	)
	require.NoError(t, err, "failed to start postgres container")

	connString, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "failed to get postgres connection string")

	return &postgresHarness{
		container:  container,
		connString: connString,
	}
}

// createPostgresDatabase creates one PostgreSQL database for the subtest.
func (h *HarnessTest) createPostgresDatabase() string {
	h.Helper()
	require.NotNil(h, h.postgres, "postgres container not initialized")

	dbName := sanitizedPgDBName(h.Name())
	adminDB, err := sql.Open("pgx", h.postgres.connString)
	require.NoError(h, err, "failed to open postgres admin connection")

	defer func() {
		_ = adminDB.Close()
	}()

	_, err = adminDB.ExecContext(h.Context(), "CREATE DATABASE "+dbName)
	require.NoError(h, err, "failed to create postgres database")

	h.Cleanup(func() {
		h.dropPostgresDatabase(dbName)
	})

	return strings.Replace(
		h.postgres.connString, "/postgres?", "/"+dbName+"?", 1,
	)
}

// dropPostgresDatabase drops one PostgreSQL database created for a subtest.
func (h *HarnessTest) dropPostgresDatabase(dbName string) {
	h.Helper()

	adminDB, err := sql.Open("pgx", h.postgres.connString)
	if err != nil {
		h.Logf("failed to open postgres admin connection: %v", err)
		return
	}

	defer func() {
		_ = adminDB.Close()
	}()

	_, err = adminDB.ExecContext(
		context.Background(),
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "+
			"WHERE datname = $1", dbName,
	)
	if err != nil {
		h.Logf("failed to terminate postgres database sessions: %v", err)
	}

	_, err = adminDB.ExecContext(
		context.Background(), "DROP DATABASE IF EXISTS "+dbName,
	)
	if err != nil {
		h.Logf("failed to drop postgres database %q: %v", dbName, err)
	}
}

// sanitizedPgDBName converts a test name to a PostgreSQL database name.
func sanitizedPgDBName(name string) string {
	dbName := strings.ToLower(name)
	dbName = regexp.MustCompile(`[^a-z0-9_]`).ReplaceAllString(dbName, "_")
	dbName = strings.Trim(dbName, "_")

	if dbName == "" || (dbName[0] < 'a' || dbName[0] > 'z') {
		dbName = "itest_" + dbName
	}

	if len(dbName) <= pgMaxIdentifierLen {
		return dbName
	}

	suffixLen := len(pgHashSeparator) + pgHashSuffixLen
	prefixLen := pgMaxIdentifierLen - suffixLen
	checksum := crc32.ChecksumIEEE([]byte(dbName))
	hashSuffix := fmt.Sprintf("%08x", checksum)

	return dbName[:prefixLen] + pgHashSeparator + hashSuffix
}

// OpenWalletDB opens a wallet database instance rooted at baseDir.
//
// The returned cleanup function should be called to close the database.
func OpenWalletDB(dbType, baseDir string) (walletdb.DB, func() error, error) {
	switch dbType {
	case dbNameKvdb:
		dbPath := filepath.Join(baseDir, walletDBFilename)

		db, err := walletdb.Create(kvdbDriver, dbPath, true,
			defaultTestTimeout, false)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to create bdb instance: %w",
				err)
		}

		cleanup := func() error {
			return db.Close()
		}

		return db, cleanup, nil

	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrUnknownDBBackend, dbType)
	}
}
