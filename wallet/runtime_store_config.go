package wallet

import (
	"fmt"
	"path/filepath"
	"time"
)

// DBBackend identifies the wallet runtime database backend.
type DBBackend string

const (
	// DBBackendKVDB keeps runtime wallet state on walletdb.
	DBBackendKVDB DBBackend = "kvdb"

	// DBBackendSQLite selects the SQLite SQL store.
	DBBackendSQLite DBBackend = "sqlite"

	// DBBackendPostgres selects the PostgreSQL SQL store.
	DBBackendPostgres DBBackend = "postgres"
)

// KVDBConfig holds kvdb-specific wallet store settings.
type KVDBConfig struct {
	// DBPath is the filesystem path to the walletdb database file.
	DBPath string

	// NoFreelistSync controls bbolt freelist synchronization.
	NoFreelistSync bool

	// Timeout is the walletdb open/create timeout. A zero value uses the
	// default timeout.
	Timeout time.Duration
}

// SQLiteDBConfig holds SQLite-specific runtime store settings.
type SQLiteDBConfig struct {
	// DBPath is the filesystem path to the SQLite database file.
	DBPath string

	// MaxConnections is the maximum number of open connections. Set to zero
	// to use the store default.
	MaxConnections int
}

// PostgresDBConfig holds PostgreSQL-specific runtime store settings.
type PostgresDBConfig struct {
	// DSN is the PostgreSQL connection string.
	DSN string

	// MaxConnections is the maximum number of open connections. Set to zero
	// to use the store default.
	MaxConnections int
}

// DBConfig selects and configures the wallet runtime store backend. A
// zero-valued Backend selects DBBackendKVDB, so wallets default to the
// legacy walletdb store. Set Backend to DBBackendSQLite or
// DBBackendPostgres explicitly to use the SQL runtime store.
type DBConfig struct {
	// Backend identifies the selected runtime store backend.
	Backend DBBackend

	// KVDB holds kvdb settings used by the legacy compatibility store. It is
	// also the runtime store config when Backend is kvdb.
	KVDB KVDBConfig

	// SQLite holds SQLite settings used when Backend is sqlite.
	SQLite SQLiteDBConfig

	// Postgres holds PostgreSQL settings used when Backend is postgres.
	Postgres PostgresDBConfig
}

// Validate checks that the runtime store configuration is internally
// consistent. It does not open any database connections.
//
//nolint:cyclop // One validation switch over the backend enum is clearest here.
func (c DBConfig) Validate() error {
	c = c.withDefaults()

	if c.KVDB.Timeout < 0 {
		return fmt.Errorf("%w: DB.KVDB.Timeout", ErrInvalidParam)
	}

	switch c.Backend {
	case DBBackendKVDB:
		if c.SQLite != (SQLiteDBConfig{}) {
			return fmt.Errorf("%w: DB.SQLite requires backend %q",
				ErrInvalidParam, DBBackendSQLite)
		}

		if c.Postgres != (PostgresDBConfig{}) {
			return fmt.Errorf("%w: DB.Postgres requires backend %q",
				ErrInvalidParam, DBBackendPostgres)
		}

	case DBBackendSQLite:
		if c.Postgres != (PostgresDBConfig{}) {
			return fmt.Errorf("%w: DB.Postgres requires backend %q",
				ErrInvalidParam, DBBackendPostgres)
		}

		if c.SQLite.DBPath == "" {
			return fmt.Errorf("%w: DB.SQLite.DBPath", ErrMissingParam)
		}

		if c.SQLite.MaxConnections < 0 {
			return fmt.Errorf("%w: DB.SQLite.MaxConnections",
				ErrInvalidParam)
		}

	case DBBackendPostgres:
		if c.SQLite != (SQLiteDBConfig{}) {
			return fmt.Errorf("%w: DB.SQLite requires backend %q",
				ErrInvalidParam, DBBackendSQLite)
		}

		if c.Postgres.DSN == "" {
			return fmt.Errorf("%w: DB.Postgres.DSN", ErrMissingParam)
		}

		if c.Postgres.MaxConnections < 0 {
			return fmt.Errorf("%w: DB.Postgres.MaxConnections",
				ErrInvalidParam)
		}

	default:
		return fmt.Errorf("%w: DB.Backend %q",
			ErrInvalidParam, c.Backend)
	}

	return nil
}

// validateLegacyKVDB checks the legacy kvdb compatibility config required by
// the current wallet manager boundary.
func (c DBConfig) validateLegacyKVDB() error {
	if c.KVDB.DBPath == "" {
		return fmt.Errorf("%w: DB.KVDB.DBPath", ErrMissingParam)
	}

	return nil
}

// defaultSQLiteDBName is the SQLite runtime database filename derived for new
// wallets that leave DB.SQLite.DBPath unset. It lives alongside the legacy
// kvdb database so both stores share a wallet directory.
const defaultSQLiteDBName = "wallet.sqlite"

// withDefaults returns c with the implicit runtime store defaults applied.
//
// An unset Backend selects DBBackendKVDB so wallets default to the legacy
// walletdb store; callers must set Backend to DBBackendSQLite or
// DBBackendPostgres explicitly to use the SQL runtime store. When the resolved
// backend is SQLite and no SQLite path was given, a deterministic default is
// derived next to the legacy kvdb database (DB.KVDB.DBPath) so the runtime
// store has a stable on-disk location.
func (c DBConfig) withDefaults() DBConfig {
	if c.Backend == "" {
		c.Backend = DBBackendKVDB
	}

	if c.Backend == DBBackendSQLite && c.SQLite.DBPath == "" &&
		c.KVDB.DBPath != "" {

		c.SQLite.DBPath = filepath.Join(
			filepath.Dir(c.KVDB.DBPath), defaultSQLiteDBName,
		)
	}

	return c
}
