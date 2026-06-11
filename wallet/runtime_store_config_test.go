package wallet

import (
	"path/filepath"
	"testing"

	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/stretchr/testify/require"
)

// TestDBConfigValidate verifies runtime database config validation.
func TestDBConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cfg        DBConfig
		wantErr    error
		wantErrMsg string
	}{
		{
			// An unset backend now defaults to SQLite and derives
			// the SQLite path from the kvdb path, so a config with
			// only KVDB.DBPath set validates.
			name: "unset defaults to sqlite",
			cfg: DBConfig{
				KVDB: KVDBConfig{DBPath: "wallet.db"},
			},
		},
		{
			// A fully empty config defaults to SQLite but has no
			// kvdb path to derive the SQLite path from, so it is
			// invalid.
			name:       "empty config is invalid",
			cfg:        DBConfig{},
			wantErr:    ErrMissingParam,
			wantErrMsg: "DB.SQLite.DBPath",
		},
		{
			name: "kvdb explicit",
			cfg: DBConfig{
				Backend: DBBackendKVDB,
			},
		},
		{
			name: "sqlite",
			cfg: DBConfig{
				Backend: DBBackendSQLite,
				SQLite: SQLiteDBConfig{
					DBPath: "wallet.sqlite",
				},
			},
		},
		{
			name: "postgres",
			cfg: DBConfig{
				Backend: DBBackendPostgres,
				Postgres: PostgresDBConfig{
					DSN: "postgres://user:pass@host/db",
				},
			},
		},
		{
			name: "unknown backend",
			cfg: DBConfig{
				Backend: DBBackend("mysql"),
			},
			wantErr:    ErrInvalidParam,
			wantErrMsg: "DB.Backend",
		},
		{
			name: "sqlite missing path",
			cfg: DBConfig{
				Backend: DBBackendSQLite,
			},
			wantErr:    ErrMissingParam,
			wantErrMsg: "DB.SQLite.DBPath",
		},
		{
			name: "sqlite negative max connections",
			cfg: DBConfig{
				Backend: DBBackendSQLite,
				SQLite: SQLiteDBConfig{
					DBPath:         "wallet.sqlite",
					MaxConnections: -1,
				},
			},
			wantErr:    ErrInvalidParam,
			wantErrMsg: "DB.SQLite.MaxConnections",
		},
		{
			name: "postgres missing dsn",
			cfg: DBConfig{
				Backend: DBBackendPostgres,
			},
			wantErr:    ErrMissingParam,
			wantErrMsg: "DB.Postgres.DSN",
		},
		{
			name: "kvdb with sqlite config",
			cfg: DBConfig{
				Backend: DBBackendKVDB,
				SQLite: SQLiteDBConfig{
					DBPath: "wallet.sqlite",
				},
			},
			wantErr:    ErrInvalidParam,
			wantErrMsg: "DB.SQLite requires backend",
		},
		{
			name: "sqlite with postgres config",
			cfg: DBConfig{
				Backend: DBBackendSQLite,
				SQLite: SQLiteDBConfig{
					DBPath: "wallet.sqlite",
				},
				Postgres: PostgresDBConfig{
					DSN: "postgres://user:pass@host/db",
				},
			},
			wantErr:    ErrInvalidParam,
			wantErrMsg: "DB.Postgres requires backend",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.cfg.Validate()
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, tc.wantErr)
			require.ErrorContains(t, err, tc.wantErrMsg)
		})
	}
}

// TestConfigValidateRuntimeStore verifies wallet Config runtime store checks.
func TestConfigValidateRuntimeStore(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)

	cfg := Config{
		DB:             testDBConfig(db),
		Chain:          &bwmock.Chain{},
		ChainParams:    &chainParams,
		Name:           "test-wallet",
		RecoveryWindow: MinRecoveryWindow,
	}
	require.NoError(t, cfg.validate())

	cfg.DB = DBConfig{
		KVDB:    cfg.DB.KVDB,
		Backend: DBBackend("mysql"),
	}
	err := cfg.validate()
	require.ErrorIs(t, err, ErrInvalidParam)
	require.ErrorContains(t, err, "DB.Backend")
}

// TestDBConfigWithDefaults verifies the implicit runtime store defaults: an
// unset backend selects SQLite and, when no SQLite path is given, a SQLite
// path is derived next to the legacy kvdb database.
func TestDBConfigWithDefaults(t *testing.T) {
	t.Parallel()

	const kvdbDir = "/data"

	kvdbPath := filepath.Join(kvdbDir, "wallet.db")

	t.Run("unset backend defaults to sqlite", func(t *testing.T) {
		t.Parallel()

		got := DBConfig{
			KVDB: KVDBConfig{DBPath: kvdbPath},
		}.withDefaults()

		require.Equal(t, DBBackendSQLite, got.Backend)
		require.Equal(
			t, filepath.Join(kvdbDir, defaultSQLiteDBName),
			got.SQLite.DBPath,
		)
	})

	t.Run("explicit sqlite path is preserved", func(t *testing.T) {
		t.Parallel()

		const customPath = "/custom/db.sqlite"

		got := DBConfig{
			KVDB:   KVDBConfig{DBPath: kvdbPath},
			SQLite: SQLiteDBConfig{DBPath: customPath},
		}.withDefaults()

		require.Equal(t, DBBackendSQLite, got.Backend)
		require.Equal(t, customPath, got.SQLite.DBPath)
	})

	t.Run("explicit kvdb derives no sqlite path", func(t *testing.T) {
		t.Parallel()

		got := DBConfig{
			Backend: DBBackendKVDB,
			KVDB:    KVDBConfig{DBPath: kvdbPath},
		}.withDefaults()

		require.Equal(t, DBBackendKVDB, got.Backend)
		require.Empty(t, got.SQLite.DBPath)
	})
}
