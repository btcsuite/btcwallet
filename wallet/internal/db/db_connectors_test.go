package db_test

import (
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	"github.com/stretchr/testify/require"
)

// TestPostgresNewStoreValidateConfig rejects invalid input before connecting.
func TestPostgresNewStoreValidateConfig(t *testing.T) {
	t.Parallel()

	// Arrange: Each row isolates the earliest invalid PostgreSQL setting.
	tests := []struct {
		name    string
		cfg     pg.Config
		wantErr error
	}{
		{
			name: "empty DSN",
			cfg: pg.Config{
				Dsn: "",
			},
			wantErr: db.ErrEmptyDSN,
		},
		{
			name: "negative max connections",
			cfg: pg.Config{
				Dsn:            "postgres://test",
				MaxConnections: -1,
			},
			wantErr: db.ErrNegativeMaxConns,
		},
		{
			name:    "missing identity",
			cfg:     pg.Config{Dsn: "postgres://test"},
			wantErr: db.ErrInvalidDatabaseIdentity,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act: Let NewStore validate before opening a connection.
			store, err := pg.NewStore(t.Context(), tc.cfg)

			// Assert: The isolated error prevents a Store from escaping.
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, store)
		})
	}
}

// TestPostgresNewStoreConnectionFailure proves valid identity reaches ping.
func TestPostgresNewStoreConnectionFailure(t *testing.T) {
	t.Parallel()

	// Arrange: Pair a valid identity with an unreachable endpoint.
	identity, err := db.NewDatabaseIdentity(&chaincfg.RegressionNetParams, nil)
	require.NoError(t, err)

	cfg := pg.Config{
		Dsn:      "postgres://localhost:1/testdb",
		Identity: identity,
	}

	// Act: Attempt to connect using the complete configuration.
	store, err := pg.NewStore(t.Context(), cfg)

	// Assert: The connection context is preserved and no Store escapes.
	require.Error(t, err)
	require.ErrorContains(t, err, "ping database")
	require.NotErrorIs(t, err, db.ErrEmptyDSN)
	require.NotErrorIs(t, err, db.ErrNegativeMaxConns)

	require.Nil(t, store)
}

// TestSQLiteNewStoreValidateConfig rejects invalid input before connecting.
func TestSQLiteNewStoreValidateConfig(t *testing.T) {
	t.Parallel()

	// Arrange: Each row isolates the earliest invalid SQLite setting.
	tests := []struct {
		name    string
		cfg     sqlite.Config
		wantErr error
	}{
		{
			name: "empty DB path",
			cfg: sqlite.Config{
				DBPath: "",
			},
			wantErr: db.ErrEmptyDBPath,
		},
		{
			name: "negative max connections",
			cfg: sqlite.Config{
				DBPath:         "/tmp/test.db",
				MaxConnections: -1,
			},
			wantErr: db.ErrNegativeMaxConns,
		},
		{
			name:    "missing identity",
			cfg:     sqlite.Config{DBPath: "/tmp/test.db"},
			wantErr: db.ErrInvalidDatabaseIdentity,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act: Let NewStore validate before opening a connection.
			store, err := sqlite.NewStore(t.Context(), tc.cfg)

			// Assert: The isolated error prevents a Store from escaping.
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, store)
		})
	}
}

// TestSQLiteNewStoreSuccess proves Config identity opens and closes a Store.
func TestSQLiteNewStoreSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Supply a valid ordinary-network identity and an isolated file.
	identity, err := db.NewDatabaseIdentity(&chaincfg.RegressionNetParams, nil)
	require.NoError(t, err)
	cfg := sqlite.Config{
		DBPath:   filepath.Join(t.TempDir(), "wallet.db"),
		Identity: identity,
	}

	// Act: Open the Store against the isolated database file.
	store, err := sqlite.NewStore(t.Context(), cfg)

	// Assert: A complete configuration opens and closes cleanly.
	require.NoError(t, err)
	require.NotNil(t, store)
	require.NoError(t, store.Close())
}
