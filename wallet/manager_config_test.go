package wallet

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// testSQLiteDBName is the SQLite data source the config tests share.
const testSQLiteDBName = "wallet.sqlite"

// TestManagerConfigValidate verifies that a Manager's database configuration is
// checked once, at construction, and that nothing is defaulted: an unset
// backend or data source is an error rather than a guess, so a wallet is never
// opened somewhere the caller did not name.
func TestManagerConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     ManagerConfig
		wantIs  error
		wantMsg string
	}{
		{
			name: "kvdb",
			cfg: ManagerConfig{
				Backend:     DBBackendKVDB,
				DataSource:  WalletDBName,
				ChainParams: &chaincfg.SimNetParams,
			},
		},
		{
			name: "sqlite",
			cfg: ManagerConfig{
				Backend:     DBBackendSQLite,
				DataSource:  testSQLiteDBName,
				ChainParams: &chaincfg.SimNetParams,
			},
		},
		{
			name: "postgres",
			cfg: ManagerConfig{
				Backend:     DBBackendPostgres,
				DataSource:  "postgres://user:pass@localhost/wallet",
				ChainParams: &chaincfg.SimNetParams,
			},
		},
		{
			// kvdb reads these; sqlite ignores them. Neither is an
			// error, which is what makes the flat shape workable.
			name: "kvdb knobs on sqlite are ignored",
			cfg: ManagerConfig{
				Backend:        DBBackendSQLite,
				DataSource:     testSQLiteDBName,
				ChainParams:    &chaincfg.SimNetParams,
				NoFreelistSync: true,
				Timeout:        time.Second,
			},
		},
		{
			name:    "no backend",
			cfg:     ManagerConfig{DataSource: WalletDBName},
			wantIs:  ErrMissingParam,
			wantMsg: "Backend",
		},
		{
			name: "unknown backend",
			cfg: ManagerConfig{
				Backend:     DBBackend("mysql"),
				DataSource:  WalletDBName,
				ChainParams: &chaincfg.SimNetParams,
			},
			wantIs:  errUnsupportedBackend,
			wantMsg: "mysql",
		},
		{
			name: "no data source",
			cfg: ManagerConfig{
				Backend:     DBBackendKVDB,
				ChainParams: &chaincfg.SimNetParams,
			},
			wantIs:  ErrMissingParam,
			wantMsg: "DataSource",
		},
		{
			name: "no chain params",
			cfg: ManagerConfig{
				Backend:    DBBackendKVDB,
				DataSource: WalletDBName,
			},
			wantIs:  ErrMissingParam,
			wantMsg: "ChainParams",
		},
		{
			name: "negative max connections",
			cfg: ManagerConfig{
				Backend:        DBBackendSQLite,
				DataSource:     testSQLiteDBName,
				ChainParams:    &chaincfg.SimNetParams,
				MaxConnections: -1,
			},
			wantIs:  ErrInvalidParam,
			wantMsg: "MaxConnections",
		},
		{
			name: "postgres negative max connections",
			cfg: ManagerConfig{
				Backend:        DBBackendPostgres,
				DataSource:     "postgres://localhost/wallet",
				ChainParams:    &chaincfg.SimNetParams,
				MaxConnections: -1,
			},
			wantIs:  ErrInvalidParam,
			wantMsg: "MaxConnections",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.cfg.validate()
			if test.wantIs == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, test.wantIs)
			require.ErrorContains(t, err, test.wantMsg)
		})
	}
}

// TestNewManagerRejectsInvalidSQLIdentity proves identity precedes SQL setup.
func TestNewManagerRejectsInvalidSQLIdentity(t *testing.T) {
	t.Parallel()

	// Arrange: A missing signet digest and unusable source expose ordering.
	for _, backend := range []DBBackend{DBBackendSQLite, DBBackendPostgres} {
		cfg := ManagerConfig{
			Backend: backend, DataSource: "\x00/db",
			ChainParams: &chaincfg.SigNetParams,
		}

		// Act: Construct the Manager through the selected SQL backend.
		manager, err := NewManager(t.Context(), cfg)

		// Assert: Invalid identity wins before the unusable source is read.
		require.ErrorIs(t, err, db.ErrInvalidDatabaseIdentity, backend)
		require.Nil(t, manager, backend)
	}
}

// TestManagerConfigTimeout verifies that an unset walletdb timeout falls
// back to the default instead of zero, which walletdb treats as no wait.
func TestManagerConfigTimeout(t *testing.T) {
	t.Parallel()

	require.Equal(t, defaultKVDBTimeout, ManagerConfig{}.timeout())
	require.Equal(
		t, time.Second, ManagerConfig{Timeout: time.Second}.timeout(),
	)
}
