package bench

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	"github.com/stretchr/testify/require"
)

// sqlBenchmarkFixture gives common setup local methods for the build-selected
// Store, snapshot and restore operations. SQLite needs only ManagerConfig;
// the PostgreSQL variant also owns its container. ManagerConfig belongs to
// wallet, so it cannot receive these bench-package methods.
type sqlBenchmarkFixture struct {
	config wallet.ManagerConfig
}

// newSQLBenchmarkFixture selects private storage so saved data stays closed
// while each invocation opens its own database through the normal Manager.
func newSQLBenchmarkFixture(tb testing.TB) *sqlBenchmarkFixture {
	tb.Helper()

	return &sqlBenchmarkFixture{
		config: wallet.ManagerConfig{
			Backend:     wallet.DBBackendSQLite,
			DataSource:  filepath.Join(tb.TempDir(), "wallet.sqlite"),
			ChainParams: chaincfg.RegressionNetParams,
			ChainSource: bwmock.NewGenesisChain(tb, false),
		},
	}
}

// openStore gives the common seeder normal database writes. Its caller closes
// this pool before stopping Manager and publishing the closed-file snapshot.
func (f *sqlBenchmarkFixture) openStore(tb testing.TB) (db.Store,
	func() error) {

	tb.Helper()

	identity, err := db.NewDatabaseIdentity(&f.config.ChainParams, nil)
	require.NoError(tb, err)

	store, err := sqlite.NewStore(tb.Context(), sqlite.Config{
		DBPath:   f.config.DataSource,
		Identity: identity,
	})
	require.NoError(tb, err)

	return store, store.Close
}

// snapshot opens the closed database after its final pool has checkpointed
// WAL. The common publisher owns closing the returned reader.
func (f *sqlBenchmarkFixture) snapshot(tb testing.TB) io.ReadCloser {
	tb.Helper()

	file, err := os.Open(filepath.Clean(f.config.DataSource))
	require.NoError(tb, err)

	return file
}

// restore copies saved data to this invocation's private file before Manager
// startup, so preparation caches cannot enter the measured Wallet.
func (f *sqlBenchmarkFixture) restore(tb testing.TB, fixture string) {
	tb.Helper()

	data, err := os.ReadFile(filepath.Clean(fixture))
	require.NoError(tb, err)

	require.NoError(tb, os.WriteFile(f.config.DataSource, data, 0o600))
}
