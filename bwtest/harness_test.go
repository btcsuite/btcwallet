package bwtest

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// TestDeregisterWalletRemovesRegisteredWallet verifies that deregistration
// removes only the requested wallet and leaves its sibling registered.
func TestDeregisterWalletRemovesRegisteredWallet(t *testing.T) {
	t.Parallel()

	// Arrange: two wallets registered under one Manager.
	manager := &wallet.Manager{}
	removed := &wallet.Wallet{}
	sibling := &wallet.Wallet{}
	h := &HarnessTest{
		T: t,
		wallets: map[*wallet.Manager]walletRegistration{
			manager: {
				removed: nil,
				sibling: nil,
			},
		}}

	// Act: the wallet is deregistered, then queried again as absent and
	// nil.
	removedWallet := h.DeregisterWallet(removed)
	removedAgain := h.DeregisterWallet(removed)
	removedNil := h.DeregisterWallet(nil)

	// Assert: the sibling remains and absent wallets are reported safely.
	require.True(t, removedWallet)
	require.False(t, removedAgain)
	require.False(t, removedNil)
	require.ElementsMatch(t, []*wallet.Wallet{sibling}, h.ActiveWallets())
}

// TestRegisterWalletSupportsMultipleWalletsPerManager verifies that one
// Manager can own multiple registered wallets.
func TestRegisterWalletSupportsMultipleWalletsPerManager(t *testing.T) {
	t.Parallel()

	// Arrange: one manager with two wallet pointers.
	manager := &wallet.Manager{}
	first := &wallet.Wallet{}
	second := &wallet.Wallet{}
	h := &HarnessTest{
		T: t,
		wallets: map[*wallet.Manager]walletRegistration{
			manager: {},
		},
	}

	// Act: register both wallets under the same manager.
	h.RegisterWallet(manager, first)
	h.RegisterWallet(manager, second)

	// Assert: both wallets are active regardless of map order.
	active := h.ActiveWallets()
	require.ElementsMatch(t, []*wallet.Wallet{first, second}, active)
	require.Len(t, h.wallets[manager], 2)
	require.Nil(t, h.wallets[manager][first])
	require.Nil(t, h.wallets[manager][second])
}

// TestReleaseManagerRejectsRegisteredWallet verifies that Manager ownership
// cannot be released while any wallet remains registered.
func TestReleaseManagerRejectsRegisteredWallet(t *testing.T) {
	t.Parallel()

	// Arrange: a Manager with one registered wallet.
	manager := &wallet.Manager{}
	w := &wallet.Wallet{}
	h := &HarnessTest{
		T: t,
		wallets: map[*wallet.Manager]walletRegistration{
			manager: {
				w: nil,
			},
		},
	}

	// Act: release is attempted while the registration is non-empty.
	released := h.ReleaseManager(manager)

	// Assert: release is rejected and the Manager remains owned.
	require.False(t, released)
	require.Contains(t, h.wallets, manager)
}

// TestReleaseManagerRemovesRegisteredManager verifies that releasing an empty
// Manager retains unrelated registrations and reports an absent Manager.
func TestReleaseManagerRemovesRegisteredManager(t *testing.T) {
	t.Parallel()

	// Arrange: a harness with three empty Manager registrations.
	first := &wallet.Manager{}
	released := &wallet.Manager{}
	last := &wallet.Manager{}
	h := &HarnessTest{
		T: t,
		wallets: map[*wallet.Manager]walletRegistration{
			first:    {},
			released: {},
			last:     {},
		},
	}

	// Act: the middle Manager is released from teardown ownership.
	require.True(t, h.ReleaseManager(released))

	// Assert: only it is removed and absence is safe.
	require.Len(t, h.wallets, 2)
	_, firstRegistered := h.wallets[first]
	_, lastRegistered := h.wallets[last]

	require.True(t, firstRegistered)
	require.True(t, lastRegistered)
	require.False(t, h.ReleaseManager(released))
	require.False(t, h.ReleaseManager(nil))
}

// TestReleaseManagerTransfersTeardownOwnership verifies that a successfully
// closed Manager can be removed from teardown without a second close.
func TestReleaseManagerTransfersTeardownOwnership(t *testing.T) {
	t.Parallel()

	// Arrange: give the harness the strict chain mock required by the
	// Manager's shared runtime policy. This lifecycle-only test does not
	// expect any chain calls.
	chainSource := &bwmock.Chain{}
	h := &HarnessTest{
		T:              t,
		dbType:         "kvdb",
		ChainClient:    chainSource,
		WalletDBSource: filepath.Join(t.TempDir(), "wallet.db"),
	}
	manager := h.NewWalletManager()
	require.NotNil(t, h.wallets[manager])

	// Act: the test closes the Manager before releasing teardown ownership.
	require.NoError(t, manager.Close())
	require.True(t, h.ReleaseManager(manager))

	// Assert: teardown succeeds without a second close and the database
	// reopened.
	require.NoError(t, h.teardownWallets(t.Context()))
	reopened, err := wallet.NewManager(t.Context(), wallet.ManagerConfig{
		//nolint:staticcheck // This test intentionally reopens legacy kvdb.
		Backend:     wallet.DBBackendKVDB,
		DataSource:  h.WalletDBSource,
		ChainParams: *h.NetParams(),
		ChainSource: h.ChainClient,
	})
	require.NoError(
		t, err, "released Manager must leave the database available",
	)
	require.NoError(t, reopened.Close())
	chainSource.AssertExpectations(t)
}

// TestTeardownWalletsClosesManagerAfterFailedCreate verifies that centralized
// teardown releases a Manager even when wallet creation fails.
func TestTeardownWalletsClosesManagerAfterFailedCreate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		dbType  string
		backend wallet.DBBackend
	}{
		{
			name:   "kvdb",
			dbType: dbNameKvdb,
			//nolint:staticcheck // This case covers legacy kvdb teardown.
			backend: wallet.DBBackendKVDB,
		},
		{
			name:    "sqlite",
			dbType:  dbNameSQLite,
			backend: wallet.DBBackendSQLite,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testManagerTeardownAfterFailedCreate(
				t, testCase.dbType, testCase.backend,
			)
		})
	}
}

// testManagerTeardownAfterFailedCreate exercises centralized Manager cleanup
// for one database backend.
func testManagerTeardownAfterFailedCreate(t *testing.T, dbType string,
	backend wallet.DBBackend) {

	t.Helper()

	// Arrange: provide the complete Manager policy, including a strict chain
	// mock with no expected calls because this test stops before chain sync.
	chainSource := &bwmock.Chain{}
	h := &HarnessTest{
		T:              t,
		dbType:         dbType,
		ChainClient:    chainSource,
		WalletDBSource: filepath.Join(t.TempDir(), "wallet.db"),
	}

	manager := h.NewWalletManager()
	require.NotNil(t, manager)

	// Act: force Create to fail after the Manager has opened its database,
	// then run centralized teardown through the same path used by the
	// integration harness.
	w, err := manager.Create(wallet.CreateWalletParams{
		Mode:              wallet.ModeGenSeed,
		PrivatePassphrase: []byte("private"),
	})
	require.ErrorIs(t, err, wallet.ErrMissingParam)
	require.Nil(t, w)

	// Bound teardown so a missing Manager close fails instead of hanging.
	done := make(chan error, 1)
	go func() {
		done <- h.teardownWallets(t.Context())
	}()

	select {
	case err := <-done:
		require.NoError(t, err)

	case <-time.After(teardownWaitLimit):
		t.Fatal("teardownWallets did not return: the Manager was " +
			"probably never closed")
	}

	// Assert: a fresh Manager proves teardown released the database, while
	// the strict chain mock proves neither failed creation nor cleanup
	// crossed into chain synchronization.
	reopenCfg := wallet.ManagerConfig{
		Backend:     backend,
		DataSource:  h.WalletDBSource,
		ChainParams: *h.NetParams(),
		ChainSource: h.ChainClient,
	}
	reopened, err := wallet.NewManager(t.Context(), reopenCfg)
	require.NoError(t, err, "teardown must release the database")
	require.NoError(t, reopened.Close())
	chainSource.AssertExpectations(t)
}

// TestBackendArtifactPostgresRejectsInvalidDSN verifies that PostgreSQL
// validation uses a connection probe instead of treating the DSN as a file.
func TestBackendArtifactPostgresRejectsInvalidDSN(t *testing.T) {
	t.Parallel()

	err := validateBackendArtifact(dbNamePostgres, "://invalid")
	require.ErrorContains(t, err, "postgres")
}

// teardownWaitLimit bounds teardown so a leaked Manager fails the test.
const teardownWaitLimit = 30 * time.Second

// TestBackendArtifactValidatesExpectedBackend verifies that backend artifact
// validation reports positive, mismatched, and malformed headers without
// depending on testing.T failure state.
func TestBackendArtifactValidatesExpectedBackend(t *testing.T) {
	t.Parallel()

	sqliteHeader := make([]byte, bboltMagicOffset+bboltMagicLen)
	copy(sqliteHeader, sqliteHeaderMagic)

	kvdbHeader := make([]byte, bboltMagicOffset+bboltMagicLen)
	binary.LittleEndian.PutUint32(
		kvdbHeader[bboltMagicOffset:], bboltMagic,
	)

	testCases := []struct {
		name    string
		dbType  string
		header  []byte
		wantErr string
	}{
		{name: "sqlite matches", dbType: dbNameSQLite,
			header: sqliteHeader},
		{name: "kvdb matches", dbType: dbNameKvdb,
			header: kvdbHeader},
		{
			name:    "sqlite mismatches kvdb",
			dbType:  dbNameKvdb,
			header:  sqliteHeader,
			wantErr: "is a sqlite database",
		},
		{
			name:    "kvdb mismatches sqlite",
			dbType:  dbNameSQLite,
			header:  kvdbHeader,
			wantErr: "is a kvdb database",
		},
		{
			name:    "unknown header",
			dbType:  dbNameSQLite,
			header:  make([]byte, bboltMagicOffset+bboltMagicLen),
			wantErr: "unrecognized wallet database artifact",
		},
		{
			name:    "truncated header",
			dbType:  dbNameKvdb,
			header:  []byte("short"),
			wantErr: "read wallet database header",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			dbPath := filepath.Join(t.TempDir(), "wallet.db")
			err := os.WriteFile(dbPath, testCase.header, 0o600)
			require.NoError(t, err)

			err = validateBackendArtifact(testCase.dbType, dbPath)
			if testCase.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.ErrorContains(t, err, testCase.wantErr)
		})
	}
}
