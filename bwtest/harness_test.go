package bwtest

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

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

	h := &HarnessTest{
		T:            t,
		dbType:       dbType,
		WalletDBPath: filepath.Join(t.TempDir(), "wallet.db"),
	}

	manager := h.NewWalletManager()
	require.NotNil(t, manager)

	// Force Create to fail after the Manager has opened its database.
	pubPass := []byte("public")
	cfg := wallet.Config{
		Name:          "failed-create",
		PubPassphrase: pubPass,
	}
	w, err := manager.Create(cfg, wallet.CreateWalletParams{
		Mode:              wallet.ModeGenSeed,
		PubPassphrase:     pubPass,
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

	// A fresh Manager proves the database was released.
	reopened, err := wallet.NewManager(t.Context(), wallet.ManagerConfig{
		Backend:     backend,
		DataSource:  h.WalletDBPath,
		ChainParams: h.NetParams(),
	})
	require.NoError(t, err, "teardown must release the database")
	require.NoError(t, reopened.Close())
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
