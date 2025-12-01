//go:build itest

package itest

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestCreateWallet verifies that CreateWallet correctly creates a wallet
// and returns its information.
func TestCreateWallet(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)
	params := CreateWalletParamsFixture("test-wallet")

	info, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)
	require.NotNil(t, info)

	require.Equal(t, info.ID, uint32(1), "first wallet ID should be 1")
	require.Equal(t, params.Name, info.Name)
	require.Equal(t, params.IsImported, info.IsImported)
	require.Equal(t, params.ManagerVersion, info.ManagerVersion)
	require.Equal(t, params.IsWatchOnly, info.IsWatchOnly)

	require.Nil(t, info.SyncedTo)
	require.Equal(t, uint32(0), info.BirthdayBlock.Height)
}

// TestCreateWallet_DuplicateName verifies that creating a wallet with a
// duplicate name fails with an appropriate error.
func TestCreateWallet_DuplicateName(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)
	params := CreateWalletParamsFixture("duplicate-wallet")

	_, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	// Attempt to create second wallet with same name.
	_, err = store.CreateWallet(t.Context(), params)
	require.Error(t, err, "expected error creating duplicate wallet")

	// We still do not normalize this error across database backends,
	// and each engine returns its own message. Because of that,
	// we only check for the shared parts of the message here.
	require.ErrorContains(t, err, "wallets")
	require.ErrorContains(t, err, "name")
	require.ErrorContains(t, err, "constraint")
}

// TestCreateWallet_Variants tests different wallet types.
func TestCreateWallet_Variants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params func(string) db.CreateWalletParams
	}{
		{
			name:   "imported wallet",
			params: CreateImportedWalletParams,
		},
		{
			name:   "watch-only wallet",
			params: CreateWatchOnlyWalletParams,
		},
		{
			name:   "standard wallet",
			params: CreateWalletParamsFixture,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, _ := NewTestStore(t)
			params := tc.params(tc.name)

			info, err := store.CreateWallet(t.Context(), params)
			require.NoError(t, err)
			require.NotNil(t, info)
			require.Equal(t, params.IsImported, info.IsImported)
			require.Equal(t, params.IsWatchOnly, info.IsWatchOnly)
		})
	}
}

// TestGetWallet verifies that GetWallet retrieves a wallet by name.
func TestGetWallet(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	params := CreateWalletParamsFixture("get-test-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), params.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
}

// TestGetWallet_NotFound verifies that GetWallet returns ErrWalletNotFound
// when the wallet doesn't exist.
func TestGetWallet_NotFound(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	_, err := store.GetWallet(t.Context(), "non-existent-wallet")
	require.Error(t, err)
	require.ErrorIs(t, err, db.ErrWalletNotFound)
}

// TestListWallets verifies that ListWallets returns all wallets.
func TestListWallets(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	// Initially empty.
	wallets, err := store.ListWallets(t.Context())
	require.NoError(t, err)
	require.Empty(t, wallets)

	// Create three wallets.
	names := []string{"wallet-1", "wallet-2", "wallet-3"}
	for _, name := range names {
		params := CreateWalletParamsFixture(name)
		_, err := store.CreateWallet(t.Context(), params)
		require.NoError(t, err)
	}

	wallets, err = store.ListWallets(t.Context())
	require.NoError(t, err)
	require.Len(t, wallets, 3)

	// Verify all names are present.
	walletsName := make([]string, len(wallets))
	for i, w := range wallets {
		walletsName[i] = w.Name
	}
	require.ElementsMatch(t, names, walletsName)
}

// TestUpdateWallet_SyncedTo checks that updating the wallet's synced-to block
// works correctly.
func TestUpdateWallet_SyncedTo(t *testing.T) {
	t.Parallel()

	store, dbConn := NewTestStore(t)

	params := CreateWalletParamsFixture("update-sync-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	block := CreateBlockFixture(t, dbConn, 100)

	updateParams := db.UpdateWalletParams{
		WalletID: created.ID,
		SyncedTo: &block,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved.SyncedTo)
	require.Equal(t, block.Height, retrieved.SyncedTo.Height)

	// Assert fields that were not updated remain unchanged.
	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
	require.Equal(t, created.BirthdayBlock.Height,
		retrieved.BirthdayBlock.Height)
}

// TestUpdateWallet_BirthdayBlock checks that updating the wallet's birthday
// block works correctly.
func TestUpdateWallet_BirthdayBlock(t *testing.T) {
	t.Parallel()

	store, dbConn := NewTestStore(t)

	params := CreateWalletParamsFixture("update-birthday-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	block := CreateBlockFixture(t, dbConn, 50)

	updateParams := db.UpdateWalletParams{
		WalletID:      created.ID,
		BirthdayBlock: &block,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.Equal(t, block.Height, retrieved.BirthdayBlock.Height)
	require.Equal(t, block.Hash, retrieved.BirthdayBlock.Hash)

	// Assert fields that were not updated remain unchanged.
	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
	require.Nil(t, retrieved.SyncedTo)
}

// TestUpdateWallet_NotFound verifies that updating a non-existent wallet fails.
func TestUpdateWallet_NotFound(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	updateParams := db.UpdateWalletParams{
		WalletID: 99999, // Non-existent ID.
	}

	err := store.UpdateWallet(t.Context(), updateParams)
	require.Error(t, err)
	require.ErrorIs(t, err, db.ErrWalletNotFound)
}

// TestGetEncryptedHDSeed verifies retrieving the encrypted HD seed.
func TestGetEncryptedHDSeed(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	params := CreateWalletParamsFixture("seed-wallet")
	expectedSeed := params.EncryptedMasterPrivKey

	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
	require.NoError(t, err)
	require.Equal(t, expectedSeed, seed)
}

// TestGetEncryptedHDSeed_WatchOnly verifies that watch-only wallets
// have no encrypted seed.
func TestGetEncryptedHDSeed_WatchOnly(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	params := CreateWatchOnlyWalletParams("watch-only-seed")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
	require.Nil(t, seed, "watch-only wallets should not have HD seed")
	require.ErrorIs(t, err, db.ErrSecretNotFound)
}

// TestUpdateWalletSecrets checks that updating the wallet secrets works
// correctly.
func TestUpdateWalletSecrets(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	params := CreateWalletParamsFixture("secrets-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	newSecrets := db.UpdateWalletSecretsParams{
		WalletID:                 created.ID,
		MasterPrivParams:         RandomBytes(16),
		EncryptedCryptoPrivKey:   RandomBytes(32),
		EncryptedCryptoScriptKey: RandomBytes(32),
		EncryptedMasterHdPrivKey: RandomBytes(32),
	}

	err = store.UpdateWalletSecrets(t.Context(), newSecrets)
	require.NoError(t, err)

	seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
	require.NoError(t, err)
	require.Equal(t, newSecrets.EncryptedMasterHdPrivKey, seed)
}
