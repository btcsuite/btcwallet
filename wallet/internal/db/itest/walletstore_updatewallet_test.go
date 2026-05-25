//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestUpdateWalletSyncedTo checks that updating the wallet's synced-to block
// works correctly.
func TestUpdateWalletSyncedTo(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()

	params := CreateWalletParamsFixture("update-sync-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	block := CreateBlockFixture(t, queries, 100)

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
	require.Nil(t, retrieved.BirthdayBlock)
}

// TestUpdateWalletBirthdayBlock checks that updating the wallet's birthday
// block works correctly.
func TestUpdateWalletBirthdayBlock(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()

	params := CreateWalletParamsFixture("update-birthday-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	// Initially, BirthdayBlock should be nil.
	require.Nil(t, created.BirthdayBlock)

	block := CreateBlockFixture(t, queries, 50)

	updateParams := db.UpdateWalletParams{
		WalletID:      created.ID,
		BirthdayBlock: &block,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved.BirthdayBlock)
	require.Equal(t, block.Height, retrieved.BirthdayBlock.Height)
	require.Equal(t, block.Hash, retrieved.BirthdayBlock.Hash)
	require.Equal(t, block.Timestamp.Unix(),
		retrieved.BirthdayBlock.Timestamp.Unix())

	// Assert fields that were not updated remain unchanged.
	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
	require.Nil(t, retrieved.SyncedTo)
}

// TestUpdateWalletBirthday checks that updating the wallet's birthday
// timestamp works correctly.
func TestUpdateWalletBirthday(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("birthday-timestamp-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	// Set birthday timestamp without setting birthday block.
	birthdayTime := time.Now().UTC().Add(-30 * 24 * time.Hour)
	updateParams := db.UpdateWalletParams{
		WalletID: created.ID,
		Birthday: &birthdayTime,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.Equal(t, birthdayTime.Unix(), retrieved.Birthday.Unix())

	// Assert fields that were not updated remain unchanged.
	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
	require.Nil(t, retrieved.BirthdayBlock)
	require.Nil(t, retrieved.SyncedTo)
}

// TestUpdateWalletNotFound verifies that updating a non-existent wallet fails.
func TestUpdateWalletNotFound(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	before := store.StatsSnapshot()

	updateParams := db.UpdateWalletParams{
		WalletID: 99999, // Non-existent ID.
	}

	err := store.UpdateWallet(t.Context(), updateParams)
	require.Error(t, err)
	require.ErrorIs(t, err, db.ErrWalletNotFound)

	after := store.StatsSnapshot()
	require.Equal(t, before, after)
}

// TestUpdateWalletAutoBlockInsertion verifies that UpdateWallet automatically
// inserts blocks when updating SyncedTo or BirthdayBlock.
func TestUpdateWalletAutoBlockInsertion(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("auto-block-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	// Create a block WITHOUT pre-inserting it into the blocks table.
	block := db.Block{
		Height:    uint32(100),
		Hash:      RandomHash(),
		Timestamp: time.Now().UTC(),
	}

	// Update wallet with SyncedTo - should automatically insert the block.
	updateParams := db.UpdateWalletParams{
		WalletID: created.ID,
		SyncedTo: &block,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	// Verify the wallet was updated.
	retrieved, err := store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved.SyncedTo)
	require.Equal(t, block.Height, retrieved.SyncedTo.Height)
	require.Equal(t, block.Hash, retrieved.SyncedTo.Hash)

	// Update again with the same block - should be idempotent.
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err, "updating with same block should be idempotent")

	// Create another block for BirthdayBlock.
	birthdayBlock := db.Block{
		Height:    uint32(50),
		Hash:      RandomHash(),
		Timestamp: time.Now().UTC().Add(-time.Hour),
	}

	// Update wallet with BirthdayBlock - should automatically insert it.
	updateParams = db.UpdateWalletParams{
		WalletID:      created.ID,
		BirthdayBlock: &birthdayBlock,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	// Verify both blocks are set.
	retrieved, err = store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved.SyncedTo)
	require.NotNil(t, retrieved.BirthdayBlock)
	require.Equal(t, block.Height, retrieved.SyncedTo.Height)
	require.Equal(t, birthdayBlock.Height, retrieved.BirthdayBlock.Height)
}
