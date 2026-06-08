//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestRollbackToBlockAtomicRollsBackSyncTipOnFailure proves that
// RollbackToBlock rewinds the wallet sync tip and rolls back transaction state
// inside one backend transaction: when the rollback step fails, the sync-tip
// rewind is discarded rather than committed on its own.
//
// The scenario forces a mid-rollback failure with a backend trigger that fails
// block deletion. RollbackToBlock rewinds the wallet sync state to the fork
// point, then fails while deleting block rows. Because both effects share one
// transaction, the wallet's persisted sync tip must remain at its original
// block.
//
// This test is non-tautological: a sync-state rewind committed in a separate
// transaction from the block rollback would leave the wallet pointed below the
// coinbase block even though the rollback failed, failing the final assertion.
func TestRollbackToBlockAtomicRollsBackSyncTipOnFailure(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletName := "wallet-rollback-atomic"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")
	queries := store.Queries()

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	// The fork block survives the rollback; the sync tip would rewind to it.
	forkBlock := CreateBlockFixture(t, queries, 419)

	// Confirm a coinbase transaction at the next block and point the wallet
	// sync tip at it, so a successful rollback would visibly move the tip back
	// to the fork block.
	coinbaseBlock := CreateBlockFixture(t, queries, 420)
	coinbaseTx := newCoinbaseTx(addr.ScriptPubKey)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710004200, 0),
		Block:    &coinbaseBlock,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &coinbaseBlock,
	})
	require.NoError(t, err)

	// Confirm the starting sync tip is the coinbase block.
	before, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.NotNil(t, before.SyncedTo)
	require.Equal(t, coinbaseBlock.Height, before.SyncedTo.Height)

	// Force the block deletion stage to fail after rollback has rewound the
	// wallet sync state inside the same transaction.
	forceRollbackBlockDeleteFailure(t, store)

	// The rollback (boundary = coinbase height) must fail while deleting the
	// rollback block after rewinding the sync state to the fork point.
	err = store.RollbackToBlock(t.Context(), coinbaseBlock.Height)
	require.ErrorContains(t, err, "delete blocks at or above height")

	// The sync tip must be unchanged: the failed rollback rolled the sync-tip
	// rewind back with it, so the wallet still points at the coinbase block.
	after, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.NotNil(t, after.SyncedTo)
	require.Equal(t, coinbaseBlock.Height, after.SyncedTo.Height)
	require.NotEqual(t, forkBlock.Height, after.SyncedTo.Height)
}

// TestRollbackToBlockRewindsSyncTipAndRollsBack proves the happy path: a
// rollback to a block height both rewinds the wallet sync tip to the fork point
// at height-1 and disconnects the orphaned block's transactions in one
// transaction.
func TestRollbackToBlockRewindsSyncTipAndRollsBack(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletName := "wallet-rollback-happy"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")
	queries := store.Queries()

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	// The fork block at height-1 survives the rollback and becomes the new
	// sync tip.
	forkBlock := CreateBlockFixture(t, queries, 439)

	confirmedBlock := CreateBlockFixture(t, queries, 440)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 6000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710004300, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &confirmedBlock,
	})
	require.NoError(t, err)

	err = store.RollbackToBlock(t.Context(), confirmedBlock.Height)
	require.NoError(t, err)

	// The sync tip moved back to the fork point at height-1.
	after, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.NotNil(t, after.SyncedTo)
	require.Equal(t, forkBlock.Height, after.SyncedTo.Height)
	require.Equal(t, forkBlock.Hash, after.SyncedTo.Hash)

	// The previously confirmed transaction is now unmined.
	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, txInfo.Block)
}
