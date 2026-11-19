//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
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

	// Arrange: Persist a confirmed credit and tip, then fail deletion after
	// the rewind has begun inside the same transaction.
	store := NewTestStore(t)
	walletName := "wallet-rollback-atomic"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")
	queries := store.Queries()

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	// The fork block survives the rollback; the sync tip would rewind to it.
	forkBlock := CreateBlockFixture(t, queries, walletID, 419)

	// Confirm a coinbase transaction at the next block and point the wallet
	// sync tip at it, so a successful rollback would visibly move the tip back
	// to the fork block.
	coinbaseBlock := CreateBlockFixture(t, queries, walletID, 420)
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
	forceRollbackBlockDeleteFailure(t, store, walletID)

	beforeTx, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID, Txid: coinbaseTx.TxHash(),
	})
	require.NoError(t, err)

	for _, tc := range []struct {
		name       string
		disconnect bool
	}{
		{
			name: "height rollback",
		},
		{
			name:       "observed disconnect",
			disconnect: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Act: Both public operations reach the same failing delete,
			// after checkpoint mutation but before the transaction commits.
			if tc.disconnect {
				err = store.DisconnectBlock(t.Context(), walletID,
					coinbaseBlock, &forkBlock,
					map[uint32]*chainhash.Hash{coinbaseBlock.Height: nil})
			} else {
				err = store.RollbackToBlock(t.Context(), walletID,
					coinbaseBlock.Height)
			}

			// Assert: Neither a checkpoint nor its confirming transaction
			// changes when any part of the atomic rewind fails.
			require.ErrorContains(t, err, "delete blocks at or above height")
			after, readErr := store.GetWallet(t.Context(), walletName)
			require.NoError(t, readErr)
			require.Equal(t, before, after)
			afterTx, readErr := store.GetTx(t.Context(), db.GetTxQuery{
				WalletID: walletID, Txid: coinbaseTx.TxHash(),
			})
			require.NoError(t, readErr)
			require.Equal(t, beforeTx, afterTx)
		})
	}
}

// TestRollbackToBlockRewindsSyncTipAndRollsBack proves the happy path: a
// rollback to a block height both rewinds the wallet sync tip to the fork point
// at height-1 and disconnects the orphaned block's transactions in one
// transaction.
func TestRollbackToBlockRewindsSyncTipAndRollsBack(t *testing.T) {
	t.Parallel()

	// Arrange: Two Wallets retain different hashes at the same height, each
	// with its own confirmed credit, sync tip and birthday reference.
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
	forkBlock := CreateBlockFixture(t, queries, walletID, 439)

	confirmedBlock := CreateBlockFixture(t, queries, walletID, 440)
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
		WalletID:      walletID,
		SyncedTo:      &confirmedBlock,
		BirthdayBlock: &confirmedBlock,
	})
	require.NoError(t, err)

	otherID := newWallet(t, store, "independent-wallet")
	createDerivedAccount(t, store, otherID, db.KeyScopeBIP0084, "default")
	otherAddr := newDerivedAddress(
		t, store, otherID, db.KeyScopeBIP0084, "default", false,
	)
	otherBlock := confirmedBlock
	otherBlock.Hash[0] ^= 1
	require.NoError(t, store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: otherID, SyncedTo: &otherBlock, BirthdayBlock: &otherBlock,
	}))

	otherTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: otherAddr.ScriptPubKey}},
	)
	require.NoError(t, store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: otherID, Tx: otherTx, Block: &otherBlock,
		Received: time.Unix(1710004300, 0), Status: db.TxStatusPublished,
		Credits: map[uint32]address.Address{0: nil},
	}))
	otherBefore, err := store.GetWallet(t.Context(), "independent-wallet")
	require.NoError(t, err)
	otherTxBefore, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: otherID, Txid: otherTx.TxHash(),
	})
	require.NoError(t, err)
	otherOutputs, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: otherID,
	})
	require.NoError(t, err)

	// Act: Rewind A while B still retains its independent chain view.

	err = store.RollbackToBlock(t.Context(), walletID, confirmedBlock.Height)
	require.NoError(t, err)

	// Assert: A rewinds its checkpoint and confirmation, while every
	// observed B record still resolves to its original replacement hash.
	after, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.NotNil(t, after.SyncedTo)
	require.Equal(t, forkBlock.Height, after.SyncedTo.Height)
	require.Equal(t, forkBlock.Hash, after.SyncedTo.Hash)
	require.Equal(t, after.SyncedTo, after.BirthdayBlock)

	// The previously confirmed transaction is now unmined.
	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, txInfo.Block)

	otherAfter, err := store.GetWallet(t.Context(), "independent-wallet")
	require.NoError(t, err)
	require.Equal(t, otherBefore, otherAfter)
	otherTxAfter, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: otherID, Txid: otherTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, otherTxBefore, otherTxAfter)
	otherOutputsAfter, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: otherID,
	})
	require.NoError(t, err)
	require.Equal(t, otherOutputs, otherOutputsAfter)
}
