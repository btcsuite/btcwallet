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

// TestRollbackPreservesStateOnFailure checks that both rollback entry points
// restore Wallet progress and transaction state if deleting the block fails.
func TestRollbackPreservesStateOnFailure(t *testing.T) {
	t.Parallel()

	for _, method := range []string{"RollbackToBlock", "DisconnectBlock"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			// Arrange: Give this method its own confirmed credit and tip.
			// The delete trigger fails after the reference rewind.
			const name = "wallet-rollback-atomic"

			ctx := t.Context()
			store := NewTestStore(t)
			id := newWallet(t, store, name)
			createDerivedAccount(
				t, store, id, db.KeyScopeBIP0084, "default",
			)
			addr := newDerivedAddress(
				t, store, id, db.KeyScopeBIP0084, "default", false,
			)

			fork := CreateBlockFixture(t, store.Queries(), id, 419)
			tip := CreateBlockFixture(t, store.Queries(), id, 420)
			reward := newCoinbaseTx(addr.ScriptPubKey)
			err := store.CreateTx(ctx, db.CreateTxParams{
				WalletID: id,
				Tx:       reward,
				Received: time.Unix(1710004200, 0),
				Block:    &tip,
				Status:   db.TxStatusPublished,
				Credits:  map[uint32]address.Address{0: nil},
			})
			require.NoError(t, err)
			err = store.UpdateWallet(ctx, db.UpdateWalletParams{
				WalletID: id, SyncedTo: &tip,
			})
			require.NoError(t, err)

			before, err := store.GetWallet(ctx, name)
			require.NoError(t, err)

			query := db.GetTxQuery{WalletID: id, Txid: reward.TxHash()}
			beforeTx, err := store.GetTx(ctx, query)
			require.NoError(t, err)
			forceRollbackBlockDeleteFailure(t, store, id)

			// Act: Trigger deletion through the selected public entry point.
			switch method {
			case "RollbackToBlock":
				err = store.RollbackToBlock(ctx, id, tip.Height)

			case "DisconnectBlock":
				err = store.DisconnectBlock(ctx, id, tip, &fork,
					map[uint32]*chainhash.Hash{tip.Height: nil})
			}

			// Assert: Identify the injected failure by driver code and text,
			// then compare both snapshots after the failed transaction.
			requireDriverConstraintError(
				t, err, driverRollbackDeleteFailure,
			)
			require.ErrorContains(
				t, err, "forced rollback block delete failure",
			)
			after, err := store.GetWallet(ctx, name)
			require.NoError(t, err)
			require.Equal(t, before, after)

			afterTx, err := store.GetTx(ctx, query)
			require.NoError(t, err)
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
