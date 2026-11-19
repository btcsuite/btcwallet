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

// TestDisconnectBlockIdentities checks the observed-disconnect guard separately
// from height rollback, including a height with no transaction to classify it.
func TestDisconnectBlockIdentities(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		storedHash chainhash.Hash
		known      bool
		wantRewind bool
		wantErr    error
	}{
		{
			name:       "matching orphan",
			storedHash: chainhash.Hash{2},
			known:      true,
			wantRewind: true,
		},
		{
			name:       "stale after replacement",
			storedHash: chainhash.Hash{3},
			known:      true,
		},
		{
			name:       "unknown empty height",
			storedHash: chainhash.Hash{2},
			wantErr:    db.ErrInvalidParam,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: The observed height has no transactions. Its owned
			// block identity and explicit canonical evidence must decide
			// whether it can be removed, without touching the other Wallet.
			store := NewTestStore(t)
			walletID := newWallet(t, store, "disconnect-owner")
			fork := CreateBlockFixture(t, store.Queries(), walletID, 1)
			disconnected := db.Block{
				Height:    2,
				Hash:      chainhash.Hash{2},
				Timestamp: time.Unix(2, 0).UTC(),
			}
			stored := disconnected
			stored.Hash = tc.storedHash
			err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
				WalletID: walletID, SyncedTo: &stored,
			})
			require.NoError(t, err)
			otherID := newWallet(t, store, "disconnect-sibling")
			otherBlock := disconnected
			otherBlock.Hash = chainhash.Hash{99}
			err = store.UpdateWallet(t.Context(), db.UpdateWalletParams{
				WalletID: otherID, SyncedTo: &otherBlock,
			})
			require.NoError(t, err)
			otherBefore, err := store.GetWallet(
				t.Context(), "disconnect-sibling",
			)
			require.NoError(t, err)

			canonical := make(map[uint32]*chainhash.Hash)
			if tc.known {
				canonical[disconnected.Height] = &chainhash.Hash{4}
			}

			// Act: Validate and apply the actual observed-disconnect API.
			err = store.DisconnectBlock(t.Context(), walletID,
				disconnected, &fork, canonical)

			// Assert: Only a proven matching orphan rewinds; both rejected
			// evidence and a delayed old event preserve the installed tip.
			require.ErrorIs(t, err, tc.wantErr)
			current, err := store.GetWallet(
				t.Context(), "disconnect-owner",
			)
			require.NoError(t, err)

			want := stored
			if tc.wantRewind {
				want = fork
			}

			require.Equal(t, want.Height, current.SyncedTo.Height)
			require.Equal(t, want.Hash, current.SyncedTo.Hash)
			otherAfter, err := store.GetWallet(
				t.Context(), "disconnect-sibling",
			)
			require.NoError(t, err)
			require.Equal(t, otherBefore, otherAfter)
		})
	}
}

// TestDisconnectBlockPreservesCanonicalHistory protects live observations above
// a lagging checkpoint from an unrelated later block's disconnection.
func TestDisconnectBlockPreservesCanonicalHistory(t *testing.T) {
	t.Parallel()

	// Arrange: Catch-up is committed only through 419, but a live canonical
	// coinbase at 420 and its pending spend are already recorded. The orphan
	// at 421 must not give a rewind authority over that earlier valid history.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "canonical-live-history")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")
	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	fork := CreateBlockFixture(t, store.Queries(), walletID, 419)
	canonical := CreateBlockFixture(t, store.Queries(), walletID, 420)
	orphan := CreateBlockFixture(t, store.Queries(), walletID, 421)
	coinbase := newCoinbaseTx(addr.ScriptPubKey)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbase,
		Block:    &canonical,
		Status:   db.TxStatusPublished,
		Received: time.Unix(1710004200, 0),
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	spend := newRegularTx(
		[]wire.OutPoint{{Hash: coinbase.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 1000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       spend,
		Status:   db.TxStatusPublished,
		Received: time.Unix(1710004201, 0),
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)
	err = store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID, SyncedTo: &fork,
	})
	require.NoError(t, err)
	coinbaseBefore, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID, Txid: coinbase.TxHash(),
	})
	require.NoError(t, err)
	spendBefore, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID, Txid: spend.TxHash(),
	})
	require.NoError(t, err)

	// Act: The source detached 421; its earlier proven checkpoint fork does
	// not imply that canonical observations between 419 and 421 are abandoned.
	err = store.DisconnectBlock(t.Context(), walletID, orphan, &fork,
		map[uint32]*chainhash.Hash{
			canonical.Height: &canonical.Hash,
			orphan.Height:    nil,
		})

	// Assert: Keep both the valid pending graph and canonical confirmation.
	// The empty orphan disappears without moving the committed checkpoint.
	require.NoError(t, err)
	coinbaseAfter, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID, Txid: coinbase.TxHash(),
	})
	require.NoError(t, err)
	spendAfter, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID, Txid: spend.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, spendBefore, spendAfter)
	require.Equal(t, coinbaseBefore, coinbaseAfter)
	current, err := store.GetWallet(t.Context(), "canonical-live-history")
	require.NoError(t, err)
	require.Equal(t, fork.Height, current.SyncedTo.Height)
	require.Equal(t, fork.Hash, current.SyncedTo.Hash)
	_, err = store.ListSyncedBlocks(t.Context(), db.ListSyncedBlocksQuery{
		WalletID:    walletID,
		StartHeight: orphan.Height,
		EndHeight:   orphan.Height,
	})
	require.ErrorIs(t, err, db.ErrBlockNotFound)
}
