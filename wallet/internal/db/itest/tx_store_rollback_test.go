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

// TestDisconnectBlockIdentities checks the observed-disconnect guard separately
// from height rollback, including a height with no transaction to classify it.
func TestDisconnectBlockIdentities(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		storedHash chainhash.Hash
		forkDelta  byte
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
			name:       "stale after replacement with unrelated fork",
			forkDelta:  1,
			storedHash: chainhash.Hash{3},
			known:      true,
		},
		{
			name:       "wrong fork hash",
			storedHash: chainhash.Hash{2},
			forkDelta:  1,
			known:      true,
			wantErr:    db.ErrBlockMismatch,
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
			// whether both references rewind, without touching the sibling.
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
				WalletID:      walletID,
				SyncedTo:      &stored,
				BirthdayBlock: &stored,
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

			// Supply a different fork identity at the stored height when the
			// case tests stale evidence or an invalid rewind destination.
			previous := fork
			previous.Hash[0] ^= tc.forkDelta

			// Act: Submit the observed block and claimed fork in one write.
			err = store.DisconnectBlock(t.Context(), walletID,
				disconnected, &previous, canonical)

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
			require.Equal(t, current.SyncedTo, current.BirthdayBlock)

			// Reading the retained row also detects history deletion hidden
			// behind an otherwise unchanged checkpoint.
			blocks, err := store.ListSyncedBlocks(
				t.Context(), db.ListSyncedBlocksQuery{
					WalletID: walletID, StartHeight: want.Height,
					EndHeight: want.Height,
				},
			)
			require.NoError(t, err)
			require.Len(t, blocks, 1)
			require.Equal(t, want.Hash, blocks[0].Hash)

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
	// empty row at 420 and coinbase at 421 are already recorded. The orphan
	// at 422 cannot invalidate that history or demand proof for the empty tail.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "canonical-live-history")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")
	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	fork := CreateBlockFixture(t, store.Queries(), walletID, 419)
	empty := CreateBlockFixture(t, store.Queries(), walletID, 420)
	canonical := CreateBlockFixture(t, store.Queries(), walletID, 421)
	orphan := CreateBlockFixture(t, store.Queries(), walletID, 422)
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

	// Act: The source detached 422; its earlier proven checkpoint fork does
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
	retained, err := store.ListSyncedBlocks(
		t.Context(), db.ListSyncedBlocksQuery{
			WalletID:    walletID,
			StartHeight: empty.Height,
			EndHeight:   empty.Height,
		},
	)
	require.NoError(t, err)
	require.Equal(t, empty.Hash, retained[0].Hash)
	_, err = store.ListSyncedBlocks(t.Context(), db.ListSyncedBlocksQuery{
		WalletID:    walletID,
		StartHeight: orphan.Height,
		EndHeight:   orphan.Height,
	})
	require.ErrorIs(t, err, db.ErrBlockNotFound)
}
