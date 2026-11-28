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

// TestDisconnectBlockAtomicRollsBackSyncTipOnFailure proves that
// DisconnectBlock rewinds the wallet sync tip and rolls back tx state inside
// one backend tx: when the block-deletion step fails, the sync-tip rewind is
// discarded rather than committed on its own.
//
// The scenario forces a mid-disconnect failure with a backend trigger that
// fails wallet_blocks deletion. DisconnectBlock rewinds the wallet sync state
// to the fork point, then fails while deleting the block row. Because both
// effects share one tx, the wallet's persisted sync tip, confirmed tx, and
// block row must remain intact.
func TestDisconnectBlockAtomicRollsBackSyncTipOnFailure(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := NewTestStore(t)
	walletName := "wallet-disconnect-atomic"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")
	queries := store.Queries()

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	// The fork block survives the disconnect; the sync tip would rewind to it.
	forkBlock := CreateBlockFixture(t, queries, walletID, 419)

	// Confirm a coinbase tx at the next block and point the wallet sync tip at
	// it, so a successful disconnect would move the tip back to the fork block.
	coinbaseBlock := CreateBlockFixture(t, queries, walletID, 420)
	coinbaseTx := newCoinbaseTx(addr.ScriptPubKey)
	err := store.CreateTx(ctx, db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710004200, 0),
		Block:    &coinbaseBlock,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.UpdateWallet(ctx, db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &coinbaseBlock,
	})
	require.NoError(t, err)

	// Capture the pre-disconnect wallet and tx snapshots before installing the
	// delete failure trigger.
	beforeWallet, err := store.GetWallet(ctx, walletName)
	require.NoError(t, err)
	require.NotNil(t, beforeWallet.SyncedTo)
	require.Equal(t, coinbaseBlock.Height, beforeWallet.SyncedTo.Height)

	beforeTx, err := store.GetTx(ctx, db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)

	// Force the wallet_blocks deletion stage to fail after disconnect has
	// rewound the wallet sync state inside the same tx.
	forceRollbackBlockDeleteFailure(t, store, walletID)

	// Attempt to disconnect the coinbase block and verify the injected trigger
	// aborts the operation.
	err = store.DisconnectBlock(
		ctx, walletID, coinbaseBlock, &forkBlock,
		map[uint32]*chainhash.Hash{coinbaseBlock.Height: nil},
	)
	require.ErrorContains(t, err, "delete disconnected block")
	require.ErrorContains(t, err, "forced rollback block delete failure")

	// Verify the failed disconnect left the sync tip, confirmed coinbase tx,
	// and stored block row unchanged.
	afterWallet, err := store.GetWallet(ctx, walletName)
	require.NoError(t, err)
	require.Equal(t, beforeWallet, afterWallet)

	afterTx, err := store.GetTx(ctx, db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, beforeTx, afterTx)

	blocks, err := store.ListSyncedBlocks(ctx, db.ListSyncedBlocksQuery{
		WalletID:    walletID,
		StartHeight: coinbaseBlock.Height,
		EndHeight:   coinbaseBlock.Height,
	})
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Equal(t, coinbaseBlock.Hash, blocks[0].Hash)
}

// TestDisconnectBlockIsolatesWalletHistory proves that two Wallets in one SQL
// Store keep independent same-height block rows, checkpoints, and confirmed
// txns, and disconnecting one Wallet's tip does not modify the other Wallet's
// history.
func TestDisconnectBlockIsolatesWalletHistory(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := NewTestStore(t)
	queries := store.Queries()

	// Create two independent Wallets with default accounts and receive
	// addresses in the same Store.
	walletAName := "wallet-history-iso-a"
	walletBName := "wallet-history-iso-b"
	walletAID := newWallet(t, store, walletAName)
	walletBID := newWallet(t, store, walletBName)
	createDerivedAccount(t, store, walletAID, db.KeyScopeBIP0084, "default")
	createDerivedAccount(t, store, walletBID, db.KeyScopeBIP0084, "default")

	addrA := newDerivedAddress(
		t, store, walletAID, db.KeyScopeBIP0084, "default", false,
	)
	addrB := newDerivedAddress(
		t, store, walletBID, db.KeyScopeBIP0084, "default", false,
	)

	// Persist distinct block hashes at the same heights for both Wallets and
	// confirm one tx in each Wallet's tip block.
	forkA := CreateBlockFixture(t, queries, walletAID, 500)
	forkB := CreateBlockFixture(t, queries, walletBID, 500)
	tipA := CreateBlockFixture(t, queries, walletAID, 501)
	tipB := CreateBlockFixture(t, queries, walletBID, 501)
	require.NotEqual(t, tipA.Hash, tipB.Hash)

	txA := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: addrA.ScriptPubKey}},
	)
	err := store.CreateTx(ctx, db.CreateTxParams{
		WalletID: walletAID,
		Tx:       txA,
		Received: time.Unix(1710005000, 0),
		Block:    &tipA,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	txB := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 8000, PkScript: addrB.ScriptPubKey}},
	)
	err = store.CreateTx(ctx, db.CreateTxParams{
		WalletID: walletBID,
		Tx:       txB,
		Received: time.Unix(1710005001, 0),
		Block:    &tipB,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.UpdateWallet(ctx, db.UpdateWalletParams{
		WalletID: walletAID,
		SyncedTo: &tipA,
	})
	require.NoError(t, err)

	err = store.UpdateWallet(ctx, db.UpdateWalletParams{
		WalletID: walletBID,
		SyncedTo: &tipB,
	})
	require.NoError(t, err)

	// Verify GetWallet resolves each Wallet's own same-height block hash
	// before disconnecting Wallet A.
	beforeA, err := store.GetWallet(ctx, walletAName)
	require.NoError(t, err)
	require.NotNil(t, beforeA.SyncedTo)
	require.Equal(t, tipA.Height, beforeA.SyncedTo.Height)
	require.Equal(t, tipA.Hash, beforeA.SyncedTo.Hash)

	beforeB, err := store.GetWallet(ctx, walletBName)
	require.NoError(t, err)
	require.NotNil(t, beforeB.SyncedTo)
	require.Equal(t, tipB.Height, beforeB.SyncedTo.Height)
	require.Equal(t, tipB.Hash, beforeB.SyncedTo.Hash)

	// Disconnect Wallet A's tip block while leaving Wallet B untouched.
	err = store.DisconnectBlock(
		ctx, walletAID, tipA, &forkA,
		map[uint32]*chainhash.Hash{tipA.Height: nil},
	)
	require.NoError(t, err)

	// Verify Wallet A rewound to forkA, unconfirmed txA, and deleted its tip
	// block row.
	afterA, err := store.GetWallet(ctx, walletAName)
	require.NoError(t, err)
	require.NotNil(t, afterA.SyncedTo)
	require.Equal(t, forkA.Height, afterA.SyncedTo.Height)
	require.Equal(t, forkA.Hash, afterA.SyncedTo.Hash)

	txInfoA, err := store.GetTx(ctx, db.GetTxQuery{
		WalletID: walletAID,
		Txid:     txA.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, txInfoA.Block)

	_, err = store.ListSyncedBlocks(ctx, db.ListSyncedBlocksQuery{
		WalletID:    walletAID,
		StartHeight: tipA.Height,
		EndHeight:   tipA.Height,
	})
	require.ErrorIs(t, err, db.ErrBlockNotFound)

	// Verify Wallet B retained its tip checkpoint, block hash, and confirmed tx
	// at the same height.
	afterB, err := store.GetWallet(ctx, walletBName)
	require.NoError(t, err)
	require.NotNil(t, afterB.SyncedTo)
	require.Equal(t, tipB.Height, afterB.SyncedTo.Height)
	require.Equal(t, tipB.Hash, afterB.SyncedTo.Hash)

	txInfoB, err := store.GetTx(ctx, db.GetTxQuery{
		WalletID: walletBID,
		Txid:     txB.TxHash(),
	})
	require.NoError(t, err)
	require.NotNil(t, txInfoB.Block)
	require.Equal(t, tipB.Height, txInfoB.Block.Height)
	require.Equal(t, tipB.Hash, txInfoB.Block.Hash)

	blocksB, err := store.ListSyncedBlocks(ctx, db.ListSyncedBlocksQuery{
		WalletID:    walletBID,
		StartHeight: forkB.Height,
		EndHeight:   tipB.Height,
	})
	require.NoError(t, err)
	require.Len(t, blocksB, 2)
	require.Equal(t, forkB.Hash, blocksB[0].Hash)
	require.Equal(t, tipB.Hash, blocksB[1].Hash)
}
