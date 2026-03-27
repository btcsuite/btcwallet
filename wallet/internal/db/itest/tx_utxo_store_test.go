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

// TestCreateTxStoresWalletCredit verifies that CreateTx stores the transaction
// row and the requested wallet-owned output in one atomic write.
//
// Scenario:
//   - One wallet records a new unmined transaction with one wallet-owned
//     credited output.
//
// Setup:
//   - Create one wallet, one derived account, and one wallet-owned address.
//   - Build one transaction that pays that address.
//
// Action:
//   - Insert the transaction through CreateTx.
//
// Assertions:
//   - The transaction row exists.
//   - The credited output exists in the wallet UTXO set.
func TestCreateTxStoresWalletCredit(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-tx-credit")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000300, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	_, ok := txIDByHash(t, store, walletID, tx.TxHash())
	require.True(t, ok)
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: tx.TxHash(), Index: 0,
	}))
}

// TestCreateTxStoresConfirmedCoinbase verifies that CreateTx can record one
// coinbase transaction directly in its confirmed state when the block is
// already known.
//
// Scenario:
//   - One wallet learns about one coinbase credit together with its confirming
//     block.
//
// Setup:
//   - Create one wallet, one derived account, one wallet-owned address, and one
//     matching block fixture.
//   - Build one coinbase transaction that pays that wallet-owned address.
//
// Action:
//   - Insert the coinbase through CreateTx with the block assignment present.
//
// Assertions:
//   - The transaction row exists.
//   - The wallet-owned coinbase output exists in the current UTXO set.
func TestCreateTxStoresConfirmedCoinbase(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-confirmed-coinbase")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	block := CreateBlockFixture(t, store.Queries(), 210)
	coinbaseTx := newCoinbaseTx(addr.ScriptPubKey)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710000350, 0),
		Block:    &block,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	_, ok := txIDByHash(t, store, walletID, coinbaseTx.TxHash())
	require.True(t, ok)
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: coinbaseTx.TxHash(), Index: 0,
	}))
}

// TestCreateTxRejectsInvalidParentWalletOutput verifies that CreateTx rejects a
// child that spends a wallet-owned output whose parent transaction is already
// invalid.
//
// Scenario:
//   - One wallet output exists, but its parent transaction has already been
//     marked failed.
//
// Setup:
//   - Create one wallet-owned parent credit.
//   - Rewrite the parent transaction status to failed.
//   - Build one child transaction that spends that wallet-owned output.
//
// Action:
//   - Insert the child through CreateTx.
//
// Assertions:
//   - CreateTx returns ErrTxInputInvalidParent.
//   - No child row or child spend edge is persisted.
//   - The original parent row remains stored.
func TestCreateTxRejectsInvalidParentWalletOutput(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-invalid-parent")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 50000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710000400, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	setTxStatus(t, store, walletID, parentTx.TxHash(), db.TxStatusFailed)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 49000, PkScript: []byte{0x51}}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710000410, 0),
		Status:   db.TxStatusPending,
	})
	require.ErrorIs(t, err, db.ErrTxInputInvalidParent)
	require.Empty(t, childSpendingTxIDs(t, store, walletID, parentTx.TxHash()))
	_, ok := txIDByHash(t, store, walletID, childTx.TxHash())
	require.False(t, ok)
	_, ok = txIDByHash(t, store, walletID, parentTx.TxHash())
	require.True(t, ok)
}

// TestCreateTxRejectsSecondPendingSpend verifies that CreateTx rejects a second
// pending transaction that spends the same wallet-owned output.
//
// Scenario:
//   - One wallet-owned output already has one pending child spender.
//
// Setup:
//   - Create one wallet-owned parent credit.
//   - Insert one first child transaction that spends it.
//   - Build one second child that spends the same outpoint.
//
// Action:
//   - Insert the second child through CreateTx.
//
// Assertions:
//   - CreateTx returns ErrTxInputConflict.
//   - Only the first child remains recorded as the spender.
//   - The second child row is not inserted.
func TestCreateTxRejectsSecondPendingSpend(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-second-spend-conflict")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710000500, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	spentOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	firstChild := newRegularTx(
		[]wire.OutPoint{spentOutPoint},
		[]*wire.TxOut{{Value: 4000, PkScript: []byte{0x51}}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       firstChild,
		Received: time.Unix(1710000510, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	secondChild := newRegularTx(
		[]wire.OutPoint{spentOutPoint},
		[]*wire.TxOut{{Value: 3000, PkScript: []byte{0x52}}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       secondChild,
		Received: time.Unix(1710000520, 0),
		Status:   db.TxStatusPending,
	})
	require.ErrorIs(t, err, db.ErrTxInputConflict)

	childIDs := childSpendingTxIDs(t, store, walletID, parentTx.TxHash())
	require.Len(t, childIDs, 1)

	_, ok := txIDByHash(t, store, walletID, firstChild.TxHash())
	require.True(t, ok)
	_, ok = txIDByHash(t, store, walletID, secondChild.TxHash())
	require.False(t, ok)
}

// TestCreateTxRejectsDuplicateTx verifies that CreateTx inserts one wallet-
// scoped transaction row only once.
//
// Scenario:
//   - One wallet transaction hash is already present in the store.
//
// Setup:
//   - Create one wallet and insert one pending transaction row.
//
// Action:
//   - Attempt to insert the same transaction hash again.
//
// Assertions:
//   - CreateTx returns ErrTxAlreadyExists.
//   - The original row remains stored once.
func TestCreateTxRejectsDuplicateTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-tx-duplicate")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: []byte{0x51}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000580, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000590, 0),
		Status:   db.TxStatusPending,
	})
	require.ErrorIs(t, err, db.ErrTxAlreadyExists)

	_, ok := txIDByHash(t, store, walletID, tx.TxHash())
	require.True(t, ok)
}

// TestGetTxReturnsStoredPendingTx verifies that GetTx rebuilds the public
// transaction view for one stored unmined row.
//
// Scenario:
//   - One pending wallet transaction has already been inserted.
//
// Setup:
//   - Create one wallet and insert one pending transaction row.
//
// Action:
//   - Retrieve the transaction through GetTx.
//
// Assertions:
//   - GetTx returns the stored hash, status, label, and nil block metadata.
func TestGetTxReturnsStoredPendingTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-tx")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: []byte{0x51}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000600, 0),
		Status:   db.TxStatusPending,
		Label:    "pending-note",
	})
	require.NoError(t, err)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, tx.TxHash(), info.Hash)
	require.Equal(t, db.TxStatusPending, info.Status)
	require.Equal(t, "pending-note", info.Label)
	require.Nil(t, info.Block)
}

// TestGetTxNotFound verifies that GetTx returns ErrTxNotFound when the wallet
// has no matching transaction row.
//
// Scenario:
//   - One wallet has no stored transaction for the requested hash.
//
// Setup:
//   - Create one wallet and choose one random transaction hash.
//
// Action:
//   - Query the missing hash through GetTx.
//
// Assertions:
//   - GetTx returns ErrTxNotFound.
func TestGetTxNotFound(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-tx-missing")

	_, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     RandomHash(),
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestUpdateTxRequiresExistingConfirmedBlock verifies that UpdateTx rejects a
// state patch whose referenced block height is missing from the shared blocks
// table.
//
// Scenario:
//   - One stored pending transaction is later patched with a missing block.
//
// Setup:
//   - Create one wallet and insert one pending transaction row.
//   - Build one block reference without inserting that block row.
//
// Action:
//   - Apply the confirmation patch through UpdateTx.
//
// Assertions:
//   - UpdateTx returns ErrBlockNotFound.
//   - The transaction remains unconfirmed.
func TestUpdateTxRequiresExistingConfirmedBlock(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-confirmed-tx-missing-block")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: []byte{0x51}}},
	)
	block := db.Block{
		Hash:      RandomHash(),
		Height:    240,
		Timestamp: time.Unix(1710000560, 0),
	}

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000570, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     tx.TxHash(),
		State: &db.UpdateTxState{
			Block:  &block,
			Status: db.TxStatusPublished,
		},
	})
	require.ErrorIs(t, err, db.ErrBlockNotFound)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, info.Block)
}

// TestUpdateTxRejectsMismatchedConfirmedBlock verifies that UpdateTx rejects a
// state patch when the supplied block metadata does not match the stored block
// row for that height.
//
// Scenario:
//   - One stored pending transaction is later patched with mismatched block
//     metadata for an existing height.
//
// Setup:
//   - Create one wallet and insert one pending transaction row.
//   - Insert the real block row for the target height.
//   - Build a second block reference with the same height but different hash.
//
// Action:
//   - Apply the mismatched confirmation patch through UpdateTx.
//
// Assertions:
//   - UpdateTx returns ErrBlockMismatch.
//   - The existing transaction row remains unconfirmed and pending.
func TestUpdateTxRejectsMismatchedConfirmedBlock(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-update-tx-block-mismatch")
	queries := store.Queries()

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: []byte{0x51}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000550, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	block := CreateBlockFixture(t, queries, 240)
	mismatchBlock := block
	mismatchBlock.Hash = RandomHash()

	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     tx.TxHash(),
		State: &db.UpdateTxState{
			Block:  &mismatchBlock,
			Status: db.TxStatusPublished,
		},
	})
	require.ErrorIs(t, err, db.ErrBlockMismatch)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, info.Block)
	require.Equal(t, db.TxStatusPending, info.Status)
}

// TestUpdateTxUpdatesStoredLabel verifies that UpdateTx can patch the stored
// user-visible label without mutating chain-state metadata.
//
// Scenario:
//   - One pending wallet transaction already exists with an old label.
//
// Setup:
//   - Create one wallet and insert one pending transaction row with a label.
//
// Action:
//   - Patch only the label through UpdateTx.
//
// Assertions:
//   - The stored label changes.
//   - The transaction stays pending and unconfirmed.
func TestUpdateTxUpdatesStoredLabel(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-update-tx-label")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: []byte{0x51}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000700, 0),
		Status:   db.TxStatusPending,
		Label:    "old-label",
	})
	require.NoError(t, err)

	label := "new-label"
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     tx.TxHash(),
		Label:    &label,
	})
	require.NoError(t, err)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, "new-label", info.Label)
	require.Equal(t, db.TxStatusPending, info.Status)
}

// TestUpdateTxConfirmsStoredPendingTx verifies that UpdateTx can attach a
// confirming block to an already-stored unmined row.
//
// Scenario:
//   - One pending wallet transaction is later observed in a block.
//
// Setup:
//   - Create one wallet and insert one pending transaction row.
//   - Insert one matching block row.
//
// Action:
//   - Apply a published state patch with that block through UpdateTx.
//
// Assertions:
//   - The transaction now carries the block metadata.
//   - The status becomes published.
func TestUpdateTxConfirmsStoredPendingTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-update-tx-confirm")
	queries := store.Queries()

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 6000, PkScript: []byte{0x51}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000710, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	block := CreateBlockFixture(t, queries, 220)
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     tx.TxHash(),
		State: &db.UpdateTxState{
			Block:  &block,
			Status: db.TxStatusPublished,
		},
	})
	require.NoError(t, err)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.NotNil(t, info.Block)
	require.Equal(t, block.Height, info.Block.Height)
	require.Equal(t, block.Hash, info.Block.Hash)
	require.Equal(t, db.TxStatusPublished, info.Status)
}

// TestUpdateTxNotFound verifies that UpdateTx returns ErrTxNotFound when the
// wallet has no matching transaction row.
//
// Scenario:
//   - One wallet has no stored transaction for the requested hash.
//
// Setup:
//   - Create one wallet and one label patch.
//
// Action:
//   - Apply the patch to a random missing tx hash.
//
// Assertions:
//   - UpdateTx returns ErrTxNotFound.
func TestUpdateTxNotFound(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-update-label-missing")

	label := "new-label"
	err := store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     RandomHash(),
		Label:    &label,
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestUpdateTxRejectsEmptyPatch verifies that UpdateTx rejects a request that
// does not ask to mutate any transaction field.
//
// Scenario:
//   - One wallet transaction exists, but the caller provides no label or state
//     mutation.
//
// Setup:
//   - Create one wallet and insert one pending transaction row.
//
// Action:
//   - Call UpdateTx with an empty patch.
//
// Assertions:
//   - UpdateTx returns ErrInvalidParam.
func TestUpdateTxRejectsEmptyPatch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-update-empty-patch")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 6000, PkScript: []byte{0x51}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000720, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.ErrorIs(t, err, db.ErrInvalidParam)
}

// TestListTxnsReturnsRowsWithoutBlock verifies that the no-confirming-block
// query path excludes confirmed rows while still surfacing retained invalid
// history that no longer has block metadata.
//
// Scenario:
//   - One wallet has confirmed history, active unmined history, and retained
//     invalid history without blocks.
//
// Setup:
//   - Insert one confirmed transaction, one pending transaction, and one failed
//     transaction whose block is nil.
//
// Action:
//   - Query ListTxns with UnminedOnly set.
//
// Assertions:
//   - Only unmined rows are returned.
//   - Both the active pending row and the failed history row are present.
func TestListTxnsReturnsRowsWithoutBlock(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-txns-without-block")
	queries := store.Queries()

	confirmedBlock := CreateBlockFixture(t, queries, 200)
	confirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: []byte{0x51}}},
	)
	unminedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 8000, PkScript: []byte{0x52}}},
	)
	failedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 8100, PkScript: []byte{0x53}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       confirmedTx,
		Received: time.Unix(1710000800, 0),
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     confirmedTx.TxHash(),
		State: &db.UpdateTxState{
			Block:  &confirmedBlock,
			Status: db.TxStatusPublished,
		},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       unminedTx,
		Received: time.Unix(1710000810, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       failedTx,
		Received: time.Unix(1710000815, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)
	setTxStatus(t, store, walletID, failedTx.TxHash(), db.TxStatusFailed)

	infos, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		UnminedOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, infos, 2)

	statusesByHash := make(map[chainhash.Hash]db.TxStatus, len(infos))
	for _, info := range infos {
		require.Nil(t, info.Block)
		statusesByHash[info.Hash] = info.Status
	}

	require.Equal(t, db.TxStatusPending, statusesByHash[unminedTx.TxHash()])
	require.Equal(t, db.TxStatusFailed, statusesByHash[failedTx.TxHash()])
}

// TestListTxnsReturnsConfirmedTxsByHeightRange verifies that the
// confirmed-range query path excludes unmined rows and respects the height
// bounds.
//
// Scenario:
//   - One wallet has confirmed transactions at multiple heights plus one
//     unmined row.
//
// Setup:
//   - Insert two confirmed transactions at different heights and one pending
//     transaction without a block.
//
// Action:
//   - Query ListTxns for one exact confirmed height range.
//
// Assertions:
//   - Only the matching confirmed transaction is returned.
//   - The unmined row is excluded.
func TestListTxnsReturnsConfirmedTxsByHeightRange(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-txns-confirmed")
	queries := store.Queries()

	blockOne := CreateBlockFixture(t, queries, 210)
	blockTwo := CreateBlockFixture(t, queries, 211)

	txOne := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 9000, PkScript: []byte{0x51}}},
	)
	txTwo := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 10000, PkScript: []byte{0x52}}},
	)
	unminedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 11000, PkScript: []byte{0x53}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       txOne,
		Received: time.Unix(1710000900, 0),
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     txOne.TxHash(),
		State: &db.UpdateTxState{
			Block:  &blockOne,
			Status: db.TxStatusPublished,
		},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       txTwo,
		Received: time.Unix(1710000910, 0),
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     txTwo.TxHash(),
		State: &db.UpdateTxState{
			Block:  &blockTwo,
			Status: db.TxStatusPublished,
		},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       unminedTx,
		Received: time.Unix(1710000920, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	infos, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		StartHeight: 211,
		EndHeight:   211,
	})
	require.NoError(t, err)
	require.Len(t, infos, 1)
	require.Equal(t, txTwo.TxHash(), infos[0].Hash)
	require.NotNil(t, infos[0].Block)
	require.Equal(t, uint32(211), infos[0].Block.Height)
}

// TestDeleteTxRemovesLeafUnminedTx verifies that DeleteTx removes a leaf
// unmined row and restores any parent spend markers it introduced.
//
// Scenario:
//   - One unmined child transaction is the only spender of one wallet-owned
//     parent output.
//
// Setup:
//   - Create one wallet-owned parent credit and one unmined child spender.
//
// Action:
//   - Delete the child through DeleteTx.
//
// Assertions:
//   - The child row is removed.
//   - The parent output becomes spendable again.
//   - No child spend edges remain.
func TestDeleteTxRemovesLeafUnminedTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-leaf")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710001000, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4000, PkScript: []byte{0x51}}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710001010, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.NoError(t, err)
	require.Empty(t, childSpendingTxIDs(t, store, walletID, parentTx.TxHash()))
	_, ok := txIDByHash(t, store, walletID, childTx.TxHash())
	require.False(t, ok)
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: parentTx.TxHash(), Index: 0,
	}))
}

// TestDeleteTxRejectsNonLeafTx verifies that DeleteTx refuses to erase an
// unmined transaction that still has direct child spenders.
//
// Scenario:
//   - One parent transaction still has one direct unmined child spender.
//
// Setup:
//   - Create one wallet-owned parent credit and one child that spends it.
//
// Action:
//   - Attempt to delete the parent through DeleteTx.
//
// Assertions:
//   - DeleteTx returns ErrDeleteRequiresLeaf.
//   - Both parent and child rows remain stored.
func TestDeleteTxRejectsNonLeafTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-non-leaf")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710001100, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4000, PkScript: addr.ScriptPubKey}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710001110, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     parentTx.TxHash(),
	})
	require.ErrorIs(t, err, db.ErrDeleteRequiresLeaf)
	_, ok := txIDByHash(t, store, walletID, parentTx.TxHash())
	require.True(t, ok)
	_, ok = txIDByHash(t, store, walletID, childTx.TxHash())
	require.True(t, ok)
}

// TestDeleteTxRemovesParentWithFailedChild verifies that DeleteTx only treats
// still-active unmined children as leaf blockers.
//
// Scenario:
//   - One parent transaction still has one direct child row, but that child has
//     already been marked failed.
//
// Setup:
//   - Create one wallet-owned parent credit and one child that spends it.
//   - Mark the child failed to simulate an already-invalid branch.
//
// Action:
//   - Delete the parent through DeleteTx.
//
// Assertions:
//   - DeleteTx succeeds because the failed child is no longer part of the
//     active unmined graph.
//   - The parent row is removed.
func TestDeleteTxRemovesParentWithFailedChild(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-parent-failed-child")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710001115, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4000, PkScript: addr.ScriptPubKey}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710001120, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)
	setTxStatus(t, store, walletID, childTx.TxHash(), db.TxStatusFailed)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     parentTx.TxHash(),
	})
	require.NoError(t, err)

	_, ok := txIDByHash(t, store, walletID, parentTx.TxHash())
	require.False(t, ok)
}

// TestRollbackToBlockFailsCoinbaseDescendants verifies that RollbackToBlock
// marks every unmined descendant of a disconnected coinbase root as failed and
// clears the recorded spend edges they had claimed.
//
// Scenario:
//   - One confirmed coinbase credit has one unmined child spender and one
//     unmined grandchild spender beneath it.
//
// Setup:
//   - Create one wallet-owned coinbase output and confirm it in one block.
//   - Insert one child transaction that spends that output and creates one new
//     wallet-owned credit.
//   - Insert one grandchild that spends the child's wallet-owned output.
//
// Action:
//   - Roll back the block that confirmed the coinbase root.
//
// Assertions:
//   - Both unmined descendants become failed.
//   - The spend edges from the coinbase root and child are cleared.
func TestRollbackToBlockFailsCoinbaseDescendants(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-rollback-coinbase-descendants")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")
	queries := store.Queries()

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	coinbaseTx := newCoinbaseTx(addr.ScriptPubKey)

	block := CreateBlockFixture(t, queries, 300)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710001200, 0),
		Block:    &block,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: coinbaseTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710001210, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	grandchildTx := newRegularTx(
		[]wire.OutPoint{{Hash: childTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 3000, PkScript: []byte{0x51}}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       grandchildTx,
		Received: time.Unix(1710001220, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	require.Len(t, childSpendingTxIDs(t, store, walletID, coinbaseTx.TxHash()),
		1)
	require.Len(t, childSpendingTxIDs(t, store, walletID, childTx.TxHash()), 1)

	err = store.RollbackToBlock(t.Context(), block.Height)
	require.NoError(t, err)

	childInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, childInfo.Status)
	require.Nil(t, childInfo.Block)

	grandchildInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     grandchildTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, grandchildInfo.Status)
	require.Nil(t, grandchildInfo.Block)

	require.Empty(t, childSpendingTxIDs(t, store, walletID, coinbaseTx.TxHash()))
	require.Empty(t, childSpendingTxIDs(t, store, walletID, childTx.TxHash()))
}

// newCoinbaseTx builds a simple coinbase fixture transaction.
func newCoinbaseTx(pkScript []byte) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: ^uint32(0)}})
	tx.AddTxOut(&wire.TxOut{Value: 5000, PkScript: pkScript})

	return tx
}

// newRegularTx builds a simple fixture transaction with the provided inputs and
// outputs.
func newRegularTx(inputs []wire.OutPoint, outputs []*wire.TxOut) *wire.MsgTx {
	tx := wire.NewMsgTx(2)

	for _, prevOut := range inputs {
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: prevOut})
	}

	for _, txOut := range outputs {
		tx.AddTxOut(txOut)
	}

	return tx
}

// randomOutPoint returns one fixture outpoint backed by a random hash.
func randomOutPoint() wire.OutPoint {
	return wire.OutPoint{Hash: RandomHash(), Index: 0}
}
