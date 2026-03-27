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
