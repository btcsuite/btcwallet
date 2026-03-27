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

// TestGetAndListTxRejectCorruptedStatus verifies that tx reads fail loudly when
// the stored status escapes the supported enum.
func TestGetAndListTxRejectCorruptedStatus(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-corrupted-tx-status")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 265)

	pendingTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2100, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       pendingTx,
			Received: time.Unix(1710000895, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	confirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 3100, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       confirmedTx,
			Received: time.Unix(1710000896, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	corruptTransactionStatus(t, store, walletID, pendingTx.TxHash(), 99)

	_, err = store.GetTx(
		t.Context(),
		db.GetTxQuery{
			WalletID: walletID,
			Txid:     pendingTx.TxHash(),
		},
	)
	require.ErrorContains(t, err, "invalid tx status")

	_, err = store.ListTxns(
		t.Context(),
		db.ListTxnsQuery{
			WalletID:    walletID,
			UnminedOnly: true,
		},
	)
	require.ErrorContains(t, err, "invalid tx status")

	corruptTransactionStatus(t, store, walletID, confirmedTx.TxHash(), 99)

	_, err = store.ListTxns(
		t.Context(),
		db.ListTxnsQuery{
			WalletID:    walletID,
			StartHeight: confirmedBlock.Height,
			EndHeight:   confirmedBlock.Height,
		},
	)
	require.ErrorContains(t, err, "invalid tx status")
}

// TestDeleteTxRejectsCorruptedStatus verifies that DeleteTx rejects stored rows
// with an invalid wallet-visible status code.
func TestDeleteTxRejectsCorruptedStatus(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-corrupted-status")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2300, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000897, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	corruptTransactionStatus(t, store, walletID, tx.TxHash(), 99)

	err = store.DeleteTx(
		t.Context(),
		db.DeleteTxParams{
			WalletID: walletID,
			Txid:     tx.TxHash(),
		},
	)
	require.ErrorContains(t, err, "invalid tx status")
}

// TestListTxnsRejectsCorruptedUnminedHash verifies that unmined transaction
// listings fail when a stored transaction hash cannot be decoded.
func TestListTxnsRejectsCorruptedUnminedHash(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-corrupted-unmined-hash")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2700, PkScript: []byte{0x51}}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710001400, 0),
			Status:   db.TxStatusPending,
		},
	)
	require.NoError(t, err)

	corruptTransactionHash(t, store, walletID, tx.TxHash(), []byte{1, 2, 3})

	_, err = store.ListTxns(
		t.Context(),
		db.ListTxnsQuery{
			WalletID:    walletID,
			UnminedOnly: true,
		},
	)
	require.ErrorContains(t, err, "tx hash")
}

// TestGetTxRejectsCorruptedConfirmedBlockHeight verifies that confirmed reads
// fail when the joined block height cannot map back into the public block model.
func TestGetTxRejectsCorruptedConfirmedBlockHeight(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-corrupted-confirmed-height")
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 280)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2800, PkScript: []byte{0x51}}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710001410, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
		},
	)
	require.NoError(t, err)

	corruptTransactionBlockHeight(t, store, walletID, tx.TxHash(), -1)

	_, err = store.GetTx(
		t.Context(),
		db.GetTxQuery{
			WalletID: walletID,
			Txid:     tx.TxHash(),
		},
	)
	require.ErrorContains(t, err, "block height")
}

// TestDeleteTxRejectsCorruptedLiveChild verifies that DeleteTx surfaces child
// decode failures while checking the live leaf invariant.
func TestDeleteTxRejectsCorruptedLiveChild(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-corrupted-child")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       parentTx,
			Received: time.Unix(1710001015, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4000, PkScript: []byte{0x51}}},
	)
	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       childTx,
			Received: time.Unix(1710001020, 0),
			Status:   db.TxStatusPending,
		},
	)
	require.NoError(t, err)

	corruptTransactionHash(t, store, walletID, childTx.TxHash(), []byte{1, 2, 3})

	err = store.DeleteTx(
		t.Context(),
		db.DeleteTxParams{
			WalletID: walletID,
			Txid:     parentTx.TxHash(),
		},
	)
	require.ErrorContains(t, err, "tx hash")
}

// TestRollbackToBlockRejectsCorruptedCoinbaseRootHash verifies that rollback
// fails loudly when a disconnected coinbase root carries an invalid stored hash.
func TestRollbackToBlockRejectsCorruptedCoinbaseRootHash(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-rollback-corrupted-coinbase-hash")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	coinbaseBlock := CreateBlockFixture(t, queries, 290)
	coinbaseTx := newCoinbaseTx(addr.ScriptPubKey)

	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       coinbaseTx,
			Received: time.Unix(1710001420, 0),
			Block:    &coinbaseBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	corruptTransactionHash(t, store, walletID, coinbaseTx.TxHash(), []byte{1, 2, 3})

	err = store.RollbackToBlock(t.Context(), coinbaseBlock.Height)
	require.ErrorContains(t, err, "rollback coinbase hash")
}
