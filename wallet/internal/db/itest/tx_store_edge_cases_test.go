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

// TestDeleteTxRejectsConfirmedAndMissing verifies DeleteTx's live-unconfirmed
// precondition and not-found handling.
func TestDeleteTxRejectsConfirmedAndMissing(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-confirmed-or-missing")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 260)

	confirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       confirmedTx,
			Received: time.Unix(1710000900, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	err = store.DeleteTx(
		t.Context(),
		db.DeleteTxParams{
			WalletID: walletID,
			Txid:     confirmedTx.TxHash(),
		},
	)
	require.ErrorContains(t, err, "delete requires an unmined transaction")

	confirmedInfo, err := store.GetTx(
		t.Context(),
		db.GetTxQuery{
			WalletID: walletID,
			Txid:     confirmedTx.TxHash(),
		},
	)
	require.NoError(t, err)
	require.NotNil(t, confirmedInfo.Block)

	err = store.DeleteTx(
		t.Context(),
		db.DeleteTxParams{
			WalletID: walletID,
			Txid:     RandomHash(),
		},
	)
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestDeleteTxRejectsNonLeafExternalChild verifies that DeleteTx scans the raw
// unmined graph, not only wallet-owned credit edges, when enforcing leaf-only
// deletion.
func TestDeleteTxRejectsNonLeafExternalChild(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-non-leaf-external-child")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{
			{Value: 6000, PkScript: addr.ScriptPubKey},
			{Value: 500, PkScript: []byte{0x51}},
		},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       parentTx,
			Received: time.Unix(1710001000, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 1}},
		[]*wire.TxOut{{Value: 300, PkScript: []byte{0x52}}},
	)
	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       childTx,
			Received: time.Unix(1710001010, 0),
			Status:   db.TxStatusPending,
		},
	)
	require.NoError(t, err)

	err = store.DeleteTx(
		t.Context(),
		db.DeleteTxParams{
			WalletID: walletID,
			Txid:     parentTx.TxHash(),
		},
	)
	require.ErrorIs(t, err, db.ErrDeleteRequiresLeaf)

	parentInfo, err := store.GetTx(
		t.Context(),
		db.GetTxQuery{
			WalletID: walletID,
			Txid:     parentTx.TxHash(),
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, parentInfo.Status)

	childInfo, err := store.GetTx(
		t.Context(),
		db.GetTxQuery{
			WalletID: walletID,
			Txid:     childTx.TxHash(),
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, childInfo.Status)
}

// TestTxReadsReturnQueryErrorsWhenClosed verifies that transaction read and
// update methods wrap backend query errors when the store is closed.
func TestTxReadsReturnQueryErrorsWhenClosed(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-closed-tx-reads")
	err := store.Close()
	require.NoError(t, err)

	label := "closed"
	err = store.UpdateTx(
		t.Context(),
		db.UpdateTxParams{
			WalletID: walletID,
			Txid:     RandomHash(),
			Label:    &label,
		},
	)
	require.ErrorContains(t, err, "begin tx")

	_, err = store.GetTx(
		t.Context(),
		db.GetTxQuery{
			WalletID: walletID,
			Txid:     RandomHash(),
		},
	)
	require.ErrorContains(t, err, "get tx")

	_, err = store.ListTxns(
		t.Context(),
		db.ListTxnsQuery{
			WalletID:    walletID,
			UnminedOnly: true,
		},
	)
	require.ErrorContains(t, err, "list txns without block")

	_, err = store.ListTxns(
		t.Context(),
		db.ListTxnsQuery{
			WalletID:    walletID,
			StartHeight: 1,
			EndHeight:   1,
		},
	)
	require.ErrorContains(t, err, "list txns by height")
}
