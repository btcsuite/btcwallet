//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestInvalidateUnminedTxFailsBranch verifies that invalidating one unmined
// root fails the whole dependent branch and restores the wallet-owned parent
// output.
func TestInvalidateUnminedTxFailsBranch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-invalidate-unmined-branch")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	rootTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       rootTx,
			Received: time.Unix(1710003100, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: rootTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4900, PkScript: []byte{0x51}}},
	)
	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       childTx,
			Received: time.Unix(1710003110, 0),
			Status:   db.TxStatusPending,
		},
	)
	require.NoError(t, err)

	grandchildTx := newRegularTx(
		[]wire.OutPoint{{Hash: childTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4800, PkScript: []byte{0x52}}},
	)
	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       grandchildTx,
			Received: time.Unix(1710003120, 0),
			Status:   db.TxStatusPending,
		},
	)
	require.NoError(t, err)

	err = store.InvalidateUnminedTx(
		t.Context(),
		db.InvalidateUnminedTxParams{
			WalletID: walletID,
			Txid:     rootTx.TxHash(),
		},
	)
	require.NoError(t, err)

	rootInfo, err := store.GetTx(
		t.Context(),
		db.GetTxQuery{
			WalletID: walletID,
			Txid:     rootTx.TxHash(),
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, rootInfo.Status)
	require.Nil(t, rootInfo.Block)

	childInfo, err := store.GetTx(
		t.Context(),
		db.GetTxQuery{
			WalletID: walletID,
			Txid:     childTx.TxHash(),
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, childInfo.Status)

	grandchildInfo, err := store.GetTx(
		t.Context(),
		db.GetTxQuery{
			WalletID: walletID,
			Txid:     grandchildTx.TxHash(),
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, grandchildInfo.Status)

	require.Empty(t, childSpendingTxIDs(t, store, walletID, rootTx.TxHash()))
}

// TestInvalidateUnminedTxRejectsConfirmedAndMissing verifies the backend load
// paths for confirmed rows and missing tx hashes.
func TestInvalidateUnminedTxRejectsConfirmedAndMissing(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-invalidate-unmined-errors")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	block := CreateBlockFixture(t, store.Queries(), 320)
	confirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5200, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       confirmedTx,
			Received: time.Unix(1710003130, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	err = store.InvalidateUnminedTx(
		t.Context(),
		db.InvalidateUnminedTxParams{
			WalletID: walletID,
			Txid:     confirmedTx.TxHash(),
		},
	)
	require.ErrorIs(t, err, db.ErrInvalidateTx)

	err = store.InvalidateUnminedTx(
		t.Context(),
		db.InvalidateUnminedTxParams{
			WalletID: walletID,
			Txid:     RandomHash(),
		},
	)
	require.ErrorIs(t, err, db.ErrTxNotFound)
}
