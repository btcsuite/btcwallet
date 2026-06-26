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

// TestCreateTxRejectsUnknownCreditAddress verifies that credited outputs must
// resolve to a wallet-owned address before CreateTx can store the UTXO row.
func TestCreateTxRejectsUnknownCreditAddress(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-unknown-credit-address")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2500, PkScript: []byte{0x51}}},
	)

	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000800, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.ErrorIs(t, err, db.ErrAddressNotFound)

	_, err = store.GetTx(
		t.Context(),
		db.GetTxQuery{
			WalletID: walletID,
			Txid:     tx.TxHash(),
		},
	)
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestCreateTxRejectsInvalidParams verifies that CreateTx returns shared
// parameter-validation errors before opening a backend transaction.
func TestCreateTxRejectsInvalidParams(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-invalid-create-tx-params")

	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Status:   db.TxStatusPending,
		},
	)
	require.ErrorContains(t, err, "tx is required")
}

// TestCreateTxRejectsDuplicateConfirmedTransaction verifies that duplicate
// confirmed inserts fail instead of silently creating a second row.
func TestCreateTxRejectsDuplicateConfirmedTransaction(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-duplicate-confirmed-tx")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 261)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 4500, PkScript: addr.ScriptPubKey}},
	)
	params := db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000850, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	}

	err := store.CreateTx(t.Context(), params)
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), params)
	require.ErrorIs(t, err, db.ErrTxAlreadyExists)
}

// TestCreateTxRejectsMissingConfirmingBlockForExistingUnminedRow verifies that
// re-confirming an existing unmined row still requires the confirming block to
// exist in block history.
func TestCreateTxRejectsMissingConfirmingBlockForExistingUnminedRow(
	t *testing.T) {

	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-missing-confirming-block")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 4600, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000860, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000861, 0),
			Block: &db.Block{
				Hash:      RandomHash(),
				Height:    999,
				Timestamp: time.Unix(1710000862, 0),
			},
			Status:  db.TxStatusPublished,
			Credits: map[uint32]address.Address{0: nil},
		},
	)
	require.ErrorContains(t, err, "require confirming block")
}
