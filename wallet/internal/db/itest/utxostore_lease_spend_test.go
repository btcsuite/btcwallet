//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// newLeasedSpendFixture creates two wallet UTXOs, leases the first without
// expiry and the second for a duration, and returns an unrecorded transaction
// spending both.
func newLeasedSpendFixture(t *testing.T, store db.Store,
	name string) (uint32, []wire.OutPoint, *wire.MsgTx) {

	t.Helper()

	walletID, outPoints := newLeaseSetFixture(t, store, name, 2)

	_, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       db.LockID{1},
		OutPoint: outPoints[0],
		NoExpiry: true,
	})
	require.NoError(t, err)

	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       db.LockID{1},
		OutPoint: outPoints[1],
		Duration: time.Hour,
	})
	require.NoError(t, err)

	spend := newRegularTx(
		outPoints, []*wire.TxOut{{Value: 15_000, PkScript: []byte{0x51}}},
	)

	return walletID, outPoints, spend
}

// TestConfirmedSpendDeletesLeases verifies that recording a confirmed spend
// deletes the leases on its inputs under either expiration policy, so they
// do not return when the spend is later disconnected and removed.
func TestConfirmedSpendDeletesLeases(t *testing.T) {
	t.Parallel()

	// Arrange: Lease two outputs and build a transaction spending both.
	store := NewTestStore(t)
	walletID, _, spend := newLeasedSpendFixture(
		t, store, "wallet-lease-confirmed-spend",
	)
	block := CreateBlockFixture(t, store.Queries(), 500)

	// Act: Record the spend as confirmed, then disconnect and remove it.
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       spend,
		Received: time.Unix(1710001900, 0),
		Block:    &block,
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)

	err = store.RollbackToBlock(t.Context(), block.Height)
	require.NoError(t, err)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     spend.TxHash(),
	})
	require.NoError(t, err)

	utxos, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
	})
	require.NoError(t, err)

	// Assert: Both outputs are unspent again and neither is leased.
	require.Len(t, utxos, 2)
	require.Empty(t, leasedByID(t, store, walletID))
}

// TestUpdateTxConfirmedSpendDeletesLeases verifies that confirming a recorded
// spend through UpdateTx deletes the leases on its inputs.
func TestUpdateTxConfirmedSpendDeletesLeases(t *testing.T) {
	t.Parallel()

	// Arrange: Lease two outputs and record an unconfirmed spend of both.
	store := NewTestStore(t)
	walletID, _, spend := newLeasedSpendFixture(
		t, store, "wallet-lease-update-confirmed-spend",
	)
	block := CreateBlockFixture(t, store.Queries(), 500)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       spend,
		Received: time.Unix(1710001900, 0),
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)

	// Act: Confirm the spend, then disconnect and remove it.
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     spend.TxHash(),
		State: &db.UpdateTxState{
			Block:  &block,
			Status: db.TxStatusPublished,
		},
	})
	require.NoError(t, err)

	err = store.RollbackToBlock(t.Context(), block.Height)
	require.NoError(t, err)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     spend.TxHash(),
	})
	require.NoError(t, err)

	utxos, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
	})
	require.NoError(t, err)

	// Assert: Both outputs are unspent again and neither is leased.
	require.Len(t, utxos, 2)
	require.Empty(t, leasedByID(t, store, walletID))
}

// TestUnconfirmedSpendKeepsLeases verifies that recording an unconfirmed
// spend keeps the leases on its inputs, so they reserve the outputs again
// once the spend is removed.
func TestUnconfirmedSpendKeepsLeases(t *testing.T) {
	t.Parallel()

	// Arrange: Lease two outputs and build a transaction spending both.
	store := NewTestStore(t)
	walletID, outPoints, spend := newLeasedSpendFixture(
		t, store, "wallet-lease-unconfirmed-spend",
	)

	// Act: Record the spend unconfirmed, then remove it.
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       spend,
		Received: time.Unix(1710001900, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     spend.TxHash(),
	})
	require.NoError(t, err)

	// Assert: Both leases are active again.
	require.Equal(t, map[wire.OutPoint]db.LockID{
		outPoints[0]: {1}, outPoints[1]: {1},
	}, leasedByID(t, store, walletID))
}

// TestUpdateTxUnconfirmedSpendKeepsLeases verifies that rewriting a recorded
// spend's state without a block keeps the leases on its inputs.
func TestUpdateTxUnconfirmedSpendKeepsLeases(t *testing.T) {
	t.Parallel()

	// Arrange: Lease two outputs and record an unconfirmed spend of both.
	store := NewTestStore(t)
	walletID, outPoints, spend := newLeasedSpendFixture(
		t, store, "wallet-lease-update-unconfirmed-spend",
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       spend,
		Received: time.Unix(1710001900, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	// Act: Rewrite the spend's state without a block, then remove it.
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     spend.TxHash(),
		State:    &db.UpdateTxState{Status: db.TxStatusPublished},
	})
	require.NoError(t, err)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     spend.TxHash(),
	})
	require.NoError(t, err)

	// Assert: Both leases are active again.
	require.Equal(t, map[wire.OutPoint]db.LockID{
		outPoints[0]: {1}, outPoints[1]: {1},
	}, leasedByID(t, store, walletID))
}
