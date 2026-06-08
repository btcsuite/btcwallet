//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	"github.com/stretchr/testify/require"
)

// TestLeaseOutputMissingUtxo verifies that leasing a missing outpoint returns
// the public not-found error.
func TestLeaseOutputMissingUtxo(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-lease-missing-utxo")

	_, err := store.LeaseOutput(
		t.Context(),
		db.LeaseOutputParams{
			WalletID: walletID,
			ID:       RandomHash(),
			OutPoint: wire.OutPoint{Hash: RandomHash(), Index: 0},
			Duration: time.Minute,
		},
	)
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestReleaseOutputMissingUtxo verifies that releasing a missing outpoint
// returns the public not-found error.
func TestReleaseOutputMissingUtxo(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-release-missing-utxo")

	err := store.ReleaseOutput(
		t.Context(),
		db.ReleaseOutputParams{
			WalletID: walletID,
			ID:       RandomHash(),
			OutPoint: wire.OutPoint{Hash: RandomHash(), Index: 0},
		},
	)
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestReleaseOutputTwiceIsNoOp verifies that a second release becomes a no-op
// after the original lease has already been removed.
func TestReleaseOutputTwiceIsNoOp(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-release-output-twice")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 270)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 8000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710001300, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	leaseOutPoint := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
	leaseID := RandomHash()
	_, err = store.LeaseOutput(
		t.Context(),
		db.LeaseOutputParams{
			WalletID: walletID,
			ID:       leaseID,
			OutPoint: leaseOutPoint,
			Duration: time.Hour,
		},
	)
	require.NoError(t, err)

	err = store.ReleaseOutput(
		t.Context(),
		db.ReleaseOutputParams{
			WalletID: walletID,
			ID:       leaseID,
			OutPoint: leaseOutPoint,
		},
	)
	require.NoError(t, err)

	err = store.ReleaseOutput(
		t.Context(),
		db.ReleaseOutputParams{
			WalletID: walletID,
			ID:       leaseID,
			OutPoint: leaseOutPoint,
		},
	)
	require.NoError(t, err)

	leases, err := store.ListLeasedOutputs(t.Context(), walletID)
	require.NoError(t, err)
	require.Empty(t, leases)
}

// TestDeleteExpiredLeasesRemovesOnlyExpired verifies that cleanup removes
// expired leases without touching active leases for the same wallet.
func TestDeleteExpiredLeasesRemovesOnlyExpired(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-expired-leases")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr0 := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	addr1 := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	confirmedBlock := CreateBlockFixture(t, store.Queries(), 271)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{
			Value:    8000,
			PkScript: addr0.ScriptPubKey,
		}, {
			Value:    9000,
			PkScript: addr1.ScriptPubKey,
		}},
	)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710001400, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
		Credits: map[uint32]btcutil.Address{
			0: nil,
			1: nil,
		},
	})
	require.NoError(t, err)

	expiredID := RandomHash()
	activeID := RandomHash()
	expiredOutPoint := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
	activeOutPoint := wire.OutPoint{Hash: tx.TxHash(), Index: 1}
	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       expiredID,
		OutPoint: expiredOutPoint,
		Duration: time.Hour,
	})
	require.NoError(t, err)
	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       activeID,
		OutPoint: activeOutPoint,
		Duration: time.Hour,
	})
	require.NoError(t, err)

	query := "UPDATE utxo_leases SET expires_at = ? " +
		"WHERE wallet_id = ? AND lock_id = ?"
	if _, ok := any(store).(*pg.Store); ok {
		query = "UPDATE utxo_leases SET expires_at = $1 " +
			"WHERE wallet_id = $2 AND lock_id = $3"
	}

	result, err := store.DB().ExecContext(
		t.Context(), query, time.Now().Add(-time.Hour).UTC(),
		int64(walletID), expiredID[:],
	)
	require.NoError(t, err)
	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), rows)

	err = store.DeleteExpiredLeases(t.Context(), walletID)
	require.NoError(t, err)

	leases, err := store.ListLeasedOutputs(t.Context(), walletID)
	require.NoError(t, err)
	require.Len(t, leases, 1)
	require.Equal(t, activeOutPoint, leases[0].OutPoint)
	require.Equal(t, db.LockID(activeID), leases[0].LockID)
}

// TestListLeasedOutputsRejectsCorruptedLockID verifies that active lease reads
// fail loudly when the stored lock ID cannot be decoded.
func TestListLeasedOutputsRejectsCorruptedLockID(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-corrupted-lease-lock-id")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 271)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 8100, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710001430, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	leaseID := RandomHash()
	_, err = store.LeaseOutput(
		t.Context(),
		db.LeaseOutputParams{
			WalletID: walletID,
			ID:       leaseID,
			OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
			Duration: time.Minute,
		},
	)
	require.NoError(t, err)

	corruptActiveLeaseLockID(
		t, store, walletID, tx.TxHash(), 0, []byte{1, 2, 3},
	)

	_, err = store.ListLeasedOutputs(t.Context(), walletID)
	require.ErrorContains(t, err, "lock id")
}

// TestListLeasedOutputsRejectsCorruptedOutputIndex verifies that active lease
// reads fail when the joined UTXO output index falls outside the public range.
func TestListLeasedOutputsRejectsCorruptedOutputIndex(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-corrupted-lease-output-index")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 272)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 8200, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710001440, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	leaseID := RandomHash()
	_, err = store.LeaseOutput(
		t.Context(),
		db.LeaseOutputParams{
			WalletID: walletID,
			ID:       leaseID,
			OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
			Duration: time.Minute,
		},
	)
	require.NoError(t, err)

	corruptUtxoOutputIndex(t, store, walletID, tx.TxHash(), 0, -1)

	_, err = store.ListLeasedOutputs(t.Context(), walletID)
	require.ErrorContains(t, err, "lease output index")
}

// TestGetUtxoAndLeaseRejectLargeOutputIndex verifies backend-specific handling
// for outpoint indexes that exceed the supported SQL integer range.
func TestGetUtxoAndLeaseRejectLargeOutputIndex(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-large-output-index")
	outPoint := wire.OutPoint{Hash: RandomHash(), Index: ^uint32(0)}

	_, err := store.GetUtxo(
		t.Context(),
		db.GetUtxoQuery{
			WalletID: walletID,
			OutPoint: outPoint,
		},
	)

	_, leaseErr := store.LeaseOutput(
		t.Context(),
		db.LeaseOutputParams{
			WalletID: walletID,
			ID:       RandomHash(),
			OutPoint: outPoint,
			Duration: time.Minute,
		},
	)

	releaseErr := store.ReleaseOutput(
		t.Context(),
		db.ReleaseOutputParams{
			WalletID: walletID,
			ID:       RandomHash(),
			OutPoint: outPoint,
		},
	)

	if _, ok := any(store).(*pg.Store); ok {
		require.ErrorContains(t, err, "convert output index")
		require.ErrorContains(t, leaseErr, "convert output index")
		require.ErrorContains(t, releaseErr, "could not cast")

		return
	}

	require.ErrorIs(t, err, db.ErrUtxoNotFound)
	require.ErrorIs(t, leaseErr, db.ErrUtxoNotFound)
	require.ErrorIs(t, releaseErr, db.ErrUtxoNotFound)
}

// TestUtxoReadsReturnQueryErrorsWhenClosed verifies that UTXO read methods wrap
// backend query errors when the underlying connection is closed.
func TestUtxoReadsReturnQueryErrorsWhenClosed(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-closed-utxo-reads")
	err := store.Close()
	require.NoError(t, err)

	_, err = store.GetUtxo(
		t.Context(),
		db.GetUtxoQuery{
			WalletID: walletID,
			OutPoint: wire.OutPoint{Hash: RandomHash(), Index: 0},
		},
	)
	require.ErrorContains(t, err, "get utxo")

	_, err = store.ListUTXOs(
		t.Context(),
		db.ListUtxosQuery{WalletID: walletID},
	)
	require.ErrorContains(t, err, "list utxos")

	_, err = store.ListLeasedOutputs(t.Context(), walletID)
	require.ErrorContains(t, err, "list active utxo leases")

	_, err = store.Balance(
		t.Context(),
		db.BalanceParams{WalletID: walletID},
	)
	require.ErrorContains(t, err, "balance")
}
