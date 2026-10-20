//go:build itest

package itest

import (
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	"github.com/stretchr/testify/require"
)

const (
	// leaseFundingHeight is the block confirming each fixture's funding
	// output.
	leaseFundingHeight = 100

	// leaseReleaseDepth is the spend depth fixtures request for
	// confirmation-controlled leases.
	leaseReleaseDepth = 3
)

// leasePolicyFixture holds one confirmed wallet output and an unmined
// transaction that spends it.
type leasePolicyFixture struct {
	store        db.Store
	walletID     uint32
	fundingBlock db.Block
	outPoint     wire.OutPoint
	spendTx      *wire.MsgTx
}

// newLeasePolicyFixture creates a wallet with one output confirmed at
// leaseFundingHeight and builds, but does not record, a transaction spending
// it.
func newLeasePolicyFixture(t *testing.T, name string) *leasePolicyFixture {
	t.Helper()

	store := NewTestStore(t)
	walletID := newWallet(t, store, name)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	fundingBlock := NewBlockFixture(leaseFundingHeight)
	fundingTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 50000, PkScript: addr.ScriptPubKey}},
	)
	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       fundingTx,
			Received: time.Unix(1710007000, 0),
			Block:    &fundingBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		}},
		SyncedTo: &fundingBlock,
	})
	require.NoError(t, err)

	outPoint := wire.OutPoint{Hash: fundingTx.TxHash(), Index: 0}
	spendTx := newRegularTx(
		[]wire.OutPoint{outPoint}, []*wire.TxOut{{Value: 40000}},
	)

	return &leasePolicyFixture{
		store:        store,
		walletID:     walletID,
		fundingBlock: fundingBlock,
		outPoint:     outPoint,
		spendTx:      spendTx,
	}
}

// lease leases the fixture output under id with the requested spend depth.
func (f *leasePolicyFixture) lease(t *testing.T, id db.LockID,
	releaseAfterSpendConfs uint32) *db.LeasedOutput {

	t.Helper()

	lease, err := f.store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID:               f.walletID,
		ID:                     id,
		OutPoint:               f.outPoint,
		Duration:               time.Hour,
		ReleaseAfterSpendConfs: releaseAfterSpendConfs,
	})
	require.NoError(t, err)

	return lease
}

// requireLease asserts that the fixture output is the only listed lease and
// carries the expected owner and spend progress.
func (f *leasePolicyFixture) requireLease(t *testing.T, id db.LockID,
	spendHeight int32) {

	t.Helper()

	leases, err := f.store.ListLeasedOutputs(t.Context(), f.walletID)
	require.NoError(t, err)
	require.Len(t, leases, 1)
	require.Equal(t, f.outPoint, leases[0].OutPoint)
	require.Equal(t, id, leases[0].LockID)
	require.Equal(t, uint32(leaseReleaseDepth),
		leases[0].ReleaseAfterSpendConfs)
	require.Equal(t, spendHeight, leases[0].ConfirmedSpendHeight)
}

// expireLeases moves every lease expiration of the fixture wallet into the
// past.
func (f *leasePolicyFixture) expireLeases(t *testing.T) {
	t.Helper()

	query := "UPDATE utxo_leases SET expires_at = ? WHERE wallet_id = ?"
	if _, ok := f.store.(*pg.Store); ok {
		query = "UPDATE utxo_leases SET expires_at = $1 WHERE wallet_id = $2"
	}

	sqlStore, ok := f.store.(interface {
		DB() *sql.DB
	})
	require.True(t, ok)

	_, err := sqlStore.DB().ExecContext(
		t.Context(), query, time.Now().Add(-time.Hour).UTC(),
		int64(f.walletID),
	)
	require.NoError(t, err)
}

// TestConfirmationLeaseRenewalKeepsDepth verifies that a same-owner renewal
// with zero depth keeps the stored spend depth.
func TestConfirmationLeaseRenewalKeepsDepth(t *testing.T) {
	t.Parallel()

	f := newLeasePolicyFixture(t, "wallet-confirmation-lease-renewal")
	owner := db.LockID{1}

	lease := f.lease(t, owner, leaseReleaseDepth)
	require.Equal(t, uint32(leaseReleaseDepth), lease.ReleaseAfterSpendConfs)
	require.Zero(t, lease.ConfirmedSpendHeight)

	lease = f.lease(t, owner, 0)
	require.Equal(t, uint32(leaseReleaseDepth), lease.ReleaseAfterSpendConfs)
	f.requireLease(t, owner, 0)
}

// TestConfirmationLeaseIgnoresWallClockExpiry verifies that a lease with a
// release depth stays active, listed, and owned after its stored expiration
// passes, while a timed lease on the same wallet is not protected.
func TestConfirmationLeaseIgnoresWallClockExpiry(t *testing.T) {
	t.Parallel()

	f := newLeasePolicyFixture(t, "wallet-confirmation-lease-expiry")
	owner := db.LockID{1}

	lease := f.lease(t, owner, leaseReleaseDepth)
	require.Equal(t, uint32(leaseReleaseDepth), lease.ReleaseAfterSpendConfs)
	require.Zero(t, lease.ConfirmedSpendHeight)

	f.expireLeases(t)

	err := f.store.DeleteExpiredLeases(t.Context(), f.walletID)
	require.NoError(t, err)
	f.requireLease(t, owner, 0)

	// Another owner can neither take over nor release the lease.
	_, err = f.store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: f.walletID,
		ID:       db.LockID{2},
		OutPoint: f.outPoint,
		Duration: time.Hour,
	})
	require.ErrorIs(t, err, db.ErrOutputAlreadyLeased)

	err = f.store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: f.walletID,
		ID:       db.LockID{2},
		OutPoint: f.outPoint,
	})
	require.ErrorIs(t, err, db.ErrOutputUnlockNotAllowed)

	// The output still reads as locked in UTXO and balance views.
	utxo, err := f.store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: f.walletID,
		OutPoint: f.outPoint,
	})
	require.NoError(t, err)
	require.True(t, utxo.IsLocked)

	utxos, err := f.store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: f.walletID,
	})
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.True(t, utxos[0].IsLocked)

	balance, err := f.store.Balance(t.Context(), db.BalanceParams{
		WalletID: f.walletID,
	})
	require.NoError(t, err)
	require.Equal(t, balance.Total, balance.Locked)
}
