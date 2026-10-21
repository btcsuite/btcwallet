//go:build itest

package itest

import (
	"context"
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

// publishSpend records the spending transaction as unmined.
func (f *leasePolicyFixture) publishSpend(t *testing.T) {
	t.Helper()

	err := f.store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: f.walletID,
		Tx:       f.spendTx,
		Received: time.Unix(1710007100, 0),
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)
}

// confirmSpend confirms the recorded spending transaction at height through
// the chain sync batch path.
func (f *leasePolicyFixture) confirmSpend(t *testing.T, height uint32) {
	t.Helper()

	block := NewBlockFixture(height)
	err := f.store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: f.walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: f.walletID,
			Tx:       f.spendTx,
			Received: time.Unix(1710007100, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
		}},
	})
	require.NoError(t, err)
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

// TestConfirmationLeaseTracksSpendAcrossRollback verifies that a
// confirmation-controlled lease records the confirmed spend height, marks a
// disconnected spend with -1, and records reconfirmation.
func TestConfirmationLeaseTracksSpendAcrossRollback(t *testing.T) {
	t.Parallel()

	f := newLeasePolicyFixture(t, "wallet-confirmation-lease-rollback")
	owner := db.LockID{1}

	f.lease(t, owner, leaseReleaseDepth)
	f.expireLeases(t)

	// An unmined spend keeps the lease listed without progress, even when
	// its unmined state is rewritten.
	f.publishSpend(t)
	err := f.store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: f.walletID,
		Txid:     f.spendTx.TxHash(),
		State:    &db.UpdateTxState{Status: db.TxStatusPublished},
	})
	require.NoError(t, err)
	f.requireLease(t, owner, 0)

	f.confirmSpend(t, leaseFundingHeight+1)
	f.requireLease(t, owner, leaseFundingHeight+1)

	err = f.store.RollbackToBlock(t.Context(), leaseFundingHeight+1)
	require.NoError(t, err)
	f.requireLease(t, owner, -1)

	f.confirmSpend(t, leaseFundingHeight+2)
	f.requireLease(t, owner, leaseFundingHeight+2)
}

// TestConfirmationLeaseRecordsDirectConfirmedSpend verifies that a spend first
// recorded as already confirmed sets the lease progress, covering writers that
// never move the spender from unmined to mined.
func TestConfirmationLeaseRecordsDirectConfirmedSpend(t *testing.T) {
	t.Parallel()

	f := newLeasePolicyFixture(t, "wallet-confirmation-lease-direct")
	owner := db.LockID{1}

	f.lease(t, owner, leaseReleaseDepth)

	// The spender is first seen in a block, so it is inserted confirmed.
	f.confirmSpend(t, leaseFundingHeight+1)
	f.requireLease(t, owner, leaseFundingHeight+1)
}

// TestConfirmationLeaseRewindMarksDisconnectedSpend verifies that a
// wallet-scoped rewind below the spend height marks the observed spend as
// disconnected.
func TestConfirmationLeaseRewindMarksDisconnectedSpend(t *testing.T) {
	t.Parallel()

	f := newLeasePolicyFixture(t, "wallet-confirmation-lease-rewind")
	owner := db.LockID{1}

	f.lease(t, owner, leaseReleaseDepth)
	f.publishSpend(t)
	f.confirmSpend(t, leaseFundingHeight+1)
	f.requireLease(t, owner, leaseFundingHeight+1)

	err := f.store.RewindWallet(t.Context(), db.RewindWalletParams{
		WalletID: f.walletID,
		Block:    f.fundingBlock,
	})
	require.NoError(t, err)
	f.requireLease(t, owner, -1)
}

// TestTimedLeaseEndsWithSpend verifies that a timed lease keeps its existing
// contract: it is not listed once its output is spent, even after that spend
// confirms and disconnects, and the spent output is no longer releasable.
func TestTimedLeaseEndsWithSpend(t *testing.T) {
	t.Parallel()

	f := newLeasePolicyFixture(t, "wallet-timed-lease-spend")
	owner := db.LockID{1}

	lease := f.lease(t, owner, 0)
	require.Zero(t, lease.ReleaseAfterSpendConfs)

	f.publishSpend(t)
	f.confirmSpend(t, leaseFundingHeight+1)

	err := f.store.RollbackToBlock(t.Context(), leaseFundingHeight+1)
	require.NoError(t, err)

	leases, err := f.store.ListLeasedOutputs(t.Context(), f.walletID)
	require.NoError(t, err)
	require.Empty(t, leases)

	err = f.store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: f.walletID,
		ID:       owner,
		OutPoint: f.outPoint,
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// invalidateFunding disconnects the fixture's funding block and invalidates
// the funding transaction.
func (f *leasePolicyFixture) invalidateFunding(t *testing.T) {
	t.Helper()

	err := f.store.RollbackToBlock(t.Context(), leaseFundingHeight)
	require.NoError(t, err)

	err = f.store.InvalidateUnminedTx(
		t.Context(), db.InvalidateUnminedTxParams{
			WalletID: f.walletID,
			Txid:     f.outPoint.Hash,
		},
	)
	require.NoError(t, err)
}

// TestConfirmationLeaseOutlivesInvalidatedFunding verifies that a
// confirmation-controlled lease stays listed and owner-releasable after its
// funding transaction is invalidated, since neither expiry nor a spend can
// remove it.
func TestConfirmationLeaseOutlivesInvalidatedFunding(t *testing.T) {
	t.Parallel()

	f := newLeasePolicyFixture(t, "wallet-lease-invalid-funding")
	owner := db.LockID{1}

	f.lease(t, owner, leaseReleaseDepth)
	f.invalidateFunding(t)
	f.requireLease(t, owner, 0)

	err := f.store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: f.walletID,
		ID:       db.LockID{2},
		OutPoint: f.outPoint,
	})
	require.ErrorIs(t, err, db.ErrOutputUnlockNotAllowed)

	err = f.store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: f.walletID,
		ID:       owner,
		OutPoint: f.outPoint,
	})
	require.NoError(t, err)

	leases, err := f.store.ListLeasedOutputs(t.Context(), f.walletID)
	require.NoError(t, err)
	require.Empty(t, leases)
}

// TestTimedLeaseEndsWithFundingInvalidation verifies that a timed lease is no
// longer listed or releasable once its funding transaction is invalidated.
func TestTimedLeaseEndsWithFundingInvalidation(t *testing.T) {
	t.Parallel()

	f := newLeasePolicyFixture(t, "wallet-timed-lease-invalid-funding")
	owner := db.LockID{1}

	f.lease(t, owner, 0)
	f.invalidateFunding(t)

	leases, err := f.store.ListLeasedOutputs(t.Context(), f.walletID)
	require.NoError(t, err)
	require.Empty(t, leases)

	err = f.store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: f.walletID,
		ID:       owner,
		OutPoint: f.outPoint,
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// tipWriter names a Store method that advances a wallet's sync tip.
type tipWriter uint8

const (
	// tipWriterTxBatch advances the tip through ApplyTxBatch.
	tipWriterTxBatch tipWriter = iota

	// tipWriterScanBatch advances the tip through ApplyScanBatch.
	tipWriterScanBatch

	// tipWriterUpdateWallet advances the tip through UpdateWallet.
	tipWriterUpdateWallet
)

// advanceTip moves the fixture wallet's sync tip to a new block at height
// through the given writer.
func (f *leasePolicyFixture) advanceTip(t *testing.T, writer tipWriter,
	height uint32) {

	t.Helper()

	block := NewBlockFixture(height)

	var err error

	switch writer {
	case tipWriterTxBatch:
		err = f.store.ApplyTxBatch(t.Context(), db.TxBatchParams{
			WalletID: f.walletID,
			SyncedTo: &block,
		})

	case tipWriterScanBatch:
		err = f.store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
			WalletID:     f.walletID,
			SyncedBlocks: []db.Block{block},
		})

	case tipWriterUpdateWallet:
		err = f.store.UpdateWallet(t.Context(), db.UpdateWalletParams{
			WalletID: f.walletID,
			SyncedTo: &block,
		})

	default:
		t.Fatalf("unknown tip writer %d", writer)
	}

	require.NoError(t, err)
}

// TestConfirmationLeaseReleasesAtSpendDepth verifies that every writer that
// advances the wallet sync tip releases a confirmation-controlled lease exactly
// when its spend reaches the requested depth, and not one block earlier.
func TestConfirmationLeaseReleasesAtSpendDepth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		writer tipWriter
	}{
		{name: "tx batch sync tip", writer: tipWriterTxBatch},
		{name: "scan batch synced blocks", writer: tipWriterScanBatch},
		{name: "update wallet sync tip", writer: tipWriterUpdateWallet},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newLeasePolicyFixture(t, "wallet-lease-maturity")
			owner := db.LockID{1}
			spendHeight := uint32(leaseFundingHeight + 1)

			f.lease(t, owner, leaseReleaseDepth)
			f.publishSpend(t)
			f.confirmSpend(t, spendHeight)

			// One block short of the requested depth keeps the lease.
			f.advanceTip(t, tc.writer, spendHeight+leaseReleaseDepth-2)
			f.requireLease(t, owner, int32(spendHeight))

			f.advanceTip(t, tc.writer, spendHeight+leaseReleaseDepth-1)

			leases, err := f.store.ListLeasedOutputs(
				t.Context(), f.walletID,
			)
			require.NoError(t, err)
			require.Empty(t, leases)
		})
	}
}

// TestConfirmationLeaseMaturesInSpendBatch verifies that a batch which both
// confirms the spend and advances the tip to the release depth releases the
// lease, so maturity is checked after the batch records its transactions.
func TestConfirmationLeaseMaturesInSpendBatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		apply func(f *leasePolicyFixture, ctx context.Context,
			spend []db.CreateTxParams, blocks []db.Block) error
	}{
		{
			name: "tx batch",
			apply: func(f *leasePolicyFixture, ctx context.Context,
				spend []db.CreateTxParams, blocks []db.Block) error {

				return f.store.ApplyTxBatch(ctx, db.TxBatchParams{
					WalletID:     f.walletID,
					Transactions: spend,
					SyncedTo:     &blocks[len(blocks)-1],
				})
			},
		},
		{
			name: "scan batch",
			apply: func(f *leasePolicyFixture, ctx context.Context,
				spend []db.CreateTxParams, blocks []db.Block) error {

				return f.store.ApplyScanBatch(ctx, db.ScanBatchParams{
					WalletID:     f.walletID,
					Transactions: spend,
					SyncedBlocks: blocks,
				})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newLeasePolicyFixture(t, "wallet-lease-spend-batch")
			f.lease(t, db.LockID{1}, leaseReleaseDepth)

			blocks := make([]db.Block, leaseReleaseDepth)
			for i := range blocks {
				blocks[i] = NewBlockFixture(
					leaseFundingHeight + 1 + uint32(i),
				)
			}

			spend := []db.CreateTxParams{{
				WalletID: f.walletID,
				Tx:       f.spendTx,
				Received: time.Unix(1710007100, 0),
				Block:    &blocks[0],
				Status:   db.TxStatusPublished,
			}}

			err := tc.apply(f, t.Context(), spend, blocks)
			require.NoError(t, err)

			leases, err := f.store.ListLeasedOutputs(
				t.Context(), f.walletID,
			)
			require.NoError(t, err)
			require.Empty(t, leases)
		})
	}
}

// TestConfirmationLeaseWithoutConfirmedSpendSurvivesTip verifies that tip
// advances never release a lease whose spend is unconfirmed or disconnected,
// because only a confirmed spend carries maturity progress.
func TestConfirmationLeaseWithoutConfirmedSpendSurvivesTip(t *testing.T) {
	t.Parallel()

	f := newLeasePolicyFixture(t, "wallet-lease-disconnected-tip")
	owner := db.LockID{1}
	spendHeight := uint32(leaseFundingHeight + 1)

	f.lease(t, owner, leaseReleaseDepth)
	f.publishSpend(t)
	f.confirmSpend(t, spendHeight)

	err := f.store.RollbackToBlock(t.Context(), spendHeight)
	require.NoError(t, err)

	tip := NewBlockFixture(spendHeight + 10*leaseReleaseDepth)
	err = f.store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: f.walletID,
		SyncedTo: &tip,
	})
	require.NoError(t, err)
	f.requireLease(t, owner, -1)
}

// TestConfirmationLeaseMaturesOnLateSpend verifies that a spend recorded
// below the existing sync tip releases an already-matured lease, even when
// the write does not move the tip.
func TestConfirmationLeaseMaturesOnLateSpend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		apply func(f *leasePolicyFixture, ctx context.Context,
			spend []db.CreateTxParams) error
	}{
		{
			name: "tx batch",
			apply: func(f *leasePolicyFixture, ctx context.Context,
				spend []db.CreateTxParams) error {

				return f.store.ApplyTxBatch(ctx, db.TxBatchParams{
					WalletID:     f.walletID,
					Transactions: spend,
				})
			},
		},
		{
			name: "targeted scan batch",
			apply: func(f *leasePolicyFixture, ctx context.Context,
				spend []db.CreateTxParams) error {

				return f.store.ApplyScanBatch(ctx, db.ScanBatchParams{
					WalletID:     f.walletID,
					Transactions: spend,
				})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newLeasePolicyFixture(t, "wallet-lease-late-spend")
			f.lease(t, db.LockID{1}, leaseReleaseDepth)

			spendBlock := NewBlockFixture(leaseFundingHeight + 1)
			f.advanceTip(
				t, tipWriterUpdateWallet,
				spendBlock.Height+leaseReleaseDepth-1,
			)

			spend := []db.CreateTxParams{{
				WalletID: f.walletID,
				Tx:       f.spendTx,
				Received: time.Unix(1710007100, 0),
				Block:    &spendBlock,
				Status:   db.TxStatusPublished,
			}}

			err := tc.apply(f, t.Context(), spend)
			require.NoError(t, err)

			leases, err := f.store.ListLeasedOutputs(
				t.Context(), f.walletID,
			)
			require.NoError(t, err)
			require.Empty(t, leases)
		})
	}
}
