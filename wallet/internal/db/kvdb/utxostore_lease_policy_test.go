package kvdb

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

const (
	// kvdbLeaseCreditHeight is the block confirming each test credit.
	kvdbLeaseCreditHeight = 1

	// kvdbLeaseSpendHeight is the block confirming each test spend.
	kvdbLeaseSpendHeight = 5

	// kvdbLeaseDepth is the release depth requested by the tests.
	kvdbLeaseDepth = 3
)

// leaseConfirmedOutput leases outPoint under id with the test release depth.
func leaseConfirmedOutput(t *testing.T, store *Store, id db.LockID,
	outPoint wire.OutPoint, releaseAfterSpendConfs uint32) *db.LeasedOutput {

	t.Helper()

	lease, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		ID:                     id,
		OutPoint:               outPoint,
		Duration:               time.Hour,
		ReleaseAfterSpendConfs: releaseAfterSpendConfs,
	})
	require.NoError(t, err)

	return lease
}

// insertConfirmedSpend records a transaction spending outPoint in a block at
// height.
func insertConfirmedSpend(t *testing.T, dbConn walletdb.DB,
	txStore *wtxmgr.Store, outPoint wire.OutPoint, height int32) {

	t.Helper()

	spendTx := &wire.MsgTx{Version: 1}
	spendTx.AddTxIn(&wire.TxIn{PreviousOutPoint: outPoint})
	spendTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
	spendRec, err := wtxmgr.NewTxRecordFromMsgTx(spendTx, time.Now())
	require.NoError(t, err)

	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: chainhash.Hash{byte(height)},
			Height: height},
		Time: time.Now(),
	}

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		return txStore.InsertTx(ns, spendRec, block)
	})
	require.NoError(t, err)
}

// requireOnlyLease asserts that the store lists exactly one lease with the
// expected owner and spend progress.
func requireOnlyLease(t *testing.T, store *Store, outPoint wire.OutPoint,
	id db.LockID, spendHeight int32) {

	t.Helper()

	leases, err := store.ListLeasedOutputs(t.Context(), 0)
	require.NoError(t, err)
	require.Len(t, leases, 1)
	require.Equal(t, outPoint, leases[0].OutPoint)
	require.Equal(t, id, leases[0].LockID)
	require.Equal(t, uint32(kvdbLeaseDepth), leases[0].ReleaseAfterSpendConfs)
	require.Equal(t, spendHeight, leases[0].ConfirmedSpendHeight)
}

// kvdbTipWriter names a Store method that advances the wallet sync tip.
type kvdbTipWriter uint8

const (
	// kvdbTipWriterTxBatch advances the tip through ApplyTxBatch.
	kvdbTipWriterTxBatch kvdbTipWriter = iota

	// kvdbTipWriterScanBatch advances the tip through ApplyScanBatch.
	kvdbTipWriterScanBatch

	// kvdbTipWriterUpdateWallet advances the tip through UpdateWallet.
	kvdbTipWriterUpdateWallet
)

// advanceKvdbTip moves the sync tip to a block at height through writer.
func advanceKvdbTip(t *testing.T, store *Store, writer kvdbTipWriter,
	height uint32) {

	t.Helper()

	block := someBlock(t, height)

	var err error

	switch writer {
	case kvdbTipWriterTxBatch:
		err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
			SyncedTo: block,
		})

	case kvdbTipWriterScanBatch:
		err = store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
			SyncedBlocks: []db.Block{*block},
		})

	case kvdbTipWriterUpdateWallet:
		err = store.UpdateWallet(t.Context(), db.UpdateWalletParams{
			SyncedTo: block,
		})

	default:
		t.Fatalf("unknown tip writer %d", writer)
	}

	require.NoError(t, err)
}

// TestConfirmationLeaseMaturesOnSyncTip verifies that every kvdb writer that
// advances the sync tip releases a confirmation-controlled lease at its
// requested depth, and not one block earlier.
func TestConfirmationLeaseMaturesOnSyncTip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		writer kvdbTipWriter
	}{
		{name: "tx batch sync tip", writer: kvdbTipWriterTxBatch},
		{name: "scan batch synced blocks", writer: kvdbTipWriterScanBatch},
		{name: "update wallet sync tip", writer: kvdbTipWriterUpdateWallet},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dbConn, cleanup := newTestDB(t)
			t.Cleanup(cleanup)

			addrStore := newAddrStore(t, dbConn)
			txStore := newTxStore(t, dbConn)
			store := NewStore(dbConn, txStore, addrStore)
			outPoint := insertKnownCredit(
				t, dbConn, txStore, []byte{0x51}, 1000,
				kvdbLeaseCreditHeight,
			)
			owner := db.LockID{1}

			leaseConfirmedOutput(
				t, store, owner, outPoint, kvdbLeaseDepth,
			)
			insertConfirmedSpend(
				t, dbConn, txStore, outPoint, kvdbLeaseSpendHeight,
			)

			// One block short of the requested depth.
			advanceKvdbTip(
				t, store, tc.writer,
				kvdbLeaseSpendHeight+kvdbLeaseDepth-2,
			)
			requireOnlyLease(
				t, store, outPoint, owner, kvdbLeaseSpendHeight,
			)

			advanceKvdbTip(
				t, store, tc.writer,
				kvdbLeaseSpendHeight+kvdbLeaseDepth-1,
			)

			leases, err := store.ListLeasedOutputs(t.Context(), 0)
			require.NoError(t, err)
			require.Empty(t, leases)
		})
	}
}

// TestConfirmationLeaseMaturesOnLateSpend verifies that a kvdb batch which
// records a spend below an unchanged sync tip releases an already-matured
// lease.
func TestConfirmationLeaseMaturesOnLateSpend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		apply func(store *Store, ctx context.Context,
			spend []db.CreateTxParams) error
	}{
		{
			name: "tx batch",
			apply: func(store *Store, ctx context.Context,
				spend []db.CreateTxParams) error {

				return store.ApplyTxBatch(ctx, db.TxBatchParams{
					Transactions: spend,
				})
			},
		},
		{
			name: "targeted scan batch",
			apply: func(store *Store, ctx context.Context,
				spend []db.CreateTxParams) error {

				return store.ApplyScanBatch(ctx, db.ScanBatchParams{
					Transactions: spend,
				})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dbConn, cleanup := newTestDB(t)
			t.Cleanup(cleanup)

			addrStore := newAddrStore(t, dbConn)
			txStore := newTxStore(t, dbConn)
			store := NewStore(dbConn, txStore, addrStore)
			outPoint := insertKnownCredit(
				t, dbConn, txStore, []byte{0x51}, 1000,
				kvdbLeaseCreditHeight,
			)

			leaseConfirmedOutput(
				t, store, db.LockID{1}, outPoint, kvdbLeaseDepth,
			)
			advanceKvdbTip(
				t, store, kvdbTipWriterUpdateWallet,
				kvdbLeaseSpendHeight+kvdbLeaseDepth-1,
			)

			spendTx := &wire.MsgTx{Version: 1}
			spendTx.AddTxIn(&wire.TxIn{PreviousOutPoint: outPoint})
			spendTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
			spend := []db.CreateTxParams{{
				Tx:       spendTx,
				Received: time.Now(),
				Block:    someBlock(t, kvdbLeaseSpendHeight),
				Status:   db.TxStatusPublished,
			}}

			err := tc.apply(store, t.Context(), spend)
			require.NoError(t, err)

			leases, err := store.ListLeasedOutputs(t.Context(), 0)
			require.NoError(t, err)
			require.Empty(t, leases)
		})
	}
}

// TestConfirmationLeaseSurvivesReopen verifies that the release depth and a
// disconnected-spend marker survive reopening the legacy transaction store.
func TestConfirmationLeaseSurvivesReopen(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 1000, kvdbLeaseCreditHeight,
	)
	owner := db.LockID{1}

	leaseConfirmedOutput(t, store, owner, outPoint, kvdbLeaseDepth)
	insertConfirmedSpend(t, dbConn, txStore, outPoint, kvdbLeaseSpendHeight)

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		return txStore.Rollback(ns, kvdbLeaseSpendHeight)
	})
	require.NoError(t, err)

	var reopened *wtxmgr.Store

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)

		var err error

		reopened, err = wtxmgr.Open(ns, &chaincfg.RegressionNetParams)

		return err
	})
	require.NoError(t, err)

	requireOnlyLease(
		t, NewStore(dbConn, reopened, nil), outPoint, owner, -1,
	)
}
