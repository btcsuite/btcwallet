package kvdb

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// legacyLocks returns the lock records wtxmgr reports as active.
func legacyLocks(t *testing.T, dbConn walletdb.DB,
	txStore *wtxmgr.Store) []*wtxmgr.LockedOutput {

	t.Helper()

	var locks []*wtxmgr.LockedOutput

	err := walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		var err error

		locks, err = txStore.ListLockedOutputs(
			tx.ReadBucket(wtxmgrNamespaceKey),
		)

		return err
	})
	require.NoError(t, err)

	return locks
}

// TestLeaseNoExpiryStoresReleaseDepth verifies that kvdb stores a lease
// without expiry as a wtxmgr lock with release depth one, which stays active
// through expired-lease cleanup and against another owner.
func TestLeaseNoExpiryStoresReleaseDepth(t *testing.T) {
	t.Parallel()

	// Arrange: Store one known credit.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 2500, 2,
	)

	// Act: Lease it without expiry, run expired-lease cleanup, and try to
	// take it under another ID.
	lease, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		ID:       db.LockID{1},
		OutPoint: outPoint,
		NoExpiry: true,
	})
	require.NoError(t, err)

	err = store.DeleteExpiredLeases(t.Context(), 0)
	require.NoError(t, err)

	_, takeErr := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		ID:       db.LockID{2},
		OutPoint: outPoint,
		Duration: time.Minute,
	})

	leases, err := store.ListLeasedOutputs(t.Context(), 0)
	require.NoError(t, err)

	locks := legacyLocks(t, dbConn, txStore)

	// Assert: The lease reports no expiry, stays listed, and is stored with
	// release depth one.
	require.True(t, lease.NoExpiry)
	require.True(t, lease.Expiration.IsZero())
	require.ErrorIs(t, takeErr, db.ErrOutputAlreadyLeased)
	require.Equal(t, []db.LeasedOutput{*lease}, leases)
	require.Len(t, locks, 1)
	require.Equal(t, uint32(noExpiryLeaseDepth),
		locks[0].ReleaseAfterSpendConfs)
}

// TestLeaseNoExpiryRenewalKeepsPolicy verifies that a same-owner renewal with
// a duration keeps a lease without expiry, matching the SQL backends.
func TestLeaseNoExpiryRenewalKeepsPolicy(t *testing.T) {
	t.Parallel()

	// Arrange: Lease one known credit without expiry.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 2500, 2,
	)

	_, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		ID:       db.LockID{1},
		OutPoint: outPoint,
		NoExpiry: true,
	})
	require.NoError(t, err)

	// Act: Renew it under the same ID with a duration.
	renewal, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		ID:       db.LockID{1},
		OutPoint: outPoint,
		Duration: time.Minute,
	})
	require.NoError(t, err)

	leases, err := store.ListLeasedOutputs(t.Context(), 0)
	require.NoError(t, err)

	// Assert: The renewal reports, and stored, a lease without expiry.
	require.True(t, renewal.NoExpiry)
	require.True(t, renewal.Expiration.IsZero())
	require.Equal(t, []db.LeasedOutput{*renewal}, leases)
}

// TestLeaseNoExpiryRejectsDuration verifies that kvdb rejects a lease
// without expiry that also carries a duration, singly and as a set, and
// leaves no lease behind.
func TestLeaseNoExpiryRejectsDuration(t *testing.T) {
	t.Parallel()

	// Arrange: Store one known credit.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 2500, 2,
	)

	// Act: Lease it without expiry and with a duration, singly and as a
	// set.
	_, leaseErr := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		ID:       db.LockID{1},
		OutPoint: outPoint,
		Duration: time.Minute,
		NoExpiry: true,
	})
	_, setErr := store.LeaseOutputs(t.Context(), db.LeaseOutputsParams{
		ID:        db.LockID{1},
		OutPoints: []wire.OutPoint{outPoint},
		Duration:  time.Minute,
		NoExpiry:  true,
	})

	// Assert: Both calls are rejected and no lock was written.
	require.ErrorIs(t, leaseErr, db.ErrInvalidParam)
	require.ErrorIs(t, setErr, db.ErrInvalidParam)
	require.Empty(t, legacyLocks(t, dbConn, txStore))
}

// TestLeaseOutputsNoExpiry verifies that kvdb leases a whole set without
// expiry and reports each lease in request order.
func TestLeaseOutputsNoExpiry(t *testing.T) {
	t.Parallel()

	// Arrange: Store two known credits.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	first := insertKnownCredit(t, dbConn, txStore, []byte{0x51}, 2500, 2)
	second := insertKnownCredit(t, dbConn, txStore, []byte{0x51}, 3500, 2)

	// Act: Lease both without expiry.
	leases, err := store.LeaseOutputs(t.Context(), db.LeaseOutputsParams{
		ID:        db.LockID{1},
		OutPoints: []wire.OutPoint{second, first},
		NoExpiry:  true,
	})
	require.NoError(t, err)

	// Assert: Both leases have no expiry and follow the request order.
	require.Equal(t, []db.LeasedOutput{
		{OutPoint: second, LockID: db.LockID{1}, NoExpiry: true},
		{OutPoint: first, LockID: db.LockID{1}, NoExpiry: true},
	}, leases)
}

// TestLeaseNoExpiryEndsWithConfirmedSpend verifies that wtxmgr deletes a lease
// without expiry in the write that records its output's confirmed spend.
func TestLeaseNoExpiryEndsWithConfirmedSpend(t *testing.T) {
	t.Parallel()

	// Arrange: Lease one known credit without expiry and build a spend.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 2500, 2,
	)

	_, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		ID:       db.LockID{1},
		OutPoint: outPoint,
		NoExpiry: true,
	})
	require.NoError(t, err)

	spendTx := &wire.MsgTx{Version: 1}
	spendTx.AddTxIn(&wire.TxIn{PreviousOutPoint: outPoint})
	spendTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
	spendRec, err := wtxmgr.NewTxRecordFromMsgTx(spendTx, time.Now())
	require.NoError(t, err)

	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: chainhash.Hash{5}, Height: 5},
		Time:  time.Now(),
	}

	// Act: Record the spend in a block.
	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		return txStore.InsertTx(
			tx.ReadWriteBucket(wtxmgrNamespaceKey), spendRec, block,
		)
	})
	require.NoError(t, err)

	// Assert: No lock record remains.
	require.Empty(t, legacyLocks(t, dbConn, txStore))
}

// TestLeaseNoExpiryKeptByUnminedSpend verifies that an unmined spend keeps a
// lease without expiry, so the output stays reserved if the spend is removed.
func TestLeaseNoExpiryKeptByUnminedSpend(t *testing.T) {
	t.Parallel()

	// Arrange: Lease one known credit without expiry.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 2500, 2,
	)

	_, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		ID:       db.LockID{1},
		OutPoint: outPoint,
		NoExpiry: true,
	})
	require.NoError(t, err)

	// Act: Record an unmined spend of the output.
	insertUnminedSpend(t, dbConn, txStore, outPoint)

	// Assert: The lock record remains with its release depth.
	locks := legacyLocks(t, dbConn, txStore)
	require.Len(t, locks, 1)
	require.Equal(t, outPoint, locks[0].Outpoint)
	require.Equal(t, uint32(noExpiryLeaseDepth),
		locks[0].ReleaseAfterSpendConfs)
}
