package kvdb

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestReleaseOutputSuccess verifies that kvdb.Store.ReleaseOutput removes an
// existing output lease from the underlying wtxmgr store.
func TestReleaseOutputSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	// Arrange: insert a current credit and lease it so there is something
	// to release.
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 1000, 1,
	)

	_, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{1},
			OutPoint: outPoint,
			Duration: time.Hour,
		},
	)
	require.NoError(t, err)

	// Act: release the lease through the kvdb store implementation.
	err = store.ReleaseOutput(
		t.Context(), db.ReleaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{1},
			OutPoint: outPoint,
		},
	)
	require.NoError(t, err)

	// Assert: the lock set is now empty.
	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		locked, err := txStore.ListLockedOutputs(ns)
		require.NoError(t, err)
		require.Empty(t, locked)

		return nil
	})
	require.NoError(t, err)
}

// TestReleaseOutputMissingNamespace verifies a helpful error is returned when
// the `wtxmgr` namespace bucket is not present.
func TestReleaseOutputMissingNamespace(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	store := NewStore(dbConn, nil, nil)

	err := store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: 0,
		ID:       [32]byte{1},
		OutPoint: wire.OutPoint{Hash: [32]byte{1}, Index: 0},
	})
	require.Error(t, err)
	require.ErrorIs(t, err, walletdb.ErrBucketNotFound)
}

// TestReleaseOutputWrongLockID verifies that releasing a current output with
// a lock ID other than the active one reports db.ErrOutputUnlockNotAllowed,
// matching the shared db.UTXOStore release contract.
func TestReleaseOutputWrongLockID(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	// Arrange: insert a current credit and lease it under lock ID 1.
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 2500, 2,
	)

	_, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{1},
			OutPoint: outPoint,
			Duration: time.Hour,
		},
	)
	require.NoError(t, err)

	// Act: attempt to release using a different lock ID.
	err = store.ReleaseOutput(
		t.Context(), db.ReleaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{2},
			OutPoint: outPoint,
		},
	)

	// Assert: the mismatched lock ID is rejected with the db sentinel.
	require.ErrorIs(t, err, db.ErrOutputUnlockNotAllowed)
}

// TestReleaseOutputMissingUtxo verifies that releasing an outpoint that is not
// in the current wallet UTXO set reports db.ErrUtxoNotFound.
func TestReleaseOutputMissingUtxo(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	// Act: release an outpoint that was never inserted as a credit.
	err := store.ReleaseOutput(
		t.Context(), db.ReleaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{1},
			OutPoint: wire.OutPoint{Hash: [32]byte{9}, Index: 0},
		},
	)

	// Assert: the unknown outpoint maps to the db sentinel.
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestReleaseOutputRejectsSpentByUnminedTx verifies that an output already
// spent by an unmined wallet transaction is no longer current and therefore
// reports db.ErrUtxoNotFound on release, even when it still carries a lease.
func TestReleaseOutputRejectsSpentByUnminedTx(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	// Arrange: insert a current credit, lease it, then spend it with an
	// unmined transaction so it drops out of the current UTXO set.
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 1500, 1,
	)

	_, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{1},
			OutPoint: outPoint,
			Duration: time.Hour,
		},
	)
	require.NoError(t, err)

	insertUnminedSpend(t, dbConn, txStore, outPoint)

	// Act: release the now non-current output.
	err = store.ReleaseOutput(
		t.Context(), db.ReleaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{1},
			OutPoint: outPoint,
		},
	)

	// Assert: the non-current output maps to the db sentinel.
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestReleaseOutputAlreadyUnlocked verifies that releasing a current output
// that carries no active lease is a no-op rather than an error, matching the
// expired/already-released behavior of the shared release contract.
func TestReleaseOutputAlreadyUnlocked(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	// Arrange: insert a current credit that was never leased.
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 2500, 2,
	)

	// Act: release the unleased output.
	err := store.ReleaseOutput(
		t.Context(), db.ReleaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{1},
			OutPoint: outPoint,
		},
	)

	// Assert: an output with no active lease releases as a no-op.
	require.NoError(t, err)
}

// TestDeleteExpiredLeases verifies that expired output leases are removed while
// active leases remain in the legacy wtxmgr store.
func TestDeleteExpiredLeases(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	var expired, active wire.OutPoint

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		recExpired, err := wtxmgr.NewTxRecordFromMsgTx(
			&wire.MsgTx{Version: 1, TxOut: []*wire.TxOut{{
				Value:    1000,
				PkScript: []byte{0x51},
			}}}, time.Now(),
		)
		if err != nil {
			return err
		}

		recActive, err := wtxmgr.NewTxRecordFromMsgTx(
			&wire.MsgTx{Version: 1, TxOut: []*wire.TxOut{{
				Value:    2000,
				PkScript: []byte{0x51},
			}}}, time.Now(),
		)
		if err != nil {
			return err
		}

		block := &wtxmgr.BlockMeta{Block: wtxmgr.Block{Height: 1}}

		err = txStore.InsertTx(ns, recExpired, block)
		if err != nil {
			return err
		}

		err = txStore.AddCredit(ns, recExpired, block, 0, false)
		if err != nil {
			return err
		}

		err = txStore.InsertTx(ns, recActive, block)
		if err != nil {
			return err
		}

		err = txStore.AddCredit(ns, recActive, block, 0, false)
		if err != nil {
			return err
		}

		expired = wire.OutPoint{Hash: recExpired.Hash, Index: 0}
		active = wire.OutPoint{Hash: recActive.Hash, Index: 0}

		_, err = txStore.LockOutput(ns, wtxmgr.LockID{1}, expired, -time.Hour)
		if err != nil {
			return err
		}

		_, err = txStore.LockOutput(ns, wtxmgr.LockID{2}, active, time.Hour)

		return err
	})
	require.NoError(t, err)

	err = store.DeleteExpiredLeases(t.Context(), 0)
	require.NoError(t, err)

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		locked, err := txStore.ListLockedOutputs(ns)
		require.NoError(t, err)
		require.Len(t, locked, 1)
		require.Equal(t, active, locked[0].Outpoint)

		return nil
	})
	require.NoError(t, err)
}

// TestListOutputsToWatchReturnsLockedCredit verifies that recovery watch lists
// include credits even when they are currently leased.
func TestListOutputsToWatchReturnsLockedCredit(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	pkScript := []byte{0x51, 0x21}
	outPoint := insertKnownCredit(t, dbConn, txStore, pkScript, 3000, 4)

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		_, err := txStore.LockOutput(
			ns, wtxmgr.LockID{3}, outPoint, time.Hour,
		)

		return err
	})
	require.NoError(t, err)

	utxos, err := store.ListOutputsToWatch(t.Context(), 0)
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.Equal(t, outPoint, utxos[0].OutPoint)
	require.Equal(t, pkScript, utxos[0].PkScript)
}

// TestGetUtxoSuccess verifies that kvdb.Store adapts one wallet-owned legacy
// credit into the db-native UTXO shape.
func TestGetUtxoSuccess(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	outPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(1500), 1,
		false,
	)

	utxo, err := store.GetUtxo(
		t.Context(), db.GetUtxoQuery{
			WalletID: 0,
			OutPoint: outPoint,
		},
	)
	require.NoError(t, err)
	require.Equal(t, outPoint, utxo.OutPoint)
	require.Equal(t, btcutil.Amount(1500), utxo.Amount)
	require.NotEmpty(t, utxo.PkScript)
	require.Equal(t, uint32(1), utxo.Height)
	require.Equal(t, waddrmgr.DefaultAccountName, utxo.AccountName)
	require.Equal(t, db.WitnessPubKey, utxo.AddrType)
	require.False(t, utxo.HasScript)
	require.Equal(t, db.KeyScopeBIP0084, utxo.KeyScope)
}

// TestGetUtxoNotFound verifies that kvdb.Store maps the legacy missing-UTXO
// error onto db.ErrUtxoNotFound.
func TestGetUtxoNotFound(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	_, err := store.GetUtxo(
		t.Context(), db.GetUtxoQuery{
			WalletID: 0,
			OutPoint: wire.OutPoint{Hash: [32]byte{9}, Index: 0},
		},
	)
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestGetUtxoRejectsSpentByUnminedTx verifies GetUtxo only returns outputs
// that remain current after unmined wallet spends are considered.
func TestGetUtxoRejectsSpentByUnminedTx(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 1500, 1,
	)
	insertUnminedSpend(t, dbConn, txStore, outPoint)

	_, err := store.GetUtxo(
		t.Context(), db.GetUtxoQuery{
			WalletID: 0,
			OutPoint: outPoint,
		},
	)
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestResolveAccountForCreditChecksAllScriptAddresses verifies bare-multisig
// UTXO enrichment does not stop at the first extracted script member when that
// member is not wallet-owned.
func TestResolveAccountForCreditChecksAllScriptAddresses(t *testing.T) {
	t.Parallel()

	members, script := newMultisigScriptMembers(t)

	acctStore := &bwmock.AccountStore{}
	acctStore.On("Scope").Return(waddrmgr.KeyScopeBIP0084)

	addrStore := &bwmock.AddrStore{}
	addrStore.On(
		"AddrAccount", mock.Anything, matchAddress(members[0]),
	).Return(
		nil, uint32(0), waddrmgr.ManagerError{
			ErrorCode:   waddrmgr.ErrAddressNotFound,
			Description: "address not found",
		},
	).Once()
	addrStore.On(
		"AddrAccount", mock.Anything, matchAddress(members[1]),
	).Return(acctStore, uint32(7), nil).Once()

	store := NewStore(nil, nil, addrStore)
	credit := &wtxmgr.Credit{PkScript: script}

	binding, addr, err := store.resolveAccountForCredit(
		nil, credit, &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	require.Equal(t, members[1].EncodeAddress(), addr.EncodeAddress())
	require.Same(t, acctStore, binding.acctStore)
	require.Equal(t, uint32(7), binding.acctNum)
	require.Equal(t, db.KeyScope(waddrmgr.KeyScopeBIP0084), binding.scope)

	addrStore.AssertExpectations(t)
	acctStore.AssertExpectations(t)
}

// TestCalcConfsGenesisHeight verifies the shared kvdb confirmation helper
// treats height zero as unconfirmed.
func TestCalcConfsGenesisHeight(t *testing.T) {
	t.Parallel()

	require.Equal(t, int32(0), calcConfs(0, 100))
}

// TestLeaseOutputSuccess verifies that kvdb.Store adapts one legacy lease write
// into the db-native leased-output view.
func TestLeaseOutputSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 2500, 2,
	)

	lease, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{1},
			OutPoint: outPoint,
			Duration: time.Hour,
		},
	)
	require.NoError(t, err)
	require.Equal(t, outPoint, lease.OutPoint)
	require.Equal(t, db.LockID{1}, lease.LockID)
	require.True(t, lease.Expiration.After(time.Now().UTC()))
}

// TestLeaseOutputRejectsSpentByUnminedTx verifies leases cannot be acquired for
// outputs already spent by an unmined wallet transaction.
func TestLeaseOutputRejectsSpentByUnminedTx(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 2500, 2,
	)
	insertUnminedSpend(t, dbConn, txStore, outPoint)

	_, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{1},
			OutPoint: outPoint,
			Duration: time.Hour,
		},
	)
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestLeaseOutputsLeasesCompleteSet verifies that LeaseOutputs leases every
// requested outpoint under one ID, and that ReleaseOutput frees one early.
func TestLeaseOutputsLeasesCompleteSet(t *testing.T) {
	t.Parallel()

	// Arrange: Store two distinct known credits.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	first := insertKnownCredit(t, dbConn, txStore, []byte{0x51}, 2500, 2)
	second := insertKnownCredit(t, dbConn, txStore, []byte{0x51}, 3000, 2)

	// Act: Lease both outpoints in one call, then release the first.
	leases, err := store.LeaseOutputs(t.Context(), db.LeaseOutputsParams{
		ID:        db.LockID{1},
		OutPoints: []wire.OutPoint{first, second},
		Duration:  time.Hour,
	})
	require.NoError(t, err)

	leasedBefore, err := store.ListLeasedOutputs(t.Context(), 0)
	require.NoError(t, err)

	err = store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		ID:       db.LockID{1},
		OutPoint: first,
	})
	require.NoError(t, err)

	leasedAfter, err := store.ListLeasedOutputs(t.Context(), 0)
	require.NoError(t, err)

	// Assert: Both outpoints were leased in request order under the ID
	// with a future expiry, and the early release left only the second.
	require.Len(t, leases, 2)
	require.Equal(t, first, leases[0].OutPoint)
	require.Equal(t, second, leases[1].OutPoint)

	for _, lease := range leases {
		require.Equal(t, db.LockID{1}, lease.LockID)
		require.True(t, lease.Expiration.After(time.Now().UTC()))
	}

	require.ElementsMatch(t, []wire.OutPoint{first, second},
		leasedOutPoints(leasedBefore))
	require.Equal(t, []wire.OutPoint{second}, leasedOutPoints(leasedAfter))
}

// TestLeaseOutputsConflictAcquiresNoPartialSet verifies that a conflicting
// lease anywhere in the set leaves no lease from the failed call behind.
func TestLeaseOutputsConflictAcquiresNoPartialSet(t *testing.T) {
	t.Parallel()

	// Arrange: Store two known credits and lease the second under another
	// ID.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	first := insertKnownCredit(t, dbConn, txStore, []byte{0x51}, 2500, 2)
	second := insertKnownCredit(t, dbConn, txStore, []byte{0x51}, 3000, 2)

	_, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		ID:       db.LockID{2},
		OutPoint: second,
		Duration: time.Hour,
	})
	require.NoError(t, err)

	// Act: Lease the set with the first outpoint ahead of the conflicting
	// one.
	leases, err := store.LeaseOutputs(t.Context(), db.LeaseOutputsParams{
		ID:        db.LockID{1},
		OutPoints: []wire.OutPoint{first, second},
		Duration:  time.Hour,
	})

	// Assert: The call fails with the conflict error and the first
	// outpoint's lease was rolled back, leaving only the other ID's lease.
	require.ErrorIs(t, err, db.ErrOutputAlreadyLeased)
	require.Nil(t, leases)

	leased, err := store.ListLeasedOutputs(t.Context(), 0)
	require.NoError(t, err)
	require.Equal(t, []wire.OutPoint{second}, leasedOutPoints(leased))
}

// TestLeaseOutputsMissingUtxoAcquiresNoPartialSet verifies that a missing
// output anywhere in the set leaves no lease from the failed call behind.
func TestLeaseOutputsMissingUtxoAcquiresNoPartialSet(t *testing.T) {
	t.Parallel()

	// Arrange: Store one known credit and pick an unknown outpoint.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	first := insertKnownCredit(t, dbConn, txStore, []byte{0x51}, 2500, 2)
	missing := wire.OutPoint{Hash: [32]byte{9}}

	// Act: Lease the set with the first outpoint ahead of the missing
	// one.
	leases, err := store.LeaseOutputs(t.Context(), db.LeaseOutputsParams{
		ID:        db.LockID{1},
		OutPoints: []wire.OutPoint{first, missing},
		Duration:  time.Hour,
	})

	// Assert: The call fails with the not-found error and the first
	// outpoint's lease was rolled back, leaving no leases.
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
	require.Nil(t, leases)

	leased, err := store.ListLeasedOutputs(t.Context(), 0)
	require.NoError(t, err)
	require.Empty(t, leased)
}

// TestLeaseOutputsTakesOverExpiredLease verifies that an expired lease held by
// another ID does not block LeaseOutputs, so the set call takes the output
// over.
//
// wtxmgr reads lease expiry from an unexported clock, so the test writes the
// holder's lease with an expiry in the past rather than advancing time.
func TestLeaseOutputsTakesOverExpiredLease(t *testing.T) {
	t.Parallel()

	// Arrange: Store two known credits and lease the second under another
	// ID with an expiry in the past.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	first := insertKnownCredit(t, dbConn, txStore, []byte{0x51}, 2500, 2)
	second := insertKnownCredit(t, dbConn, txStore, []byte{0x51}, 3000, 2)

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		_, err := txStore.LockOutput(
			ns, wtxmgr.LockID{2}, second, -time.Hour,
		)

		return err
	})
	require.NoError(t, err)

	// Act: Lease the set under a new ID.
	leases, err := store.LeaseOutputs(t.Context(), db.LeaseOutputsParams{
		ID:        db.LockID{1},
		OutPoints: []wire.OutPoint{first, second},
		Duration:  time.Hour,
	})
	require.NoError(t, err)

	leased, err := store.ListLeasedOutputs(t.Context(), 0)
	require.NoError(t, err)

	// Assert: The set call owns both outpoints with a future expiry.
	require.Len(t, leases, 2)
	require.Equal(t, first, leases[0].OutPoint)
	require.Equal(t, second, leases[1].OutPoint)

	for _, lease := range leases {
		require.Equal(t, db.LockID{1}, lease.LockID)
		require.True(t, lease.Expiration.After(time.Now().UTC()))
	}

	require.Len(t, leased, 2)

	for _, lease := range leased {
		require.Equal(t, db.LockID{1}, lease.LockID)
	}

	require.ElementsMatch(t, []wire.OutPoint{first, second},
		leasedOutPoints(leased))
}

// leasedOutPoints returns the outpoints of the given leases.
func leasedOutPoints(leases []db.LeasedOutput) []wire.OutPoint {
	outPoints := make([]wire.OutPoint, 0, len(leases))
	for _, lease := range leases {
		outPoints = append(outPoints, lease.OutPoint)
	}

	return outPoints
}

// TestListLeasedOutputsSuccess verifies that kvdb.Store exposes the active
// legacy lease set through the db-native shape.
func TestListLeasedOutputsSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 3000, 3,
	)

	_, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{2},
			OutPoint: outPoint,
			Duration: time.Hour,
		},
	)
	require.NoError(t, err)

	leases, err := store.ListLeasedOutputs(t.Context(), 0)
	require.NoError(t, err)
	require.Len(t, leases, 1)
	require.Equal(t, outPoint, leases[0].OutPoint)
	require.Equal(t, db.LockID{2}, leases[0].LockID)
}

// TestListUTXOsIncludesLockedOutputs verifies kvdb returns current UTXOs even
// when they are actively leased.
func TestListUTXOsIncludesLockedOutputs(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	// Credit two wallet-owned outputs so they resolve to an account and
	// surface through the enriched listing path (unowned scripts are
	// dropped, matching the SQL backends).
	scope := waddrmgr.KeyScopeBIP0084
	lockedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(3000),
		balanceTestTipHeight, false,
	)
	unlockedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(4000),
		balanceTestTipHeight, false,
	)

	_, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{3},
			OutPoint: lockedPoint,
			Duration: time.Hour,
		},
	)
	require.NoError(t, err)

	utxos, err := store.ListUTXOs(
		t.Context(), db.ListUtxosQuery{
			WalletID: 0,
		},
	)
	require.NoError(t, err)
	require.Len(t, utxos, 2)
	require.ElementsMatch(t, []wire.OutPoint{
		lockedPoint, unlockedPoint,
	}, []wire.OutPoint{
		utxos[0].OutPoint, utxos[1].OutPoint,
	})

	// The leased output reports IsLocked; the other does not. This is the
	// original intent of the test: a leased UTXO still appears in the
	// listing, now distinguished by the enriched IsLocked flag.
	byOutPoint := make(map[wire.OutPoint]db.UtxoInfo, len(utxos))
	for _, u := range utxos {
		byOutPoint[u.OutPoint] = u
	}

	require.True(t, byOutPoint[lockedPoint].IsLocked)
	require.False(t, byOutPoint[unlockedPoint].IsLocked)
}

// TestUTXOEnrichmentFields verifies kvdb UTXO listing populates enriched
// account, script type, and lock metadata.
func TestUTXOEnrichmentFields(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	wantScope := db.KeyScopeBIP0084

	lockedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(20000),
		balanceTestTipHeight, false,
	)
	unlockedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(30000),
		balanceTestTipHeight, false,
	)

	// Lease only one output so IsLocked separates the two rows.
	_, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: 0,
			OutPoint: lockedPoint,
			ID:       db.LockID{1},
			Duration: 30 * time.Minute,
		},
	)
	require.NoError(t, err)

	// ListUTXOs returns both rows with the derived-account enrichment.
	utxos, err := store.ListUTXOs(
		t.Context(), db.ListUtxosQuery{
			WalletID: 0,
		},
	)
	require.NoError(t, err)
	require.Len(t, utxos, 2)

	byOutPoint := make(map[wire.OutPoint]db.UtxoInfo, len(utxos))
	for _, u := range utxos {
		byOutPoint[u.OutPoint] = u
	}

	locked, ok := byOutPoint[lockedPoint]
	require.True(t, ok, "locked UTXO missing from ListUTXOs")
	require.Equal(t, waddrmgr.DefaultAccountName, locked.AccountName)
	require.Equal(t, db.WitnessPubKey, locked.AddrType)
	require.False(t, locked.HasScript)
	require.True(t, locked.IsLocked)
	require.Equal(t, wantScope, locked.KeyScope)

	unlocked, ok := byOutPoint[unlockedPoint]
	require.True(t, ok, "unlocked UTXO missing from ListUTXOs")
	require.Equal(t, waddrmgr.DefaultAccountName, unlocked.AccountName)
	require.Equal(t, db.WitnessPubKey, unlocked.AddrType)
	require.False(t, unlocked.HasScript)
	require.False(t, unlocked.IsLocked)
	require.Equal(t, wantScope, unlocked.KeyScope)

	// GetUtxo surfaces the same enriched view as ListUTXOs, including the
	// active-lease IsLocked flag and the owning account's KeyScope.
	got, err := store.GetUtxo(
		t.Context(), db.GetUtxoQuery{
			WalletID: 0,
			OutPoint: lockedPoint,
		},
	)
	require.NoError(t, err)
	require.Equal(t, waddrmgr.DefaultAccountName, got.AccountName)
	require.Equal(t, db.WitnessPubKey, got.AddrType)
	require.False(t, got.HasScript)
	require.True(t, got.IsLocked)
	require.Equal(t, wantScope, got.KeyScope)
}

// TestListLeasedOutputsDropsSpentLeases verifies kvdb omits active leases once
// the leased outpoint is spent by an unmined wallet transaction.
func TestListLeasedOutputsDropsSpentLeases(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 3000, 3,
	)

	_, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{4},
			OutPoint: outPoint,
			Duration: time.Hour,
		},
	)
	require.NoError(t, err)

	insertUnminedSpend(t, dbConn, txStore, outPoint)

	leases, err := store.ListLeasedOutputs(t.Context(), 0)
	require.NoError(t, err)
	require.Empty(t, leases)
}

// TestListUTXOsFiltersByConfirms verifies that kvdb.Store applies the
// confirmation filters before returning db-native UTXO rows. The
// account / scope / name filters are exercised end-to-end by the
// cross-backend itests under wallet/internal/db/itest, where real
// addrmgr fixtures populate the enrichment fields and the filter
// semantics can be asserted across pg, sqlite, and kvdb together.
func TestListUTXOsFiltersByConfirms(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(4000), 4,
		false,
	)
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(5000), 5,
		false,
	)
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(6000), 0,
		false,
	)

	minConfs := int32(1)

	utxos, err := store.ListUTXOs(
		t.Context(), db.ListUtxosQuery{
			WalletID: 0,
			MinConfs: &minConfs,
		},
	)
	require.NoError(t, err)
	require.Len(t, utxos, 2)
}

// insertKnownCredit inserts one test credit and returns its outpoint.
func insertKnownCredit(t *testing.T, dbConn walletdb.DB, txStore *wtxmgr.Store,
	pkScript []byte, value int64, height int32) wire.OutPoint {

	t.Helper()

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: [32]byte{1}},
	})
	txMsg.AddTxOut(&wire.TxOut{Value: value, PkScript: pkScript})

	received := time.Now().UTC()
	rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, received)
	require.NoError(t, err)

	var block *wtxmgr.BlockMeta
	if height >= 0 {
		block = &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Height: height},
			Time:  received,
		}
	}

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return walletdb.ErrBucketNotFound
		}

		err := txStore.InsertTx(ns, rec, block)
		if err != nil {
			return fmt.Errorf("insert tx: %w", err)
		}

		err = txStore.AddCredit(ns, rec, block, 0, false)
		if err != nil {
			return fmt.Errorf("add credit: %w", err)
		}

		return nil
	})
	require.NoError(t, err)

	return wire.OutPoint{Hash: rec.Hash, Index: 0}
}

// insertUnminedSpend records an unmined wallet transaction that spends the
// given outpoint.
func insertUnminedSpend(t *testing.T, dbConn walletdb.DB,
	txStore *wtxmgr.Store, outPoint wire.OutPoint) {

	t.Helper()

	spendTx := &wire.MsgTx{Version: 1}
	spendTx.AddTxIn(&wire.TxIn{PreviousOutPoint: outPoint})
	spendTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
	spendRec, err := wtxmgr.NewTxRecordFromMsgTx(spendTx, time.Now())
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return walletdb.ErrBucketNotFound
		}

		return txStore.InsertTx(ns, spendRec, nil)
	})
	require.NoError(t, err)
}

// TestBalanceRejectsAccountWithoutScope verifies that Balance enforces
// the BalanceParams contract: an Account filter requires a Scope filter to
// avoid cross-scope account-number collisions.
func TestBalanceRejectsAccountWithoutScope(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	store := NewStore(dbConn, nil, nil)

	acct := uint32(0)
	_, err := store.Balance(t.Context(), db.BalanceParams{
		Account: &acct,
	})
	require.ErrorIs(t, err, db.ErrBalanceParamsAccountWithoutScope)
}

// TestBalanceEmptyWallet verifies that Balance returns zero on a wallet
// with no UTXOs and a nil tx store.
func TestBalanceEmptyWallet(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	store := NewStore(dbConn, nil, nil)

	result, err := store.Balance(t.Context(), db.BalanceParams{})
	require.NoError(t, err)
	require.Zero(t, result.Total)
}

// TestListUTXOsExcludesImportedFromNumericAccountFilter verifies that kvdb
// matches SQL semantics for the db.ListUtxosQuery.Account filter: a numeric
// Account filter never selects imported UTXOs (those carry the legacy
// ImportedAddrAccount pseudo-account number, which has no numeric counterpart
// on SQL backends), while derived accounts remain selectable by number.
// Imported UTXOs stay reachable through (Scope, AccountName).
func TestListUTXOsExcludesImportedFromNumericAccountFilter(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScopeBIP0084

	// Arrange: one derived-account (account 0) UTXO and one imported-key
	// UTXO under the legacy ImportedAddrAccount pseudo-account.
	derivedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(1000),
		balanceTestTipHeight, false,
	)
	importedPoint := creditImportedKeyAtHeight(
		t, store.db, mgr, txStore, scope, btcutil.Amount(2000),
		balanceTestTipHeight,
	)

	// A numeric Account filter set to the imported pseudo-account number
	// must select nothing: imported rows are not numerically addressable,
	// matching SQL's NULL account_number.
	importedAcct := uint32(waddrmgr.ImportedAddrAccount)
	utxos, err := store.ListUTXOs(
		t.Context(), db.ListUtxosQuery{
			WalletID: 0,
			Scope:    &dbScope,
			Account:  &importedAcct,
		},
	)
	require.NoError(t, err)
	require.Empty(t, utxos)

	// A numeric Account filter for the derived account returns only the
	// derived UTXO; the imported UTXO is excluded.
	derivedAcct := uint32(0)
	utxos, err = store.ListUTXOs(
		t.Context(), db.ListUtxosQuery{
			WalletID: 0,
			Scope:    &dbScope,
			Account:  &derivedAcct,
		},
	)
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.Equal(t, derivedPoint, utxos[0].OutPoint)

	// The imported UTXO remains selectable via (Scope, AccountName).
	importedName := waddrmgr.ImportedAddrAccountName
	utxos, err = store.ListUTXOs(
		t.Context(), db.ListUtxosQuery{
			WalletID:    0,
			Scope:       &dbScope,
			AccountName: &importedName,
		},
	)
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.Equal(t, importedPoint, utxos[0].OutPoint)
	require.NotNil(t, utxos[0].Spendable)
	require.True(t, *utxos[0].Spendable)
}

// TestListUTXOsExcludesWatchOnlyAccountFromNumericAccountFilter verifies that
// kvdb excludes a numberless imported xpub from the numeric Account filter
// despite its internal account number, while a declared imported number selects
// only its own UTXO; the numberless import remains reachable by name.
func TestListUTXOsExcludesWatchOnlyAccountFromNumericAccountFilter(
	t *testing.T) {

	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScopeBIP0084

	// Arrange: Credit derived, numberless imported and declared imported
	// accounts with distinct outputs to expose incorrect numeric selection.
	importedName := "imported-xpub-list"
	importedAcct := createImportedXpubAccount(
		t, store, scope, importedName, 0xBE,
	)
	declaredAcct := createImportedXpubAccount(
		t, store, scope, "declared-xpub-list", 0xBF, 7,
	)

	derivedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(1000),
		balanceTestTipHeight, false,
	)
	importedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, importedAcct,
		btcutil.Amount(2000), balanceTestTipHeight, false,
	)
	declaredPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, declaredAcct,
		btcutil.Amount(3000), balanceTestTipHeight, false,
	)

	// Act: List each account by number and the numberless import by name,
	// using the same public query that callers use to find owned outputs.
	importedUTXOs, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: 0,
		Scope:    &dbScope,
		Account:  &importedAcct,
	})
	require.NoError(t, err)

	derivedAcct := uint32(0)
	derivedUTXOs, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: 0,
		Scope:    &dbScope,
		Account:  &derivedAcct,
	})
	require.NoError(t, err)

	namedUTXOs, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID:    0,
		Scope:       &dbScope,
		AccountName: &importedName,
	})
	require.NoError(t, err)
	declaredUTXOs, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: 0,
		Scope:    &dbScope,
		Account:  &declaredAcct,
	})
	require.NoError(t, err)

	// Assert: Numeric selection isolates both known accounts and excludes
	// the numberless import, which retains its named watch-only result.
	require.Empty(t, importedUTXOs)
	require.Len(t, derivedUTXOs, 1)
	require.Equal(t, derivedPoint, derivedUTXOs[0].OutPoint)
	require.Len(t, namedUTXOs, 1)
	require.Equal(t, importedPoint, namedUTXOs[0].OutPoint)
	require.NotNil(t, namedUTXOs[0].Spendable)
	require.False(t, *namedUTXOs[0].Spendable)
	require.Len(t, declaredUTXOs, 1)
	require.Equal(t, declaredPoint, declaredUTXOs[0].OutPoint)
}

// createImportedXpubAccount creates an imported (watch-only) xpub account via
// CreateImportedAccount, which allocates an ordinary kvdb account number
// rather than the legacy ImportedAddrAccount pseudo-account. An optional number
// creates a depth-three key and declares its account path; without it, the
// public account remains numberless. The returned internal number lets fixtures
// credit either kind, and the seed byte keeps successive accounts distinct.
func createImportedXpubAccount(t *testing.T, store *Store,
	scope waddrmgr.KeyScope, name string, seedByte byte,
	number ...uint32) uint32 {

	t.Helper()

	// Retain supplied metadata through the optional Store input.
	fingerprint := uint32(0xDEADBEEF)

	seed := bytes.Repeat([]byte{seedByte}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)

	// Declared imports require an account key at the requested hardened path;
	// existing numberless fixtures keep their original key and allocation.
	var accountNumber *uint32
	if len(number) > 0 {
		accountNumber = &number[0]
		for _, child := range []uint32{
			scope.Purpose, scope.Coin, *accountNumber,
		} {
			master, err = master.Derive(
				hdkeychain.HardenedKeyStart + child,
			)
			require.NoError(t, err)
		}
	}

	masterPub, err := master.Neuter()
	require.NoError(t, err)

	dbScope := db.KeyScope{Purpose: scope.Purpose, Coin: scope.Coin}

	_, err = store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			AccountNumber:     accountNumber,
			Scope:             dbScope,
			Name:              name,
			MasterFingerprint: &fingerprint,
			PublicKey:         []byte(masterPub.String()),
		},
	)
	require.NoError(t, err)

	scopedMgr, err := store.addrStore.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	var account uint32

	err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)

		var inner error

		account, inner = scopedMgr.LookupAccount(ns, name)

		return inner
	})
	require.NoError(t, err)

	// These are HD account fixtures, so their native slot must differ from
	// the raw-import pseudo-account whose exclusion has separate coverage.
	require.NotEqual(t, uint32(waddrmgr.ImportedAddrAccount), account)

	return account
}
