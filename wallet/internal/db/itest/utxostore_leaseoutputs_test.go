//go:build itest

package itest

import (
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// newLeaseSetFixture creates a wallet with one pending transaction paying
// count wallet-owned outputs and returns the wallet ID and those outpoints.
func newLeaseSetFixture(t *testing.T, store db.Store, name string,
	count int) (uint32, []wire.OutPoint) {

	t.Helper()

	walletID := newWallet(t, store, name)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	outputs := make([]*wire.TxOut, 0, count)
	credits := make(map[uint32]address.Address, count)

	for i := range count {
		outputs = append(outputs, &wire.TxOut{
			Value: int64(10_000 + i), PkScript: addr.ScriptPubKey,
		})
		credits[uint32(i)] = nil
	}

	tx := newRegularTx([]wire.OutPoint{randomOutPoint()}, outputs)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710001800, 0),
		Status:   db.TxStatusPending,
		Credits:  credits,
	})
	require.NoError(t, err)

	outPoints := make([]wire.OutPoint, 0, count)
	for i := range count {
		outPoints = append(outPoints, wire.OutPoint{
			Hash: tx.TxHash(), Index: uint32(i),
		})
	}

	return walletID, outPoints
}

// leasedByID returns the wallet's active leases as an outpoint-to-lock map.
func leasedByID(t *testing.T, store db.Store,
	walletID uint32) map[wire.OutPoint]db.LockID {

	t.Helper()

	leases, err := store.ListLeasedOutputs(t.Context(), walletID)
	require.NoError(t, err)

	byOutPoint := make(map[wire.OutPoint]db.LockID, len(leases))
	for _, lease := range leases {
		byOutPoint[lease.OutPoint] = lease.LockID
	}

	return byOutPoint
}

// TestLeaseOutputsLeasesCompleteSet verifies that LeaseOutputs leases every
// requested outpoint under one ID with one expiry, and that ReleaseOutput
// frees one early.
func TestLeaseOutputsLeasesCompleteSet(t *testing.T) {
	t.Parallel()

	// Arrange: Create two current wallet UTXOs.
	store := NewTestStore(t)
	walletID, outPoints := newLeaseSetFixture(
		t, store, "wallet-lease-outputs-complete", 2,
	)

	// Act: Lease both in one call, then release the first early.
	before := time.Now().UTC()
	leases, err := store.LeaseOutputs(t.Context(), db.LeaseOutputsParams{
		WalletID:  walletID,
		ID:        db.LockID{1},
		OutPoints: outPoints,
		Duration:  10 * time.Minute,
	})
	require.NoError(t, err)

	leasedBefore := leasedByID(t, store, walletID)

	err = store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: walletID,
		ID:       db.LockID{1},
		OutPoint: outPoints[0],
	})
	require.NoError(t, err)

	leasedAfter := leasedByID(t, store, walletID)

	// Assert: Both outputs were leased under the ID with the same
	// expiry about ten minutes out, and the release freed only the first.
	require.Len(t, leases, 2)
	require.Equal(t, leases[0].Expiration, leases[1].Expiration)
	require.WithinDuration(
		t, before.Add(10*time.Minute), leases[0].Expiration,
		time.Minute,
	)
	require.Equal(t, map[wire.OutPoint]db.LockID{
		outPoints[0]: {1}, outPoints[1]: {1},
	}, leasedBefore)
	require.Equal(t, map[wire.OutPoint]db.LockID{
		outPoints[1]: {1},
	}, leasedAfter)
}

// TestLeaseOutputsConflictAcquiresNoPartialSet verifies that a conflicting
// lease anywhere in the set rolls back every lease the call wrote.
func TestLeaseOutputsConflictAcquiresNoPartialSet(t *testing.T) {
	t.Parallel()

	// Arrange: Create three wallet UTXOs and lease the last one under
	// another ID.
	store := NewTestStore(t)
	walletID, outPoints := newLeaseSetFixture(
		t, store, "wallet-lease-outputs-conflict", 3,
	)

	_, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       db.LockID{2},
		OutPoint: outPoints[2],
		Duration: time.Hour,
	})
	require.NoError(t, err)

	// Act: Lease the set with the conflicting outpoint last, so the first
	// two writes happen before the failure.
	leases, err := store.LeaseOutputs(t.Context(), db.LeaseOutputsParams{
		WalletID:  walletID,
		ID:        db.LockID{1},
		OutPoints: outPoints,
		Duration:  time.Hour,
	})

	// Assert: The call fails with the conflict error and only the other
	// ID's lease remains.
	require.ErrorIs(t, err, db.ErrOutputAlreadyLeased)
	require.Nil(t, leases)
	require.Equal(t, map[wire.OutPoint]db.LockID{
		outPoints[2]: {2},
	}, leasedByID(t, store, walletID))
}

// TestLeaseOutputsMissingUtxoAcquiresNoPartialSet verifies that a missing
// output anywhere in the set rolls back every lease the call wrote.
func TestLeaseOutputsMissingUtxoAcquiresNoPartialSet(t *testing.T) {
	t.Parallel()

	// Arrange: Create two wallet UTXOs and append an unknown outpoint.
	store := NewTestStore(t)
	walletID, outPoints := newLeaseSetFixture(
		t, store, "wallet-lease-outputs-missing", 2,
	)
	outPoints = append(outPoints, randomOutPoint())

	// Act: Lease the set with the missing outpoint last, so the first two
	// writes happen before the failure.
	leases, err := store.LeaseOutputs(t.Context(), db.LeaseOutputsParams{
		WalletID:  walletID,
		ID:        db.LockID{1},
		OutPoints: outPoints,
		Duration:  time.Hour,
	})

	// Assert: The call fails with the not-found error and no leases
	// remain.
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
	require.Nil(t, leases)
	require.Empty(t, leasedByID(t, store, walletID))
}

// TestLeaseOutputsTakesOverExpiredLease verifies that an expired lease held by
// another ID does not block a set reservation, so expiry alone makes outputs
// available again without any cleanup worker.
func TestLeaseOutputsTakesOverExpiredLease(t *testing.T) {
	t.Parallel()

	// Arrange: Lease the first of two UTXOs under another ID, then move
	// its expiry into the past with a direct write instead of sleeping.
	store := NewTestStore(t)
	walletID, outPoints := newLeaseSetFixture(
		t, store, "wallet-lease-outputs-expired", 2,
	)

	expiredID := db.LockID{2}
	_, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       expiredID,
		OutPoint: outPoints[0],
		Duration: time.Hour,
	})
	require.NoError(t, err)

	expireLease(t, store.DB(), walletID, expiredID)

	// Act: Reserve both UTXOs under a new ID.
	_, err = store.LeaseOutputs(t.Context(), db.LeaseOutputsParams{
		WalletID:  walletID,
		ID:        db.LockID{1},
		OutPoints: outPoints,
		Duration:  10 * time.Minute,
	})

	// Assert: The expired lease was taken over and the new ID owns both.
	require.NoError(t, err)
	require.Equal(t, map[wire.OutPoint]db.LockID{
		outPoints[0]: {1}, outPoints[1]: {1},
	}, leasedByID(t, store, walletID))
}

// TestLeaseOutputsConcurrentOverlap verifies that two concurrent reservations
// sharing outpoints cannot both succeed, and that the loser keeps none of its
// other outputs. The sets name their shared outputs in opposite orders, so on
// PostgreSQL the race must end in an ordinary lease conflict rather than a
// deadlock abort. The scheduler decides the interleaving, so this only makes
// the deadlock-prone one possible; the deterministic proof of canonical
// acquisition order is TestLeaseOutputsWithOps in the db package.
func TestLeaseOutputsConcurrentOverlap(t *testing.T) {
	t.Parallel()

	// Arrange: Create four UTXOs and two sets that each own one output
	// and share the middle two in opposite orders.
	store := NewTestStore(t)
	walletID, outPoints := newLeaseSetFixture(
		t, store, "wallet-lease-outputs-concurrent", 4,
	)
	sets := [][]wire.OutPoint{
		{outPoints[0], outPoints[1], outPoints[2]},
		{outPoints[3], outPoints[2], outPoints[1]},
	}

	// Act: Start both reservations together under different IDs.
	errs := make([]error, len(sets))
	start := make(chan struct{})

	var wg sync.WaitGroup
	for i, set := range sets {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			_, errs[i] = store.LeaseOutputs(
				t.Context(), db.LeaseOutputsParams{
					WalletID:  walletID,
					ID:        db.LockID{byte(i + 1)},
					OutPoints: set,
					Duration:  time.Hour,
				},
			)
		}()
	}

	close(start)
	wg.Wait()

	// Assert: Exactly one reservation won and owns its complete set; the
	// other failed with a lease conflict, never a deadlock, and holds
	// nothing.
	winner, loser := 0, 1
	if errs[0] != nil {
		winner, loser = 1, 0
	}

	require.NoError(t, errs[winner])
	require.ErrorIs(t, errs[loser], db.ErrOutputAlreadyLeased)

	want := make(map[wire.OutPoint]db.LockID, len(sets[winner]))
	for _, outPoint := range sets[winner] {
		want[outPoint] = db.LockID{byte(winner + 1)}
	}

	require.Equal(t, want, leasedByID(t, store, walletID))
}
