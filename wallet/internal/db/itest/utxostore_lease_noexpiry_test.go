//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestNoExpiryLeaseStaysActive verifies that a lease without expiry reserves
// its output on every lease-aware read and survives expired-lease cleanup.
func TestNoExpiryLeaseStaysActive(t *testing.T) {
	t.Parallel()

	// Arrange: Lease one output without expiry.
	store := NewTestStore(t)
	walletID, outPoints := newLeaseSetFixture(
		t, store, "wallet-lease-no-expiry-active", 1,
	)
	outPoint := outPoints[0]

	lease, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       db.LockID{1},
		OutPoint: outPoint,
		NoExpiry: true,
	})
	require.NoError(t, err)

	// Act: Run expired-lease cleanup, then try to take and release the
	// lease under another ID.
	err = store.DeleteExpiredLeases(t.Context(), walletID)
	require.NoError(t, err)

	_, takeErr := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       db.LockID{2},
		OutPoint: outPoint,
		Duration: time.Minute,
	})
	releaseErr := store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: walletID,
		ID:       db.LockID{2},
		OutPoint: outPoint,
	})

	// Read the lease back through every lease-aware view.
	leases, err := store.ListLeasedOutputs(t.Context(), walletID)
	require.NoError(t, err)

	utxo, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: outPoint,
	})
	require.NoError(t, err)

	utxos, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
	})
	require.NoError(t, err)

	balance, err := store.Balance(t.Context(), db.BalanceParams{
		WalletID: walletID,
	})
	require.NoError(t, err)

	// Assert: The lease reports no expiry and stays active on every read.
	require.True(t, lease.NoExpiry)
	require.True(t, lease.Expiration.IsZero())
	require.ErrorIs(t, takeErr, db.ErrOutputAlreadyLeased)
	require.ErrorIs(t, releaseErr, db.ErrOutputUnlockNotAllowed)
	require.Equal(t, []db.LeasedOutput{*lease}, leases)
	require.True(t, utxo.IsLocked)
	require.Len(t, utxos, 1)
	require.True(t, utxos[0].IsLocked)
	require.Equal(t, utxo.Amount, balance.Locked)
}

// TestNoExpiryLeaseRenewal verifies that a same-owner renewal never shortens
// a lease without expiry, and that a no-expiry renewal lifts a timed lease.
func TestNoExpiryLeaseRenewal(t *testing.T) {
	t.Parallel()

	// Arrange: Lease one output without expiry and one with a duration.
	store := NewTestStore(t)
	walletID, outPoints := newLeaseSetFixture(
		t, store, "wallet-lease-no-expiry-renewal", 2,
	)

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
		Duration: time.Minute,
	})
	require.NoError(t, err)

	// Act: Renew the first with a duration and the second without expiry.
	timedRenewal, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: walletID,
			ID:       db.LockID{1},
			OutPoint: outPoints[0],
			Duration: time.Minute,
		},
	)
	require.NoError(t, err)

	noExpiryRenewal, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: walletID,
			ID:       db.LockID{1},
			OutPoint: outPoints[1],
			NoExpiry: true,
		},
	)
	require.NoError(t, err)

	leases, err := store.ListLeasedOutputs(t.Context(), walletID)
	require.NoError(t, err)

	// Assert: Both renewals report, and stored, a lease without expiry.
	require.True(t, timedRenewal.NoExpiry)
	require.True(t, noExpiryRenewal.NoExpiry)
	require.ElementsMatch(t, []db.LeasedOutput{
		*timedRenewal, *noExpiryRenewal,
	}, leases)
}

// TestLeaseOutputsNoExpiry verifies that LeaseOutputs leases a whole set
// without expiry, and that listing orders those leases after timed ones on
// both SQL dialects.
func TestLeaseOutputsNoExpiry(t *testing.T) {
	t.Parallel()

	// Arrange: Create three current wallet UTXOs.
	store := NewTestStore(t)
	walletID, outPoints := newLeaseSetFixture(
		t, store, "wallet-lease-outputs-no-expiry", 3,
	)

	// Act: Lease the first two without expiry and the last with a
	// duration.
	leases, err := store.LeaseOutputs(t.Context(), db.LeaseOutputsParams{
		WalletID:  walletID,
		ID:        db.LockID{1},
		OutPoints: outPoints[:2],
		NoExpiry:  true,
	})
	require.NoError(t, err)

	timed, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       db.LockID{1},
		OutPoint: outPoints[2],
		Duration: time.Minute,
	})
	require.NoError(t, err)

	listed, err := store.ListLeasedOutputs(t.Context(), walletID)
	require.NoError(t, err)

	// Assert: The set has no expiry, and the timed lease is listed first.
	require.Len(t, leases, 2)
	require.True(t, leases[0].NoExpiry)
	require.True(t, leases[1].NoExpiry)
	require.Len(t, listed, 3)
	require.Equal(t, *timed, listed[0])
	require.ElementsMatch(t, leases, listed[1:])
}
