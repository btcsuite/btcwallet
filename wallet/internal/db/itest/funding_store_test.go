package itest

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlstore"
	"github.com/stretchr/testify/require"
)

// testFundingStore runs the SQL funding-plan, lease-grouping, and address-guard
// vector against one SQL backend. These runtime guards are SQL-only, so the
// vector is skipped for the KV backend.
func testFundingStore(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	t.Run("plan lifecycle", func(t *testing.T) {
		testFundingPlanLifecycle(t, harness)
	})
	t.Run("plan groups leases", func(t *testing.T) {
		testFundingPlanGroupsLeases(t, harness)
	})
	t.Run("plan retention gc", func(t *testing.T) {
		testFundingPlanRetentionGC(t, harness)
	})
	t.Run("derivation path uniqueness", func(t *testing.T) {
		testDerivationPathUniqueness(t, harness)
	})
	t.Run("branch index cas", func(t *testing.T) {
		testBranchIndexCAS(t, harness)
	})
}

// reservationToken builds a deterministic 32-byte reservation token, matching
// the lock-id width a funding plan's leases reuse.
func reservationToken(value byte) []byte {
	return bytes.Repeat([]byte{value}, 32)
}

// testFundingPlanLifecycle verifies each terminal transition from a reserved
// plan and that an illegal transition or an unknown reservation is rejected.
func testFundingPlanLifecycle(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	walletID := harness.createWallet(
		t, "funding-lifecycle", testBlock(920), testBlock(921),
	)
	store := harness.newRuntime(walletID)

	reserve := func(token byte) []byte {
		id := reservationToken(token)
		runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
			planID, err := rt.ReserveFundingPlan(sqlstore.FundingPlan{
				ReservationID: id,
				Purpose:       "construction",
				CreatedAt:     time.Unix(1_000, 0),
				ExpiresAt:     time.Unix(2_000, 0),
			})
			require.NoError(t, err)
			require.Positive(t, planID)

			return nil
		})

		return id
	}
	requireStatus := func(id []byte, status string) {
		runtimeView(t, store, func(rt *sqlstore.RuntimeStore) error {
			plan, found, err := rt.FundingPlan(id)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, status, plan.Status)

			return nil
		})
	}

	// A reserved plan consumes into a committed transaction, recording the
	// transaction it funded.
	committedTx := harness.insertTransaction(
		t, walletID, testHash(0x40), 921, 0, false,
	)
	consumed := reserve(0x01)
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.ConsumeFundingPlan(consumed, committedTx)
	})
	requireStatus(consumed, sqlstore.FundingPlanConsumed)
	runtimeView(t, store, func(rt *sqlstore.RuntimeStore) error {
		plan, found, err := rt.FundingPlan(consumed)
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, committedTx, plan.CommittedTxID)

		return nil
	})

	// A reserved plan releases when its transaction is abandoned.
	released := reserve(0x02)
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.ReleaseFundingPlan(released)
	})
	requireStatus(released, sqlstore.FundingPlanReleased)

	// A reserved plan expires when its deadline passes.
	expired := reserve(0x03)
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.ExpireFundingPlan(expired)
	})
	requireStatus(expired, sqlstore.FundingPlanExpired)

	// Releasing an already consumed plan is an illegal transition.
	illegalErr := store.RuntimeUpdate(
		context.Background(), func(rt *sqlstore.RuntimeStore) error {
			return rt.ReleaseFundingPlan(consumed)
		}, nil,
	)
	require.ErrorIs(t, illegalErr, db.ErrReservationConflict)

	// Consuming an unknown reservation is also a conflict.
	unknownErr := store.RuntimeUpdate(
		context.Background(), func(rt *sqlstore.RuntimeStore) error {
			return rt.ConsumeFundingPlan(reservationToken(0x09), 0)
		}, nil,
	)
	require.ErrorIs(t, unknownErr, db.ErrReservationConflict)
}

// testFundingPlanGroupsLeases verifies that a plan groups its own leases under
// the reservation token and that consuming or releasing a plan removes only its
// own leases while external leases remain untouched.
func testFundingPlanGroupsLeases(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	walletID := harness.createWallet(
		t, "funding-groups", testBlock(922), testBlock(923),
	)
	store := harness.newRuntime(walletID)

	countLeases := func(ownerType string) int {
		var count int

		err := harness.queryRow(t, `
			SELECT count(*) FROM utxo_leases
			WHERE wallet_id = ? AND owner_type = ?
		`, walletID, ownerType).Scan(&count)
		require.NoError(t, err)

		return count
	}

	// An external caller lease must survive every plan operation.
	externalHash := testHash(0x71)
	harness.exec(t, `
		INSERT INTO utxo_leases (
			wallet_id, tx_hash, output_index, lock_id, expires_unix,
			owner_type
		) VALUES (?, ?, 0, ?, 5000, 'external')
	`, walletID, externalHash[:], reservationToken(0x77))

	// Reserve a plan and group two leases under it.
	reservation := reservationToken(0x21)
	leaseHashA := testHash(0x31)
	leaseHashB := testHash(0x32)
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		_, err := rt.ReserveFundingPlan(sqlstore.FundingPlan{
			ReservationID: reservation,
			Purpose:       "construction",
			CreatedAt:     time.Unix(1_000, 0),
			ExpiresAt:     time.Unix(2_000, 0),
		})
		require.NoError(t, err)

		err = rt.AddFundingPlanLease(
			reservation, leaseHashA[:], 0, time.Unix(2_000, 0),
		)
		require.NoError(t, err)

		return rt.AddFundingPlanLease(
			reservation, leaseHashB[:], 1, time.Unix(2_000, 0),
		)
	})
	require.Equal(t, 2, countLeases("funding_plan"))
	require.Equal(t, 1, countLeases("external"))

	// A plan-owned lease reuses the reservation id as its durable lock id.
	var lockID []byte
	err := harness.queryRow(t, `
		SELECT lock_id FROM utxo_leases WHERE wallet_id = ? AND tx_hash = ?
	`, walletID, leaseHashA[:]).Scan(&lockID)
	require.NoError(t, err)
	require.Equal(t, reservation, lockID)

	// Consuming the plan deletes only its own leases.
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.ConsumeFundingPlan(reservation, 0)
	})
	require.Equal(t, 0, countLeases("funding_plan"))
	require.Equal(t, 1, countLeases("external"))

	// A second plan released the same way also spares the external lease.
	otherReservation := reservationToken(0x22)
	leaseHashC := testHash(0x33)
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		_, err := rt.ReserveFundingPlan(sqlstore.FundingPlan{
			ReservationID: otherReservation,
			Purpose:       "construction",
			CreatedAt:     time.Unix(1_000, 0),
			ExpiresAt:     time.Unix(2_000, 0),
		})
		require.NoError(t, err)

		return rt.AddFundingPlanLease(
			otherReservation, leaseHashC[:], 0, time.Unix(2_000, 0),
		)
	})
	require.Equal(t, 1, countLeases("funding_plan"))

	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.ReleaseFundingPlan(otherReservation)
	})
	require.Equal(t, 0, countLeases("funding_plan"))
	require.Equal(t, 1, countLeases("external"))
}

// testFundingPlanRetentionGC verifies that retention collection removes a
// terminal, past-deadline plan that owns no leases while it never collects a
// reserved plan or a terminal plan that still owns leases.
func testFundingPlanRetentionGC(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	walletID := harness.createWallet(
		t, "funding-retention", testBlock(924), testBlock(925),
	)
	store := harness.newRuntime(walletID)

	reserveExpired := func(token byte) []byte {
		id := reservationToken(token)
		runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
			_, err := rt.ReserveFundingPlan(sqlstore.FundingPlan{
				ReservationID: id,
				Purpose:       "construction",
				CreatedAt:     time.Unix(1_000, 0),
				ExpiresAt:     time.Unix(1_000, 0),
			})

			return err
		})

		return id
	}

	// A consumed plan past its deadline that owns no leases is collectable.
	collectable := reserveExpired(0x41)
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.ConsumeFundingPlan(collectable, 0)
	})

	// A reserved plan past its deadline is not terminal, so it is retained.
	reserved := reserveExpired(0x42)

	// A terminal plan that still owns a lease is retained until the lease is
	// gone. Construct that state directly: reserve, add a lease, then mark the
	// plan released without deleting the lease.
	retained := reserveExpired(0x43)
	retainedHash := testHash(0x53)
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.AddFundingPlanLease(
			retained, retainedHash[:], 0, time.Unix(2_000, 0),
		)
	})
	harness.exec(t, `
		UPDATE funding_plans SET status = 'released'
		WHERE wallet_id = ? AND reservation_id = ?
	`, walletID, retained)

	// Collection removes only the terminal, past-deadline, lease-free plan.
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		deleted, err := rt.CollectExpiredFundingPlans(time.Unix(5_000, 0))
		require.NoError(t, err)
		require.Equal(t, int64(1), deleted)

		return nil
	})

	assertExists := func(id []byte, want bool) {
		runtimeView(t, store, func(rt *sqlstore.RuntimeStore) error {
			_, found, err := rt.FundingPlan(id)
			require.NoError(t, err)
			require.Equal(t, want, found)

			return nil
		})
	}
	assertExists(collectable, false)
	assertExists(reserved, true)
	assertExists(retained, true)
}

// testDerivationPathUniqueness verifies that the derived-address uniqueness
// guard rejects a duplicate derivation path while allowing imported addresses,
// which carry a null branch and index and are excluded from the constraint.
func testDerivationPathUniqueness(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	walletID := harness.createWallet(
		t, "derivation-uniqueness", testBlock(926), testBlock(927),
	)
	store := harness.newStore(walletID)
	harness.seedScope(t, store, waddrmgr.KeyScopeBIP0084, 0)

	var scopeID int64
	err := harness.queryRow(t,
		"SELECT id FROM key_scopes WHERE wallet_id = ?", walletID,
	).Scan(&scopeID)
	require.NoError(t, err)

	insertDerived := func(hash []byte, branch, index int64) error {
		_, err := harness.conn.ExecContext(context.Background(), harness.bind(`
			INSERT INTO addresses (
				wallet_id, scope_id, address_hash, account_number,
				address_type, added_at, sync_status, branch, address_index,
				used
			) VALUES (?, ?, ?, 0, 0, 0, 0, ?, ?, FALSE)
		`), walletID, scopeID, hash, branch, index)

		return err
	}
	insertImported := func(hash []byte) error {
		_, err := harness.conn.ExecContext(context.Background(), harness.bind(`
			INSERT INTO addresses (
				wallet_id, scope_id, address_hash, account_number,
				address_type, added_at, sync_status, encrypted_pub_key, used
			) VALUES (?, ?, ?, 0, 1, 0, 0, ?, FALSE)
		`), walletID, scopeID, hash, []byte{0x02})

		return err
	}

	// A first derived address at (branch 0, index 5) is accepted.
	first := testHash(0x01)
	require.NoError(t, insertDerived(first[:], 0, 5))

	// A second derived address at the same path but a distinct hash is
	// rejected by the derivation-path uniqueness guard.
	duplicate := testHash(0x02)
	require.Error(t, insertDerived(duplicate[:], 0, 5))

	// The same index on a different branch is a distinct path and is accepted.
	otherBranch := testHash(0x03)
	require.NoError(t, insertDerived(otherBranch[:], 1, 5))

	// Imported addresses carry a null branch and index, so two of them coexist
	// even though neither has a derivation path.
	importedA := testHash(0x04)
	importedB := testHash(0x05)
	require.NoError(t, insertImported(importedA[:]))
	require.NoError(t, insertImported(importedB[:]))
}

// testBranchIndexCAS verifies that the branch-index compare-and-swap advances
// only on a matching expected index, returns the advanced index, and is a typed
// stale signal on a mismatch, while each branch advances independently.
func testBranchIndexCAS(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	walletID := harness.createWallet(
		t, "branch-index-cas", testBlock(928), testBlock(929),
	)
	store := harness.newStore(walletID)
	scope := waddrmgr.KeyScopeBIP0084
	account := uint32(0)

	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		err := addr.PutKeyScope(waddrmgr.KeyScopeState{
			Scope:      scope,
			AddrSchema: waddrmgr.ScopeAddrMap[scope],
		})
		require.NoError(t, err)

		return addr.PutAccount(waddrmgr.AccountState{
			Scope:             scope,
			Account:           account,
			Type:              waddrmgr.AccountDefault,
			Name:              "cas-account",
			EncryptedPubKey:   []byte{1},
			NextExternalIndex: 5,
			NextInternalIndex: 9,
		})
	}, func() {})
	require.NoError(t, err)

	runtime := harness.newRuntime(walletID)

	// A matching compare-and-swap advances the external branch and returns the
	// new index.
	runtimeUpdate(t, runtime, func(rt *sqlstore.RuntimeStore) error {
		advanced, err := rt.AdvanceBranchIndex(
			scope, account, waddrmgr.ExternalBranch, 5, 6,
		)
		require.NoError(t, err)
		require.Equal(t, uint32(6), advanced)

		return nil
	})

	// A stale external compare-and-swap (the index already moved) is a typed
	// stale signal and advances nothing.
	staleErr := runtime.RuntimeUpdate(ctx, func(rt *sqlstore.RuntimeStore) error {
		_, err := rt.AdvanceBranchIndex(
			scope, account, waddrmgr.ExternalBranch, 5, 6,
		)

		return err
	}, nil)
	require.ErrorIs(t, staleErr, db.ErrStaleAccountIndex)

	// The internal branch advances independently of the external branch.
	runtimeUpdate(t, runtime, func(rt *sqlstore.RuntimeStore) error {
		advanced, err := rt.AdvanceBranchIndex(
			scope, account, waddrmgr.InternalBranch, 9, 10,
		)
		require.NoError(t, err)
		require.Equal(t, uint32(10), advanced)

		return nil
	})

	// Both branches persisted exactly one advance.
	err = store.View(ctx, func(tx db.ReadTx) error {
		got, err := tx.Addr().Account(scope, account)
		require.NoError(t, err)
		require.Equal(t, uint32(6), got.NextExternalIndex)
		require.Equal(t, uint32(10), got.NextInternalIndex)

		return nil
	}, func() {})
	require.NoError(t, err)
}
