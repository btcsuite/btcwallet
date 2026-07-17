package itest

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlstore"
	"github.com/stretchr/testify/require"
)

// testRuntimeStore runs the SQL runtime-state and operation-journal vector
// against one SQL backend. The runtime schema is SQL-only, so this vector is
// skipped for the KV backend, which uses natural record guards instead.
func testRuntimeStore(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	t.Run("version cas", func(t *testing.T) {
		testRuntimeVersionCAS(t, harness)
	})
	t.Run("guards", func(t *testing.T) {
		testRuntimeGuards(t, harness)
	})
	t.Run("journal duplicate operation", func(t *testing.T) {
		testRuntimeJournalDuplicate(t, harness)
	})
	t.Run("committed retry result", func(t *testing.T) {
		testRuntimeCommittedRetry(t, harness)
	})
	t.Run("result facts cascade", func(t *testing.T) {
		testRuntimeResultFactsCascade(t, harness)
	})
	t.Run("operation retention gc", func(t *testing.T) {
		testRuntimeRetentionGC(t, harness)
	})
}

// testRuntimeVersionCAS verifies that each domain version bump advances only on
// a matching expected value, that a stale bump returns the domain's typed error
// without advancing the version, and that a bump is confined to its own domain.
func testRuntimeVersionCAS(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	walletID := harness.createWallet(
		t, "runtime-version-cas", testBlock(900), testBlock(901),
	)
	store := harness.newRuntime(walletID)

	// The runtime-state row starts every counter at zero once ensured.
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		require.NoError(t, rt.EnsureState())

		state, err := rt.State()
		require.NoError(t, err)
		require.Equal(t, sqlstore.RuntimeState{}, state)

		return nil
	})

	// A matching compare-and-swap advances the state version by one and
	// leaves the other domains untouched.
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.BumpStateVersion(0)
	})
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		state, err := rt.State()
		require.NoError(t, err)
		require.Equal(t, sqlstore.RuntimeState{StateVersion: 1}, state)

		return nil
	})

	// A stale state bump (and an identical replay) returns the typed stale
	// error and never advances the version.
	staleErr := store.RuntimeUpdate(ctx, func(rt *sqlstore.RuntimeStore) error {
		return rt.BumpStateVersion(0)
	}, nil)
	require.ErrorIs(t, staleErr, db.ErrStaleWalletState)

	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		state, err := rt.State()
		require.NoError(t, err)
		require.Equal(t, int64(1), state.StateVersion)

		return nil
	})

	// The history epoch and secret version bump independently, each with its
	// own typed stale error.
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.BumpHistoryEpoch(0)
	})
	historyStale := store.RuntimeUpdate(
		ctx, func(rt *sqlstore.RuntimeStore) error {
			return rt.BumpHistoryEpoch(0)
		}, nil,
	)
	require.ErrorIs(t, historyStale, db.ErrStaleHistoryEpoch)

	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.BumpSecretVersion(0)
	})
	secretStale := store.RuntimeUpdate(
		ctx, func(rt *sqlstore.RuntimeStore) error {
			return rt.BumpSecretVersion(0)
		}, nil,
	)
	require.ErrorIs(t, secretStale, db.ErrStaleSecretState)

	// Each domain advanced exactly once and independently.
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		state, err := rt.State()
		require.NoError(t, err)
		require.Equal(t, sqlstore.RuntimeState{
			StateVersion:  1,
			HistoryEpoch:  1,
			SecretVersion: 1,
		}, state)

		return nil
	})
}

// testRuntimeGuards verifies the reusable version-guard family applied through
// ApplyGuards: every declared guard advances its domain by one, a nil field is
// skipped, and a single stale guard rolls the whole application back so no
// version advances.
func testRuntimeGuards(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	walletID := harness.createWallet(
		t, "runtime-guards", testBlock(920), testBlock(921),
	)
	store := harness.newRuntime(walletID)

	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.EnsureState()
	})

	// Applying all three version guards at their current values advances each
	// domain by one in one transaction.
	zero := int64(0)
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.ApplyGuards(db.Guards{
			ExpectedStateVersion:  &zero,
			ExpectedHistoryEpoch:  &zero,
			ExpectedSecretVersion: &zero,
		})
	})
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		state, err := rt.State()
		require.NoError(t, err)
		require.Equal(t, sqlstore.RuntimeState{
			StateVersion:  1,
			HistoryEpoch:  1,
			SecretVersion: 1,
		}, state)

		return nil
	})

	// A nil field is not guarded, so only the declared domain advances.
	one := int64(1)
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.ApplyGuards(db.Guards{ExpectedStateVersion: &one})
	})
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		state, err := rt.State()
		require.NoError(t, err)
		require.Equal(t, sqlstore.RuntimeState{
			StateVersion:  2,
			HistoryEpoch:  1,
			SecretVersion: 1,
		}, state)

		return nil
	})

	// A stale guard rolls the whole application back: the matching state guard
	// is applied first but the stale history guard fails, so no version
	// advances and the typed history error surfaces.
	two := int64(2)
	staleErr := store.RuntimeUpdate(
		ctx, func(rt *sqlstore.RuntimeStore) error {
			return rt.ApplyGuards(db.Guards{
				ExpectedStateVersion: &two,
				ExpectedHistoryEpoch: &zero,
			})
		}, nil,
	)
	require.ErrorIs(t, staleErr, db.ErrStaleHistoryEpoch)

	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		state, err := rt.State()
		require.NoError(t, err)
		require.Equal(t, sqlstore.RuntimeState{
			StateVersion:  2,
			HistoryEpoch:  1,
			SecretVersion: 1,
		}, state)

		return nil
	})
}

// testRuntimeJournalDuplicate verifies that recording an operation is
// idempotent for the exact request, while reusing the operation id with a
// different request hash or history epoch is rejected.
func testRuntimeJournalDuplicate(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	walletID := harness.createWallet(
		t, "runtime-journal-dup", testBlock(902), testBlock(903),
	)
	store := harness.newRuntime(walletID)

	op := sqlstore.CommittedOperation{
		Domain:       "address",
		OperationID:  []byte("op-dup"),
		RequestHash:  []byte("request-a"),
		HistoryEpoch: 0,
		ResultRef:    []byte("ref-1"),
		ResultHash:   []byte("hash-1"),
		CreatedAt:    time.Unix(1_000, 0),
		ExpiresAt:    time.Unix(2_000, 0),
		Facts: []sqlstore.ResultFact{{
			Type:    "credit",
			Key:     []byte("key-1"),
			Payload: []byte("payload-1"),
		}},
	}

	// The first record persists the committed operation.
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.RecordCommittedOperation(op)
	})

	// Re-recording the exact same request is an idempotent no-op.
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.RecordCommittedOperation(op)
	})

	// Reusing the operation id with a different request hash is a conflict.
	conflictingHash := op
	conflictingHash.RequestHash = []byte("request-b")
	hashErr := store.RuntimeUpdate(
		ctx, func(rt *sqlstore.RuntimeStore) error {
			return rt.RecordCommittedOperation(conflictingHash)
		}, nil,
	)
	require.ErrorIs(t, hashErr, db.ErrOperationConflict)

	// Reusing the operation id under a different history epoch is a conflict.
	conflictingEpoch := op
	conflictingEpoch.HistoryEpoch = 1
	epochErr := store.RuntimeUpdate(
		ctx, func(rt *sqlstore.RuntimeStore) error {
			return rt.RecordCommittedOperation(conflictingEpoch)
		}, nil,
	)
	require.ErrorIs(t, epochErr, db.ErrOperationConflict)

	// The conflicting attempts left the original result unchanged.
	runtimeView(t, store, func(rt *sqlstore.RuntimeStore) error {
		result, found, err := rt.CommittedResult(op.Domain, op.OperationID)
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, op.ResultHash, result.ResultHash)

		return nil
	})
}

// testRuntimeCommittedRetry verifies that a retry of a committed operation is
// served the prior result from the journal instead of rerunning the mutation.
func testRuntimeCommittedRetry(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	walletID := harness.createWallet(
		t, "runtime-committed-retry", testBlock(904), testBlock(905),
	)
	store := harness.newRuntime(walletID)

	op := sqlstore.CommittedOperation{
		Domain:       "scan",
		OperationID:  []byte("op-retry"),
		RequestHash:  []byte("request"),
		HistoryEpoch: 0,
		ResultRef:    []byte("result-ref"),
		ResultHash:   []byte("result-hash"),
		CreatedAt:    time.Unix(1_000, 0),
		ExpiresAt:    time.Unix(2_000, 0),
		Facts: []sqlstore.ResultFact{
			{Type: "credit", Key: []byte("k0"), Payload: []byte("p0")},
			{Type: "spend", Key: nil, Payload: []byte("p1")},
		},
	}

	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.RecordCommittedOperation(op)
	})

	// A retry reads the durable result identified by result_ref/result_hash
	// together with the ordered result facts.
	runtimeView(t, store, func(rt *sqlstore.RuntimeStore) error {
		result, found, err := rt.CommittedResult(op.Domain, op.OperationID)
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, op.ResultRef, result.ResultRef)
		require.Equal(t, op.ResultHash, result.ResultHash)
		require.Equal(t, op.Facts, result.Facts)

		return nil
	})

	// An unknown operation has no committed result.
	runtimeView(t, store, func(rt *sqlstore.RuntimeStore) error {
		_, found, err := rt.CommittedResult("scan", []byte("op-missing"))
		require.NoError(t, err)
		require.False(t, found)

		return nil
	})
}

// testRuntimeResultFactsCascade verifies that deleting a journal row cascades
// to its result facts.
func testRuntimeResultFactsCascade(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	walletID := harness.createWallet(
		t, "runtime-facts-cascade", testBlock(906), testBlock(907),
	)
	store := harness.newRuntime(walletID)

	op := sqlstore.CommittedOperation{
		Domain:       "transaction",
		OperationID:  []byte("op-cascade"),
		RequestHash:  []byte("request"),
		HistoryEpoch: 0,
		ResultRef:    []byte("ref"),
		ResultHash:   []byte("hash"),
		CreatedAt:    time.Unix(1_000, 0),

		// Already past its retention deadline so the collector removes it.
		ExpiresAt: time.Unix(1_000, 0),
		Facts: []sqlstore.ResultFact{
			{Type: "credit", Key: []byte("k0"), Payload: []byte("p0")},
			{Type: "credit", Key: []byte("k1"), Payload: []byte("p1")},
		},
	}

	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		return rt.RecordCommittedOperation(op)
	})
	require.Equal(t, len(op.Facts), harness.countResultFacts(t, walletID, op))

	// Deleting the terminal, expired journal row cascades to its facts.
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		deleted, err := rt.CollectExpiredOperations(time.Unix(5_000, 0))
		require.NoError(t, err)
		require.Equal(t, int64(1), deleted)

		return nil
	})
	require.Equal(t, 0, harness.countResultFacts(t, walletID, op))

	runtimeView(t, store, func(rt *sqlstore.RuntimeStore) error {
		_, found, err := rt.CommittedResult(op.Domain, op.OperationID)
		require.NoError(t, err)
		require.False(t, found)

		return nil
	})
}

// testRuntimeRetentionGC verifies that retention collection removes expired
// terminal rows but never an unexpired row or an in-flight started row.
func testRuntimeRetentionGC(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	walletID := harness.createWallet(
		t, "runtime-retention-gc", testBlock(908), testBlock(909),
	)
	store := harness.newRuntime(walletID)

	unexpired := sqlstore.CommittedOperation{
		Domain:      "scan",
		OperationID: []byte("op-unexpired"),
		RequestHash: []byte("request"),
		ResultRef:   []byte("ref"),
		ResultHash:  []byte("hash"),
		CreatedAt:   time.Unix(1_000, 0),
		ExpiresAt:   time.Unix(10_000, 0),
	}
	expired := sqlstore.CommittedOperation{
		Domain:      "scan",
		OperationID: []byte("op-expired"),
		RequestHash: []byte("request"),
		ResultRef:   []byte("ref"),
		ResultHash:  []byte("hash"),
		CreatedAt:   time.Unix(1_000, 0),
		ExpiresAt:   time.Unix(1_000, 0),
	}

	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		require.NoError(t, rt.RecordCommittedOperation(unexpired))

		return rt.RecordCommittedOperation(expired)
	})

	// An in-flight started row is durable only for this assertion; it must be
	// skipped by the collector even though it is past its deadline.
	harness.insertStartedOperation(t, walletID, "scan", []byte("op-started"))

	// Collection at a time after the expired deadline removes only the
	// expired committed row, leaving the unexpired and started rows.
	runtimeUpdate(t, store, func(rt *sqlstore.RuntimeStore) error {
		deleted, err := rt.CollectExpiredOperations(time.Unix(5_000, 0))
		require.NoError(t, err)
		require.Equal(t, int64(1), deleted)

		return nil
	})

	runtimeView(t, store, func(rt *sqlstore.RuntimeStore) error {
		_, found, err := rt.CommittedResult(
			unexpired.Domain, unexpired.OperationID,
		)
		require.NoError(t, err)
		require.True(t, found)

		_, found, err = rt.CommittedResult(
			expired.Domain, expired.OperationID,
		)
		require.NoError(t, err)
		require.False(t, found)

		return nil
	})

	require.Equal(
		t, 1, harness.countOperationStatus(t, walletID, "started"),
	)
}

// runtimeUpdate runs body in a runtime write transaction and fails the test on
// any error.
func runtimeUpdate(t *testing.T, store *sqlstore.Store,
	body func(*sqlstore.RuntimeStore) error) {

	t.Helper()

	require.NoError(t, store.RuntimeUpdate(context.Background(), body, nil))
}

// runtimeView runs body in a runtime read transaction and fails the test on any
// error.
func runtimeView(t *testing.T, store *sqlstore.Store,
	body func(*sqlstore.RuntimeStore) error) {

	t.Helper()

	require.NoError(t, store.RuntimeView(context.Background(), body, nil))
}

// countResultFacts returns the number of persisted result facts for one
// operation.
func (h *managerStoreHarness) countResultFacts(t *testing.T, walletID int64,
	op sqlstore.CommittedOperation) int {

	t.Helper()

	var count int

	err := h.queryRow(t, `
		SELECT count(*) FROM operation_result_facts
		WHERE wallet_id = ? AND domain = ? AND operation_id = ?
	`, walletID, op.Domain, op.OperationID).Scan(&count)
	require.NoError(t, err)

	return count
}

// countOperationStatus returns the number of journal rows with one status.
func (h *managerStoreHarness) countOperationStatus(t *testing.T, walletID int64,
	status string) int {

	t.Helper()

	var count int

	err := h.queryRow(t, `
		SELECT count(*) FROM operation_journal
		WHERE wallet_id = ? AND status = ?
	`, walletID, status).Scan(&count)
	require.NoError(t, err)

	return count
}

// insertStartedOperation writes an in-flight started journal row directly, used
// to assert that retention collection never removes a non-terminal row.
func (h *managerStoreHarness) insertStartedOperation(t *testing.T,
	walletID int64, domain string, operationID []byte) {

	t.Helper()

	h.exec(t, `
		INSERT INTO operation_journal (
			wallet_id, domain, operation_id, request_hash, history_epoch,
			status, created_at, expires_at
		) VALUES (?, ?, ?, ?, 0, 'started', 0, 1)
	`, walletID, domain, operationID, []byte("request"))
}
