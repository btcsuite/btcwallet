package itest

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlstore"
	"github.com/btcsuite/btcwallet/wallet/internal/runtime"
	"github.com/stretchr/testify/require"
)

// errForcedCommitFailure is the sentinel the runtime failure-injection tests
// return from the before-commit failpoint to force a non-retryable rollback.
var errForcedCommitFailure = errors.New("forced commit failure")

// spikeScope is the key scope every spike wallet seeds its account under.
var spikeScope = waddrmgr.KeyScopeBIP0084

// spikeSeedIndex is the external branch next index every spike account is
// seeded at, so the first reservation allocates it and advances to the next.
const spikeSeedIndex = 5

// spikeBlockHeight hands out distinct block heights so each spike wallet's
// fixtures never collide in the shared conformance database.
var spikeBlockHeight atomic.Int32

// TestRuntimeStoreBoundary asserts the runtime path exposes only semantic
// methods and never the low-level View/Update persistence boundary. This is the
// package-boundary check for the RuntimeStore/PersistenceStore split.
func TestRuntimeStoreBoundary(t *testing.T) {
	t.Parallel()

	// The neutral RuntimeStore interface must expose the semantic operation
	// and none of the low-level transaction-boundary methods.
	runtimeType := reflect.TypeFor[db.RuntimeStore]()
	_, hasReserve := runtimeType.MethodByName("ReserveNextBranchIndex")
	require.True(t, hasReserve,
		"RuntimeStore must expose the semantic reservation method")

	for _, forbidden := range []string{"View", "Update"} {
		_, has := runtimeType.MethodByName(forbidden)
		require.Falsef(t, has,
			"RuntimeStore must not expose %s", forbidden)
	}

	// A concrete runtime store must not satisfy the low-level
	// PersistenceStore (View/Update) contract, so a migrated runtime path
	// cannot reach the raw transaction boundary.
	runtimeVal := sqlstore.NewRuntimeStore(nil)
	_, isPersistence := runtimeVal.(db.PersistenceStore)
	require.False(t, isPersistence,
		"runtime store must not satisfy PersistenceStore")

	// Sanity: PersistenceStore is the low-level surface the SQL store
	// implements, and it is distinct from the runtime path.
	var _ db.PersistenceStore = (*sqlstore.Store)(nil)
}

// testSpikeStore runs the Phase 1A transaction-contract spike vector against
// one SQL backend, proving the Exit Gate for the mutation-gate, compare-and-
// swap, and cache-publication contract.
func testSpikeStore(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	t.Run("forced retry idempotent", func(t *testing.T) {
		testSpikeForcedRetryIdempotent(t, harness)
	})
	t.Run("no change before commit", func(t *testing.T) {
		testSpikeNoChangeBeforeCommit(t, harness)
	})
	t.Run("ambiguous resolved by reread", func(t *testing.T) {
		testSpikeAmbiguousResolved(t, harness)
	})
	t.Run("linearizable gate publish", func(t *testing.T) {
		testSpikeLinearizableGate(t, harness)
	})
	t.Run("stale reloads cache", func(t *testing.T) {
		testSpikeStaleReloadsCache(t, harness)
	})
}

// testSpikeForcedRetryIdempotent proves Exit Gate 1: a forced retry of the
// spike operation changes durable state exactly once and publishes the cache
// once, whether the retry is a callback retry inside one commit or an
// operation-level replay.
func testSpikeForcedRetryIdempotent(t *testing.T,
	harness *managerStoreHarness) {

	t.Helper()

	ctx := context.Background()

	t.Run("callback retry", func(t *testing.T) {
		var attempts atomic.Int32

		fpCtx := db.WithFailpoints(ctx, &db.Failpoints{
			ForceTxRetries: 1,
			OnTxAttempt: func(int) {
				attempts.Add(1)
			},
		})

		var publishes atomic.Int32

		setup := newSpikeSetup(
			t, harness, "spike-callback-retry",
			runtime.WithBeforePublish(func() {
				publishes.Add(1)
			}),
		)

		res, err := setup.coord.ReserveNextIndex(
			fpCtx, setup.key, []byte("op-callback-retry"),
		)
		require.NoError(t, err)
		require.Equal(t, uint32(5), res.AllocatedIndex)
		require.Equal(t, uint32(6), res.NextIndex)

		// The commit body ran twice (one rolled-back attempt plus the
		// committed one) but durable state advanced exactly once.
		require.Equal(t, int32(2), attempts.Load())
		require.Equal(t, uint32(6), setup.durableIndex(t))
		require.Equal(t, 1, setup.journalRows(t))

		// The cache was published exactly once despite the retry.
		require.Equal(t, int32(1), publishes.Load())

		cached, ok := setup.coord.CachedNextIndex(setup.key)
		require.True(t, ok)
		require.Equal(t, uint32(6), cached)
	})

	t.Run("operation replay", func(t *testing.T) {
		var publishes atomic.Int32

		setup := newSpikeSetup(
			t, harness, "spike-op-replay",
			runtime.WithBeforePublish(func() {
				publishes.Add(1)
			}),
		)
		opID := []byte("op-replay")

		first, err := setup.coord.ReserveNextIndex(ctx, setup.key, opID)
		require.NoError(t, err)
		require.False(t, first.Replayed)
		require.Equal(t, uint32(5), first.AllocatedIndex)
		require.Equal(t, uint32(6), first.NextIndex)

		// A retry with the same operation id is served from the journal:
		// no second advance and no second cache publication.
		second, err := setup.coord.ReserveNextIndex(ctx, setup.key, opID)
		require.NoError(t, err)
		require.True(t, second.Replayed)
		require.Equal(t, uint32(5), second.AllocatedIndex)
		require.Equal(t, uint32(6), second.NextIndex)

		require.Equal(t, uint32(6), setup.durableIndex(t))
		require.Equal(t, 1, setup.journalRows(t))
		require.Equal(t, int32(1), publishes.Load())
	})
}

// testSpikeNoChangeBeforeCommit proves Exit Gate 2: a failed commit leaves both
// durable state and the cache unchanged, so no cache or external state changes
// before the durable commit succeeds. It also checks the positive path.
func testSpikeNoChangeBeforeCommit(t *testing.T,
	harness *managerStoreHarness) {

	t.Helper()

	ctx := context.Background()

	var publishes atomic.Int32

	fpCtx := db.WithFailpoints(ctx, &db.Failpoints{
		BeforeCommit: func() error {
			return errForcedCommitFailure
		},
	})
	setup := newSpikeSetup(
		t, harness, "spike-no-change",
		runtime.WithBeforePublish(func() {
			publishes.Add(1)
		}),
	)

	// The forced commit failure rolls the whole transaction back.
	_, err := setup.coord.ReserveNextIndex(
		fpCtx, setup.key, []byte("op-fail"),
	)
	require.Error(t, err)

	// Nothing changed: the durable index is still the seeded value, no
	// journal row exists, and the cache was never published.
	require.Equal(t, uint32(5), setup.durableIndex(t))
	require.Equal(t, 0, setup.journalRows(t))
	require.Equal(t, int32(0), publishes.Load())

	_, cached := setup.coord.CachedNextIndex(setup.key)
	require.False(t, cached)

	// A later successful commit through a clean store does change state,
	// confirming the seeded account was otherwise reservable.
	clean := runtime.New(sqlstore.NewRuntimeStore(setup.store))
	res, err := clean.ReserveNextIndex(ctx, setup.key, []byte("op-ok"))
	require.NoError(t, err)
	require.Equal(t, uint32(5), res.AllocatedIndex)
	require.Equal(t, uint32(6), setup.durableIndex(t))
}

// testSpikeAmbiguousResolved proves Exit Gate 3: an ambiguous commit is
// resolved by rereading durable state, not by blindly repeating the operation,
// so the index still advances exactly once.
func testSpikeAmbiguousResolved(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	fpCtx := db.WithFailpoints(ctx, &db.Failpoints{
		AfterCommit: func() error {
			return db.ErrAmbiguousCommit
		},
	})
	setup := newSpikeSetup(t, harness, "spike-ambiguous")

	// The commit lands durably but is reported ambiguous; the coordinator
	// resolves it by durable reread and publishes the committed result.
	res, err := setup.coord.ReserveNextIndex(
		fpCtx, setup.key, []byte("op-ambiguous"),
	)
	require.NoError(t, err)
	require.True(t, res.Replayed)
	require.Equal(t, uint32(5), res.AllocatedIndex)
	require.Equal(t, uint32(6), res.NextIndex)

	// The durable index advanced exactly once (no double-apply from a blind
	// repeat) and the cache holds the resolved value.
	require.Equal(t, uint32(6), setup.durableIndex(t))
	require.Equal(t, 1, setup.journalRows(t))
	cached, ok := setup.coord.CachedNextIndex(setup.key)
	require.True(t, ok)
	require.Equal(t, uint32(6), cached)
}

// testSpikeLinearizableGate proves Exit Gate 4: a concurrent cache-sensitive
// reader cannot observe a committed index before the corresponding cache
// update. A writer parks under the exclusive gate after the durable commit but
// before publication; a shared reader must block until publication and then
// observe the new value.
func testSpikeLinearizableGate(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	committed := make(chan struct{})
	proceed := make(chan struct{})

	var publishes atomic.Int32

	setup := newSpikeSetup(
		t, harness, "spike-linearizable",
		runtime.WithBeforePublish(func() {
			// Pause only on the second publication (the observed op),
			// holding the gate between commit and cache publication.
			if publishes.Add(1) == 2 {
				close(committed)
				<-proceed
			}
		}),
	)

	// Warm the cache so the reader has an old value it could wrongly observe.
	warm, err := setup.coord.ReserveNextIndex(
		ctx, setup.key, []byte("op-warm"),
	)
	require.NoError(t, err)
	require.Equal(t, uint32(6), warm.NextIndex)

	// Launch the observed writer; it commits 6 -> 7 then parks before
	// publishing. Results flow back through channels so assertions stay on
	// the test goroutine.
	type writerResult struct {
		res runtime.Reservation
		err error
	}

	writerDone := make(chan writerResult, 1)
	go func() {
		res, err := setup.coord.ReserveNextIndex(
			ctx, setup.key, []byte("op-observed"),
		)
		writerDone <- writerResult{res: res, err: err}
	}()

	// Wait until the writer has durably committed but not yet published.
	<-committed

	// The database already holds the advanced index while the cache still
	// holds the old one; a cache-sensitive reader must not observe the new
	// index yet, because it blocks on the shared gate the writer holds.
	require.Equal(t, uint32(7), setup.durableIndex(t))

	type readerResult struct {
		index uint32
		ok    bool
	}

	readerDone := make(chan readerResult, 1)
	go func() {
		index, ok := setup.coord.CachedNextIndex(setup.key)
		readerDone <- readerResult{index: index, ok: ok}
	}()

	select {
	case <-readerDone:
		t.Fatal("reader observed the cache before the commit was " +
			"published")
	case <-time.After(200 * time.Millisecond):
		// Good: the reader is blocked on the gate.
	}

	// Release the writer; publication completes and the gate is released.
	close(proceed)

	writer := <-writerDone
	require.NoError(t, writer.err)
	require.Equal(t, uint32(7), writer.res.NextIndex)

	// The reader unblocks only after publication and observes the new value,
	// never the stale one.
	reader := <-readerDone
	require.True(t, reader.ok)
	require.Equal(t, uint32(7), reader.index)
}

// testSpikeStaleReloadsCache checks the cross-process conflict path: when the
// durable index advances behind the coordinator, the compare-and-swap fails
// with a typed stale error and the cache is reloaded from durable state rather
// than left inconsistent.
func testSpikeStaleReloadsCache(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	setup := newSpikeSetup(t, harness, "spike-stale")

	// Warm the cache to the durable value.
	_, err := setup.coord.ReserveNextIndex(ctx, setup.key, []byte("op-warm"))
	require.NoError(t, err)

	cached, ok := setup.coord.CachedNextIndex(setup.key)
	require.True(t, ok)
	require.Equal(t, uint32(6), cached)

	// Advance the durable index behind the coordinator, simulating a
	// cross-process writer.
	setup.setDurableIndex(t, 10)

	// The next reservation's compare-and-swap is stale; the coordinator
	// reports the typed error and reloads the cache from durable state.
	_, err = setup.coord.ReserveNextIndex(ctx, setup.key, []byte("op-stale"))
	require.ErrorIs(t, err, db.ErrStaleAccountIndex)

	reloaded, ok := setup.coord.CachedNextIndex(setup.key)
	require.True(t, ok)
	require.Equal(t, uint32(10), reloaded)

	// After the reload the coordinator can allocate again from the fresh
	// durable value.
	res, err := setup.coord.ReserveNextIndex(ctx, setup.key, []byte("op-post"))
	require.NoError(t, err)
	require.Equal(t, uint32(10), res.AllocatedIndex)
	require.Equal(t, uint32(11), setup.durableIndex(t))
}

// spikeSetup bundles one seeded spike wallet with its coordinator and the
// helpers used to assert durable and journal state.
type spikeSetup struct {
	harness  *managerStoreHarness
	walletID int64
	store    *sqlstore.Store
	coord    *runtime.Coordinator
	key      runtime.BranchKey
}

// newSpikeSetup creates an isolated wallet, seeds one account at the spike seed
// index, and builds a coordinator over a runtime store. Failure injection is
// per call through db.WithFailpoints on the operation context.
func newSpikeSetup(t *testing.T, harness *managerStoreHarness, name string,
	opts ...runtime.Option) *spikeSetup {

	t.Helper()

	height := 1000 + spikeBlockHeight.Add(2)
	walletID := harness.createWallet(
		t, name, testBlock(height-1), testBlock(height),
	)
	store := harness.newRuntime(walletID)

	seedSpikeAccount(t, harness.newStore(walletID))

	coord := runtime.New(sqlstore.NewRuntimeStore(store), opts...)

	return &spikeSetup{
		harness:  harness,
		walletID: walletID,
		store:    store,
		coord:    coord,
		key: runtime.BranchKey{
			Scope:   spikeScope,
			Account: 0,
			Branch:  waddrmgr.ExternalBranch,
		},
	}
}

// seedSpikeAccount seeds the spike key scope and a single account whose
// external branch starts at the spike seed index.
func seedSpikeAccount(t *testing.T, store db.Store) {
	t.Helper()

	err := store.Update(context.Background(), func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		err := addr.PutKeyScope(waddrmgr.KeyScopeState{
			Scope:      spikeScope,
			AddrSchema: waddrmgr.ScopeAddrMap[spikeScope],
		})
		if err != nil {
			return err
		}

		return addr.PutAccount(waddrmgr.AccountState{
			Scope:             spikeScope,
			Account:           0,
			Type:              waddrmgr.AccountDefault,
			Name:              "spike-account",
			EncryptedPubKey:   []byte{1},
			NextExternalIndex: spikeSeedIndex,
		})
	}, func() {})
	require.NoError(t, err)
}

// durableIndex reads the account's current external next index straight from a
// clean runtime store, bypassing the coordinator cache.
func (s *spikeSetup) durableIndex(t *testing.T) uint32 {
	t.Helper()

	index, err := sqlstore.NewRuntimeStore(s.store).CurrentBranchIndex(
		context.Background(), s.key.Scope, s.key.Account, s.key.Branch,
	)
	require.NoError(t, err)

	return index
}

// setDurableIndex advances the account's external next index directly, modeling
// a cross-process writer that moved the durable state.
func (s *spikeSetup) setDurableIndex(t *testing.T, index uint32) {
	t.Helper()

	s.harness.exec(t, `
		UPDATE accounts SET next_external_index = ?
		WHERE scope_id = (
			SELECT id FROM key_scopes WHERE wallet_id = ?
		) AND account_number = ?
	`, index, s.walletID, s.key.Account)
}

// journalRows returns the number of committed branch-index journal rows for the
// wallet.
func (s *spikeSetup) journalRows(t *testing.T) int {
	t.Helper()

	var count int

	err := s.harness.queryRow(t, `
		SELECT count(*) FROM operation_journal
		WHERE wallet_id = ? AND domain = 'branch-index'
	`, s.walletID).Scan(&count)
	require.NoError(t, err)

	return count
}
