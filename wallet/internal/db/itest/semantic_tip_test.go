package itest

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlstore"
	"github.com/btcsuite/btcwallet/wallet/internal/runtime"
	"github.com/stretchr/testify/require"
)

// tipBlockHeight hands out distinct block-height ranges so each tip wallet's
// fixtures never collide in the shared conformance database.
var tipBlockHeight atomic.Int32

// testSemanticTip runs the wallet-tip advance through the runtime Coordinator
// and the failure-injection wrapper, proving the Phase 1B Exit Gate for the
// representative second operation on one SQL backend: a forced callback retry
// changes durable state once and emits its event once, a rejected commit leaves
// no partial write, an ambiguous commit is resolved by durable reread, a
// post-commit notification is delivered and can be deterministically dropped,
// and a stale expected tip reloads the cache.
func testSemanticTip(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	t.Run("forced retry idempotent", func(t *testing.T) {
		testTipForcedRetryIdempotent(t, harness)
	})
	t.Run("no change before commit", func(t *testing.T) {
		testTipNoChangeBeforeCommit(t, harness)
	})
	t.Run("ambiguous resolved by reread", func(t *testing.T) {
		testTipAmbiguousResolved(t, harness)
	})
	t.Run("notification delivered and dropped", func(t *testing.T) {
		testTipNotification(t, harness)
	})
	t.Run("stale reloads tip", func(t *testing.T) {
		testTipStaleReloads(t, harness)
	})
}

// testTipForcedRetryIdempotent proves a forced callback retry advances the
// durable tip exactly once, journals one row, publishes the cache once, and
// emits its post-commit event exactly once, never during the rolled-back
// attempt.
func testTipForcedRetryIdempotent(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	var (
		attempts  atomic.Int32
		publishes atomic.Int32
		events    []db.Event
	)

	setup := newTipSetup(
		t, harness, "tip-retry",
		runtime.WithBeforePublish(func() { publishes.Add(1) }),
		runtime.WithNotifier(func(e []db.Event) {
			events = append(events, e...)
		}),
	)

	fpCtx := db.WithFailpoints(ctx, &db.Failpoints{
		ForceTxRetries: 1,
		OnTxAttempt:    func(int) { attempts.Add(1) },
	})

	newTip := tipRef(testBlock(setup.tipHeight + 1))
	res, err := setup.coord.AdvanceTip(fpCtx, newTip, []byte("op-tip-retry"))
	require.NoError(t, err)
	require.Equal(t, setup.tipHeight+1, res.Tip.Height)

	// The body ran twice (one rolled-back attempt plus the committed one) but
	// the durable tip advanced exactly once.
	require.Equal(t, int32(2), attempts.Load())
	require.Equal(t, setup.tipHeight+1, harness.syncedHeight(t, setup.walletID))
	require.Equal(t, 1, setup.journalRows(t))
	require.Equal(t, int32(1), publishes.Load())

	// The event was emitted exactly once, post-commit, not by the rolled-back
	// attempt.
	require.Len(t, events, 1)
	require.Equal(t, db.WalletTipEvent(newTip).ID, events[0].ID)
}

// testTipNoChangeBeforeCommit proves a rejected commit rolls back completely:
// the tip is unchanged, the new block is not recorded, no journal row exists,
// and neither the cache nor a notification is produced.
func testTipNoChangeBeforeCommit(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	var (
		publishes atomic.Int32
		events    []db.Event
	)

	setup := newTipSetup(
		t, harness, "tip-no-change",
		runtime.WithBeforePublish(func() { publishes.Add(1) }),
		runtime.WithNotifier(func(e []db.Event) {
			events = append(events, e...)
		}),
	)

	fpCtx := db.WithFailpoints(ctx, &db.Failpoints{
		BeforeCommit: func() error { return errForcedCommitFailure },
	})

	newTip := tipRef(testBlock(setup.tipHeight + 1))
	_, err := setup.coord.AdvanceTip(fpCtx, newTip, []byte("op-tip-fail"))
	require.Error(t, err)

	// Nothing changed: the tip is still the seeded value, the new block was
	// rolled back with the transaction, no journal row exists, and neither the
	// cache nor a notification fired.
	require.Equal(t, setup.tipHeight, harness.syncedHeight(t, setup.walletID))
	require.False(t, harness.blockExists(t, setup.tipHeight+1))
	require.Equal(t, 0, setup.journalRows(t))
	require.Equal(t, int32(0), publishes.Load())
	require.Empty(t, events)

	// A later clean advance through a fresh coordinator does change state,
	// confirming the wallet was otherwise advanceable.
	clean := runtime.New(sqlstore.NewRuntimeStore(setup.store))
	res, err := clean.AdvanceTip(ctx, newTip, []byte("op-tip-ok"))
	require.NoError(t, err)
	require.Equal(t, setup.tipHeight+1, res.Tip.Height)
	require.Equal(t, setup.tipHeight+1, harness.syncedHeight(t, setup.walletID))
}

// testTipAmbiguousResolved proves an ambiguous commit is resolved by durable
// reread: the tip advances exactly once, and the post-commit event is recovered
// from the journal and still delivered.
func testTipAmbiguousResolved(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	var events []db.Event

	setup := newTipSetup(
		t, harness, "tip-ambiguous",
		runtime.WithNotifier(func(e []db.Event) {
			events = append(events, e...)
		}),
	)

	fpCtx := db.WithFailpoints(ctx, &db.Failpoints{
		AfterCommit: func() error { return db.ErrAmbiguousCommit },
	})

	newTip := tipRef(testBlock(setup.tipHeight + 1))
	res, err := setup.coord.AdvanceTip(
		fpCtx, newTip, []byte("op-tip-ambiguous"),
	)
	require.NoError(t, err)
	require.True(t, res.Replayed)
	require.Equal(t, setup.tipHeight+1, res.Tip.Height)

	// The tip advanced exactly once (no blind repeat), and the event survived
	// the ambiguous resolution.
	require.Equal(t, setup.tipHeight+1, harness.syncedHeight(t, setup.walletID))
	require.Equal(t, 1, setup.journalRows(t))
	require.Len(t, events, 1)
	require.Equal(t, db.WalletTipEvent(newTip).ID, events[0].ID)
}

// testTipNotification proves the post-commit notification is delivered on a
// clean commit and can be deterministically dropped, in which case the durable
// tip still advanced and the caller still receives the committed event so
// restart reconciliation can recover the dropped notification.
func testTipNotification(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	t.Run("delivered", func(t *testing.T) {
		var events []db.Event

		setup := newTipSetup(
			t, harness, "tip-notify-ok",
			runtime.WithNotifier(func(e []db.Event) {
				events = append(events, e...)
			}),
		)

		newTip := tipRef(testBlock(setup.tipHeight + 1))
		res, err := setup.coord.AdvanceTip(
			ctx, newTip, []byte("op-tip-notify"),
		)
		require.NoError(t, err)
		require.Len(t, res.Events, 1)
		require.Len(t, events, 1)
		require.Equal(t, db.WalletTipEvent(newTip).ID, events[0].ID)
	})

	t.Run("dropped", func(t *testing.T) {
		var events []db.Event

		setup := newTipSetup(
			t, harness, "tip-notify-drop",
			runtime.WithNotifier(func(e []db.Event) {
				events = append(events, e...)
			}),
		)

		fpCtx := db.WithFailpoints(ctx, &db.Failpoints{DropNotify: true})

		newTip := tipRef(testBlock(setup.tipHeight + 1))
		res, err := setup.coord.AdvanceTip(
			fpCtx, newTip, []byte("op-tip-drop"),
		)
		require.NoError(t, err)

		// The tip advanced durably and the caller still holds the committed
		// event, but the notifier never fired: the recoverable
		// notification-loss window.
		require.Equal(
			t, setup.tipHeight+1, harness.syncedHeight(t, setup.walletID),
		)
		require.Len(t, res.Events, 1)
		require.Empty(t, events)
	})
}

// testTipStaleReloads proves a stale expected tip fails with the typed error
// and reloads the cache from durable state, after which the coordinator can
// advance again from the fresh tip.
func testTipStaleReloads(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	setup := newTipSetup(t, harness, "tip-stale")

	// Warm the cache by advancing the tip once.
	first, err := setup.coord.AdvanceTip(
		ctx, tipRef(testBlock(setup.tipHeight+1)), []byte("op-warm"),
	)
	require.NoError(t, err)
	require.Equal(t, setup.tipHeight+1, first.Tip.Height)

	cached, ok := setup.coord.CachedTip()
	require.True(t, ok)
	require.Equal(t, setup.tipHeight+1, cached.Height)

	// A separate coordinator advances the durable tip behind the first,
	// modeling a cross-process writer.
	other := runtime.New(sqlstore.NewRuntimeStore(setup.store))
	_, err = other.AdvanceTip(
		ctx, tipRef(testBlock(setup.tipHeight+2)), []byte("op-other"),
	)
	require.NoError(t, err)

	// The next advance from the stale cached tip is rejected and the cache is
	// reloaded from durable state.
	_, err = setup.coord.AdvanceTip(
		ctx, tipRef(testBlock(setup.tipHeight+2)), []byte("op-stale"),
	)
	require.ErrorIs(t, err, db.ErrStaleTip)

	reloaded, ok := setup.coord.CachedTip()
	require.True(t, ok)
	require.Equal(t, setup.tipHeight+2, reloaded.Height)

	// After the reload the coordinator advances again from the fresh tip.
	res, err := setup.coord.AdvanceTip(
		ctx, tipRef(testBlock(setup.tipHeight+3)), []byte("op-post"),
	)
	require.NoError(t, err)
	require.Equal(t, setup.tipHeight+3, res.Tip.Height)
}

// tipSetup bundles one seeded wallet with its coordinator and the helpers used
// to assert durable tip and journal state.
type tipSetup struct {
	harness   *managerStoreHarness
	walletID  int64
	store     *sqlstore.Store
	coord     *runtime.Coordinator
	tipHeight int32
}

// newTipSetup creates an isolated wallet synced to a fresh tip height and builds
// a coordinator over a runtime store. Failure injection is per call through
// db.WithFailpoints on the operation context.
func newTipSetup(t *testing.T, harness *managerStoreHarness, name string,
	opts ...runtime.Option) *tipSetup {

	t.Helper()

	height := 4000 + tipBlockHeight.Add(10)
	walletID := harness.createWallet(
		t, name, testBlock(height-1), testBlock(height),
	)
	store := harness.newRuntime(walletID)
	coord := runtime.New(sqlstore.NewRuntimeStore(store), opts...)

	return &tipSetup{
		harness:   harness,
		walletID:  walletID,
		store:     store,
		coord:     coord,
		tipHeight: height,
	}
}

// journalRows returns the number of committed wallet-tip journal rows for the
// wallet.
func (s *tipSetup) journalRows(t *testing.T) int {
	t.Helper()

	var count int

	err := s.harness.queryRow(t, `
		SELECT count(*) FROM operation_journal
		WHERE wallet_id = ? AND domain = 'wallet-tip'
	`, s.walletID).Scan(&count)
	require.NoError(t, err)

	return count
}
