package itest

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/runtime"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// scanBlockHeight hands out distinct block-height ranges so each scan wallet's
// fixtures never collide in the shared conformance database.
var scanBlockHeight atomic.Int32

// scanSetup bundles one seeded wallet with a key scope, coordinator, and the
// helpers used to assert durable scan and rewind state.
type scanSetup struct {
	harness    *managerStoreHarness
	walletID   int64
	store      db.Store
	coord      *runtime.Coordinator
	scope      waddrmgr.KeyScope
	baseHeight int32
}

// newScanSetup creates an isolated wallet synced to a fresh base tip, seeds one
// key scope with a default account, and builds a coordinator over a runtime
// store. Failure injection is per call through db.WithFailpoints on the
// operation context.
func newScanSetup(t *testing.T, harness *managerStoreHarness, name string,
	opts ...runtime.Option) *scanSetup {

	t.Helper()

	height := 5000 + scanBlockHeight.Add(20)
	walletID := harness.createWallet(
		t, name, testBlock(height-1), testBlock(height),
	)
	store := harness.newStore(walletID)
	harness.seedScope(t, store, addrStoreScope, 0)

	coord := runtime.New(harness.newRuntimeStore(walletID), opts...)

	return &scanSetup{
		harness:    harness,
		walletID:   walletID,
		store:      store,
		coord:      coord,
		scope:      addrStoreScope,
		baseHeight: height,
	}
}

// testScanStore runs the recovery scan-batch and wallet-rewind semantic
// operations on every backend, proving the Phase 3a store-op layer: a batch
// commits its addresses, transactions, credits, spends, usage marks, blocks,
// horizons, and tip atomically; a partial failure leaves nothing committed; a
// stale base tip or branch index is a typed error with no partial write; a
// rewind reconciles state back to a target and is idempotent on re-preparation.
// It runs on KV, SQLite, and PostgreSQL and asserts identical observable
// results (committed facts, balances, typed errors), so passing on each backend
// proves observable parity.
func testScanStore(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	t.Run("atomic commit", func(t *testing.T) {
		testScanAtomicCommit(t, harness)
	})
	t.Run("credit spend within batch", func(t *testing.T) {
		testScanCreditSpend(t, harness)
	})
	t.Run("unmined incidence", func(t *testing.T) {
		testScanUnminedIncidence(t, harness)
	})
	t.Run("partial failure rolls back", func(t *testing.T) {
		testScanPartialFailure(t, harness)
	})
	t.Run("stale base tip", func(t *testing.T) {
		testScanStaleTip(t, harness)
	})
	t.Run("stale branch index", func(t *testing.T) {
		testScanStaleIndex(t, harness)
	})
	t.Run("rewind reconciles", func(t *testing.T) {
		testRewindReconciles(t, harness)
	})
	t.Run("rewind idempotent", func(t *testing.T) {
		testRewindIdempotent(t, harness)
	})
}

// testScanAtomicCommit proves a representative scan batch commits every part
// atomically and materializes its events, and doubles as the cross-backend
// observable-parity vector.
func testScanAtomicCommit(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	var events []db.Event

	setup := newScanSetup(
		t, harness, "scan-atomic",
		runtime.WithNotifier(func(e []db.Event) { events = append(events, e...) }),
	)

	req, txHash, newBlock := representativeScanBatch(t, setup, []byte("op-scan"))

	res, err := setup.coord.CommitScan(ctx, req)
	require.NoError(t, err)
	require.False(t, res.Replayed)
	require.Equal(t, newBlock, res.Tip)

	// The synced tip advanced and the branch horizon extended.
	require.Equal(
		t, setup.baseHeight+1, harness.syncedHeight(t, setup.walletID),
	)
	require.Equal(t, newBlock.Hash, harness.syncedBlockHash(t, setup.walletID))
	require.Equal(t, uint32(3), durableBranchIndex(
		t, harness, setup.walletID, waddrmgr.ExternalBranch,
	))

	// The discovered addresses persisted and the used mark applied.
	addrs := durableAddresses(t, harness, setup.walletID, 0)
	require.Len(t, addrs, 3)
	require.True(t, scanAddressUsed(t, setup, 0, waddrmgr.ExternalBranch, 0))

	// The mined transaction and its credit persisted, so the balance reflects
	// the batch.
	details := scanTxDetails(t, setup, txHash)
	require.NotNil(t, details)
	require.Equal(t, setup.baseHeight+1, details.Block.Height)
	require.Equal(t, int64(50_000), scanBalance(t, setup, setup.baseHeight+1))

	// The committed facts are the relevant-tx event followed by the
	// block-connected event, delivered once to the notifier.
	require.Len(t, res.Events, 2)
	require.Equal(
		t, db.RelevantTxEvent(txHash, &newBlock).ID, res.Events[0].ID,
	)
	require.Equal(t, db.BlockConnectedEvent(newBlock).ID, res.Events[1].ID)
	require.Len(t, events, 2)
	require.Equal(t, res.Events[0].ID, events[0].ID)

	// The caches were published after the durable commit.
	cachedTip, ok := setup.coord.CachedTip()
	require.True(t, ok)
	require.Equal(t, newBlock, cachedTip)
	cachedIndex, ok := setup.coord.CachedNextIndex(runtime.BranchKey{
		Scope: setup.scope, Account: 0, Branch: waddrmgr.ExternalBranch,
	})
	require.True(t, ok)
	require.Equal(t, uint32(3), cachedIndex)
}

// testScanCreditSpend proves the batch records a credit spend when one of its
// transactions spends a wallet credit added earlier in the same batch: the
// funding credit becomes spent and only the spending transaction's own credit
// remains unspent.
func testScanCreditSpend(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	setup := newScanSetup(t, harness, "scan-spend")
	block := tipRef(testBlock(setup.baseHeight + 1))

	// funding pays a wallet credit at output 0; spend consumes funding:0 and
	// pays a new wallet credit at output 0.
	funding := minedScanTx(t, testHash(0x70), 50_000, block)
	spend := minedScanTx(t, funding.Record.Hash, 40_000, block)

	_, err := setup.coord.CommitScan(ctx, db.CommitScanResultsRequest{
		ExpectedTip:  tipRef(testBlock(setup.baseHeight)),
		NewTip:       block,
		Blocks:       []db.BlockRef{block},
		Transactions: []db.ScanTransaction{funding, spend},
		OperationID:  []byte("op-spend"),
	})
	require.NoError(t, err)

	// The funding credit was spent within the batch, so only the spending
	// transaction's own credit remains unspent.
	require.Equal(t, int64(40_000), scanBalance(t, setup, setup.baseHeight+1))

	unspent := scanUnspent(t, setup)
	require.Len(t, unspent, 1)
	require.Equal(t, spend.Record.Hash, unspent[0].OutPoint.Hash)
}

// testScanUnminedIncidence proves the batch records both a mined and an unmined
// transaction incidence: the mined incidence references its block while the
// unmined incidence has none.
func testScanUnminedIncidence(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	setup := newScanSetup(t, harness, "scan-unmined")
	newBlock := tipRef(testBlock(setup.baseHeight + 1))

	mined := minedScanTx(t, testHash(0x90), 50_000, newBlock)
	unmined := unminedScanTx(t, testHash(0x91), 30_000)

	_, err := setup.coord.CommitScan(ctx, db.CommitScanResultsRequest{
		ExpectedTip:  tipRef(testBlock(setup.baseHeight)),
		NewTip:       newBlock,
		Blocks:       []db.BlockRef{newBlock},
		Transactions: []db.ScanTransaction{mined, unmined},
		OperationID:  []byte("op-unmined"),
	})
	require.NoError(t, err)

	minedDetails := scanTxDetails(t, setup, mined.Record.Hash)
	require.NotNil(t, minedDetails)
	require.Equal(t, setup.baseHeight+1, minedDetails.Block.Height)

	unminedDetails := scanTxDetails(t, setup, unmined.Record.Hash)
	require.NotNil(t, unminedDetails)
	require.Equal(t, int32(-1), unminedDetails.Block.Height)
}

// testScanPartialFailure proves a rejected commit rolls back completely: no
// address, transaction, horizon, tip, cache, or event survives.
func testScanPartialFailure(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	var (
		publishes atomic.Int32
		events    []db.Event
	)

	setup := newScanSetup(
		t, harness, "scan-partial",
		runtime.WithBeforePublish(func() { publishes.Add(1) }),
		runtime.WithNotifier(func(e []db.Event) { events = append(events, e...) }),
	)

	req, txHash, _ := representativeScanBatch(t, setup, []byte("op-scan-fail"))

	fpCtx := db.WithFailpoints(ctx, &db.Failpoints{
		BeforeCommit: func() error { return errForcedCommitFailure },
	})

	_, err := setup.coord.CommitScan(fpCtx, req)
	require.Error(t, err)

	// Nothing changed: tip, horizon, addresses, and transaction all rolled back
	// with the transaction, and neither the cache nor a notification fired.
	require.Equal(t, setup.baseHeight, harness.syncedHeight(t, setup.walletID))
	require.Equal(t, uint32(0), durableBranchIndex(
		t, harness, setup.walletID, waddrmgr.ExternalBranch,
	))
	require.Empty(t, durableAddresses(t, harness, setup.walletID, 0))
	require.Nil(t, scanTxDetails(t, setup, txHash))
	require.Equal(t, int32(0), publishes.Load())
	require.Empty(t, events)

	_, ok := setup.coord.CachedTip()
	require.False(t, ok)

	// A later clean commit through a fresh coordinator does change state,
	// confirming the wallet was otherwise committable.
	clean := runtime.New(harness.newRuntimeStore(setup.walletID))
	cleanReq, _, newBlock := representativeScanBatch(
		t, setup, []byte("op-scan-ok"),
	)
	res, err := clean.CommitScan(ctx, cleanReq)
	require.NoError(t, err)
	require.Equal(t, newBlock, res.Tip)
	require.Equal(t, setup.baseHeight+1, harness.syncedHeight(t, setup.walletID))
}

// testScanStaleTip proves a batch prepared against a stale base tip fails with
// the typed error and leaves no partial write.
func testScanStaleTip(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	setup := newScanSetup(t, harness, "scan-stale-tip")

	req, txHash, _ := representativeScanBatch(t, setup, []byte("op-stale-tip"))

	// Prepare against a recorded block that is not the current synced tip.
	req.ExpectedTip = tipRef(testBlock(setup.baseHeight - 1))

	_, err := setup.coord.CommitScan(ctx, req)
	require.ErrorIs(t, err, db.ErrStaleTip)

	// The whole batch rolled back.
	require.Equal(t, setup.baseHeight, harness.syncedHeight(t, setup.walletID))
	require.Equal(t, uint32(0), durableBranchIndex(
		t, harness, setup.walletID, waddrmgr.ExternalBranch,
	))
	require.Empty(t, durableAddresses(t, harness, setup.walletID, 0))
	require.Nil(t, scanTxDetails(t, setup, txHash))
}

// testScanStaleIndex proves a batch prepared against a stale branch index fails
// with the typed error and leaves no partial write.
func testScanStaleIndex(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	setup := newScanSetup(t, harness, "scan-stale-index")

	req, txHash, _ := representativeScanBatch(t, setup, []byte("op-stale-index"))

	// Prepare the horizon against an index the account never had.
	req.Horizons[0].ExpectedIndex = 7
	req.Horizons[0].FinalIndex = 9

	_, err := setup.coord.CommitScan(ctx, req)
	require.ErrorIs(t, err, db.ErrStaleAccountIndex)

	// The whole batch rolled back: the tip did not move and no rows landed.
	require.Equal(t, setup.baseHeight, harness.syncedHeight(t, setup.walletID))
	require.Equal(t, uint32(0), durableBranchIndex(
		t, harness, setup.walletID, waddrmgr.ExternalBranch,
	))
	require.Empty(t, durableAddresses(t, harness, setup.walletID, 0))
	require.Nil(t, scanTxDetails(t, setup, txHash))
}

// testRewindReconciles proves a rewind reconciles transaction incidences,
// credits, and sync state back to the target block: the incidence above the
// target detaches to the unmined set while the surviving incidence stays mined.
func testRewindReconciles(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	setup := newScanSetup(t, harness, "rewind-reconcile")

	// Advance two blocks in one scan batch, each with a mined credit.
	block1 := tipRef(testBlock(setup.baseHeight + 1))
	block2 := tipRef(testBlock(setup.baseHeight + 2))
	tx1 := minedScanTx(t, testHash(0x61), 40_000, block1)
	tx2 := minedScanTx(t, testHash(0x62), 60_000, block2)

	scanReq := db.CommitScanResultsRequest{
		ExpectedTip:  tipRef(testBlock(setup.baseHeight)),
		NewTip:       block2,
		Blocks:       []db.BlockRef{block1, block2},
		Transactions: []db.ScanTransaction{tx1, tx2},
		OperationID:  []byte("op-rewind-scan"),
	}
	_, err := setup.coord.CommitScan(ctx, scanReq)
	require.NoError(t, err)
	require.Equal(t, setup.baseHeight+2, harness.syncedHeight(t, setup.walletID))

	// Rewind to block1, detaching block2.
	res, err := setup.coord.CommitRewind(ctx, db.CommitWalletRewindRequest{
		ExpectedTip: block2,
		TargetBlock: block1,
		OperationID: []byte("op-rewind"),
	})
	require.NoError(t, err)
	require.False(t, res.Replayed)
	require.Equal(t, block1, res.Tip)
	require.Len(t, res.Events, 1)
	require.Equal(t, db.BlockDisconnectedEvent(block2).ID, res.Events[0].ID)

	// The sync tip moved back to the target, the surviving incidence stays
	// mined, and the detached incidence is back in the unmined set.
	require.Equal(t, setup.baseHeight+1, harness.syncedHeight(t, setup.walletID))
	require.Equal(t, block1.Hash, harness.syncedBlockHash(t, setup.walletID))

	surviving := scanTxDetails(t, setup, tx1.Record.Hash)
	require.NotNil(t, surviving)
	require.Equal(t, setup.baseHeight+1, surviving.Block.Height)

	detached := scanTxDetails(t, setup, tx2.Record.Hash)
	require.NotNil(t, detached)
	require.Equal(t, int32(-1), detached.Block.Height)
}

// testRewindIdempotent proves a rewind is idempotent on re-preparation: after
// rewinding to a target, a rewind prepared from the now-current tip to the same
// target is a no-op that changes nothing.
func testRewindIdempotent(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	setup := newScanSetup(t, harness, "rewind-idempotent")

	block1 := tipRef(testBlock(setup.baseHeight + 1))
	block2 := tipRef(testBlock(setup.baseHeight + 2))
	tx1 := minedScanTx(t, testHash(0x63), 40_000, block1)
	tx2 := minedScanTx(t, testHash(0x64), 60_000, block2)

	_, err := setup.coord.CommitScan(ctx, db.CommitScanResultsRequest{
		ExpectedTip:  tipRef(testBlock(setup.baseHeight)),
		NewTip:       block2,
		Blocks:       []db.BlockRef{block1, block2},
		Transactions: []db.ScanTransaction{tx1, tx2},
		OperationID:  []byte("op-idem-scan"),
	})
	require.NoError(t, err)

	// First rewind to block1.
	_, err = setup.coord.CommitRewind(ctx, db.CommitWalletRewindRequest{
		ExpectedTip: block2,
		TargetBlock: block1,
		OperationID: []byte("op-idem-1"),
	})
	require.NoError(t, err)
	require.Equal(t, setup.baseHeight+1, harness.syncedHeight(t, setup.walletID))

	// A rewind re-prepared from the now-current tip to the same target is a
	// no-op: nothing above block1 remains and the tip does not move.
	res, err := setup.coord.CommitRewind(ctx, db.CommitWalletRewindRequest{
		ExpectedTip: block1,
		TargetBlock: block1,
		OperationID: []byte("op-idem-2"),
	})
	require.NoError(t, err)
	require.Equal(t, block1, res.Tip)

	require.Equal(t, setup.baseHeight+1, harness.syncedHeight(t, setup.walletID))
	surviving := scanTxDetails(t, setup, tx1.Record.Hash)
	require.NotNil(t, surviving)
	require.Equal(t, setup.baseHeight+1, surviving.Block.Height)
	detached := scanTxDetails(t, setup, tx2.Record.Hash)
	require.NotNil(t, detached)
	require.Equal(t, int32(-1), detached.Block.Height)
}

// testScanJournal runs the SQL-only failure-injection vector, proving the
// operation journal makes a scan batch and a wallet rewind idempotent under a
// forced callback retry, an operation replay, and an ambiguous commit. It is
// skipped for the KV backend, which has no journal and re-prepares instead.
func testScanJournal(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	t.Run("forced retry idempotent", func(t *testing.T) {
		testScanForcedRetry(t, harness)
	})
	t.Run("operation replay idempotent", func(t *testing.T) {
		testScanOperationReplay(t, harness)
	})
	t.Run("ambiguous resolved by reread", func(t *testing.T) {
		testScanAmbiguousResolved(t, harness)
	})
	t.Run("rewind operation replay", func(t *testing.T) {
		testRewindOperationReplay(t, harness)
	})
}

// testScanForcedRetry proves a forced callback retry applies the batch exactly
// once: the body runs twice but the durable tip, credit, and journal change
// once, and the event is emitted once.
func testScanForcedRetry(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	var (
		attempts atomic.Int32
		events   []db.Event
	)

	setup := newScanSetup(
		t, harness, "scan-retry",
		runtime.WithNotifier(func(e []db.Event) { events = append(events, e...) }),
	)

	req, _, newBlock := representativeScanBatch(t, setup, []byte("op-retry"))

	fpCtx := db.WithFailpoints(ctx, &db.Failpoints{
		ForceTxRetries: 1,
		OnTxAttempt:    func(int) { attempts.Add(1) },
	})

	res, err := setup.coord.CommitScan(fpCtx, req)
	require.NoError(t, err)
	require.Equal(t, newBlock, res.Tip)

	// The body ran twice (one rolled-back attempt plus the committed one) but
	// the durable state advanced exactly once.
	require.Equal(t, int32(2), attempts.Load())
	require.Equal(t, setup.baseHeight+1, harness.syncedHeight(t, setup.walletID))
	require.Equal(t, int64(50_000), scanBalance(t, setup, setup.baseHeight+1))
	require.Equal(t, 1, scanJournalRows(t, harness, setup.walletID, "scan-batch"))
	require.Len(t, events, 2)
}

// testScanOperationReplay proves re-running a committed batch with the same
// operation id is served from the journal: the result reports a replay and the
// durable state does not change again.
func testScanOperationReplay(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	setup := newScanSetup(t, harness, "scan-replay")
	req, _, newBlock := representativeScanBatch(t, setup, []byte("op-replay"))

	first, err := setup.coord.CommitScan(ctx, req)
	require.NoError(t, err)
	require.False(t, first.Replayed)

	// A fresh coordinator models a restart with a cold cache; the same operation
	// id replays from the journal.
	fresh := runtime.New(harness.newRuntimeStore(setup.walletID))
	second, err := fresh.CommitScan(ctx, req)
	require.NoError(t, err)
	require.True(t, second.Replayed)
	require.Equal(t, newBlock, second.Tip)

	// The durable state advanced exactly once: one journal row and a single
	// credit's balance, not a doubled one.
	require.Equal(t, setup.baseHeight+1, harness.syncedHeight(t, setup.walletID))
	require.Equal(t, int64(50_000), scanBalance(t, setup, setup.baseHeight+1))
	require.Equal(t, 1, scanJournalRows(t, harness, setup.walletID, "scan-batch"))
	require.Len(t, durableAddresses(t, harness, setup.walletID, 0), 3)
}

// testScanAmbiguousResolved proves an ambiguous commit is resolved by durable
// reread: the batch is applied once and its events survive the resolution.
func testScanAmbiguousResolved(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	var events []db.Event

	setup := newScanSetup(
		t, harness, "scan-ambiguous",
		runtime.WithNotifier(func(e []db.Event) { events = append(events, e...) }),
	)

	req, _, newBlock := representativeScanBatch(t, setup, []byte("op-ambiguous"))

	fpCtx := db.WithFailpoints(ctx, &db.Failpoints{
		AfterCommit: func() error { return db.ErrAmbiguousCommit },
	})

	res, err := setup.coord.CommitScan(fpCtx, req)
	require.NoError(t, err)
	require.True(t, res.Replayed)
	require.Equal(t, newBlock, res.Tip)

	// The batch applied exactly once and the events were recovered.
	require.Equal(t, setup.baseHeight+1, harness.syncedHeight(t, setup.walletID))
	require.Equal(t, 1, scanJournalRows(t, harness, setup.walletID, "scan-batch"))
	require.Len(t, events, 2)
}

// testRewindOperationReplay proves re-running a committed rewind with the same
// operation id replays from the journal, so a retry after an advance moved the
// tip still returns the committed rewind result instead of a stale-tip error.
func testRewindOperationReplay(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	setup := newScanSetup(t, harness, "rewind-replay")

	block1 := tipRef(testBlock(setup.baseHeight + 1))
	block2 := tipRef(testBlock(setup.baseHeight + 2))
	tx1 := minedScanTx(t, testHash(0x65), 40_000, block1)
	tx2 := minedScanTx(t, testHash(0x66), 60_000, block2)

	_, err := setup.coord.CommitScan(ctx, db.CommitScanResultsRequest{
		ExpectedTip:  tipRef(testBlock(setup.baseHeight)),
		NewTip:       block2,
		Blocks:       []db.BlockRef{block1, block2},
		Transactions: []db.ScanTransaction{tx1, tx2},
		OperationID:  []byte("op-rr-scan"),
	})
	require.NoError(t, err)

	rewind := db.CommitWalletRewindRequest{
		ExpectedTip: block2,
		TargetBlock: block1,
		OperationID: []byte("op-rr"),
	}

	first, err := setup.coord.CommitRewind(ctx, rewind)
	require.NoError(t, err)
	require.False(t, first.Replayed)

	// A fresh coordinator replays the same rewind id from the journal even
	// though the durable tip is now block1, not the request's expected block2.
	fresh := runtime.New(harness.newRuntimeStore(setup.walletID))
	second, err := fresh.CommitRewind(ctx, rewind)
	require.NoError(t, err)
	require.True(t, second.Replayed)
	require.Equal(t, block1, second.Tip)
	require.Equal(t, 1, scanJournalRows(
		t, harness, setup.walletID, "wallet-rewind",
	))
}

// representativeScanBatch builds the representative scan batch: a horizon
// extension with three discovered addresses, one mined transaction with a
// credit, a usage mark, and a single-block tip advance. It returns the request
// plus the committed transaction hash and new tip for assertions.
func representativeScanBatch(t *testing.T, setup *scanSetup,
	opID []byte) (db.CommitScanResultsRequest, chainhash.Hash, db.BlockRef) {

	t.Helper()

	newBlock := tipRef(testBlock(setup.baseHeight + 1))
	scanTx := minedScanTx(t, testHash(0x60), 50_000, newBlock)
	addrs := addrRows(0, waddrmgr.ExternalBranch, 0, 1, 2)

	req := db.CommitScanResultsRequest{
		ExpectedTip: tipRef(testBlock(setup.baseHeight)),
		NewTip:      newBlock,
		Blocks:      []db.BlockRef{newBlock},
		Horizons: []db.BranchHorizon{{
			Scope:         setup.scope,
			Account:       0,
			Branch:        waddrmgr.ExternalBranch,
			ExpectedIndex: 0,
			FinalIndex:    3,
		}},
		Addresses:    addrs,
		Transactions: []db.ScanTransaction{scanTx},
		UsedAddresses: []db.AddressUse{{
			Scope:     setup.scope,
			AddressID: addrs[0].AddressID,
		}},
		OperationID: opID,
	}

	return req, scanTx.Record.Hash, newBlock
}

// scanTxRecord builds a transaction record spending one previous outpoint and
// paying one output at index zero, ready for a scan batch.
func scanTxRecord(t *testing.T, prev chainhash.Hash,
	value int64) *wtxmgr.TxRecord {

	t.Helper()

	msg := wire.NewMsgTx(2)
	msg.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: prev, Index: 0},
	})
	msg.AddTxOut(&wire.TxOut{Value: value, PkScript: []byte{0x51}})

	record, err := wtxmgr.NewTxRecordFromMsgTx(msg, time.Unix(3_000, 0))
	require.NoError(t, err)

	return record
}

// minedScanTx builds a scan transaction mined in the given block, paying one
// wallet-owned credit at output zero.
func minedScanTx(t *testing.T, prev chainhash.Hash, value int64,
	block db.BlockRef) db.ScanTransaction {

	t.Helper()

	return db.ScanTransaction{
		Record: scanTxRecord(t, prev, value),
		Block: &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Hash: block.Hash, Height: block.Height},
			Time:  block.Timestamp,
		},
		Credits: []db.ScanCredit{{Index: 0, Change: false}},
	}
}

// unminedScanTx builds an unmined scan transaction paying one wallet-owned
// credit at output zero.
func unminedScanTx(t *testing.T, prev chainhash.Hash,
	value int64) db.ScanTransaction {

	t.Helper()

	return db.ScanTransaction{
		Record:  scanTxRecord(t, prev, value),
		Block:   nil,
		Credits: []db.ScanCredit{{Index: 0, Change: false}},
	}
}

// scanTxDetails reads a transaction's details via the backend-neutral store,
// returning nil when the transaction is absent.
func scanTxDetails(t *testing.T, setup *scanSetup,
	hash chainhash.Hash) *wtxmgr.TxDetails {

	t.Helper()

	var details *wtxmgr.TxDetails

	err := setup.store.View(
		context.Background(), func(tx db.ReadTx) error {
			var err error

			details, err = tx.Tx().TxDetails(&hash)

			return err
		}, func() {},
	)
	require.NoError(t, err)

	return details
}

// scanUnspent reads the wallet's unspent outputs through the backend-neutral
// store.
func scanUnspent(t *testing.T, setup *scanSetup) []wtxmgr.Credit {
	t.Helper()

	var unspent []wtxmgr.Credit

	err := setup.store.View(
		context.Background(), func(tx db.ReadTx) error {
			var err error

			unspent, err = tx.Tx().UnspentOutputs()

			return err
		}, func() {},
	)
	require.NoError(t, err)

	return unspent
}

// scanBalance reads the wallet's spendable balance at the given sync height.
func scanBalance(t *testing.T, setup *scanSetup, syncHeight int32) int64 {
	t.Helper()

	var balance btcutil.Amount

	err := setup.store.View(
		context.Background(), func(tx db.ReadTx) error {
			var err error

			balance, err = tx.Tx().Balance(0, syncHeight)

			return err
		}, func() {},
	)
	require.NoError(t, err)

	return int64(balance)
}

// scanAddressUsed reports whether the address at a derivation path carries its
// used bit.
func scanAddressUsed(t *testing.T, setup *scanSetup, account, branch,
	index uint32) bool {

	t.Helper()

	for _, addr := range durableAddresses(t, setup.harness, setup.walletID,
		account) {

		if addr.Branch == nil || addr.Index == nil {
			continue
		}

		if *addr.Branch == branch && *addr.Index == index {
			return addr.Used
		}
	}

	t.Fatalf("address at branch %d index %d not found", branch, index)

	return false
}

// scanJournalRows returns the number of committed journal rows for one domain.
func scanJournalRows(t *testing.T, harness *managerStoreHarness, walletID int64,
	domain string) int {

	t.Helper()

	var count int

	err := harness.queryRow(t, `
		SELECT count(*) FROM operation_journal
		WHERE wallet_id = ? AND domain = ?
	`, walletID, domain).Scan(&count)
	require.NoError(t, err)

	return count
}
