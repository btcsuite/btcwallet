package wallet

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// Harness holds the BranchRecoveryState being tested, the recovery window being
// used, provides access to the test object, and tracks the expected horizon
// and next unfound values.
type Harness struct {
	t              *testing.T
	brs            *BranchRecoveryState
	recoveryWindow uint32
	expHorizon     uint32
	expNextUnfound uint32
}

type (
	// Stepper is a generic interface that performs an action or assertion
	// against a test Harness.
	Stepper interface {
		// Apply performs an action or assertion against branch recovery
		// state held by the Harness.  The step index is provided so
		// that any failures can report which Step failed.
		Apply(step int, harness *Harness)
	}

	// InitialiDelta is a Step that verifies our first attempt to expand the
	// branch recovery state's horizons tells us to derive a number of
	// adddresses equal to the recovery window.
	InitialDelta struct{}

	// CheckDelta is a Step that expands the branch recovery state's
	// horizon, and checks that the returned delta meets our expected
	// `delta`.
	CheckDelta struct {
		delta uint32
	}

	// CheckNumInvalid is a Step that asserts that the branch recovery
	// state reports `total` invalid children with the current horizon.
	CheckNumInvalid struct {
		total uint32
	}

	// MarkInvalid is a Step that marks the `child` as invalid in the branch
	// recovery state.
	MarkInvalid struct {
		child uint32
	}

	// ReportFound is a Step that reports `child` as being found to the
	// branch recovery state.
	ReportFound struct {
		child uint32
	}
)

// Apply extends the current horizon of the branch recovery state, and checks
// that the returned delta is equal to the test's recovery window. If the
// assertions pass, the harness's expected horizon is increased by the returned
// delta.
//
// NOTE: This should be used before applying any CheckDelta steps.
func (InitialDelta) Apply(i int, h *Harness) {
	curHorizon, delta := h.brs.ExtendHorizon()
	assertHorizon(h.t, i, curHorizon, h.expHorizon)
	assertDelta(h.t, i, delta, h.recoveryWindow)
	h.expHorizon += delta
}

// Apply extends the current horizon of the branch recovery state, and checks
// that the returned delta is equal to the CheckDelta's child value.
func (d CheckDelta) Apply(i int, h *Harness) {
	curHorizon, delta := h.brs.ExtendHorizon()
	assertHorizon(h.t, i, curHorizon, h.expHorizon)
	assertDelta(h.t, i, delta, d.delta)
	h.expHorizon += delta
}

// Apply queries the branch recovery state for the number of invalid children
// that lie between the last found address and the current horizon, and compares
// that to the CheckNumInvalid's total.
func (m CheckNumInvalid) Apply(i int, h *Harness) {
	assertNumInvalid(h.t, i, h.brs.NumInvalidInHorizon(), m.total)
}

// Apply marks the MarkInvalid's child index as invalid in the branch recovery
// state, and increments the harness's expected horizon.
func (m MarkInvalid) Apply(i int, h *Harness) {
	h.brs.MarkInvalidChild(m.child)
	h.expHorizon++
}

// Apply reports the ReportFound's child index as found in the branch recovery
// state. If the child index meets or exceeds our expected next unfound value,
// the expected value will be modified to be the child index + 1. Afterwards,
// this step asserts that the branch recovery state's next reported unfound
// value matches our potentially-updated value.
func (r ReportFound) Apply(i int, h *Harness) {
	h.brs.ReportFound(r.child)
	if r.child >= h.expNextUnfound {
		h.expNextUnfound = r.child + 1
	}
	assertNextUnfound(h.t, i, h.brs.NextUnfound(), h.expNextUnfound)
}

// Compile-time checks to ensure our steps implement the Step interface.
var _ Stepper = InitialDelta{}
var _ Stepper = CheckDelta{}
var _ Stepper = CheckNumInvalid{}
var _ Stepper = MarkInvalid{}
var _ Stepper = ReportFound{}

// TestBranchRecoveryState walks the BranchRecoveryState through a sequence of
// steps, verifying that:
//   - the horizon is properly expanded in response to found addrs
//   - report found children below or equal to previously found causes no change
//   - marking invalid children expands the horizon
func TestBranchRecoveryState(t *testing.T) {
	t.Parallel()

	const recoveryWindow = 10

	recoverySteps := []Stepper{
		// First, check that expanding our horizon returns exactly the
		// recovery window (10).
		InitialDelta{},

		// Expected horizon: 10.

		// Report finding the 2nd addr, this should cause our horizon
		// to expand by 2.
		ReportFound{1},
		CheckDelta{2},

		// Expected horizon: 12.

		// Sanity check that expanding again reports zero delta, as
		// nothing has changed.
		CheckDelta{0},

		// Now, report finding the 6th addr, which should expand our
		// horizon to 16 with a detla of 4.
		ReportFound{5},
		CheckDelta{4},

		// Expected horizon: 16.

		// Sanity check that expanding again reports zero delta, as
		// nothing has changed.
		CheckDelta{0},

		// Report finding child index 5 again, nothing should change.
		ReportFound{5},
		CheckDelta{0},

		// Report finding a lower index that what was last found,
		// nothing should change.
		ReportFound{4},
		CheckDelta{0},

		// Moving on, report finding the 11th addr, which should extend
		// our horizon to 21.
		ReportFound{10},
		CheckDelta{5},

		// Expected horizon: 21.

		// Before testing the lookahead expansion when encountering
		// invalid child keys, check that we are correctly starting with
		// no invalid keys.
		CheckNumInvalid{0},

		// Now that the window has been expanded, simulate deriving
		// invalid keys in range of addrs that are being derived for the
		// first time. The horizon will be incremented by one, as the
		// recovery manager is expected to try and derive at least the
		// next address.
		MarkInvalid{17},
		CheckNumInvalid{1},
		CheckDelta{0},

		// Expected horizon: 22.

		// Check that deriving a second invalid key shows both invalid
		// indexes currently within the horizon.
		MarkInvalid{18},
		CheckNumInvalid{2},
		CheckDelta{0},

		// Expected horizon: 23.

		// Lastly, report finding the addr immediately after our two
		// invalid keys. This should return our number of invalid keys
		// within the horizon back to 0.
		ReportFound{19},
		CheckNumInvalid{0},

		// As the 20-th key was just marked found, our horizon will need
		// to expand to 30. With the horizon at 23, the delta returned
		// should be 7.
		CheckDelta{7},
		CheckDelta{0},

		// Expected horizon: 30.
	}

	brs := NewBranchRecoveryState(recoveryWindow, nil)
	harness := &Harness{
		t:              t,
		brs:            brs,
		recoveryWindow: recoveryWindow,
	}

	for i, step := range recoverySteps {
		step.Apply(i, harness)
	}
}

// assertHorizon checks the expected recovery horizon for a step.
func assertHorizon(t *testing.T, i int, have, want uint32) {
	assertHaveWant(t, i, "incorrect horizon", have, want)
}

// assertDelta checks the expected horizon delta for a step.
func assertDelta(t *testing.T, i int, have, want uint32) {
	assertHaveWant(t, i, "incorrect delta", have, want)
}

// assertNextUnfound checks the expected next unfound child for a step.
func assertNextUnfound(t *testing.T, i int, have, want uint32) {
	assertHaveWant(t, i, "incorrect next unfound", have, want)
}

// assertNumInvalid checks the expected invalid child count for a step.
func assertNumInvalid(t *testing.T, i int, have, want uint32) {
	assertHaveWant(t, i, "incorrect num invalid children", have, want)
}

// assertHaveWant compares recovery test values with step context.
func assertHaveWant(t *testing.T, i int, msg string, have, want uint32) {
	t.Helper()
	require.Equal(t, want, have, "[step: %d] %s", i, msg)
}

// TestRecoveryManagerBatch verifies that the RecoveryManager correctly tracks
// and resets its internal batch of processed blocks.
func TestRecoveryManagerBatch(t *testing.T) {
	t.Parallel()

	// Arrange: Create a new recovery manager with a recovery window of 10
	// and a lookahead distance of 5.
	rm := NewRecoveryManager(10, 5, &chainParams)

	// Act: Add a block to the current batch.
	hash := chainhash.Hash{0x01}
	rm.AddToBlockBatch(&hash, 100, time.Now())

	// Assert: Verify that the block was correctly added to the batch.
	batch := rm.BlockBatch()
	require.Len(t, batch, 1)
	require.Equal(t, int32(100), batch[0].Height)

	// Act: Clear the current batch.
	rm.ResetBlockBatch()

	// Assert: Verify that the batch is now empty.
	require.Empty(t, rm.BlockBatch())
}

// TestBranchRecoveryStateHorizon verifies horizon expansion logic.
func TestBranchRecoveryStateHorizon(t *testing.T) {
	t.Parallel()

	// Arrange: Window 10.
	brs := NewBranchRecoveryState(10, nil)

	// Act: Initial horizon extend.
	// Horizon is 0. NextUnfound is 0. MinValid = 0 + 10 = 10.
	// Delta = 10 - 0 = 10.
	// Returns current horizon (start index) and delta.
	horizon, delta := brs.ExtendHorizon()
	require.Equal(t, uint32(0), horizon)
	require.Equal(t, uint32(10), delta)

	// Act: Report found at 5.
	brs.ReportFound(5)

	// NextUnfound becomes 6.
	require.Equal(t, uint32(6), brs.NextUnfound())

	// Act: Extend again.
	// MinValid = 6 + 10 = 16.
	// Current Horizon = 10.
	// Delta = 16 - 10 = 6.
	horizon, delta = brs.ExtendHorizon()
	require.Equal(t, uint32(10), horizon)
	require.Equal(t, uint32(6), delta)
}

// TestBranchRecoveryStateInvalidChild verifies handling of invalid keys.
func TestBranchRecoveryStateInvalidChild(t *testing.T) {
	t.Parallel()

	brs := NewBranchRecoveryState(5, nil)
	// Initial: Horizon 5.
	brs.ExtendHorizon()

	// Act: Mark index 2 as invalid.
	brs.MarkInvalidChild(2)

	// Assert: Horizon incremented to 6.
	require.Equal(t, uint32(1), brs.NumInvalidInHorizon())

	// Act: Extend.
	// NextUnfound = 0. Window = 5. Invalid = 1.
	// MinValid = 0 + 5 + 1 = 6.
	// Current Horizon = 6.
	// Delta = 0.
	horizon, delta := brs.ExtendHorizon()
	require.Equal(t, uint32(6), horizon)
	require.Equal(t, uint32(0), delta)

	// Act: Found 3.
	brs.ReportFound(3)

	// Invalid child 2 is < 3, so it should be pruned.
	require.Equal(t, uint32(0), brs.NumInvalidInHorizon())
}

// TestGetBranchState verifies the GetBranchState method of RecoveryState.
// It ensures that the method correctly fetches and caches BranchRecoveryState
// instances based on the provided BranchScope, optimizing for subsequent
// lookups by returning the cached state instead of re-creating it.
func TestGetBranchState(t *testing.T) {
	t.Parallel()

	addrMgr := &bwmock.AddrStore{}
	defer addrMgr.AssertExpectations(t)

	scope := waddrmgr.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}
	bs := waddrmgr.BranchScope{
		Scope:   scope,
		Account: 0,
		Branch:  0,
	}

	// Expect FetchScopedKeyManager to be called only once for a given
	// scope.
	addrMgr.On("FetchScopedKeyManager", scope).Return(
		&bwmock.AccountStore{}, nil,
	).Once()

	rs := NewRecoveryState(10, &chainParams, addrMgr)

	// First call should fetch the manager and create a new state.
	state1, err := rs.GetBranchState(bs)
	require.NoError(t, err)
	require.NotNil(t, state1)

	// Second call with the same scope should return the cached state.
	state2, err := rs.GetBranchState(bs)
	require.NoError(t, err)
	require.Equal(t, state1, state2)
}

// TestInitialize verifies the public Initialize method of RecoveryState.
// It ensures the method correctly sets up transient address filters and
// outpoints based on account properties and mock address derivations.
// This includes verifying that the lookahead horizons are properly synced
// and that the address filters are populated with the expected number of
// derived addresses for both external and internal branches.
func TestInitialize(t *testing.T) {
	t.Parallel()

	addrMgr := &bwmock.AddrStore{}
	defer addrMgr.AssertExpectations(t)

	accountStore := &bwmock.AccountStore{}
	defer accountStore.AssertExpectations(t)

	scope := waddrmgr.KeyScope{Purpose: 84, Coin: 0}

	props := &waddrmgr.AccountProperties{
		KeyScope:         scope,
		AccountNumber:    0,
		ExternalKeyCount: 5, // 5 found addresses
		InternalKeyCount: 3, // 3 found addresses
	}

	// FetchScopedKeyManager is called twice (once for external, once for
	// internal branch)
	addrMgr.On("FetchScopedKeyManager", scope).Return(
		accountStore, nil,
	).Times(2)

	// Helper to mock DeriveAddr calls for a given branch and
	// range of indices.
	mockDerive := func(branch, count uint32) {
		for i := range count {
			id := int(branch)*1000 + int(i)
			addr := &bwmock.Address{}
			addrStr := fmt.Sprintf("addr-%d", id)
			script := fmt.Appendf(nil, "script-%d", id)

			// Configure mockAddress expectations.
			addr.On("EncodeAddress").Return(addrStr)
			addr.On("ScriptAddress").Return(script)

			accountStore.On(
				"DeriveAddr", uint32(0), branch, i,
			).Return(addr, script, nil).Once()
		}
	}

	// External branch: 5 found, recovery window 10. Total 15 derivations
	// (0-14).
	mockDerive(0, 15)

	// Internal branch: 3 found, recovery window 10. Total 13 derivations
	// (0-12).
	mockDerive(1, 13)

	rs := NewRecoveryState(10, &chainParams, addrMgr)

	err := rs.Initialize([]*waddrmgr.AccountProperties{props}, nil, nil)
	require.NoError(t, err)

	// Verify that the address filters are populated with the expected
	// number of addresses.
	require.Len(t, rs.addrFilters, 15+13)
	require.Equal(t, 15+13, rs.WatchListSize())
}

// TestProcessBlock verifies the core private filterTx and expandHorizons
// methods through the public ProcessBlock entry point. It simulates a
// block containing transactions that trigger address discovery and horizon
// expansion. This test ensures the method correctly identifies relevant
// transactions, updates outpoints, and manages the lookahead window by
// repeatedly filtering the block and expanding horizons until convergence,
// correctly handling intra-block chains and lookahead expansions.
func TestProcessBlock(t *testing.T) {
	t.Parallel()

	addrMgr := &bwmock.AddrStore{}
	defer addrMgr.AssertExpectations(t)

	accountStore := &bwmock.AccountStore{}
	defer accountStore.AssertExpectations(t)

	scope := waddrmgr.KeyScope{Purpose: 84, Coin: 0}
	props := &waddrmgr.AccountProperties{
		KeyScope:      scope,
		AccountNumber: 0,

		// Start fresh for easier expansion testing.
		ExternalKeyCount: 0,
		InternalKeyCount: 0,
	}

	addrMgr.On("FetchScopedKeyManager", scope).Return(
		accountStore, nil,
	).Maybe() // Called by GetBranchState within Initialize/ProcessBlock

	// Store generated addresses to construct block data.
	addrs := make(map[int]btcutil.Address)

	// Helper to mock DeriveAddr and store the generated address.
	setupDerive := func(branch, idx uint32) {
		id := int(branch)*1000 + int(idx)

		// Create a valid P2PKH address for deterministic scripts.
		hash := make([]byte, 20)
		hash[0] = byte(id >> 8)
		hash[1] = byte(id)
		addr, _ := btcutil.NewAddressPubKeyHash(
			hash, &chainParams,
		)
		addrs[id] = addr

		// Set up mock expectation for DeriveAddr.
		script, _ := txscript.PayToAddrScript(addr)
		accountStore.On(
			"DeriveAddr", uint32(0), branch, idx,
		).Return(addr, script, nil).Maybe()
	}

	// 1. Initialize RecoveryState (derives initial lookahead 0-9 for both
	//    branches).
	for i := range uint32(10) {
		setupDerive(0, i) // External addresses
		setupDerive(1, i) // Internal addresses
	}

	rs := NewRecoveryState(10, &chainParams, addrMgr)
	err := rs.Initialize([]*waddrmgr.AccountProperties{props}, nil, nil)
	require.NoError(t, err)

	// 2. Setup expectations for subsequent horizon expansions:
	//
	// Finding address at index 5 (External) should make next unfound 6.
	// Horizon expands to 6 + window (10) = 16. New addresses derived from
	// 10 to 15.
	for i := uint32(10); i < 16; i++ {
		setupDerive(0, i)
	}

	// Finding address at index 12 (External) should make next unfound 13.
	// Horizon expands to 13 + window (10) = 23. New addresses derived from
	// 16 to 22.
	for i := uint32(16); i < 23; i++ {
		setupDerive(0, i)
	}

	// 3. Construct a mock block with transactions.
	block := wire.NewMsgBlock(wire.NewBlockHeader(
		0, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))

	// Tx1: Pays to Addr 5 (External Branch) - an address within initial
	// lookahead.
	addr5 := addrs[5] // Corresponds to id 5 (branch 0, index 5)
	script5, _ := txscript.PayToAddrScript(addr5)
	tx1 := wire.NewMsgTx(2)
	tx1.AddTxOut(wire.NewTxOut(1000, script5))
	_ = block.AddTransaction(tx1)

	// Tx2: Pays to Addr 12 (External Branch) - an address initially
	// outside the lookahead, but becomes visible after the first
	// expansion.
	addr12 := addrs[12] // Corresponds to id 12 (branch 0, index 12)
	script12, _ := txscript.PayToAddrScript(addr12)
	tx2 := wire.NewMsgTx(2)
	tx2.AddTxOut(wire.NewTxOut(2000, script12))
	_ = block.AddTransaction(tx2)

	// 4. Process the block and verify results.
	res, err := rs.ProcessBlock(block)
	require.NoError(t, err)

	// Expect expansion occurred due to finding index 12.
	require.True(t, res.Expanded)

	// Expect both transactions to be identified as relevant.
	require.Len(t, res.RelevantTxs, 2)

	// Verify the maximum index found for Branch 0 (External) is 12.
	bs := waddrmgr.BranchScope{Scope: scope, Account: 0, Branch: 0}
	require.Contains(t, res.FoundHorizons, bs)
	require.Equal(t, uint32(12), res.FoundHorizons[bs])
}

// TestProcessBlockKeepsSameBlockSpendOnExpansion verifies that a spend-only
// transaction is retained in the final result when a credit in the same block
// triggers a horizon expansion, forcing the filter loop to re-run. filterTx
// deletes a watched outpoint as soon as it sees a spend of it, so a naive
// re-run of filterBlock over the same block would no longer recognize that
// spend on the second pass and silently drop the spend-only transaction from
// the overwritten result. The block here pairs a spend of a pre-watched
// outpoint (with no other relevance) with a credit to a lookahead address that
// triggers expansion; the spend transaction must still appear in the final
// RelevantTxs.
func TestProcessBlockKeepsSameBlockSpendOnExpansion(t *testing.T) {
	t.Parallel()

	addrMgr := &bwmock.AddrStore{}
	defer addrMgr.AssertExpectations(t)

	accountStore := &bwmock.AccountStore{}
	defer accountStore.AssertExpectations(t)

	scope := waddrmgr.KeyScope{Purpose: 84, Coin: 0}
	props := &waddrmgr.AccountProperties{
		KeyScope:      scope,
		AccountNumber: 0,

		// Start fresh so the lookahead window is derived from scratch.
		ExternalKeyCount: 0,
		InternalKeyCount: 0,
	}

	addrMgr.On("FetchScopedKeyManager", scope).Return(
		accountStore, nil,
	).Maybe()

	// Store generated addresses to construct block data.
	addrs := make(map[int]btcutil.Address)

	// Helper to mock DeriveAddr and store the generated address.
	setupDerive := func(branch, idx uint32) {
		id := int(branch)*1000 + int(idx)

		hash := make([]byte, 20)
		hash[0] = byte(id >> 8)
		hash[1] = byte(id)
		addr, _ := btcutil.NewAddressPubKeyHash(hash, &chainParams)
		addrs[id] = addr

		script, _ := txscript.PayToAddrScript(addr)
		accountStore.On(
			"DeriveAddr", uint32(0), branch, idx,
		).Return(addr, script, nil).Maybe()
	}

	// Initial lookahead (0-9 for both branches) plus the external addresses
	// (10-15) derived once finding index 5 expands the horizon to 6+10=16.
	for i := range uint32(10) {
		setupDerive(0, i)
		setupDerive(1, i)
	}

	for i := uint32(10); i < 16; i++ {
		setupDerive(0, i)
	}

	// Pre-watch an outpoint, mirroring a UTXO the wallet already owns and
	// monitors for spends. This is the outpoint whose spend must survive
	// the same-block expansion re-run.
	watchedOp := wire.OutPoint{Hash: chainhash.Hash{0xaa}, Index: 0}
	unspent := []wtxmgr.Credit{{
		OutPoint: watchedOp,
		PkScript: []byte{0x00},
	}}

	rs := NewRecoveryState(10, &chainParams, addrMgr)
	err := rs.Initialize(
		[]*waddrmgr.AccountProperties{props}, nil, unspent,
	)
	require.NoError(t, err)

	// Construct the block.
	block := wire.NewMsgBlock(wire.NewBlockHeader(
		0, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))

	// txSpend spends the watched outpoint and pays to an unrelated address,
	// so its only relevance is the spend. It is placed first so the spend
	// (and the outpoint deletion in filterTx) happens before the credit
	// that triggers the expansion.
	unrelatedHash := make([]byte, 20)
	for i := range unrelatedHash {
		unrelatedHash[i] = 0xff
	}

	unrelatedAddr, _ := btcutil.NewAddressPubKeyHash(
		unrelatedHash, &chainParams,
	)
	unrelatedScript, _ := txscript.PayToAddrScript(unrelatedAddr)
	txSpend := wire.NewMsgTx(2)
	txSpend.AddTxIn(wire.NewTxIn(&watchedOp, nil, nil))
	txSpend.AddTxOut(wire.NewTxOut(900, unrelatedScript))
	_ = block.AddTransaction(txSpend)
	spendHash := txSpend.TxHash()

	// txCredit pays to addr 5 (within the initial lookahead), which marks
	// the address found and triggers a horizon expansion, forcing the
	// filter loop to run a second pass over the block.
	addr5 := addrs[5]
	script5, _ := txscript.PayToAddrScript(addr5)
	txCredit := wire.NewMsgTx(2)
	txCredit.AddTxOut(wire.NewTxOut(1000, script5))
	_ = block.AddTransaction(txCredit)
	creditHash := txCredit.TxHash()

	// Process the block.
	res, err := rs.ProcessBlock(block)
	require.NoError(t, err)

	// The credit must have triggered a lookahead expansion, which is what
	// forces the second filter pass that exposes the bug.
	require.True(t, res.Expanded,
		"credit to lookahead address should expand the horizon")

	// Both the spend and the credit must be reported as relevant. Before
	// the fix, the spend-only transaction was dropped on the second pass
	// because its outpoint had already been deleted.
	relevant := make(map[chainhash.Hash]struct{}, len(res.RelevantTxs))
	for _, tx := range res.RelevantTxs {
		relevant[*tx.Hash()] = struct{}{}
	}

	require.Contains(t, relevant, spendHash,
		"spend of a pre-watched outpoint must survive the same-block "+
			"expansion re-run")
	require.Contains(t, relevant, creditHash,
		"credit to a watched address must be reported as relevant")
	require.Len(t, res.RelevantTxs, 2)
}

// TestBuildCFilterData verifies the BuildCFilterData method of RecoveryState.
// It ensures that the method correctly aggregates all relevant scripts from
// both the transient address filters and the watched outpoints into a single
// list, which is then used for CFilter construction. This tests the data
// aggregation logic, independent of address derivation or block processing.
func TestBuildCFilterData(t *testing.T) {
	t.Parallel()

	addrMgr := &bwmock.AddrStore{}
	defer addrMgr.AssertExpectations(t)

	rs := NewRecoveryState(10, &chainParams, addrMgr)

	// Initially, the recovery state should be empty.
	require.True(t, rs.Empty())

	// Manually initialize maps as Initialize is not called for this test.
	rs.addrFilters = make(map[string]AddrEntry)
	rs.outpoints = make(map[wire.OutPoint][]byte)

	// Add a sample address filter entry.
	addr1, _ := btcutil.DecodeAddress(
		"mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", &chainParams,
	)
	rs.addrFilters[addr1.EncodeAddress()] = AddrEntry{
		Address: addr1,
	}

	// Add a sample watched outpoint.
	op := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
	pkScript := []byte{0x00, 0x14, 0x01, 0x02} // Dummy P2WPKH script
	rs.outpoints[op] = pkScript

	// Verify WatchListSize reflects the manually added entries.
	require.Equal(t, 2, rs.WatchListSize())

	// Build the CFilter data.
	data, err := rs.BuildCFilterData()
	require.NoError(t, err)

	// Construct the expected script for addr1.
	script1, _ := txscript.PayToAddrScript(addr1)

	// Verify the returned data contains both scripts.
	require.Len(t, data, 2)
	require.Contains(t, data, script1)
	require.Contains(t, data, pkScript)
}

// TestInitAccountState verifies the private initAccountState method.
// It focuses on ensuring that when an account's properties are processed,
// the method correctly initializes branch recovery states for both external
// and internal branches. This involves verifying that the address manager's
// FetchScopedKeyManager is called appropriately and that the recovery
// state's addrFilters are populated with the initial set of derived
// addresses based on the configured recovery window.
func TestInitAccountState(t *testing.T) {
	t.Parallel()

	addrMgr := &bwmock.AddrStore{}
	defer addrMgr.AssertExpectations(t)

	accountStore := &bwmock.AccountStore{}
	defer accountStore.AssertExpectations(t)

	scope := waddrmgr.KeyScope{Purpose: 84, Coin: 0}
	props := &waddrmgr.AccountProperties{
		KeyScope:         scope,
		AccountNumber:    0,
		ExternalKeyCount: 0,
		InternalKeyCount: 0,
	}

	// RecoveryWindow 2.
	rs := NewRecoveryState(2, &chainParams, addrMgr)
	rs.addrFilters = make(map[string]AddrEntry)

	// FetchScopedKeyManager is called twice (once for external, once for
	// internal branch).
	addrMgr.On("FetchScopedKeyManager", scope).Return(
		accountStore, nil,
	).Times(2)

	// Helper to mock DeriveAddr calls for a given branch and range of
	// indices.
	mockDerive := func(branch uint32) {
		for i := range uint32(2) {
			id := int(branch)*1000 + int(i)
			addr := &bwmock.Address{}
			addrStr := fmt.Sprintf("b%d-%d", branch, i)
			script := fmt.Appendf(nil, "script-%d", id)

			// Configure mockAddress expectations.
			addr.On("EncodeAddress").Return(addrStr)
			addr.On("ScriptAddress").Return(script)

			accountStore.On(
				"DeriveAddr", uint32(0), branch, i,
			).Return(addr, script, nil).Once()
		}
	}

	mockDerive(0) // External
	mockDerive(1) // Internal

	err := rs.initAccountState(props)
	require.NoError(t, err)
	require.Len(t, rs.addrFilters, 4)
}

// TestExpandHorizons verifies the private expandHorizons method.
// It ensures that the lookahead horizon is correctly expanded when new
// addresses are reported as found. This test specifically checks that new
// addresses are derived (via the mocked AccountStore) to maintain the recovery
// window, and that these newly derived addresses are subsequently added to the
// RecoveryState's transient addrFilters.
func TestExpandHorizons(t *testing.T) {
	t.Parallel()

	store := &bwmock.AccountStore{}
	defer store.AssertExpectations(t)

	rs := NewRecoveryState(2, nil, nil)
	rs.addrFilters = make(map[string]AddrEntry)

	// Setup a branch state manually.
	bs := waddrmgr.BranchScope{Branch: 0}
	brs := NewBranchRecoveryState(2, store)
	rs.branchStates[bs] = brs

	// Simulate finding index 0, which requires derivation of 0, 1, 2
	// because NextUnfound becomes 1, MinHorizon = 1+2=3.
	brs.ReportFound(0)

	// Expect derivation of 0, 1, 2.
	for i := range uint32(3) {
		addr := &bwmock.Address{}
		addrStr := fmt.Sprintf("addr-%d", i)
		script := fmt.Appendf(nil, "script-%d", i)

		addr.On("EncodeAddress").Return(addrStr)
		addr.On("ScriptAddress").Return(script)

		store.On("DeriveAddr", uint32(0), uint32(0), i).Return(
			addr, script, nil,
		).Once()
	}

	expanded, err := rs.expandHorizons()
	require.NoError(t, err)
	require.True(t, expanded)
	require.Len(t, rs.addrFilters, 3)
}

// TestReportFound verifies the private reportFound method.
// It ensures that the method correctly processes a map of found AddrScopes,
// identifying the maximum index found for each BranchScope. It then verifies
// that the corresponding BranchRecoveryState's internal `nextUnfound` value is
// updated appropriately based on these findings, triggering potential future
// horizon expansions.
func TestReportFound(t *testing.T) {
	t.Parallel()

	rs := NewRecoveryState(10, nil, nil)
	bs := waddrmgr.BranchScope{Branch: 0}
	brs := NewBranchRecoveryState(10, nil)
	rs.branchStates[bs] = brs

	// Simulate finding index 5 on this branch.
	found := map[waddrmgr.AddrScope]struct{}{
		{BranchScope: bs, Index: 5}: {},
	}

	horizons := rs.reportFound(found)

	require.Contains(t, horizons, bs)
	require.Equal(t, uint32(5), horizons[bs])
	require.Equal(t, uint32(6), brs.NextUnfound())
}

// TestFilterTx verifies the private filterTx method.
// It simulates a single transaction and checks its relevance against the
// RecoveryState's configured address filters and watched outpoints. This test
// ensures that the method correctly identifies credits (payments to our
// addresses) and debits (spends from our outpoints), updates the transient
// outpoints map (removing spent inputs, adding new relevant outputs), and
// populates the foundScopes and relevantOutputs maps for subsequent
// processing.
func TestFilterTx(t *testing.T) {
	t.Parallel()

	rs := NewRecoveryState(10, &chainParams, nil)
	rs.addrFilters = make(map[string]AddrEntry)
	rs.outpoints = make(map[wire.OutPoint][]byte)

	// 1. Setup Watched Address.
	// Use real address for Script parsing interaction with txscript.
	addr, _ := btcutil.DecodeAddress(
		"mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", &chainParams,
	)

	rs.addrFilters[addr.EncodeAddress()] = AddrEntry{
		Address: addr,
		addrScope: waddrmgr.AddrScope{
			BranchScope: waddrmgr.BranchScope{Branch: 0},
			Index:       10,
		},
		IsLookahead: true,
	}

	// 2. Setup Watched Outpoint.
	opHash := chainhash.Hash{0x01}
	op := wire.OutPoint{Hash: opHash, Index: 0}
	rs.outpoints[op] = []byte{0x00} // Dummy script

	// 3. Construct Tx.
	// Input spending 'op'.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&op, nil, nil))

	// Output paying to 'addr'.
	pkScript, _ := txscript.PayToAddrScript(addr)
	tx.AddTxOut(wire.NewTxOut(1000, pkScript))

	// 4. Filter.
	foundScopes := make(map[waddrmgr.AddrScope]struct{})
	isRelevant, entries := rs.filterTx(tx, foundScopes)
	require.True(t, isRelevant)

	// Verify Outpoint spent (removed).
	_, ok := rs.outpoints[op]
	require.False(t, ok, "outpoint should be removed")

	// Verify Output matched.
	txHash := tx.TxHash()

	require.Len(t, entries, 1)

	// Verify Scope found.
	expectedScope := waddrmgr.AddrScope{
		BranchScope: waddrmgr.BranchScope{Branch: 0},
		Index:       10,
	}
	require.Contains(t, foundScopes, expectedScope)

	// Verify new outpoint added.
	newOp := wire.OutPoint{Hash: txHash, Index: 0}
	_, ok = rs.outpoints[newOp]
	require.True(t, ok, "new outpoint should be watched")
}

// TestRecoveryStateWatchedOutPoints verifies the management of persistent
// watched outpoints through AddWatchedOutPoint and WatchedOutPoints.
func TestRecoveryStateWatchedOutPoints(t *testing.T) {
	t.Parallel()

	rs := NewRecoveryState(10, nil, nil)

	// Initially, no watched outpoints.
	require.Empty(t, rs.WatchedOutPoints())

	op1 := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
	addr1 := &bwmock.Address{}
	op2 := wire.OutPoint{Hash: chainhash.Hash{2}, Index: 1}
	addr2 := &bwmock.Address{}

	rs.AddWatchedOutPoint(&op1, addr1)
	rs.AddWatchedOutPoint(&op2, addr2)

	watched := rs.WatchedOutPoints()
	require.Len(t, watched, 2)
	require.Equal(t, addr1, watched[op1])
	require.Equal(t, addr2, watched[op2])
}

// TestRecoveryStateStringAndEmpty verifies the String and Empty methods of
// RecoveryState. It ensures that the String method produces a non-empty
// summary and that the Empty method accurately reflects the presence or
// absence of filters and outpoints.
func TestRecoveryStateStringAndEmpty(t *testing.T) {
	t.Parallel()

	rs := NewRecoveryState(10, nil, nil)

	// Initially, state should be empty.
	require.True(t, rs.Empty())
	require.Contains(t, rs.String(), "RecoveryState(addrs=0, outpoints=0)")

	// Add an address filter entry.
	rs.addrFilters = make(map[string]AddrEntry)
	rs.addrFilters["a"] = AddrEntry{}

	require.False(t, rs.Empty())
	require.Contains(t, rs.String(), "RecoveryState(addrs=1, outpoints=0)")

	// Add an outpoint.
	rs.outpoints = make(map[wire.OutPoint][]byte)
	op := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
	rs.outpoints[op] = []byte{}

	require.False(t, rs.Empty())
	require.Contains(t, rs.String(), "RecoveryState(addrs=1, outpoints=1)")
}

// Define a static error for testing FetchScopedKeyManager failure.
var errFetch = errors.New("fetch error")

// TestExpandHorizonsWithInvalidChild verifies that expandHorizons correctly
// handles hdkeychain.ErrInvalidChild by skipping the invalid index and
// continuing derivation until the window is full.
func TestExpandHorizonsWithInvalidChild(t *testing.T) {
	t.Parallel()

	store := &bwmock.AccountStore{}
	defer store.AssertExpectations(t)

	rs := NewRecoveryState(2, nil, nil)
	rs.addrFilters = make(map[string]AddrEntry)

	// Setup a branch state manually.
	bs := waddrmgr.BranchScope{Branch: 0}
	brs := NewBranchRecoveryState(2, store)
	rs.branchStates[bs] = brs

	// Simulate finding index 0. This triggers expansion.
	brs.ReportFound(0)

	// Expect derivation of 0 -> Success
	addr0 := &bwmock.Address{}
	addr0.On("EncodeAddress").Return("addr-0")
	addr0.On("ScriptAddress").Return([]byte("script-0"))
	store.On("DeriveAddr", uint32(0), uint32(0), uint32(0)).Return(
		addr0, []byte("script-0"), nil,
	).Once()

	// Expect derivation of 1 -> ErrInvalidChild
	store.On("DeriveAddr", uint32(0), uint32(0), uint32(1)).Return(
		nil, nil, hdkeychain.ErrInvalidChild,
	).Once()

	// Expect derivation of 2 -> Success
	addr2 := &bwmock.Address{}
	addr2.On("EncodeAddress").Return("addr-2")
	addr2.On("ScriptAddress").Return([]byte("script-2"))
	store.On("DeriveAddr", uint32(0), uint32(0), uint32(2)).Return(
		addr2, []byte("script-2"), nil,
	).Once()

	// Expect derivation of 3 -> Success (to fill window)
	addr3 := &bwmock.Address{}
	addr3.On("EncodeAddress").Return("addr-3")
	addr3.On("ScriptAddress").Return([]byte("script-3"))
	store.On("DeriveAddr", uint32(0), uint32(0), uint32(3)).Return(
		addr3, []byte("script-3"), nil,
	).Once()

	expanded, err := rs.expandHorizons()
	require.NoError(t, err)
	require.True(t, expanded)

	// Verify filters contain 0, 2, 3 (3 valid addresses).
	require.Len(t, rs.addrFilters, 3)
	require.Contains(t, rs.addrFilters, "addr-0")
	require.Contains(t, rs.addrFilters, "addr-2")
	require.Contains(t, rs.addrFilters, "addr-3")
	require.NotContains(t, rs.addrFilters, "addr-1")
}

// TestInitializeError verifies that Initialize propagates errors from
// initAccountState (e.g. FetchScopedKeyManager failures).
func TestInitializeError(t *testing.T) {
	t.Parallel()

	addrMgr := &bwmock.AddrStore{}
	defer addrMgr.AssertExpectations(t)

	rs := NewRecoveryState(10, nil, addrMgr)
	scope := waddrmgr.KeyScope{Purpose: 84, Coin: 0}
	props := &waddrmgr.AccountProperties{KeyScope: scope}

	// Mock failure.
	addrMgr.On("FetchScopedKeyManager", scope).Return(nil, errFetch).Once()

	err := rs.Initialize([]*waddrmgr.AccountProperties{props}, nil, nil)
	require.ErrorIs(t, err, errFetch)
}

// TestInitAccountStateDeriveError verifies that initAccountState propagates
// errors from DeriveAddr.
func TestInitAccountStateDeriveError(t *testing.T) {
	t.Parallel()

	addrMgr := &bwmock.AddrStore{}
	accountStore := &bwmock.AccountStore{}

	defer addrMgr.AssertExpectations(t)
	defer accountStore.AssertExpectations(t)

	rs := NewRecoveryState(10, nil, addrMgr)
	rs.addrFilters = make(map[string]AddrEntry)
	scope := waddrmgr.KeyScope{Purpose: 84, Coin: 0}
	props := &waddrmgr.AccountProperties{KeyScope: scope}

	// First call succeeds (External).
	addrMgr.On("FetchScopedKeyManager", scope).Return(
		accountStore, nil,
	).Once()

	// Derive fails immediately.
	accountStore.On(
		"DeriveAddr", uint32(0), uint32(0), uint32(0),
	).Return(nil, nil, errFetch).Once()

	err := rs.initAccountState(props)
	require.ErrorIs(t, err, errFetch)
}

// TestExpandHorizonsError verifies that expandHorizons propagates errors from
// DeriveAddr when attempting to extend the lookahead window.
func TestExpandHorizonsError(t *testing.T) {
	t.Parallel()

	accountStore := &bwmock.AccountStore{}
	defer accountStore.AssertExpectations(t)

	rs := NewRecoveryState(2, nil, nil)
	rs.addrFilters = make(map[string]AddrEntry)
	bs := waddrmgr.BranchScope{Branch: 0}
	brs := NewBranchRecoveryState(2, accountStore)
	rs.branchStates[bs] = brs

	// Trigger expansion requirement.
	brs.ReportFound(0)

	// Mock DeriveAddr error.
	accountStore.On(
		"DeriveAddr", uint32(0), uint32(0), uint32(0),
	).Return(nil, nil, errFetch).Once()

	_, err := rs.expandHorizons()
	require.ErrorIs(t, err, errFetch)
}

// TestInitializeWithState verifies Initialize with existing state.
func TestInitializeWithState(t *testing.T) {
	t.Parallel()

	addrMgr := &bwmock.AddrStore{}
	defer addrMgr.AssertExpectations(t)

	rs := NewRecoveryState(10, nil, addrMgr)

	// Mock address and outpoint.
	addr := &bwmock.Address{}
	addr.On("EncodeAddress").Return("addr1")

	outpoint := wtxmgr.Credit{
		OutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0},
		PkScript: []byte{1},
	}

	err := rs.Initialize(
		nil, []btcutil.Address{addr}, []wtxmgr.Credit{outpoint},
	)
	require.NoError(t, err)
	require.Len(t, rs.addrFilters, 1)
	require.Len(t, rs.outpoints, 1)
}

// TestProcessBlockError verifies that ProcessBlock propagates errors from
// expandHorizons.
func TestProcessBlockError(t *testing.T) {
	t.Parallel()

	store := &bwmock.AccountStore{}
	defer store.AssertExpectations(t)

	rs := NewRecoveryState(10, &chainParams, nil)
	rs.addrFilters = make(map[string]AddrEntry)
	rs.outpoints = make(map[wire.OutPoint][]byte)

	// Setup branch.
	bs := waddrmgr.BranchScope{Branch: 0}
	brs := NewBranchRecoveryState(10, store)
	rs.branchStates[bs] = brs

	// Add filter entry that triggers expansion (using real address for
	// txscript compatibility).
	realAddr, _ := btcutil.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	rs.addrFilters[realAddr.EncodeAddress()] = AddrEntry{
		Address: realAddr,
		addrScope: waddrmgr.AddrScope{
			BranchScope: bs, Index: 0,
		},
		IsLookahead: true,
	}

	// Block with tx paying to realAddr.
	block := wire.NewMsgBlock(&wire.BlockHeader{})
	tx := wire.NewMsgTx(2)
	txOut := wire.NewTxOut(1000, nil)

	var err error

	txOut.PkScript, err = txscript.PayToAddrScript(realAddr)
	require.NoError(t, err)
	tx.AddTxOut(txOut)
	_ = block.AddTransaction(tx)

	// Mock failure.
	store.On("DeriveAddr", uint32(0), uint32(0), uint32(0)).Return(
		nil, nil, errFetch).Once()

	_, err = rs.ProcessBlock(block)
	require.ErrorIs(t, err, errFetch)
}
