package wallet_test

import (
	"runtime"
	"testing"

	"github.com/btcsuite/btcwallet/wallet"
)

// Harness holds the BranchRecoveryState being tested, the recovery window being
// used, provides access to the test object, and tracks the expected horizon
// and next unfound values.
type Harness struct {
	t              *testing.T
	brs            *wallet.BranchRecoveryState
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

	brs := wallet.NewBranchRecoveryState(recoveryWindow)
	harness := &Harness{
		t:              t,
		brs:            brs,
		recoveryWindow: recoveryWindow,
	}

	for i, step := range recoverySteps {
		step.Apply(i, harness)
	}
}

func assertHorizon(t *testing.T, i int, have, want uint32) {
	assertHaveWant(t, i, "incorrect horizon", have, want)
}

func assertDelta(t *testing.T, i int, have, want uint32) {
	assertHaveWant(t, i, "incorrect delta", have, want)
}

func assertNextUnfound(t *testing.T, i int, have, want uint32) {
	assertHaveWant(t, i, "incorrect next unfound", have, want)
}

func assertNumInvalid(t *testing.T, i int, have, want uint32) {
	assertHaveWant(t, i, "incorrect num invalid children", have, want)
}

func assertHaveWant(t *testing.T, i int, msg string, have, want uint32) {
	_, _, line, _ := runtime.Caller(2)
	if want != have {
		t.Fatalf("[line: %d, step: %d] %s: got %d, want %d",
			line, i, msg, have, want)
	}
}
