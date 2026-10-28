// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txauthor

import (
	"math"
	"slices"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/stretchr/testify/require"
)

func p2pkhOutputs(amounts ...btcutil.Amount) []*wire.TxOut {
	v := make([]*wire.TxOut, 0, len(amounts))
	for _, a := range amounts {
		outScript := make([]byte, txsizes.P2PKHOutputSize)
		v = append(v, wire.NewTxOut(int64(a), outScript))
	}
	return v
}

func makeInputSource(unspents []*wire.TxOut) InputSource {
	// Return outputs in order.
	currentTotal := btcutil.Amount(0)
	currentInputs := make([]*wire.TxIn, 0, len(unspents))
	currentInputValues := make([]btcutil.Amount, 0, len(unspents))
	f := func(target btcutil.Amount) (btcutil.Amount, []*wire.TxIn, []btcutil.Amount, [][]byte, error) {
		for currentTotal < target && len(unspents) != 0 {
			u := unspents[0]
			unspents = unspents[1:]
			nextInput := wire.NewTxIn(&wire.OutPoint{}, nil, nil)
			currentTotal += btcutil.Amount(u.Value)
			currentInputs = append(currentInputs, nextInput)
			currentInputValues = append(currentInputValues, btcutil.Amount(u.Value))
		}
		return currentTotal, currentInputs, currentInputValues, make([][]byte, len(currentInputs)), nil
	}
	return InputSource(f)
}

func TestNewUnsignedTransaction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		UnspentOutputs   []*wire.TxOut
		Outputs          []*wire.TxOut
		RelayFee         btcutil.Amount
		ChangeAmount     btcutil.Amount
		InputSourceError bool
		InputCount       int
	}{
		0: {
			UnspentOutputs:   p2pkhOutputs(1e8),
			Outputs:          p2pkhOutputs(1e8),
			RelayFee:         1e3,
			InputSourceError: true,
		},
		1: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs:        p2pkhOutputs(1e6),
			RelayFee:       1e3,
			ChangeAmount: 1e8 - 1e6 - txrules.FeeForSerializeSize(1e3,
				txsizes.EstimateVirtualSize(1, 0, 0, 0, p2pkhOutputs(1e6), txsizes.P2WPKHPkScriptSize)),
			InputCount: 1,
		},
		2: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs:        p2pkhOutputs(1e6),
			RelayFee:       1e4,
			ChangeAmount: 1e8 - 1e6 - txrules.FeeForSerializeSize(1e4,
				txsizes.EstimateVirtualSize(1, 0, 0, 0, p2pkhOutputs(1e6), txsizes.P2WPKHPkScriptSize)),
			InputCount: 1,
		},
		3: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs:        p2pkhOutputs(1e6, 1e6, 1e6),
			RelayFee:       1e4,
			ChangeAmount: 1e8 - 3e6 - txrules.FeeForSerializeSize(1e4,
				txsizes.EstimateVirtualSize(1, 0, 0, 0, p2pkhOutputs(1e6, 1e6, 1e6), txsizes.P2WPKHPkScriptSize)),
			InputCount: 1,
		},
		4: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs:        p2pkhOutputs(1e6, 1e6, 1e6),
			RelayFee:       2.55e3,
			ChangeAmount: 1e8 - 3e6 - txrules.FeeForSerializeSize(2.55e3,
				txsizes.EstimateVirtualSize(1, 0, 0, 0, p2pkhOutputs(1e6, 1e6, 1e6), txsizes.P2WPKHPkScriptSize)),
			InputCount: 1,
		},

		// Test dust thresholds (546 for a 1e3 relay fee).
		5: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs: p2pkhOutputs(1e8 - 545 - txrules.FeeForSerializeSize(1e3,
				txsizes.EstimateVirtualSize(1, 0, 0, 0, p2pkhOutputs(0), txsizes.P2WPKHPkScriptSize))),
			RelayFee:     1e3,
			ChangeAmount: 545,
			InputCount:   1,
		},
		6: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs: p2pkhOutputs(1e8 - 546 - txrules.FeeForSerializeSize(1e3,
				txsizes.EstimateVirtualSize(1, 0, 0, 0, p2pkhOutputs(0), txsizes.P2WPKHPkScriptSize))),
			RelayFee:     1e3,
			ChangeAmount: 546,
			InputCount:   1,
		},

		// Test dust thresholds (1392.3 for a 2.55e3 relay fee).
		7: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs: p2pkhOutputs(1e8 - 1392 - txrules.FeeForSerializeSize(2.55e3,
				txsizes.EstimateVirtualSize(1, 0, 0, 0, p2pkhOutputs(0), txsizes.P2WPKHPkScriptSize))),
			RelayFee:     2.55e3,
			ChangeAmount: 1392,
			InputCount:   1,
		},
		8: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs: p2pkhOutputs(1e8 - 1393 - txrules.FeeForSerializeSize(2.55e3,
				txsizes.EstimateVirtualSize(1, 0, 0, 0, p2pkhOutputs(0), txsizes.P2WPKHPkScriptSize))),
			RelayFee:     2.55e3,
			ChangeAmount: 1393,
			InputCount:   1,
		},

		// Test two unspent outputs available but only one needed
		// (tested fee only includes one input rather than using a
		// serialize size for each).
		9: {
			UnspentOutputs: p2pkhOutputs(1e8, 1e8),
			Outputs: p2pkhOutputs(1e8 - 546 - txrules.FeeForSerializeSize(1e3,
				txsizes.EstimateVirtualSize(1, 0, 0, 0, p2pkhOutputs(0), txsizes.P2WPKHPkScriptSize))),
			RelayFee:     1e3,
			ChangeAmount: 546,
			InputCount:   1,
		},

		// Test that second output is not included to make the change
		// output not dust and be included in the transaction.
		//
		// It's debatable whether or not this is a good idea, but it's
		// how the function was written, so test it anyways.
		10: {
			UnspentOutputs: p2pkhOutputs(1e8, 1e8),
			Outputs: p2pkhOutputs(1e8 - 545 - txrules.FeeForSerializeSize(1e3,
				txsizes.EstimateVirtualSize(1, 0, 0, 0, p2pkhOutputs(0), txsizes.P2WPKHPkScriptSize))),
			RelayFee:     1e3,
			ChangeAmount: 545,
			InputCount:   1,
		},

		// Test two unspent outputs available where both are needed.
		11: {
			UnspentOutputs: p2pkhOutputs(1e8, 1e8),
			Outputs:        p2pkhOutputs(1e8),
			RelayFee:       1e3,
			ChangeAmount: 1e8 - txrules.FeeForSerializeSize(1e3,
				txsizes.EstimateVirtualSize(2, 0, 0, 0, p2pkhOutputs(1e8), txsizes.P2WPKHPkScriptSize)),
			InputCount: 2,
		},

		// Test that zero change outputs are not included
		// (ChangeAmount=0 means don't include any change output). The
		// single unspent output covers the payment and the maximum
		// required fee exactly, leaving nothing over.
		12: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs: p2pkhOutputs(1e8 - txrules.FeeForSerializeSize(1e3,
				txsizes.EstimateVirtualSize(1, 0, 0, 0, p2pkhOutputs(0), txsizes.P2WPKHPkScriptSize))),
			RelayFee:     1e3,
			ChangeAmount: 0,
			InputCount:   1,
		},
	}

	changeSource := &ChangeSource{
		NewScript: func() ([]byte, error) {
			// Only length matters for these tests.
			return make([]byte, txsizes.P2WPKHPkScriptSize), nil
		},
		ScriptSize: txsizes.P2WPKHPkScriptSize,
	}

	for i, test := range tests {
		inputSource := makeInputSource(test.UnspentOutputs)
		tx, err := NewUnsignedTransaction(test.Outputs, test.RelayFee, inputSource, changeSource)
		switch e := err.(type) {
		case nil:
		case InputSourceError:
			if !test.InputSourceError {
				t.Errorf("Test %d: Returned InputSourceError but expected "+
					"change output with amount %v", i, test.ChangeAmount)
			}
			continue
		default:
			t.Errorf("Test %d: Unexpected error: %v", i, e)
			continue
		}
		if tx.ChangeIndex < 0 {
			if test.ChangeAmount != 0 {
				t.Errorf("Test %d: No change output added but expected output with amount %v",
					i, test.ChangeAmount)
				continue
			}
		} else {
			changeAmount := btcutil.Amount(tx.Tx.TxOut[tx.ChangeIndex].Value)
			if test.ChangeAmount == 0 {
				t.Errorf("Test %d: Included change output with value %v but expected no change",
					i, changeAmount)
				continue
			}
			if changeAmount != test.ChangeAmount {
				t.Errorf("Test %d: Got change amount %v, Expected %v",
					i, changeAmount, test.ChangeAmount)
				continue
			}
		}
		if len(tx.Tx.TxIn) != test.InputCount {
			t.Errorf("Test %d: Used %d outputs from input source, Expected %d",
				i, len(tx.Tx.TxIn), test.InputCount)
		}
	}
}

// p2wpkhScript returns a well-formed pay-to-witness-pubkey-hash script. An
// input redeeming this script is sized identically to the one the initial fee
// estimate assumes, so construction settles on a fee in a single pass.
func p2wpkhScript() []byte {
	script := make([]byte, txsizes.P2WPKHPkScriptSize)
	script[0] = txscript.OP_0
	script[1] = txscript.OP_DATA_20

	return script
}

// countedSources bundles an input source and a change source with the tally of
// how often each was invoked, so a test can prove a request was rejected before
// either callback ran.
type countedSources struct {
	// input funds the requested target plus surplus.
	input InputSource

	// change hands out a fixed P2WPKH-sized script.
	change *ChangeSource

	// inputCalls and changeCalls count invocations of the two callbacks.
	inputCalls  int
	changeCalls int
}

// newCountedSources builds a counted input and change source pair whose input
// source funds the requested target plus surplus. A surplus of zero leaves
// nothing over for change; anything above the dust threshold produces a change
// output carrying exactly that amount.
func newCountedSources(t *testing.T, surplus btcutil.Amount) *countedSources {
	t.Helper()

	s := &countedSources{}

	s.input = func(target btcutil.Amount) (btcutil.Amount, []*wire.TxIn,
		[]btcutil.Amount, [][]byte, error) {

		s.inputCalls++

		total := target + surplus

		return total, []*wire.TxIn{{}}, []btcutil.Amount{total},
			[][]byte{p2wpkhScript()}, nil
	}

	s.change = &ChangeSource{
		NewScript: func() ([]byte, error) {
			s.changeCalls++

			return make([]byte, txsizes.P2WPKHPkScriptSize), nil
		},
		ScriptSize: txsizes.P2WPKHPkScriptSize,
	}

	return s
}

// TestNewUnsignedTransactionChecksAmounts verifies that a malformed output set
// or fee rate is refused by transaction construction, and that the refusal
// happens before either the input source or the change source is consulted.
func TestNewUnsignedTransactionChecksAmounts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		outputs  []*wire.TxOut
		relayFee btcutil.Amount
		wantErr  error
	}{{
		name:     "a zero fee rate is rejected",
		outputs:  p2pkhOutputs(1e6),
		relayFee: 0,
		wantErr:  ErrFeeRateNotPositive,
	}, {
		name:     "a negative fee rate is rejected",
		outputs:  p2pkhOutputs(1e6),
		relayFee: -1e3,
		wantErr:  ErrFeeRateNotPositive,
	}, {
		name:     "a nil output is rejected",
		outputs:  []*wire.TxOut{nil},
		relayFee: 1e3,
		wantErr:  ErrNilOutput,
	}, {
		name:     "a negative output value is rejected",
		outputs:  p2pkhOutputs(-1),
		relayFee: 1e3,
		wantErr:  ErrOutputValueNegative,
	}, {
		name:     "an output above the maximum is rejected",
		outputs:  p2pkhOutputs(btcutil.MaxSatoshi + 1),
		relayFee: 1e3,
		wantErr:  ErrOutputValueExceedsMax,
	}, {
		name: "an output set summing above the maximum is rejected",
		outputs: p2pkhOutputs(
			btcutil.MaxSatoshi-1e8, 1e8+1,
		),
		relayFee: 1e3,
		wantErr:  ErrOutputTotalExceedsMax,
	}, {
		// The rounded fee this rate implies cannot be represented, so
		// it is reported rather than silently clamped to the maximum.
		name:     "an unrepresentable rounded fee is rejected",
		outputs:  p2pkhOutputs(1e6),
		relayFee: 2e16,
		wantErr:  ErrFeeOutOfRange,
	}, {
		// This rate does not even survive multiplication by the size.
		name:     "a fee product overflow is rejected",
		outputs:  p2pkhOutputs(1e6),
		relayFee: math.MaxInt64 / 2,
		wantErr:  ErrFeeOverflow,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sources := newCountedSources(t, 0)

			tx, err := NewUnsignedTransaction(
				tc.outputs, tc.relayFee, sources.input,
				sources.change,
			)

			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, tx)
			require.Zero(t, sources.inputCalls)
			require.Zero(t, sources.changeCalls)

			// SelectInputs owns these checks, so calling it directly
			// must refuse the request just as early.
			selection, err := SelectInputs(
				tc.outputs, tc.relayFee, sources.input,
				ChangeScriptInfo{
					ScriptSize: uint(sources.change.ScriptSize),
				},
			)

			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, selection)
			require.Zero(t, sources.inputCalls)
		})
	}
}

// TestSelectInputsRejectsOversizedChangeScript verifies that a change script
// size larger than any valid script is refused before the input source is
// consulted, instead of being converted to a fee size or allocated.
func TestSelectInputsRejectsOversizedChangeScript(t *testing.T) {
	t.Parallel()

	sources := newCountedSources(t, 50_000)

	selection, err := SelectInputs(
		p2pkhOutputs(1e6), 1e3, sources.input,
		ChangeScriptInfo{ScriptSize: txscript.MaxScriptSize + 1},
	)

	require.ErrorIs(t, err, errChangeScriptSizeOutOfRange)
	require.Nil(t, selection)
	require.Zero(t, sources.inputCalls)
}

// TestNewUnsignedTransactionRejectsNegativeChangeScriptSize verifies that a
// ChangeSource declaring a negative script size is refused before either
// callback runs, since no change script has a negative size.
func TestNewUnsignedTransactionRejectsNegativeChangeScriptSize(t *testing.T) {
	t.Parallel()

	sources := newCountedSources(t, 50_000)
	sources.change.ScriptSize = -1

	tx, err := NewUnsignedTransaction(
		p2pkhOutputs(1e6), 1e3, sources.input, sources.change,
	)

	require.ErrorIs(t, err, errChangeScriptSizeOutOfRange)
	require.Nil(t, tx)
	require.Zero(t, sources.inputCalls)
	require.Zero(t, sources.changeCalls)
}

// TestNewUnsignedTransactionSweep verifies the change-only authoring a sweep
// performs: it declares no non-change outputs, so the checked output set must
// accept a nil slice, and everything the inputs carry beyond the fee must come
// back as a single change output.
func TestNewUnsignedTransactionSweep(t *testing.T) {
	t.Parallel()

	// Fund well clear of the dust threshold, so the surplus survives as a
	// change output rather than being absorbed into the fee.
	const surplus = btcutil.Amount(50_000)

	sources := newCountedSources(t, surplus)

	tx, err := NewUnsignedTransaction(nil, 1e3, sources.input, sources.change)
	require.NoError(t, err)
	require.NotNil(t, tx)
	require.Equal(t, 1, sources.inputCalls)
	require.Equal(t, 1, sources.changeCalls)

	// The sweep's only output is the change, so it takes index zero and
	// carries the whole surplus.
	require.Equal(t, 0, tx.ChangeIndex)
	require.Len(t, tx.Tx.TxOut, 1)
	require.Equal(t, int64(surplus), tx.Tx.TxOut[0].Value)
	require.Len(t, tx.Tx.TxOut[0].PkScript, txsizes.P2WPKHPkScriptSize)
}

// TestNewUnsignedTransactionNoChange verifies that a nil output set funded to
// exactly the fee authors without appending a zero-valued change output.
func TestNewUnsignedTransactionNoChange(t *testing.T) {
	t.Parallel()

	sources := newCountedSources(t, 0)

	tx, err := NewUnsignedTransaction(nil, 1e3, sources.input, sources.change)
	require.NoError(t, err)
	require.NotNil(t, tx)
	require.Equal(t, 1, sources.inputCalls)

	// A ChangeSource cannot say whether its scripts are witness programs,
	// so NewUnsignedTransaction draws the script before the dust rule can
	// judge it. Callers that must not commit dropped change use
	// InputSelection.NeedsChangeScript instead.
	require.Equal(t, 1, sources.changeCalls)

	// The input source funds exactly the requested target, which is the fee
	// alone, so there is nothing left over to pay out as change.
	require.Equal(t, -1, tx.ChangeIndex)
	require.Empty(t, tx.Tx.TxOut)
}

// TestNewUnsignedTransactionJudgesChangeScript verifies that the legacy wrapper
// judges change by the relay policy on the script its ChangeSource returns, not
// by the script's size and witness status alone. Unspendable and data carrier
// scripts are where the two disagree, and the wrapper must keep its relay
// policy behavior for them.
func TestNewUnsignedTransactionJudgesChangeScript(t *testing.T) {
	t.Parallel()

	// malformedPush declares a 75-byte push that the script cannot hold, so
	// it is unspendable at a P2WPKH script's size.
	malformedPush := make([]byte, txsizes.P2WPKHPkScriptSize)
	malformedPush[0] = txscript.OP_DATA_75

	tests := []struct {
		name       string
		script     []byte
		surplus    btcutil.Amount
		wantChange bool
	}{
		{
			name:    "unspendable change dropped",
			script:  malformedPush,
			surplus: 50_000,
		},
		{
			name:       "data carrier change kept",
			script:     []byte{txscript.OP_RETURN},
			surplus:    1,
			wantChange: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Fund the surplus and hand out the row's change
			// script.
			sources := newCountedSources(t, test.surplus)
			sources.change.NewScript = func() ([]byte, error) {
				return test.script, nil
			}

			// Act: Author a sweep, whose only possible output is the
			// change.
			tx, err := NewUnsignedTransaction(
				nil, 1e3, sources.input, sources.change,
			)

			// Assert: Change is kept exactly when the relay policy
			// accepts the script's output.
			require.NoError(t, err)
			require.Equal(
				t, txrules.IsDustOutput(
					wire.NewTxOut(int64(test.surplus), test.script),
					txrules.DefaultRelayFeePerKb,
				), !test.wantChange,
			)

			if !test.wantChange {
				require.Equal(t, -1, tx.ChangeIndex)
				require.Empty(t, tx.Tx.TxOut)

				return
			}

			require.Equal(t, 0, tx.ChangeIndex)
			require.Equal(
				t, wire.NewTxOut(int64(test.surplus), test.script),
				tx.Tx.TxOut[0],
			)
		})
	}
}

// TestInputSelectionComplete verifies that completing a selection keeps the
// caller's change script only when the leftover value survives the dust rules,
// and that completion never grows the caller's output slice in place.
func TestInputSelectionComplete(t *testing.T) {
	t.Parallel()

	changeScript := p2wpkhScript()
	changeScript[len(changeScript)-1] = 1 // Differ from input scripts.

	tests := []struct {
		name       string
		surplus    btcutil.Amount
		wantChange bool
	}{{
		name:    "zero leftover adds no change",
		surplus: 0,
	}, {
		name:    "dust leftover is added to the fee",
		surplus: 100,
	}, {
		name:       "non-dust leftover pays the change script",
		surplus:    50_000,
		wantChange: true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Select inputs for one payment whose source funds
			// the requested target plus the case's surplus. Give the
			// output slice spare capacity so an in-place append would be
			// observable.
			sources := newCountedSources(t, tc.surplus)
			outputs := make([]*wire.TxOut, 1, 2)
			outputs[0] = p2pkhOutputs(1e6)[0]

			selection, err := SelectInputs(
				outputs, 1e3, sources.input,
				NewChangeScriptInfo(changeScript),
			)
			require.NoError(t, err)
			require.Equal(t, 1, sources.inputCalls)

			// Act: Complete the selection with the caller's script.
			tx, err := selection.Complete(changeScript)

			// Assert: The change decision matches the result, the
			// inputs are carried over, and the caller's output slice
			// keeps its original element.
			require.NoError(t, err)
			require.Equal(t, tc.wantChange, selection.NeedsChangeScript())
			require.Len(t, tx.Tx.TxIn, 1)
			require.Len(t, tx.PrevScripts, 1)
			require.Equal(t, tx.PrevInputValues[0], tx.TotalInput)
			require.Nil(t, outputs[:cap(outputs)][1])

			if !tc.wantChange {
				require.Equal(t, -1, tx.ChangeIndex)
				require.Len(t, tx.Tx.TxOut, 1)

				return
			}

			// Kept change is appended after the payment and carries the
			// exact surplus to the caller's script.
			require.Equal(t, 1, tx.ChangeIndex)
			require.Len(t, tx.Tx.TxOut, 2)
			change := tx.Tx.TxOut[tx.ChangeIndex]
			require.Equal(t, int64(tc.surplus), change.Value)
			require.Equal(t, changeScript, change.PkScript)
		})
	}
}

// TestInputSelectionCompleteWithoutChange verifies that a selection that keeps
// no change completes without a change script, so a caller never has to commit
// one for change that is dropped.
func TestInputSelectionCompleteWithoutChange(t *testing.T) {
	t.Parallel()

	// Arrange: Leave a dust surplus for P2WPKH change.
	sources := newCountedSources(t, 100)
	selection, err := SelectInputs(
		p2pkhOutputs(1e6), 1e3, sources.input,
		NewChangeScriptInfo(p2wpkhScript()),
	)
	require.NoError(t, err)

	// Act: Complete the selection without a change script.
	tx, err := selection.Complete(nil)

	// Assert: The dust surplus went to the fee and no change was added.
	require.NoError(t, err)
	require.False(t, selection.NeedsChangeScript())
	require.Equal(t, -1, tx.ChangeIndex)
	require.Len(t, tx.Tx.TxOut, 1)
}

// TestInputSelectionCompleteInfoMismatch verifies that a selection keeping
// change refuses a change script whose ChangeScriptInfo differs from the one it
// was sized and judged for, since its fee and dust decisions would not hold.
func TestInputSelectionCompleteInfoMismatch(t *testing.T) {
	t.Parallel()

	p2trScript := make([]byte, txsizes.P2TRPkScriptSize)
	p2trScript[0] = txscript.OP_1
	p2trScript[1] = txscript.OP_DATA_32

	tests := []struct {
		name         string
		changeScript []byte
	}{{
		name:         "different size",
		changeScript: p2trScript,
	}, {
		name:         "missing script",
		changeScript: nil,
	}, {
		name:         "not a witness program",
		changeScript: make([]byte, txsizes.P2WPKHPkScriptSize),
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Keep change for a P2WPKH change script.
			sources := newCountedSources(t, 50_000)
			selection, err := SelectInputs(
				p2pkhOutputs(1e6), 1e3, sources.input,
				NewChangeScriptInfo(p2wpkhScript()),
			)
			require.NoError(t, err)
			require.True(t, selection.NeedsChangeScript())

			// Act: Complete with a script of other info.
			tx, err := selection.Complete(tc.changeScript)

			// Assert: The script is refused and nothing is built.
			require.ErrorIs(t, err, ErrChangeScriptInfoMismatch)
			require.Nil(t, tx)
		})
	}
}

// TestIsDustChangeMatchesRelayPolicy verifies that judging change by its
// ChangeScriptInfo agrees with the relay policy's dust rule on real scripts.
// For each standard change script it checks the amounts on both sides of the
// boundary txrules.IsDustOutput draws, so the info-based rule cannot drift
// from it.
func TestIsDustChangeMatchesRelayPolicy(t *testing.T) {
	t.Parallel()

	hash20 := make([]byte, 20)
	hash32 := make([]byte, 32)

	scripts := map[string][]byte{
		"p2pkh": slices.Concat(
			[]byte{
				txscript.OP_DUP, txscript.OP_HASH160,
				txscript.OP_DATA_20,
			},
			hash20,
			[]byte{txscript.OP_EQUALVERIFY, txscript.OP_CHECKSIG},
		),
		"p2sh": slices.Concat(
			[]byte{txscript.OP_HASH160, txscript.OP_DATA_20}, hash20,
			[]byte{txscript.OP_EQUAL},
		),
		"p2wpkh": slices.Concat(
			[]byte{txscript.OP_0, txscript.OP_DATA_20}, hash20,
		),
		"p2wsh": slices.Concat(
			[]byte{txscript.OP_0, txscript.OP_DATA_32}, hash32,
		),
		"p2tr": slices.Concat(
			[]byte{txscript.OP_1, txscript.OP_DATA_32}, hash32,
		),
	}

	relayFee := txrules.DefaultRelayFeePerKb

	for name, script := range scripts {
		// The policy boundary is the first non-dust amount.
		boundary := btcutil.Amount(0)
		for txrules.IsDustOutput(
			wire.NewTxOut(int64(boundary), script), relayFee,
		) {
			boundary++
		}

		info := NewChangeScriptInfo(script)
		for _, amount := range []btcutil.Amount{
			boundary - 1, boundary, boundary + 1,
		} {
			want := txrules.IsDustOutput(
				wire.NewTxOut(int64(amount), script), relayFee,
			)
			require.Equal(
				t, want, isDustChange(amount, info, relayFee),
				"%s at %d", name, amount,
			)
		}
	}
}
