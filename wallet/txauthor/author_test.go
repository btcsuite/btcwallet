// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txauthor

import (
	"math"
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
	// input funds exactly what it is asked for.
	input InputSource

	// change hands out a fixed P2WPKH-sized script.
	change *ChangeSource

	// inputCalls and changeCalls count invocations of the two callbacks.
	inputCalls  int
	changeCalls int
}

// newCountedSources builds a counted input and change source pair.
func newCountedSources(t *testing.T) *countedSources {
	t.Helper()

	s := &countedSources{}

	s.input = func(target btcutil.Amount) (btcutil.Amount, []*wire.TxIn,
		[]btcutil.Amount, [][]byte, error) {

		s.inputCalls++

		return target, []*wire.TxIn{{}}, []btcutil.Amount{target},
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

			sources := newCountedSources(t)

			tx, err := NewUnsignedTransaction(
				tc.outputs, tc.relayFee, sources.input,
				sources.change,
			)

			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, tx)
			require.Zero(t, sources.inputCalls)
			require.Zero(t, sources.changeCalls)
		})
	}
}

// TestNewUnsignedTransactionNilOutputs verifies that a transaction with no
// non-change outputs still authors. A sweep pays its entire input value to a
// single change output and declares no outputs of its own, so the checked
// output set must accept a nil slice.
func TestNewUnsignedTransactionNilOutputs(t *testing.T) {
	t.Parallel()

	sources := newCountedSources(t)

	tx, err := NewUnsignedTransaction(nil, 1e3, sources.input, sources.change)
	require.NoError(t, err)
	require.NotNil(t, tx)
	require.Equal(t, 1, sources.inputCalls)

	// The change script is allocated even though the result carries no
	// change output. That is the allocation timing Task 356 owns, not
	// something this test asserts as desirable: when 356 lands and the
	// script is only requested once a change output is known to survive,
	// this expectation becomes zero.
	require.Equal(t, 1, sources.changeCalls)

	// The input source funds exactly the requested target, which is the fee
	// alone, so there is nothing left over to pay out as change.
	require.Equal(t, -1, tx.ChangeIndex)
	require.Empty(t, tx.Tx.TxOut)
}

// TestNewUnsignedTransactionChecksInputs verifies that a result from a hostile
// or broken input source is refused, and that the refusal happens after the
// source was consulted but before any change is allocated from the value it
// claimed to supply.
func TestNewUnsignedTransactionChecksInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		total      btcutil.Amount
		inputCount int
		values     []btcutil.Amount
		wantErr    error
	}{{
		// Left unchecked, this is the result that pays change out of
		// value the source never supplied.
		name:       "an over-reported total is rejected",
		total:      1e8,
		inputCount: 1,
		values:     []btcutil.Amount{1e6},
		wantErr:    ErrInputTotalMismatch,
	}, {
		name:       "an under-reported total is rejected",
		total:      1e6,
		inputCount: 2,
		values:     []btcutil.Amount{1e6, 1e6},
		wantErr:    ErrInputTotalMismatch,
	}, {
		name:       "a negative reported total is rejected",
		total:      -1e8,
		inputCount: 1,
		values:     []btcutil.Amount{-1e8},
		wantErr:    ErrInputTotalNegative,
	}, {
		name:       "a negative input value is rejected",
		total:      1e8,
		inputCount: 2,
		values:     []btcutil.Amount{2e8, -1e8},
		wantErr:    ErrInputValueNegative,
	}, {
		name:       "an input value above the maximum is rejected",
		total:      maxAmount,
		inputCount: 1,
		values:     []btcutil.Amount{maxAmount + 1},
		wantErr:    ErrInputValueExceedsMax,
	}, {
		name:       "a value count unequal to the inputs is rejected",
		total:      2e8,
		inputCount: 1,
		values:     []btcutil.Amount{1e8, 1e8},
		wantErr:    ErrInputCountMismatch,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Fund the request from a source that answers with the
			// malformed result under test. Its inputs are scripted
			// so that nothing but the amounts is wrong.
			sources := newCountedSources(t)
			sources.input = func(btcutil.Amount) (btcutil.Amount,
				[]*wire.TxIn, []btcutil.Amount, [][]byte,
				error) {

				sources.inputCalls++

				scripts := make(
					[][]byte, len(tc.values),
				)
				for i := range scripts {
					scripts[i] = p2wpkhScript()
				}

				return tc.total, inputsWithCount(tc.inputCount),
					tc.values, scripts, nil
			}

			tx, err := NewUnsignedTransaction(
				p2pkhOutputs(1e6), 1e3, sources.input,
				sources.change,
			)

			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, tx)

			// The source was consulted once and its answer refused
			// there and then: no change was allocated against the
			// value it claimed.
			require.Equal(t, 1, sources.inputCalls)
			require.Zero(t, sources.changeCalls)
		})
	}
}

// TestNewUnsignedTransactionOutputOrigin verifies that the authored result
// records where every one of its outputs came from, both when a change output
// survives the dust check and when it does not.
func TestNewUnsignedTransactionOutputOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		outputs []*wire.TxOut

		// exactFunding funds the transaction to the satoshi, leaving
		// nothing over for a change output.
		exactFunding bool

		wantOrigin []int
	}{{
		// With nothing left over there is no change output, so
		// provenance is the caller's own order, unchanged.
		name:         "no change output",
		outputs:      p2pkhOutputs(1e6, 2e6),
		exactFunding: true,
		wantOrigin:   []int{0, 1},
	}, {
		// The input leaves a spendable remainder, so change is
		// appended after the caller's outputs and marked as ours.
		name:       "change output appended",
		outputs:    p2pkhOutputs(1e6, 2e6),
		wantOrigin: []int{0, 1, ChangeOutputOrigin},
	}, {
		name:       "single output with change",
		outputs:    p2pkhOutputs(1e6),
		wantOrigin: []int{0, ChangeOutputOrigin},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sources := newCountedSources(t)

			inputSource := sources.input
			if !tc.exactFunding {
				inputSource = makeInputSource(
					p2pkhOutputs(1e8),
				)
			}

			tx, err := NewUnsignedTransaction(
				tc.outputs, 1e3, inputSource, sources.change,
			)
			require.NoError(t, err)

			require.Equal(t, tc.wantOrigin, tx.OutputOrigin)

			// Provenance only means anything if it covers every
			// output, so the two must stay the same length.
			require.Len(t, tx.OutputOrigin, len(tx.Tx.TxOut))

			// The entry marked as ours must be the one the result
			// reports as change.
			if tx.ChangeIndex >= 0 {
				require.Equal(
					t, ChangeOutputOrigin,
					tx.OutputOrigin[tx.ChangeIndex],
				)
			} else {
				require.NotContains(
					t, tx.OutputOrigin, ChangeOutputOrigin,
				)
			}
		})
	}
}

// TestRandomizeChangePositionMovesOrigin verifies that provenance follows the
// change output through randomization, so that both the change output and each
// caller output can still be located afterwards. It repeats the randomization
// enough times to cover every landing position.
func TestRandomizeChangePositionMovesOrigin(t *testing.T) {
	t.Parallel()

	const outputCount = 4

	// A run of randomizations is needed because the change output may land
	// back on its own position; a single run would not exercise a move.
	for i := 0; i < 50; i++ {
		outputs := p2pkhOutputs(1e6, 2e6, 3e6)
		change := wire.NewTxOut(4e6, make([]byte, 22))

		tx := &AuthoredTx{
			Tx: &wire.MsgTx{
				TxOut: append(outputs, change),
			},
			ChangeIndex:  outputCount - 1,
			OutputOrigin: []int{0, 1, 2, ChangeOutputOrigin},
		}

		tx.RandomizeChangePosition()

		require.Len(t, tx.OutputOrigin, len(tx.Tx.TxOut))

		// Provenance and the reported change index must agree on which
		// output is the change.
		require.Equal(
			t, ChangeOutputOrigin, tx.OutputOrigin[tx.ChangeIndex],
		)
		require.Equal(
			t, change, tx.Tx.TxOut[tx.ChangeIndex],
		)

		// Every caller output must still be reachable through its
		// recorded origin, and no origin may be duplicated or lost.
		seen := make(map[int]bool, outputCount)
		for pos, origin := range tx.OutputOrigin {
			require.False(t, seen[origin])
			seen[origin] = true

			if origin == ChangeOutputOrigin {
				continue
			}

			require.Equal(
				t, outputs[origin], tx.Tx.TxOut[pos],
			)
		}
		require.Len(t, seen, outputCount)
	}
}

// TestRandomizeChangePositionWithoutOrigin verifies that an AuthoredTx built
// by hand, without provenance, still randomizes rather than panicking. Callers
// outside this package construct such values in their own tests.
func TestRandomizeChangePositionWithoutOrigin(t *testing.T) {
	t.Parallel()

	tx := &AuthoredTx{
		Tx: &wire.MsgTx{
			TxOut: p2pkhOutputs(1e6, 2e6),
		},
		ChangeIndex: 1,
	}

	require.NotPanics(t, tx.RandomizeChangePosition)
	require.Empty(t, tx.OutputOrigin)
	require.GreaterOrEqual(t, tx.ChangeIndex, 0)
}
