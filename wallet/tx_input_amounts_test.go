// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// inputsWithCount returns a slice of the requested number of placeholder
// inputs. Only its length matters to the validator, which compares it against
// the number of values a source supplied.
func inputsWithCount(count int) []*wire.TxIn {
	inputs := make([]*wire.TxIn, count)
	for i := range count {
		inputs[i] = &wire.TxIn{}
	}

	return inputs
}

// TestAddInputAmounts verifies that the wallet's checked addition reports an
// overflow instead of wrapping, and otherwise returns the plain sum.
func TestAddInputAmounts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		a       btcutil.Amount
		b       btcutil.Amount
		want    btcutil.Amount
		wantErr error
	}{{
		name: "two ordinary amounts sum",
		a:    1e8,
		b:    2e8,
		want: 3e8,
	}, {
		name: "a zero addend leaves the total alone",
		a:    1e8,
		b:    0,
		want: 1e8,
	}, {
		// The bound belongs to checkInputResult, which sees the whole
		// set. Addition only refuses to wrap.
		name: "a sum above the maximum is not itself an error",
		a:    btcutil.MaxSatoshi,
		b:    btcutil.MaxSatoshi,
		want: 2 * btcutil.MaxSatoshi,
	}, {
		name:    "a positive overflow is reported",
		a:       math.MaxInt64,
		b:       1,
		wantErr: errInputAmountOverflow,
	}, {
		name:    "a negative overflow is reported",
		a:       math.MinInt64,
		b:       -1,
		wantErr: errInputAmountOverflow,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := addInputAmounts(tc.a, tc.b)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Zero(t, got)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestCheckInputResult verifies that the validator accepts a bounded,
// internally consistent result and names the specific violation in every other
// case.
func TestCheckInputResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		total      btcutil.Amount
		inputCount int
		values     []btcutil.Amount
		wantErr    error
	}{{
		name:       "a consistent result is accepted",
		total:      3e8,
		inputCount: 2,
		values:     []btcutil.Amount{1e8, 2e8},
	}, {
		// A source with nothing to give reports a total below the
		// target rather than a malformed result.
		name:       "an empty result totalling zero is accepted",
		total:      0,
		inputCount: 0,
		values:     []btcutil.Amount{},
	}, {
		name:       "a nil value set alongside no inputs is accepted",
		total:      0,
		inputCount: 0,
		values:     nil,
	}, {
		name:       "a result summing to the maximum is accepted",
		total:      btcutil.MaxSatoshi,
		inputCount: 2,
		values: []btcutil.Amount{
			btcutil.MaxSatoshi - 1e8, 1e8,
		},
	}, {
		name:       "fewer values than inputs is rejected",
		total:      1e8,
		inputCount: 2,
		values:     []btcutil.Amount{1e8},
		wantErr:    errInputCountMismatch,
	}, {
		name:       "more values than inputs is rejected",
		total:      2e8,
		inputCount: 1,
		values:     []btcutil.Amount{1e8, 1e8},
		wantErr:    errInputCountMismatch,
	}, {
		name:       "a negative reported total is rejected",
		total:      -1,
		inputCount: 1,
		values:     []btcutil.Amount{1e8},
		wantErr:    errInputTotalNegative,
	}, {
		name:       "a reported total above the maximum is rejected",
		total:      btcutil.MaxSatoshi + 1,
		inputCount: 1,
		values:     []btcutil.Amount{btcutil.MaxSatoshi + 1},
		wantErr:    errInputTotalExceedsMax,
	}, {
		name:       "a negative input value is rejected",
		total:      1e8,
		inputCount: 2,
		values:     []btcutil.Amount{2e8, -1e8},
		wantErr:    errInputValueNegative,
	}, {
		name:       "an input value above the maximum is rejected",
		total:      btcutil.MaxSatoshi,
		inputCount: 1,
		values:     []btcutil.Amount{btcutil.MaxSatoshi + 1},
		wantErr:    errInputValueExceedsMax,
	}, {
		// Every value is individually payable, but the set is not. The
		// reported total is bounded so that the aggregate is what the
		// check has left to catch.
		name: "individually valid values summing above the " +
			"maximum are rejected",
		total:      btcutil.MaxSatoshi,
		inputCount: 2,
		values: []btcutil.Amount{
			btcutil.MaxSatoshi, btcutil.MaxSatoshi,
		},
		wantErr: errInputTotalExceedsMax,
	}, {
		// Left unchecked, this is the result that funds change out of
		// value the source never supplied.
		name:       "an over-reported total is rejected",
		total:      1e8,
		inputCount: 1,
		values:     []btcutil.Amount{1e6},
		wantErr:    errInputTotalMismatch,
	}, {
		name:       "an under-reported total is rejected",
		total:      1e6,
		inputCount: 2,
		values:     []btcutil.Amount{1e6, 1e6},
		wantErr:    errInputTotalMismatch,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := checkInputResult(
				tc.total, inputsWithCount(tc.inputCount),
				tc.values,
			)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

// TestCheckInputSource verifies that the decorator passes a sound result and a
// source's own error through untouched, and that it replaces a malformed result
// with the violation rather than letting any of it reach a caller.
func TestCheckInputSource(t *testing.T) {
	t.Parallel()

	scripts := [][]byte{{0x01}, {0x02}}

	t.Run("a nil source stays nil", func(t *testing.T) {
		t.Parallel()

		require.Nil(t, checkInputSource(nil))
	})

	t.Run("a sound result passes through", func(t *testing.T) {
		t.Parallel()

		var gotTarget btcutil.Amount

		source := func(target btcutil.Amount) (btcutil.Amount,
			[]*wire.TxIn, []btcutil.Amount, [][]byte, error) {

			gotTarget = target

			return 3e8, inputsWithCount(2),
				[]btcutil.Amount{1e8, 2e8}, scripts, nil
		}

		total, inputs, values, gotScripts, err := checkInputSource(
			source,
		)(5e7)

		require.NoError(t, err)
		require.Equal(t, btcutil.Amount(5e7), gotTarget)
		require.Equal(t, btcutil.Amount(3e8), total)
		require.Len(t, inputs, 2)
		require.Equal(t, []btcutil.Amount{1e8, 2e8}, values)
		require.Equal(t, scripts, gotScripts)
	})

	t.Run("a malformed result is refused", func(t *testing.T) {
		t.Parallel()

		source := func(btcutil.Amount) (btcutil.Amount, []*wire.TxIn,
			[]btcutil.Amount, [][]byte, error) {

			return 1e8, inputsWithCount(1),
				[]btcutil.Amount{1e6}, scripts[:1], nil
		}

		total, inputs, values, gotScripts, err := checkInputSource(
			source,
		)(1e8)

		require.ErrorIs(t, err, errInputTotalMismatch)

		// Nothing the source claimed survives the refusal, so a caller
		// that ignores the error cannot act on the amounts anyway.
		require.Zero(t, total)
		require.Nil(t, inputs)
		require.Nil(t, values)
		require.Nil(t, gotScripts)
	})

	t.Run("a source error is not replaced", func(t *testing.T) {
		t.Parallel()

		sourceErr := errors.New("store is unavailable")

		// The result accompanying the error is malformed. It must not
		// be inspected, so the source's own error is what surfaces.
		source := func(btcutil.Amount) (btcutil.Amount, []*wire.TxIn,
			[]btcutil.Amount, [][]byte, error) {

			return -1, nil, []btcutil.Amount{-1}, nil, sourceErr
		}

		_, _, _, _, err := checkInputSource(source)(1e8)

		require.ErrorIs(t, err, sourceErr)
		require.NotErrorIs(t, err, errInputTotalNegative)
	})
}
