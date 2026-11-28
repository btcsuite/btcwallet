// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txauthor

import (
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

const (
	// maxAmount is the largest representable output or fee amount.
	maxAmount = btcutil.Amount(btcutil.MaxSatoshi)

	// maxInt64Amount and minInt64Amount are the arithmetic boundaries the
	// checked add and subtract helpers guard, independent of the consensus
	// bound above.
	maxInt64Amount = btcutil.Amount(math.MaxInt64)
	minInt64Amount = btcutil.Amount(math.MinInt64)
)

// TestAddAmounts verifies that the checked addition helper reports an overflow
// instead of wrapping, in both directions.
func TestAddAmounts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		a       btcutil.Amount
		b       btcutil.Amount
		want    btcutil.Amount
		wantErr bool
	}{{
		name: "two positive amounts",
		a:    1e8,
		b:    2e8,
		want: 3e8,
	}, {
		name: "adding zero is the identity",
		a:    maxInt64Amount,
		b:    0,
		want: maxInt64Amount,
	}, {
		name: "a negative addend reduces the sum",
		a:    3e8,
		b:    -1e8,
		want: 2e8,
	}, {
		name: "the largest representable sum",
		a:    maxInt64Amount - 1,
		b:    1,
		want: maxInt64Amount,
	}, {
		name:    "positive overflow",
		a:       maxInt64Amount,
		b:       1,
		wantErr: true,
	}, {
		name:    "negative overflow",
		a:       minInt64Amount,
		b:       -1,
		wantErr: true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := addAmounts(tc.a, tc.b)

			if tc.wantErr {
				require.ErrorIs(t, err, ErrAmountOverflow)
				require.Zero(t, got)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestSubAmounts verifies that the checked subtraction helper reports an
// underflow instead of wrapping, in both directions.
func TestSubAmounts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		a       btcutil.Amount
		b       btcutil.Amount
		want    btcutil.Amount
		wantErr bool
	}{{
		name: "two positive amounts",
		a:    3e8,
		b:    1e8,
		want: 2e8,
	}, {
		name: "subtracting zero is the identity",
		a:    minInt64Amount,
		b:    0,
		want: minInt64Amount,
	}, {
		name: "a larger subtrahend yields a negative difference",
		a:    1e8,
		b:    3e8,
		want: -2e8,
	}, {
		name: "the smallest representable difference",
		a:    minInt64Amount + 1,
		b:    1,
		want: minInt64Amount,
	}, {
		name:    "negative underflow",
		a:       minInt64Amount,
		b:       1,
		wantErr: true,
	}, {
		name:    "positive underflow",
		a:       maxInt64Amount,
		b:       -1,
		wantErr: true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := subAmounts(tc.a, tc.b)

			if tc.wantErr {
				require.ErrorIs(t, err, ErrAmountUnderflow)
				require.Zero(t, got)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// outputsWithValues builds an output set carrying the given values. A negative
// count of scripts is never needed here, so every output gets the same
// throwaway script: only the values matter to the validator.
func outputsWithValues(values ...int64) []*wire.TxOut {
	outputs := make([]*wire.TxOut, 0, len(values))
	for _, value := range values {
		outputs = append(outputs, &wire.TxOut{
			Value:    value,
			PkScript: []byte{0x00},
		})
	}

	return outputs
}

// repeatedOutputs builds an output set of n elements all carrying value.
func repeatedOutputs(n int, value int64) []*wire.TxOut {
	values := make([]int64, n)
	for i := range values {
		values[i] = value
	}

	return outputsWithValues(values...)
}

// maxValueOutputsToOverflow is the smallest number of maximum-value outputs
// whose running sum leaves the int64 range. MaxSatoshi divides into MaxInt64
// just over 4392 times, so the 4393rd addition is the one that would wrap.
const maxValueOutputsToOverflow = 4393

// TestCheckOutputsAmount verifies that the output-set validator rejects a nil,
// a negative, an individually oversized, and an aggregately oversized output
// set, and returns the checked total for every set it accepts.
func TestCheckOutputsAmount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		outputs []*wire.TxOut
		want    btcutil.Amount
		wantErr error
	}{{
		// A sweep authors with no non-change outputs at all, so a nil
		// set must remain valid and total zero.
		name:    "a nil set totals zero",
		outputs: nil,
		want:    0,
	}, {
		name:    "an empty set totals zero",
		outputs: []*wire.TxOut{},
		want:    0,
	}, {
		name:    "a single output totals its own value",
		outputs: outputsWithValues(1e8),
		want:    1e8,
	}, {
		name:    "several outputs total their sum",
		outputs: outputsWithValues(1e8, 2e8, 3e8),
		want:    6e8,
	}, {
		name:    "a zero-valued output is permitted",
		outputs: outputsWithValues(0, 1e8),
		want:    1e8,
	}, {
		name:    "the maximum output value is permitted",
		outputs: outputsWithValues(btcutil.MaxSatoshi),
		want:    maxAmount,
	}, {
		name: "an aggregate at exactly the maximum is permitted",
		outputs: outputsWithValues(
			btcutil.MaxSatoshi-1e8, 1e8,
		),
		want: maxAmount,
	}, {
		name:    "a nil element is rejected",
		outputs: []*wire.TxOut{{Value: 1e8}, nil},
		wantErr: ErrNilOutput,
	}, {
		name:    "a negative value is rejected",
		outputs: outputsWithValues(1e8, -1),
		wantErr: ErrOutputValueNegative,
	}, {
		name:    "a value above the maximum is rejected",
		outputs: outputsWithValues(btcutil.MaxSatoshi + 1),
		wantErr: ErrOutputValueExceedsMax,
	}, {
		// Each element is individually valid; only their sum is not.
		name: "an aggregate above the maximum is rejected",
		outputs: outputsWithValues(
			btcutil.MaxSatoshi, btcutil.MaxSatoshi,
		),
		wantErr: ErrOutputTotalExceedsMax,
	}, {
		name: "an aggregate one satoshi above the maximum is rejected",
		outputs: outputsWithValues(
			btcutil.MaxSatoshi-1e8, 1e8+1,
		),
		wantErr: ErrOutputTotalExceedsMax,
	}, {
		// Enough maximum-value outputs to wrap the accumulator if the
		// aggregate bound were applied to the finished sum instead of
		// before each addition. The set must still be refused for the
		// bound it exceeds, not for an arithmetic overflow.
		name: "a set large enough to wrap the sum reports the bound",
		outputs: repeatedOutputs(
			maxValueOutputsToOverflow, btcutil.MaxSatoshi,
		),
		wantErr: ErrOutputTotalExceedsMax,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := CheckOutputsAmount(tc.outputs)

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

// TestCheckedFeeForSerializeSize verifies that the checked fee helper rejects a
// non-positive rate and a negative size before multiplying, reports a product
// overflow, and refuses a rounded fee outside the representable range instead
// of clamping it.
func TestCheckedFeeForSerializeSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rate    btcutil.Amount
		size    int
		want    btcutil.Amount
		wantErr error
	}{{
		name: "an ordinary rate and size",
		rate: 1e3,
		size: 1000,
		want: 1e3,
	}, {
		// 2550 * 1234 is 3,146,700, so the division leaves a remainder
		// of 700 that is dropped rather than rounded up.
		name: "a fractional fee truncates toward zero",
		rate: 2.55e3,
		size: 1234,
		want: 3146,
	}, {
		// The smallest rate a caller may pass. Its product rounds down
		// to zero, so the one-kilo-virtual-byte floor charges the rate
		// itself.
		name: "the smallest valid positive rate",
		rate: 1,
		size: 100,
		want: 1,
	}, {
		name: "a zero size is charged the rate floor",
		rate: 1e3,
		size: 0,
		want: 1e3,
	}, {
		name: "a fee at exactly the maximum",
		rate: maxAmount,
		size: feeRateDivisor,
		want: maxAmount,
	}, {
		name:    "a zero rate is rejected",
		rate:    0,
		size:    1000,
		wantErr: ErrFeeRateNotPositive,
	}, {
		name:    "a negative rate is rejected",
		rate:    -1,
		size:    1000,
		wantErr: ErrFeeRateNotPositive,
	}, {
		name:    "a product overflow is rejected",
		rate:    maxInt64Amount / 2,
		size:    4,
		wantErr: ErrFeeOverflow,
	}, {
		// The product is representable but the fee it rounds to is not
		// a valid amount, so it is reported rather than clamped.
		name:    "a rounded fee above the maximum is rejected",
		rate:    maxAmount,
		size:    feeRateDivisor + 1,
		wantErr: ErrFeeOutOfRange,
	}, {
		// Rejected by its own guard, before the multiplication, rather
		// than incidentally by the final bound on a negative fee.
		name:    "a negative size is rejected",
		rate:    1e3,
		size:    -1000,
		wantErr: ErrFeeOutOfRange,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := CheckedFeeForSerializeSize(tc.rate, tc.size)

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
