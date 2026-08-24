// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txauthor

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// feeRateDivisor is the number of virtual bytes a fee rate is quoted per. Fee
// rates are expressed in satoshis per kilo-virtual-byte, so the fee for a given
// size is the rate-by-size product divided by this value.
const feeRateDivisor = 1000

// Amount arithmetic violations. Transaction construction reports these instead
// of wrapping, truncating, or clamping a value that cannot be represented.
var (
	// ErrNilOutput is returned when an output set contains a nil element.
	ErrNilOutput = errors.New("nil transaction output")

	// ErrOutputValueNegative is returned when a single output carries a
	// negative value.
	ErrOutputValueNegative = errors.New(
		"transaction output amount is negative",
	)

	// ErrOutputValueExceedsMax is returned when a single output carries
	// more than the maximum representable amount.
	ErrOutputValueExceedsMax = errors.New(
		"transaction output amount exceeds maximum value",
	)

	// ErrOutputTotalExceedsMax is returned when an output set is
	// individually valid but sums to more than the maximum representable
	// amount.
	ErrOutputTotalExceedsMax = errors.New(
		"transaction output total exceeds maximum value",
	)

	// ErrAmountOverflow is returned when adding two amounts would overflow.
	ErrAmountOverflow = errors.New("amount addition overflows")

	// ErrAmountUnderflow is returned when subtracting two amounts would
	// underflow.
	ErrAmountUnderflow = errors.New("amount subtraction underflows")

	// ErrFeeRateNotPositive is returned when a fee rate operand is zero or
	// negative. Such a rate cannot produce a meaningful fee, so it is
	// rejected before it is ever multiplied by a size.
	ErrFeeRateNotPositive = errors.New("fee rate must be positive")

	// ErrFeeOverflow is returned when the fee-rate-by-size product
	// overflows.
	ErrFeeOverflow = errors.New("fee calculation overflows")

	// ErrFeeOutOfRange is returned when a rounded fee falls outside the
	// range of representable amounts.
	ErrFeeOutOfRange = errors.New("fee is not a representable amount")
)

// addAmounts returns the sum of two amounts, reporting ErrAmountOverflow
// rather than wrapping when the sum is not representable.
func addAmounts(a, b btcutil.Amount) (btcutil.Amount, error) {
	sum := a + b

	// A sum that moved the wrong way relative to the sign of the addend is
	// the signed-overflow signature.
	if (b > 0 && sum < a) || (b < 0 && sum > a) {
		return 0, fmt.Errorf("%w: %d + %d", ErrAmountOverflow, a, b)
	}

	return sum, nil
}

// subAmounts returns the difference of two amounts, reporting
// ErrAmountUnderflow rather than wrapping when the difference is not
// representable. It is the counterpart of addAmounts and is used for every
// subtraction that establishes sufficiency or change.
func subAmounts(a, b btcutil.Amount) (btcutil.Amount, error) {
	diff := a - b

	// A difference that moved the wrong way relative to the sign of the
	// subtrahend is the signed-overflow signature.
	if (b > 0 && diff > a) || (b < 0 && diff < a) {
		return 0, fmt.Errorf("%w: %d - %d", ErrAmountUnderflow, a, b)
	}

	return diff, nil
}

// CheckOutputs validates an output set and returns its checked total so callers
// can reuse the sum instead of re-deriving it. Every element must be non-nil
// and carry a value in 0..MaxSatoshi, and the set as a whole must not sum above
// MaxSatoshi.
//
// A nil or empty set is valid and totals zero: a sweep authors a transaction
// whose only output is change, and has no non-change outputs to declare.
//
// The running sum is added through addAmounts as defence in depth. Because
// every accepted element is non-negative and bounded by MaxSatoshi, the
// aggregate bound below is reached long before the sum could overflow, so that
// guard is not expected to fire on any set built from accepted elements.
func CheckOutputs(outputs []*wire.TxOut) (btcutil.Amount, error) {
	total := btcutil.Amount(0)

	for i, output := range outputs {
		if output == nil {
			return 0, fmt.Errorf("%w: index %d", ErrNilOutput, i)
		}

		if output.Value < 0 {
			return 0, fmt.Errorf("%w: index %d has %d",
				ErrOutputValueNegative, i, output.Value)
		}

		if output.Value > btcutil.MaxSatoshi {
			return 0, fmt.Errorf("%w: index %d has %d",
				ErrOutputValueExceedsMax, i, output.Value)
		}

		sum, err := addAmounts(total, btcutil.Amount(output.Value))
		if err != nil {
			return 0, fmt.Errorf("output total: %w", err)
		}

		total = sum
	}

	if total > btcutil.MaxSatoshi {
		return 0, fmt.Errorf("%w: %d", ErrOutputTotalExceedsMax, total)
	}

	return total, nil
}

// CheckedFeeForSerializeSize calculates the fee for a transaction of some
// virtual size at the given rate, reporting an error instead of returning a
// value that cannot be represented.
//
// Both operands are rejected before they are multiplied: a rate at or below
// zero, because no meaningful fee can follow from it, and a negative size,
// because it can only come from a caller error. The rate-by-size product is
// then checked for overflow, and the rounded fee must land within
// 0..MaxSatoshi. A fee that rounds down to zero is charged the rate itself,
// matching the one-kilo-virtual-byte floor mempools apply; the rate is positive
// by then, so the floor is too.
//
// Sizes themselves belong to the size estimator, not here. Rejecting a negative
// one is not an opinion about how sizes are computed: it keeps a wrapped
// product from landing back inside the representable range and yielding a
// plausible but wrong fee, which the final bound alone could not rule out.
func CheckedFeeForSerializeSize(feeRatePerKb btcutil.Amount,
	txSerializeSize int) (btcutil.Amount, error) {

	if feeRatePerKb <= 0 {
		return 0, fmt.Errorf("%w: %d", ErrFeeRateNotPositive,
			feeRatePerKb)
	}

	if txSerializeSize < 0 {
		return 0, fmt.Errorf("%w: negative size %d", ErrFeeOutOfRange,
			txSerializeSize)
	}

	size := btcutil.Amount(txSerializeSize)
	product := feeRatePerKb * size

	// Both operands are now non-negative, so a size of zero is the only one
	// that makes the division round-trip undefined; it trivially cannot
	// overflow.
	if size != 0 && product/size != feeRatePerKb {
		return 0, fmt.Errorf("%w: %d * %d", ErrFeeOverflow,
			feeRatePerKb, size)
	}

	fee := product / feeRateDivisor
	if fee == 0 {
		fee = feeRatePerKb
	}

	if fee > btcutil.MaxSatoshi {
		return 0, fmt.Errorf("%w: %d", ErrFeeOutOfRange, fee)
	}

	return fee, nil
}
