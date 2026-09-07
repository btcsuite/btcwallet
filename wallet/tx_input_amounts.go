// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
)

// Input amount violations. The wallet's own input sources report these instead
// of handing authoring a set of amounts that cannot be represented or
// reconciled.
//
// None of them is exported. A caller cannot ask for a malformed input set: the
// values come from the store, so reaching one of these means the store returned
// an amount it could not have written, not that the request was wrong. There is
// nothing for a caller to match on and nothing it could do differently.
var (
	// errInputCountMismatch is returned when a source reports a different
	// number of input values than inputs.
	errInputCountMismatch = errors.New(
		"input value count does not match input count",
	)

	// errInputValueNegative is returned when a single input carries a
	// negative value.
	errInputValueNegative = errors.New(
		"transaction input amount is negative",
	)

	// errInputValueExceedsMax is returned when a single input carries more
	// than the maximum representable amount.
	errInputValueExceedsMax = errors.New(
		"transaction input amount exceeds maximum value",
	)

	// errInputTotalNegative is returned when a source reports a negative
	// total.
	errInputTotalNegative = errors.New(
		"transaction input total is negative",
	)

	// errInputTotalExceedsMax is returned when an input total is more than
	// the maximum representable amount, whether as reported by the source
	// or as summed from the values it supplied.
	errInputTotalExceedsMax = errors.New(
		"transaction input total exceeds maximum value",
	)

	// errInputTotalMismatch is returned when the total a source reports is
	// not the sum of the values it supplied.
	errInputTotalMismatch = errors.New(
		"transaction input total does not match input values",
	)

	// errInputAmountOverflow is returned when accumulating an input value
	// would overflow the running total.
	errInputAmountOverflow = errors.New("input amount addition overflows")
)

// addInputAmounts returns the sum of two input amounts, reporting
// errInputAmountOverflow rather than wrapping when the sum is not
// representable. It bounds nothing else: an operand or a sum outside
// 0..MaxSatoshi is arithmetically fine here and is rejected by
// checkInputResult, which sees the whole set.
//
// The wallet owns this rather than borrowing the authoring module's equivalent.
// The two are the same three lines, but they answer to different callers: this
// one guards amounts the store produced, and keeping it here leaves the
// authoring arithmetic free to change without a wallet source depending on it.
func addInputAmounts(a, b btcutil.Amount) (btcutil.Amount, error) {
	sum := a + b

	// A sum that moved the wrong way relative to the sign of the addend is
	// the signed-overflow signature.
	if (b > 0 && sum < a) || (b < 0 && sum > a) {
		return 0, fmt.Errorf("%w: %d + %d", errInputAmountOverflow, a, b)
	}

	return sum, nil
}

// checkInputSource wraps one of the wallet's input sources so that every result
// it produces is validated before authoring can act on it. Authoring asks a
// source for coins and then spends the total it reports: on that total rest the
// sufficiency test, the fee the transaction can afford, and the change paid
// back to the wallet. A source that reports more than it supplied therefore
// funds change out of value that does not exist, and one that reports a value
// outside the representable range skews the fee. Neither is visible at the
// point of use, so it is checked at the point of return.
//
// A source error is returned untouched and its result is not inspected. That
// keeps an InputSourceError - "I cannot fund this" - distinct from a violation
// of this contract, which says the source is wrong rather than short.
//
// A nil source is returned as nil: there is nothing to wrap, and wrapping it
// would turn authoring's own nil-callback panic into one raised from here.
func checkInputSource(source txauthor.InputSource) txauthor.InputSource {
	if source == nil {
		return nil
	}

	return func(target btcutil.Amount) (btcutil.Amount, []*wire.TxIn,
		[]btcutil.Amount, [][]byte, error) {

		total, inputs, inputValues, scripts, err := source(target)
		if err != nil {
			return 0, nil, nil, nil, err
		}

		err = checkInputResult(total, inputs, inputValues)
		if err != nil {
			return 0, nil, nil, nil, err
		}

		return total, inputs, inputValues, scripts, nil
	}
}

// checkInputResult validates one input-source result: every value and the
// reported total must lie in 0..MaxSatoshi, the values must be as many as the
// inputs, and their bounded sum must be the total the source reported.
//
// An empty result is valid and totals zero. A source that has nothing to give
// says so by reporting less than the target, which is authoring's business, not
// a malformed answer.
//
// The scripts a source returns are not checked here. This validates amounts,
// and whether an input set may go unscripted belongs to the signing
// precondition rather than to this arithmetic.
func checkInputResult(total btcutil.Amount, inputs []*wire.TxIn,
	inputValues []btcutil.Amount) error {

	if len(inputValues) != len(inputs) {
		return fmt.Errorf("%w: %d values for %d inputs",
			errInputCountMismatch, len(inputValues), len(inputs))
	}

	// Bound what the source claims before summing what it supplied, so a
	// nonsense total is named as such rather than surfacing as a mismatch
	// against a perfectly good value set.
	if total < 0 {
		return fmt.Errorf("%w: %d", errInputTotalNegative, total)
	}

	if total > btcutil.MaxSatoshi {
		return fmt.Errorf("%w: reported %d", errInputTotalExceedsMax,
			total)
	}

	sum := btcutil.Amount(0)

	for i, value := range inputValues {
		if value < 0 {
			return fmt.Errorf("%w: index %d has %d",
				errInputValueNegative, i, value)
		}

		if value > btcutil.MaxSatoshi {
			return fmt.Errorf("%w: index %d has %d",
				errInputValueExceedsMax, i, value)
		}

		// The aggregate bound is applied before the addition rather
		// than to the finished sum. Both operands are within
		// 0..MaxSatoshi by now, so the remaining headroom cannot go
		// negative and the sum cannot wrap. Checking afterwards would
		// let a long enough set of individually valid inputs wrap the
		// accumulator first and report an overflow instead of the bound
		// that was actually exceeded.
		if sum > btcutil.MaxSatoshi-value {
			return fmt.Errorf("%w: exceeded at index %d",
				errInputTotalExceedsMax, i)
		}

		sum += value
	}

	if sum != total {
		return fmt.Errorf("%w: reported %d, values sum to %d",
			errInputTotalMismatch, total, sum)
	}

	return nil
}
