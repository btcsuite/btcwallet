// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package btcunit provides a set of types for dealing with bitcoin units.
package btcunit

import (
	"log/slog"
	"math"
	"math/big"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil/v2"
)

const (
	// kilo is a generic multiplier for kilo units.
	kilo = 1000

	// floatStringPrecision is the number of decimal places to use when
	// converting a fee rate to a string. We use 3 decimal places to ensure
	// that low fee rates (e.g., 1 sat/kvb = 0.001 sat/vbyte) are displayed
	// with sufficient precision and not rounded to zero.
	floatStringPrecision = 3
)

var (
	// ZeroSatPerVByte is a fee rate of 0 sat/vb.
	ZeroSatPerVByte = NewSatPerVByte(0)

	// ZeroSatPerKVByte is a fee rate of 0 sat/kvb.
	ZeroSatPerKVByte = NewSatPerKVByte(0)

	// ZeroSatPerKWeight is a fee rate of 0 sat/kw.
	ZeroSatPerKWeight = NewSatPerKWeight(0)

	// ZeroSatPerWeight is a fee rate of 0 sat/wu.
	ZeroSatPerWeight = NewSatPerWeight(0)
)

// baseFeeRate stores the canonical representation of a fee rate, which is
// satoshis per kilo-weight-unit (sat/kwu). All other fee rate units are
// derived from this.
type baseFeeRate struct {
	// satsPerKWU is the fee rate in satoshis per kilo-weight-unit. This is
	// the canonical representation for all fee rates within this package,
	// chosen for its direct alignment with Bitcoin's weight unit for fee
	// calculations and to minimize rounding errors.
	satsPerKWU *big.Rat
}

// newBaseFeeRate creates a new baseFeeRate with the given numerator and
// denominator. It panics if the denominator is zero.
func newBaseFeeRate(numerator btcutil.Amount, denominator uint64) baseFeeRate {
	if denominator == 0 {
		panic("fee rate calculation: denominator cannot be zero")
	}

	return baseFeeRate{satsPerKWU: big.NewRat(
		int64(numerator),
		safeUint64ToInt64(denominator),
	)}
}

// ToSatPerVByte converts the fee rate to sat/vb.
func (f baseFeeRate) ToSatPerVByte() SatPerVByte {
	return SatPerVByte{f}
}

// ToSatPerKVByte converts the fee rate to sat/kvb.
func (f baseFeeRate) ToSatPerKVByte() SatPerKVByte {
	return SatPerKVByte{f}
}

// ToSatPerKWeight converts the fee rate to sat/kw.
func (f baseFeeRate) ToSatPerKWeight() SatPerKWeight {
	return SatPerKWeight{f}
}

// ToSatPerWeight converts the fee rate to sat/wu.
func (f baseFeeRate) ToSatPerWeight() SatPerWeight {
	return SatPerWeight{f}
}

// FeeForWeight calculates the fee resulting from this fee rate and the given
// weight in weight units (wu).
func (f baseFeeRate) FeeForWeight(weightUnit WeightUnit) btcutil.Amount {
	// The fee rate is stored as satoshis per kilo-weight-unit (sat/kwu).
	// To calculate the fee for a given weight, we need to multiply the
	// rate by the weight expressed in kilo-weight-units. We do this by
	// creating a rational number of weightUnit.wu / kilo.
	//
	// The resulting fee is rounded down (truncated).
	feeRateRational := big.NewRat(0, 1)
	feeRateRational.Mul(
		f.satsPerKWU,
		big.NewRat(safeUint64ToInt64(weightUnit.wu), kilo),
	)

	// Extract the numerator and denominator for integer division.
	numerator := feeRateRational.Num()
	denominator := feeRateRational.Denom()

	// Perform integer division to truncate the result (round down).
	quotient := big.NewInt(0)
	quotient.Div(numerator, denominator)

	return btcutil.Amount(quotient.Int64())
}

// FeeForWeightRoundUp calculates the fee resulting from this fee rate and the
// given weight in weight units (wu), rounding up to the nearest satoshi.
func (f baseFeeRate) FeeForWeightRoundUp(weightUnit WeightUnit) btcutil.Amount {
	// The rounding logic for ceiling division is based on the formula:
	// (numerator + denominator - 1) / denominator
	// This ensures that any fractional part of the fee is rounded up to
	// the next whole satoshi.
	//
	// Calculate the fee rate as a rational number.
	feeRateRational := big.NewRat(0, 1)
	feeRateRational.Mul(
		f.satsPerKWU, big.NewRat(
			safeUint64ToInt64(weightUnit.wu), kilo,
		),
	)

	// Get the numerator and denominator of the calculated fee.
	numerator := feeRateRational.Num()
	denominator := feeRateRational.Denom()

	// Initialize a new big.Int to store the result of the ceiling division.
	result := big.NewInt(0)

	// Apply the ceiling division formula:
	// (numerator + denominator - 1) / denominator.
	result.Add(numerator, denominator)
	result.Sub(result, big.NewInt(1))
	result.Div(result, denominator)

	return btcutil.Amount(result.Int64())
}

// FeeForVByte calculates the fee resulting from this fee rate and the given
// size in vbytes (vb).
func (f baseFeeRate) FeeForVByte(vb VByte) btcutil.Amount {
	return f.FeeForWeight(vb.ToWU())
}

// FeeForKVByte calculates the fee resulting from this fee rate and the given
// vsize in kilo-vbytes.
func (f baseFeeRate) FeeForKVByte(kvb KVByte) btcutil.Amount {
	// Directly convert kilo-virtual-bytes to weight units for fee
	// calculation to maintain precision and avoid intermediate rounding
	// effects.
	return f.FeeForWeight(kvb.ToWU())
}

// FeeForKWeight calculates the fee resulting from this fee rate and the given
// weight in kilo-weight-units (kwu).
func (f baseFeeRate) FeeForKWeight(kwu KWeightUnit) btcutil.Amount {
	return f.FeeForWeight(kwu.ToWU())
}

// equal returns true if the fee rate is equal to the other fee rate.
func (f baseFeeRate) equal(other baseFeeRate) bool {
	return f.satsPerKWU.Cmp(other.satsPerKWU) == 0
}

// greaterThan returns true if the fee rate is greater than the other fee rate.
func (f baseFeeRate) greaterThan(other baseFeeRate) bool {
	return f.satsPerKWU.Cmp(other.satsPerKWU) > 0
}

// lessThan returns true if the fee rate is less than the other fee rate.
func (f baseFeeRate) lessThan(other baseFeeRate) bool {
	return f.satsPerKWU.Cmp(other.satsPerKWU) < 0
}

// greaterThanOrEqual returns true if the fee rate is greater than or equal to
// the other fee rate.
func (f baseFeeRate) greaterThanOrEqual(other baseFeeRate) bool {
	return f.satsPerKWU.Cmp(other.satsPerKWU) >= 0
}

// lessThanOrEqual returns true if the fee rate is less than or equal to the
// other fee rate.
func (f baseFeeRate) lessThanOrEqual(other baseFeeRate) bool {
	return f.satsPerKWU.Cmp(other.satsPerKWU) <= 0
}

// SatPerVByte represents a fee rate in sat/vbyte. Internally, all fee rates
// are stored and operated on as satoshis per kilo-weight-unit (sat/kw).
// Conversions to other units and fee calculations are performed using this
// canonical internal representation. The `String()` method is the only one
// that presents the fee rate in its specific sat/vbyte unit.
type SatPerVByte struct {
	baseFeeRate
}

// NewSatPerVByte creates a new fee rate in sat/vb.
func NewSatPerVByte(rate btcutil.Amount) SatPerVByte {
	return CalcSatPerVByte(rate, NewVByte(1))
}

// CalcSatPerVByte calculates the fee rate in sat/vb for a given fee and size.
func CalcSatPerVByte(fee btcutil.Amount, vb VByte) SatPerVByte {
	// To convert the rate to the canonical sat/kwu unit, we use the
	// formula: (fee * 1000) / size_in_wu.
	//
	// vb.wu provides the size in weight units (wu), implicitly accounting
	// for the WitnessScaleFactor.
	numerator := fee * kilo
	denominator := vb.wu

	return SatPerVByte{newBaseFeeRate(numerator, denominator)}
}

// String returns a human-readable string of the fee rate.
func (s SatPerVByte) String() string {
	// Calculate the fee rate in sat/vb from the canonical sat/kwu.
	// The WitnessScaleFactor (4) is used to convert weight units to vbytes.
	// The `kilo` constant is used to scale kilo-weight-units.
	kwToVbRate := big.NewRat(0, 1)
	kwToVbRate.Mul(s.satsPerKWU,
		big.NewRat(blockchain.WitnessScaleFactor, kilo),
	)

	// Format the rational number to a string with the specified precision.
	return kwToVbRate.FloatString(floatStringPrecision) + " sat/vb"
}

// Equal returns true if the fee rate is equal to the other fee rate.
func (s SatPerVByte) Equal(other SatPerVByte) bool {
	return s.equal(other.baseFeeRate)
}

// GreaterThan returns true if the fee rate is greater than the other fee rate.
func (s SatPerVByte) GreaterThan(other SatPerVByte) bool {
	return s.greaterThan(other.baseFeeRate)
}

// LessThan returns true if the fee rate is less than the other fee rate.
func (s SatPerVByte) LessThan(other SatPerVByte) bool {
	return s.lessThan(other.baseFeeRate)
}

// GreaterThanOrEqual returns true if the fee rate is greater than or equal to
// the other fee rate.
func (s SatPerVByte) GreaterThanOrEqual(other SatPerVByte) bool {
	return s.greaterThanOrEqual(other.baseFeeRate)
}

// LessThanOrEqual returns true if the fee rate is less than or equal to the
// other fee rate.
func (s SatPerVByte) LessThanOrEqual(other SatPerVByte) bool {
	return s.lessThanOrEqual(other.baseFeeRate)
}

// SatPerKVByte represents a fee rate in sat/kvb. Internally, all fee rates
// are stored and operated on as satoshis per kilo-weight-unit (sat/kw).
// Conversions to other units and fee calculations are performed using this
// canonical internal representation. The `String()` method is the only one
// that presents the fee rate in its specific sat/kvb unit.
type SatPerKVByte struct {
	baseFeeRate
}

// NewSatPerKVByte creates a new fee rate in sat/kvb.
func NewSatPerKVByte(rate btcutil.Amount) SatPerKVByte {
	return CalcSatPerKVByte(rate, NewKVByte(1))
}

// CalcSatPerKVByte calculates the fee rate in sat/kvb for a given fee and size.
func CalcSatPerKVByte(fee btcutil.Amount, kvb KVByte) SatPerKVByte {
	// To convert the rate to the canonical sat/kwu unit, we use the
	// formula: (fee * 1000) / size_in_wu.
	//
	// kvb.wu provides the size in weight units (wu), implicitly accounting
	// for the WitnessScaleFactor and kilo scaling.
	numerator := fee * kilo
	denominator := kvb.wu

	return SatPerKVByte{newBaseFeeRate(numerator, denominator)}
}

// Val returns the fee rate in sat/kvb.
//
// NOTE: This method is provided for backward compatibility with legacy APIs
// that expect a raw integer fee rate. New code should use the btcunit types
// directly.
func (s SatPerKVByte) Val() btcutil.Amount {
	return s.FeeForKVByte(NewKVByte(1))
}

// String returns a human-readable string of the fee rate.
func (s SatPerKVByte) String() string {
	// Calculate the fee rate in sat/kvb from the canonical sat/kwu.
	// The WitnessScaleFactor (4) is used to convert weight units to vbytes.
	// No `kilo` division here as we are converting to *kilo*-vbytes.
	kwToKvbRate := big.NewRat(0, 1)
	kwToKvbRate.Mul(s.satsPerKWU,
		big.NewRat(blockchain.WitnessScaleFactor, 1),
	)

	// Format the rational number to a string with the specified precision.
	return kwToKvbRate.FloatString(floatStringPrecision) +
		" sat/kvb"
}

// Equal returns true if the fee rate is equal to the other fee rate.
func (s SatPerKVByte) Equal(other SatPerKVByte) bool {
	return s.equal(other.baseFeeRate)
}

// GreaterThan returns true if the fee rate is greater than the other fee rate.
func (s SatPerKVByte) GreaterThan(other SatPerKVByte) bool {
	return s.greaterThan(other.baseFeeRate)
}

// LessThan returns true if the fee rate is less than the other fee rate.
func (s SatPerKVByte) LessThan(other SatPerKVByte) bool {
	return s.lessThan(other.baseFeeRate)
}

// GreaterThanOrEqual returns true if the fee rate is greater than or equal to
// the other fee rate.
func (s SatPerKVByte) GreaterThanOrEqual(other SatPerKVByte) bool {
	return s.greaterThanOrEqual(other.baseFeeRate)
}

// LessThanOrEqual returns true if the fee rate is less than or equal to the
// other fee rate.
func (s SatPerKVByte) LessThanOrEqual(other SatPerKVByte) bool {
	return s.lessThanOrEqual(other.baseFeeRate)
}

// SatPerKWeight represents a fee rate in sat/kw. Internally, all fee rates
// are stored and operated on as satoshis per kilo-weight-unit (sat/kw).
// Conversions to other units and fee calculations are performed using this
// canonical internal representation. The `String()` method is the only one
// that presents the fee rate in its specific sat/kw unit.
type SatPerKWeight struct {
	baseFeeRate
}

// NewSatPerKWeight creates a new fee rate in sat/kw.
func NewSatPerKWeight(rate btcutil.Amount) SatPerKWeight {
	return CalcSatPerKWeight(rate, NewKWeightUnit(1))
}

// CalcSatPerKWeight calculates the fee rate in sat/kw for a given fee and size.
func CalcSatPerKWeight(fee btcutil.Amount, kwu KWeightUnit) SatPerKWeight {
	// To convert the rate to the canonical sat/kwu unit, we use the
	// formula: (fee * 1000) / size_in_wu.
	//
	// kwu.wu provides the size in weight units (wu), implicitly accounting
	// for the kilo scaling.
	numerator := fee * kilo
	denominator := kwu.wu

	return SatPerKWeight{newBaseFeeRate(numerator, denominator)}
}

// Val returns the fee rate in sat/kw.
//
// NOTE: This method is provided for backward compatibility with legacy APIs
// that expect a raw integer fee rate. New code should use the btcunit types
// directly.
func (s SatPerKWeight) Val() btcutil.Amount {
	return s.FeeForKWeight(NewKWeightUnit(1))
}

// String returns a human-readable string of the fee rate.
func (s SatPerKWeight) String() string {
	return s.satsPerKWU.FloatString(floatStringPrecision) + " sat/kw"
}

// Equal returns true if the fee rate is equal to the other fee rate.
func (s SatPerKWeight) Equal(other SatPerKWeight) bool {
	return s.equal(other.baseFeeRate)
}

// GreaterThan returns true if the fee rate is greater than the other fee rate.
func (s SatPerKWeight) GreaterThan(other SatPerKWeight) bool {
	return s.greaterThan(other.baseFeeRate)
}

// LessThan returns true if the fee rate is less than the other fee rate.
func (s SatPerKWeight) LessThan(other SatPerKWeight) bool {
	return s.lessThan(other.baseFeeRate)
}

// GreaterThanOrEqual returns true if the fee rate is greater than or equal to
// the other fee rate.
func (s SatPerKWeight) GreaterThanOrEqual(other SatPerKWeight) bool {
	return s.greaterThanOrEqual(other.baseFeeRate)
}

// LessThanOrEqual returns true if the fee rate is less than or equal to the
// other fee rate.
func (s SatPerKWeight) LessThanOrEqual(other SatPerKWeight) bool {
	return s.lessThanOrEqual(other.baseFeeRate)
}

// SatPerWeight represents a fee rate in sat/wu. Internally, all fee rates
// are stored and operated on as satoshis per kilo-weight-unit (sat/kw).
// Conversions to other units and fee calculations are performed using this
// canonical internal representation. The `String()` method is the only one
// that presents the fee rate in its specific sat/wu unit.
type SatPerWeight struct {
	baseFeeRate
}

// NewSatPerWeight creates a new fee rate in sat/wu.
func NewSatPerWeight(rate btcutil.Amount) SatPerWeight {
	return CalcSatPerWeight(rate, NewWeightUnit(1))
}

// CalcSatPerWeight calculates the fee rate in sat/wu for a given fee and size.
func CalcSatPerWeight(fee btcutil.Amount, wu WeightUnit) SatPerWeight {
	// To convert the rate to the canonical sat/kwu unit, we use the
	// formula: (fee * 1000) / size_in_wu.
	//
	// wu.wu provides the size in weight units (wu).
	numerator := fee * kilo
	denominator := wu.wu

	return SatPerWeight{newBaseFeeRate(numerator, denominator)}
}

// String returns a human-readable string of the fee rate.
func (s SatPerWeight) String() string {
	// Calculate the fee rate in sat/wu from the canonical sat/kwu.
	// 1 sat/wu = 1000 sat/kwu. So we need to divide by kilo.
	wuRate := big.NewRat(0, 1)
	wuRate.Mul(s.satsPerKWU, big.NewRat(1, kilo))

	return wuRate.FloatString(floatStringPrecision) + " sat/wu"
}

// Equal returns true if the fee rate is equal to the other fee rate.
func (s SatPerWeight) Equal(other SatPerWeight) bool {
	return s.equal(other.baseFeeRate)
}

// GreaterThan returns true if the fee rate is greater than the other fee rate.
func (s SatPerWeight) GreaterThan(other SatPerWeight) bool {
	return s.greaterThan(other.baseFeeRate)
}

// LessThan returns true if the fee rate is less than the other fee rate.
func (s SatPerWeight) LessThan(other SatPerWeight) bool {
	return s.lessThan(other.baseFeeRate)
}

// GreaterThanOrEqual returns true if the fee rate is greater than or equal to
// the other fee rate.
func (s SatPerWeight) GreaterThanOrEqual(other SatPerWeight) bool {
	return s.greaterThanOrEqual(other.baseFeeRate)
}

// LessThanOrEqual returns true if the fee rate is less than or equal to the
// other fee rate.
func (s SatPerWeight) LessThanOrEqual(other SatPerWeight) bool {
	return s.lessThanOrEqual(other.baseFeeRate)
}

// safeUint64ToInt64 converts a uint64 to an int64, capping at math.MaxInt64.
// This is used to silence gosec warnings about integer overflows. In practice,
// the values being converted are transaction weights or sizes, which are
// limited by consensus rules and are not expected to overflow an int64.
func safeUint64ToInt64(u uint64) int64 {
	if u > math.MaxInt64 {
		slog.Warn("Capping uint64 value to math.MaxInt64",
			slog.Uint64("old", u), slog.Int64("new", math.MaxInt64))

		return math.MaxInt64
	}

	return int64(u)
}
