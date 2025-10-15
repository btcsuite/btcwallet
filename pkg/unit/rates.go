// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package unit provides a set of types for dealing with bitcoin units.
package unit

import (
	"log/slog"
	"math"
	"math/big"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
)

const (
	// SatsPerKilo is the number of satoshis in a kilo-satoshi.
	SatsPerKilo = 1000

	// floatStringPrecision is the number of decimal places to use when
	// converting a fee rate to a string.
	floatStringPrecision = 2
)

// SatPerVByte represents a fee rate in sat/vbyte. The fee rate is encoded
// as a big.Rat to allow for fractional (sub-satoshi) fee rates.
type SatPerVByte struct {
	*big.Rat
}

// NewSatPerVByte creates a new fee rate in sat/vb. The given fee and vbytes
// are used to calculate the fee rate.
func NewSatPerVByte(fee btcutil.Amount, vb VByte) SatPerVByte {
	if vb == 0 {
		return SatPerVByte{big.NewRat(0, 1)}
	}

	return SatPerVByte{
		big.NewRat(int64(fee), safeUint64ToInt64(uint64(vb))),
	}
}

// FeePerKWeight converts the current fee rate from sat/vb to sat/kw.
func (s SatPerVByte) FeePerKWeight() SatPerKWeight {
	vbToKwRate := big.NewRat(SatsPerKilo, blockchain.WitnessScaleFactor)
	kwRate := new(big.Rat).Mul(s.Rat, vbToKwRate)

	return SatPerKWeight{kwRate}
}

// FeePerKVByte converts the current fee rate from sat/vb to sat/kvb.
func (s SatPerVByte) FeePerKVByte() SatPerKVByte {
	vbToKvbRate := big.NewRat(SatsPerKilo, 1)
	kvbRate := new(big.Rat).Mul(s.Rat, vbToKvbRate)

	return SatPerKVByte{kvbRate}
}

// String returns a human-readable string of the fee rate.
func (s SatPerVByte) String() string {
	return s.FloatString(floatStringPrecision) + " sat/vb"
}

// Equal returns true if the fee rate is equal to the other fee rate.
func (s SatPerVByte) Equal(other SatPerVByte) bool {
	return s.Cmp(other.Rat) == 0
}

// GreaterThan returns true if the fee rate is greater than the other fee rate.
func (s SatPerVByte) GreaterThan(other SatPerVByte) bool {
	return s.Cmp(other.Rat) > 0
}

// LessThan returns true if the fee rate is less than the other fee rate.
func (s SatPerVByte) LessThan(other SatPerVByte) bool {
	return s.Cmp(other.Rat) < 0
}

// GreaterThanOrEqual returns true if the fee rate is greater than or equal to
// the other fee rate.
func (s SatPerVByte) GreaterThanOrEqual(other SatPerVByte) bool {
	return s.Cmp(other.Rat) >= 0
}

// LessThanOrEqual returns true if the fee rate is less than or equal to the
// other fee rate.
func (s SatPerVByte) LessThanOrEqual(other SatPerVByte) bool {
	return s.Cmp(other.Rat) <= 0
}

// SatPerKVByte represents a fee rate in sat/kb. The fee rate is encoded as a
// big.Rat to allow for fractional (sub-satoshi) fee rates.
type SatPerKVByte struct {
	*big.Rat
}

// NewSatPerKVByte creates a new fee rate in sat/kvb. The given fee and kvbytes
// are used to calculate the fee rate.
func NewSatPerKVByte(fee btcutil.Amount, kvb VByte) SatPerKVByte {
	if kvb == 0 {
		return SatPerKVByte{big.NewRat(0, 1)}
	}

	return SatPerKVByte{
		big.NewRat(
			int64(fee)*SatsPerKilo,
			safeUint64ToInt64(uint64(kvb)),
		),
	}
}

// FeeForVSize calculates the fee resulting from this fee rate and the given
// vsize in vbytes.
func (s SatPerKVByte) FeeForVSize(vbytes VByte) btcutil.Amount {
	fee := new(big.Rat).Mul(
		s.Rat,
		big.NewRat(safeUint64ToInt64(uint64(vbytes)), SatsPerKilo),
	)

	return roundToAmount(fee)
}

// FeePerKWeight converts the current fee rate from sat/kb to sat/kw.
func (s SatPerKVByte) FeePerKWeight() SatPerKWeight {
	kvbToKwRate := big.NewRat(1, blockchain.WitnessScaleFactor)
	kwRate := new(big.Rat).Mul(s.Rat, kvbToKwRate)

	return SatPerKWeight{kwRate}
}

// String returns a human-readable string of the fee rate.
func (s SatPerKVByte) String() string {
	return s.FloatString(floatStringPrecision) + " sat/kvb"
}

// Equal returns true if the fee rate is equal to the other fee rate.
func (s SatPerKVByte) Equal(other SatPerKVByte) bool {
	return s.Cmp(other.Rat) == 0
}

// GreaterThan returns true if the fee rate is greater than the other fee rate.
func (s SatPerKVByte) GreaterThan(other SatPerKVByte) bool {
	return s.Cmp(other.Rat) > 0
}

// LessThan returns true if the fee rate is less than the other fee rate.
func (s SatPerKVByte) LessThan(other SatPerKVByte) bool {
	return s.Cmp(other.Rat) < 0
}

// GreaterThanOrEqual returns true if the fee rate is greater than or equal to
// the other fee rate.
func (s SatPerKVByte) GreaterThanOrEqual(other SatPerKVByte) bool {
	return s.Cmp(other.Rat) >= 0
}

// LessThanOrEqual returns true if the fee rate is less than or equal to the
// other fee rate.
func (s SatPerKVByte) LessThanOrEqual(other SatPerKVByte) bool {
	return s.Cmp(other.Rat) <= 0
}

// SatPerKWeight represents a fee rate in sat/kw. The fee rate is encoded as a
// big.Rat to allow for fractional (sub-satoshi) fee rates.
type SatPerKWeight struct {
	*big.Rat
}

// NewSatPerKWeight creates a new fee rate in sat/kw. The given fee and weight
// are used to calculate the fee rate.
func NewSatPerKWeight(fee btcutil.Amount, wu WeightUnit) SatPerKWeight {
	if wu == 0 {
		return SatPerKWeight{big.NewRat(0, 1)}
	}

	return SatPerKWeight{
		big.NewRat(
			int64(fee)*SatsPerKilo,
			safeUint64ToInt64(uint64(wu)),
		),
	}
}

// FeeForWeight calculates the fee resulting from this fee rate and the given
// weight in weight units (wu).
func (s SatPerKWeight) FeeForWeight(wu WeightUnit) btcutil.Amount {
	// The resulting fee is rounded down, as specified in BOLT#03.
	fee := new(big.Rat).Mul(
		s.Rat, big.NewRat(safeUint64ToInt64(uint64(wu)), SatsPerKilo),
	)

	return btcutil.Amount(new(big.Int).Div(fee.Num(), fee.Denom()).Int64())
}

// FeeForWeightRoundUp calculates the fee resulting from this fee rate and the
// given weight in weight units (wu), rounding up to the nearest satoshi.
func (s SatPerKWeight) FeeForWeightRoundUp(
	wu WeightUnit) btcutil.Amount {

	// The rounding logic is based on the ceiling division formula:
	// (numerator + denominator - 1) / denominator
	//
	// This ensures that any fractional part of the fee is rounded up to
	// the next whole satoshi.
	feeRat := new(big.Rat).Mul(
		s.Rat, big.NewRat(safeUint64ToInt64(uint64(wu)), SatsPerKilo),
	)

	num := feeRat.Num()
	den := feeRat.Denom()
	num.Add(num, den)
	num.Sub(num, big.NewInt(1))
	num.Div(num, den)

	return btcutil.Amount(num.Int64())
}

// FeeForVByte calculates the fee resulting from this fee rate and the given
// size in vbytes (vb).
func (s SatPerKWeight) FeeForVByte(vb VByte) btcutil.Amount {
	return s.FeePerKVByte().FeeForVSize(vb)
}

// FeePerKVByte converts the current fee rate from sat/kw to sat/kb.
func (s SatPerKWeight) FeePerKVByte() SatPerKVByte {
	kwToKvbRate := big.NewRat(blockchain.WitnessScaleFactor, 1)
	kvbRate := new(big.Rat).Mul(s.Rat, kwToKvbRate)

	return SatPerKVByte{kvbRate}
}

// FeePerVByte converts the current fee rate from sat/kw to sat/vb.
func (s SatPerKWeight) FeePerVByte() SatPerVByte {
	kwToVbRate := big.NewRat(blockchain.WitnessScaleFactor, SatsPerKilo)
	vbRate := new(big.Rat).Mul(s.Rat, kwToVbRate)

	return SatPerVByte{vbRate}
}

// String returns a human-readable string of the fee rate.
func (s SatPerKWeight) String() string {
	return s.FloatString(floatStringPrecision) + " sat/kw"
}

// Equal returns true if the fee rate is equal to the other fee rate.
func (s SatPerKWeight) Equal(other SatPerKWeight) bool {
	return s.Cmp(other.Rat) == 0
}

// GreaterThan returns true if the fee rate is greater than the other fee rate.
func (s SatPerKWeight) GreaterThan(other SatPerKWeight) bool {
	return s.Cmp(other.Rat) > 0
}

// LessThan returns true if the fee rate is less than the other fee rate.
func (s SatPerKWeight) LessThan(other SatPerKWeight) bool {
	return s.Cmp(other.Rat) < 0
}

// GreaterThanOrEqual returns true if the fee rate is greater than or equal to
// the other fee rate.
func (s SatPerKWeight) GreaterThanOrEqual(other SatPerKWeight) bool {
	return s.Cmp(other.Rat) >= 0
}

// LessThanOrEqual returns true if the fee rate is less than or equal to the
// other fee rate.
func (s SatPerKWeight) LessThanOrEqual(other SatPerKWeight) bool {
	return s.Cmp(other.Rat) <= 0
}

// roundToAmount rounds a big.Rat to the nearest btcutil.Amount (int64),
// with halves rounded away from zero. For example, 2.4 rounds to 2, 2.5
// rounds to 3, and -2.5 rounds to -3.
func roundToAmount(r *big.Rat) btcutil.Amount {
	f, _ := r.Float64()

	return btcutil.Amount(math.Round(f))
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
