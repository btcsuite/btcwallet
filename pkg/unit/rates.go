// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package unit provides a set of types for dealing with bitcoin units.
package unit

import (
	"fmt"
	"log/slog"
	"math"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
)

const (
	// SatsPerKilo is the number of satoshis in a kilo-satoshi.
	SatsPerKilo = 1000
)

// SatPerVByte represents a fee rate in sat/vbyte.
type SatPerVByte struct {
	btcutil.Amount
}

// NewSatPerVByte creates a new fee rate in sat/vb.
func NewSatPerVByte(fee btcutil.Amount, vb VByte) SatPerVByte {
	if vb == 0 {
		return SatPerVByte{0}
	}

	return SatPerVByte{fee.MulF64(1 / float64(vb))}
}

// FeePerKWeight converts the current fee rate from sat/vb to sat/kw.
func (s SatPerVByte) FeePerKWeight() SatPerKWeight {
	return SatPerKWeight{
		s.Amount * SatsPerKilo / blockchain.WitnessScaleFactor,
	}
}

// FeePerKVByte converts the current fee rate from sat/vb to sat/kvb.
func (s SatPerVByte) FeePerKVByte() SatPerKVByte {
	return SatPerKVByte{s.Amount * SatsPerKilo}
}

// String returns a human-readable string of the fee rate.
func (s SatPerVByte) String() string {
	return fmt.Sprintf("%v sat/vb", int64(s.Amount))
}

// SatPerKVByte represents a fee rate in sat/kb.
type SatPerKVByte struct {
	btcutil.Amount
}

// NewSatPerKVByte creates a new fee rate in sat/kvb.
func NewSatPerKVByte(fee btcutil.Amount, kvb VByte) SatPerKVByte {
	if kvb == 0 {
		return SatPerKVByte{0}
	}

	return SatPerKVByte{fee.MulF64(SatsPerKilo / float64(kvb))}
}

// FeeForVSize calculates the fee resulting from this fee rate and the given
// vsize in vbytes.
func (s SatPerKVByte) FeeForVSize(vbytes VByte) btcutil.Amount {
	return s.Amount *
		btcutil.Amount(safeUint64ToInt64(uint64(vbytes))) / SatsPerKilo
}

// FeePerKWeight converts the current fee rate from sat/kb to sat/kw.
func (s SatPerKVByte) FeePerKWeight() SatPerKWeight {
	return SatPerKWeight{s.Amount / blockchain.WitnessScaleFactor}
}

// String returns a human-readable string of the fee rate.
func (s SatPerKVByte) String() string {
	return fmt.Sprintf("%v sat/kvb", int64(s.Amount))
}

// SatPerKWeight represents a fee rate in sat/kw.
type SatPerKWeight struct {
	btcutil.Amount
}

// NewSatPerKWeight creates a new fee rate in sat/kw.
func NewSatPerKWeight(fee btcutil.Amount, wu WeightUnit) SatPerKWeight {
	if wu == 0 {
		return SatPerKWeight{0}
	}

	return SatPerKWeight{fee.MulF64(SatsPerKilo / float64(wu))}
}

// FeeForWeight calculates the fee resulting from this fee rate and the given
// weight in weight units (wu).
func (s SatPerKWeight) FeeForWeight(wu WeightUnit) btcutil.Amount {
	// The resulting fee is rounded down, as specified in BOLT#03.
	return s.Amount *
		btcutil.Amount(safeUint64ToInt64(uint64(wu))) / SatsPerKilo
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
	fee := s.Amount * btcutil.Amount(safeUint64ToInt64(uint64(wu)))
	fee += SatsPerKilo - 1

	return fee / SatsPerKilo
}

// FeeForVByte calculates the fee resulting from this fee rate and the given
// size in vbytes (vb).
func (s SatPerKWeight) FeeForVByte(vb VByte) btcutil.Amount {
	return s.FeePerKVByte().FeeForVSize(vb)
}

// FeePerKVByte converts the current fee rate from sat/kw to sat/kb.
func (s SatPerKWeight) FeePerKVByte() SatPerKVByte {
	return SatPerKVByte{s.Amount * blockchain.WitnessScaleFactor}
}

// FeePerVByte converts the current fee rate from sat/kw to sat/vb.
func (s SatPerKWeight) FeePerVByte() SatPerVByte {
	return SatPerVByte{
		s.Amount * blockchain.WitnessScaleFactor / SatsPerKilo,
	}
}

// String returns a human-readable string of the fee rate.
func (s SatPerKWeight) String() string {
	return fmt.Sprintf("%v sat/kw", int64(s.Amount))
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
