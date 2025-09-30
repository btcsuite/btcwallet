package unit

import (
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
)

// SatPerVByte represents a fee rate in sat/vbyte.
type SatPerVByte btcutil.Amount

// NewSatPerVByte creates a new fee rate in sat/vb.
func NewSatPerVByte(fee btcutil.Amount, vb VByte) SatPerVByte {
	if vb == 0 {
		return 0
	}
	return SatPerVByte(fee.MulF64(1 / float64(vb)))
}

// FeePerKWeight converts the current fee rate from sat/vb to sat/kw.
func (s SatPerVByte) FeePerKWeight() SatPerKWeight {
	return SatPerKWeight(s * 1000 / blockchain.WitnessScaleFactor)
}

// FeePerKVByte converts the current fee rate from sat/vb to sat/kvb.
func (s SatPerVByte) FeePerKVByte() SatPerKVByte {
	return SatPerKVByte(s * 1000)
}

// String returns a human-readable string of the fee rate.
func (s SatPerVByte) String() string {
	return fmt.Sprintf("%v sat/vb", int64(s))
}

// SatPerKVByte represents a fee rate in sat/kb.
type SatPerKVByte btcutil.Amount

// NewSatPerKVByte creates a new fee rate in sat/kvb.
func NewSatPerKVByte(fee btcutil.Amount, kvb VByte) SatPerKVByte {
	if kvb == 0 {
		return 0
	}
	return SatPerKVByte(fee.MulF64(1000 / float64(kvb)))
}

// FeeForVSize calculates the fee resulting from this fee rate and the given
// vsize in vbytes.
func (s SatPerKVByte) FeeForVSize(vbytes VByte) btcutil.Amount {
	return btcutil.Amount(s) * btcutil.Amount(vbytes) / 1000
}

// FeePerKWeight converts the current fee rate from sat/kb to sat/kw.
func (s SatPerKVByte) FeePerKWeight() SatPerKWeight {
	return SatPerKWeight(s / blockchain.WitnessScaleFactor)
}

// String returns a human-readable string of the fee rate.
func (s SatPerKVByte) String() string {
	return fmt.Sprintf("%v sat/kvb", int64(s))
}

// SatPerKWeight represents a fee rate in sat/kw.
type SatPerKWeight btcutil.Amount

// NewSatPerKWeight creates a new fee rate in sat/kw.
func NewSatPerKWeight(fee btcutil.Amount, wu WeightUnit) SatPerKWeight {
	if wu == 0 {
		return 0
	}
	return SatPerKWeight(fee.MulF64(1000 / float64(wu)))
}

// FeeForWeight calculates the fee resulting from this fee rate and the given
// weight in weight units (wu).
func (s SatPerKWeight) FeeForWeight(wu WeightUnit) btcutil.Amount {
	// The resulting fee is rounded down, as specified in BOLT#03.
	return btcutil.Amount(s) * btcutil.Amount(wu) / 1000
}

// FeeForWeightRoundUp calculates the fee resulting from this fee rate and the
// given weight in weight units (wu), rounding up to the nearest satoshi.
func (s SatPerKWeight) FeeForWeightRoundUp(
	wu WeightUnit) btcutil.Amount {

	return (btcutil.Amount(s)*btcutil.Amount(wu) + 999) / 1000
}

// FeeForVByte calculates the fee resulting from this fee rate and the given
// size in vbytes (vb).
func (s SatPerKWeight) FeeForVByte(vb VByte) btcutil.Amount {
	return s.FeePerKVByte().FeeForVSize(vb)
}

// FeePerKVByte converts the current fee rate from sat/kw to sat/kb.
func (s SatPerKWeight) FeePerKVByte() SatPerKVByte {
	return SatPerKVByte(s * blockchain.WitnessScaleFactor)
}

// FeePerVByte converts the current fee rate from sat/kw to sat/vb.
func (s SatPerKWeight) FeePerVByte() SatPerVByte {
	return SatPerVByte(s * blockchain.WitnessScaleFactor / 1000)
}

// String returns a human-readable string of the fee rate.
func (s SatPerKWeight) String() string {
	return fmt.Sprintf("%v sat/kw", int64(s))
}
