package btcunit

import (
	"fmt"
	"math"

	"github.com/btcsuite/btcd/blockchain"
)

// WeightUnit defines a unit to express the transaction size. One weight unit
// is 1/4_000_000 of the max block size. The tx weight is calculated using
// `Base tx size * 3 + Total tx size`.
//   - Base tx size is size of the transaction serialized without the witness
//     data.
//   - Total tx size is the transaction size in bytes serialized according
//     #BIP144.
type WeightUnit struct {
	val uint64
}

// NewWeightUnit creates a new WeightUnit from a uint64.
func NewWeightUnit(val uint64) WeightUnit {
	return WeightUnit{val: val}
}

// ToVB converts a value expressed in weight units to virtual bytes.
func (wu WeightUnit) ToVB() VByte {
	// According to BIP141: Virtual transaction size is defined as
	// Transaction weight / 4 (rounded up to the next integer).
	vbytes := math.Ceil(float64(wu.val) / blockchain.WitnessScaleFactor)
	return VByte{val: uint64(vbytes)}
}

// String returns the string representation of the weight unit.
func (wu WeightUnit) String() string {
	return fmt.Sprintf("%d wu", wu.val)
}

// VByte defines a unit to express the transaction size. One virtual byte is
// 1/4th of a weight unit. The tx virtual bytes is calculated using `TxWeight /
// 4`.
type VByte struct {
	val uint64
}

// NewVByte creates a new VByte from a uint64.
func NewVByte(val uint64) VByte {
	return VByte{val: val}
}

// ToWU converts a value expressed in virtual bytes to weight units.
func (vb VByte) ToWU() WeightUnit {
	return WeightUnit{val: vb.val * blockchain.WitnessScaleFactor}
}

// String returns the string representation of the virtual byte.
func (vb VByte) String() string {
	return fmt.Sprintf("%d vb", vb.val)
}
