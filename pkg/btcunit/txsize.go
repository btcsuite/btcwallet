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

// KVByte defines a unit to express the transaction size in kilo-virtual-bytes.
type KVByte struct {
	val uint64
}

// NewKVByte creates a new KVByte from a uint64.
func NewKVByte(val uint64) KVByte {
	return KVByte{val: val}
}

// ToVB converts a value expressed in kilo-virtual-bytes to virtual bytes.
func (kvb KVByte) ToVB() VByte {
	return VByte{val: kvb.val * 1000}
}

// String returns the string representation of the kilo-virtual-byte.
func (kvb KVByte) String() string {
	return fmt.Sprintf("%d kvb", kvb.val)
}

// KWeightUnit defines a unit to express the transaction size in
// kilo-weight-units.
type KWeightUnit struct {
	val uint64
}

// NewKWeightUnit creates a new KWeightUnit from a uint64.
func NewKWeightUnit(val uint64) KWeightUnit {
	return KWeightUnit{val: val}
}

// ToWU converts a value expressed in kilo-weight-units to weight units.
func (kwu KWeightUnit) ToWU() WeightUnit {
	return WeightUnit{val: kwu.val * 1000}
}

// String returns the string representation of the kilo-weight-unit.
func (kwu KWeightUnit) String() string {
	return fmt.Sprintf("%d kwu", kwu.val)
}
