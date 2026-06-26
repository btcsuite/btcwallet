package btcunit

import (
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
)

// baseUnit stores the canonical representation of a transaction size, which is
// weight units (wu). All other size units are derived from this.
type baseUnit struct {
	wu uint64
}

// ToWU converts the unit to a WeightUnit.
func (b baseUnit) ToWU() WeightUnit {
	return WeightUnit{b}
}

// ToVB converts the unit to a VByte.
func (b baseUnit) ToVB() VByte {
	return VByte{b}
}

// ToKVB converts the unit to a KVByte.
func (b baseUnit) ToKVB() KVByte {
	return KVByte{b}
}

// ToKWU converts the unit to a KWeightUnit.
func (b baseUnit) ToKWU() KWeightUnit {
	return KWeightUnit{b}
}

// WeightUnit defines a unit to express the transaction size. One weight unit
// is 1/4_000_000 of the max block size. The tx weight is calculated using
// `Base tx size * 3 + Total tx size`.
//   - Base tx size is size of the transaction serialized without the witness
//     data.
//   - Total tx size is the transaction size in bytes serialized according
//     #BIP144.
type WeightUnit struct {
	// The internal size is recorded in weight units.
	baseUnit
}

// NewWeightUnit creates a new WeightUnit from a uint64 value.
func NewWeightUnit(val uint64) WeightUnit {
	return WeightUnit{baseUnit{wu: val}}
}

// String returns the string representation of the weight unit.
func (w WeightUnit) String() string {
	return fmt.Sprintf("%d wu", w.wu)
}

// VByte defines a unit to express the transaction size. One virtual byte is
// 1/4th of a weight unit. The tx virtual bytes is calculated using `TxWeight /
// 4`.
type VByte struct {
	// The internal size is recorded in weight units.
	baseUnit
}

// NewVByte creates a new VByte from a uint64 value.
func NewVByte(val uint64) VByte {
	return VByte{baseUnit{wu: val * blockchain.WitnessScaleFactor}}
}

// String returns the string representation of the virtual byte.
func (v VByte) String() string {
	vbytes := (v.wu + blockchain.WitnessScaleFactor - 1) /
		blockchain.WitnessScaleFactor

	return fmt.Sprintf("%d vb", vbytes)
}

// KVByte defines a unit to express the transaction size in kilo-virtual-bytes.
type KVByte struct {
	// The internal size is recorded in weight units.
	baseUnit
}

// NewKVByte creates a new KVByte from a uint64.
func NewKVByte(val uint64) KVByte {
	return KVByte{baseUnit{wu: val * kilo * blockchain.WitnessScaleFactor}}
}

// String returns the string representation of the kilo-virtual-byte.
func (k KVByte) String() string {
	vbytes := (k.wu + blockchain.WitnessScaleFactor - 1) /
		blockchain.WitnessScaleFactor

	return fmt.Sprintf("%d kvb", vbytes/kilo)
}

// KWeightUnit defines a unit to express the transaction size in
// kilo-weight-units.
type KWeightUnit struct {
	// The internal size is recorded in weight units.
	baseUnit
}

// NewKWeightUnit creates a new KWeightUnit from a uint64.
func NewKWeightUnit(val uint64) KWeightUnit {
	return KWeightUnit{baseUnit{wu: val * kilo}}
}

// String returns the string representation of the kilo-weight-unit.
func (k KWeightUnit) String() string {
	return fmt.Sprintf("%d kwu", k.wu/kilo)
}
