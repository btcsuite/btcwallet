package btcunit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBaseUnitConversions checks that the conversion methods of baseUnit are
// correct.
func TestBaseUnitConversions(t *testing.T) {
	t.Parallel()

	// Test data: 1000 weight units.
	base := baseUnit{wu: 1000}

	// Test ToWU: 1000 wu.
	wu := base.ToWU()
	require.Equal(t, uint64(1000), wu.wu)

	// Test ToVByte: 1000 wu (250 vb).
	vb := base.ToVB()
	require.Equal(t, uint64(1000), vb.wu)

	// Test ToKVByte: 1000 wu (0.25 kvb).
	kvb := base.ToKVB()
	require.Equal(t, uint64(1000), kvb.wu)

	// Test ToKWeightUnit: 1000 wu (1 kwu).
	kwu := base.ToKWU()
	require.Equal(t, uint64(1000), kwu.wu)
}

// TestTxSizeConversion checks that the conversion between weight units and
// virtual bytes is correct.
func TestTxSizeConversion(t *testing.T) {
	t.Parallel()

	// We'll use 4000 weight units (wu) as our base for testing. This is
	// equivalent to 1000 virtual bytes (vb), 1 kilo-virtual-byte (kvb),
	// and 4 kilo-weight-units (kwu).
	//
	// Initialize the same size in different units.
	wu := NewWeightUnit(4000)
	vb := NewVByte(1000)
	kvb := NewKVByte(1)
	kwu := NewKWeightUnit(4)

	// Check that the internal 'wu' values are consistent across different
	// unit types representing the same size.
	require.Equal(t, uint64(4000), wu.wu)
	require.Equal(t, uint64(4000), vb.wu)
	require.Equal(t, uint64(4000), kvb.wu)
	require.Equal(t, uint64(4000), kwu.wu)

	// Test conversions from WeightUnit. After conversion, the underlying
	// weight units (wu) should remain 4000.
	require.Equal(t, uint64(4000), wu.ToWU().wu)
	require.Equal(t, uint64(4000), wu.ToVB().wu)
	require.Equal(t, uint64(4000), wu.ToKVB().wu)
	require.Equal(t, uint64(4000), wu.ToKWU().wu)
	require.Equal(t, "4000 wu", wu.String())

	// Test conversions from VByte. After conversion, the underlying weight
	// units (wu) should remain 4000.
	require.Equal(t, uint64(4000), vb.ToWU().wu)
	require.Equal(t, uint64(4000), vb.ToVB().wu)
	require.Equal(t, uint64(4000), vb.ToKVB().wu)
	require.Equal(t, uint64(4000), vb.ToKWU().wu)
	require.Equal(t, "1000 vb", vb.String())

	// Test conversions from KVByte. After conversion, the underlying
	// weight units (wu) should remain 4000.
	require.Equal(t, uint64(4000), kvb.ToWU().wu)
	require.Equal(t, uint64(4000), kvb.ToVB().wu)
	require.Equal(t, uint64(4000), kvb.ToKVB().wu)
	require.Equal(t, uint64(4000), kvb.ToKWU().wu)
	require.Equal(t, "1 kvb", kvb.String())

	// Test conversions from KWeightUnit. After conversion, the underlying
	// weight units (wu) should remain 4000.
	require.Equal(t, uint64(4000), kwu.ToWU().wu)
	require.Equal(t, uint64(4000), kwu.ToVB().wu)
	require.Equal(t, uint64(4000), kwu.ToKVB().wu)
	require.Equal(t, uint64(4000), kwu.ToKWU().wu)
	require.Equal(t, "4 kwu", kwu.String())
}

// TestTxSizePrecision checks that precision is preserved when converting
// between units for values that are not perfectly divisible by the witness
// scale factor.
func TestTxSizePrecision(t *testing.T) {
	t.Parallel()

	// Use a weight unit value that is not divisible by 4
	// (WitnessScaleFactor).
	// 3999 % 4 = 3.
	wu := NewWeightUnit(3999)

	// Convert to VByte. This should wrap the same underlying wu value.
	vb := wu.ToVB()
	require.Equal(t, uint64(3999), vb.wu)

	// Convert back to WeightUnit. Should still be 3999.
	wu2 := vb.ToWU()
	require.Equal(t, uint64(3999), wu2.wu)

	// The string representation should still perform the rounding for
	// display.
	// ceil(3999 / 4) = 1000.
	require.Equal(t, "1000 vb", vb.String())
}

// TestTxSizeStringer tests the stringer methods of the tx size types.
func TestTxSizeStringer(t *testing.T) {
	t.Parallel()

	// Create a test weight of 1000 wu.
	wu := NewWeightUnit(1000)
	vb := NewVByte(250)
	kvb := NewKVByte(1)
	kwu := NewKWeightUnit(1)

	// Test String.
	require.Equal(t, "1000 wu", wu.String())
	require.Equal(t, "250 vb", vb.String())
	require.Equal(t, "1 kvb", kvb.String())
	require.Equal(t, "1 kwu", kwu.String())
}
