package btcunit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTxSizeConversion checks that the conversion between weight units and
// virtual bytes is correct.
func TestTxSizeConversion(t *testing.T) {
	t.Parallel()

	// Create a test weight of 1000 wu.
	wu := NewWeightUnit(1000)

	// 1000 wu should be equal to 250 vb.
	require.Equal(t, NewVByte(250), wu.ToVB())

	// 250 vb should be equal to 1000 wu.
	require.Equal(t, wu, NewVByte(250).ToWU())

	// Create a test kvbyte of 1 kvb.
	kvb := NewKVByte(1)

	// 1 kvb should be equal to 1000 vb.
	require.Equal(t, NewVByte(1000), kvb.ToVB())

	// Create a test kweightunit of 1 kwu.
	kwu := NewKWeightUnit(1)

	// 1 kwu should be equal to 1000 wu.
	require.Equal(t, NewWeightUnit(1000), kwu.ToWU())
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
