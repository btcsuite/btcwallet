package unit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTxSizeConversion checks that the conversion between weight units and
// virtual bytes is correct.
func TestTxSizeConversion(t *testing.T) {
	t.Parallel()

	// Create a test weight of 1000 wu.
	wu := WeightUnit(1000)

	// 1000 wu should be equal to 250 vb.
	require.Equal(t, VByte(250), wu.ToVB())

	// 250 vb should be equal to 1000 wu.
	require.Equal(t, wu, VByte(250).ToWU())
}
