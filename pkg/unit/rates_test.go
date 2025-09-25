package unit

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/stretchr/testify/require"
)

// TestFeeRateConversions checks that the conversion between the different fee
// rate units is correct.
func TestFeeRateConversions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		rate         any
		expectedVB   SatPerVByte
		expectedKVB  SatPerKVByte
		expectedKW   SatPerKWeight
		expectedSats btcutil.Amount
	}{
		{
			name:         "1 sat/vb",
			rate:         SatPerVByte(1),
			expectedVB:   SatPerVByte(1),
			expectedKVB:  SatPerKVByte(1000),
			expectedKW:   SatPerKWeight(250),
			expectedSats: 1,
		},
		{
			name:         "1000 sat/kvb",
			rate:         SatPerKVByte(1000),
			expectedVB:   SatPerVByte(1),
			expectedKVB:  SatPerKVByte(1000),
			expectedKW:   SatPerKWeight(250),
			expectedSats: 1000,
		},
		{
			name:         "250 sat/kw",
			rate:         SatPerKWeight(250),
			expectedVB:   SatPerVByte(1),
			expectedKVB:  SatPerKVByte(1000),
			expectedKW:   SatPerKWeight(250),
			expectedSats: 250,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			switch r := tc.rate.(type) {
			case SatPerVByte:
				require.Equal(t, tc.expectedVB, r)
				require.Equal(
					t, tc.expectedKVB, r.FeePerKVByte(),
				)
				require.Equal(
					t, tc.expectedKW, r.FeePerKWeight(),
				)
				require.Equal(
					t, tc.expectedSats, btcutil.Amount(r),
				)

			case SatPerKVByte:
				require.Equal(
					t, tc.expectedVB,
					r.FeePerKWeight().FeePerVByte(),
				)
				require.Equal(t, tc.expectedKVB, r)
				require.Equal(
					t, tc.expectedKW, r.FeePerKWeight(),
				)
				require.Equal(
					t, tc.expectedSats, btcutil.Amount(r),
				)

			case SatPerKWeight:
				require.Equal(
					t, tc.expectedVB, r.FeePerVByte(),
				)
				require.Equal(
					t, tc.expectedKVB, r.FeePerKVByte(),
				)
				require.Equal(t, tc.expectedKW, r)
				require.Equal(
					t, tc.expectedSats, btcutil.Amount(r),
				)
			}
		})
	}
}

// TestFeeForWeightRoundUp checks that the FeeForWeightRoundUp method correctly
// rounds up the fee for a given weight.
func TestFeeForWeightRoundUp(t *testing.T) {
	t.Parallel()

	feeRate := SatPerVByte(1).FeePerKWeight()
	txWeight := WeightUnit(674) // 674 weight units is 168.5 vb.

	require.EqualValues(t, 168, feeRate.FeeForWeight(txWeight))
	require.EqualValues(t, 169, feeRate.FeeForWeightRoundUp(txWeight))
}

// TestNewFeeRateConstructors checks that the New* fee rate constructors work
// as expected.
func TestNewFeeRateConstructors(t *testing.T) {
	t.Parallel()

	// Test NewSatPerKWeight.
	fee := btcutil.Amount(1000)
	wu := WeightUnit(1000)
	expectedRate := SatPerKWeight(1000)
	require.Equal(t, expectedRate, NewSatPerKWeight(fee, wu))

	// Test NewSatPerVByte.
	vb := VByte(250)
	expectedRateVB := SatPerVByte(4)
	require.Equal(t, expectedRateVB, NewSatPerVByte(fee, vb))

	// Test NewSatPerKVByte.
	kvb := VByte(1)
	expectedRateKVB := SatPerKVByte(1000000)
	require.Equal(t, expectedRateKVB, NewSatPerKVByte(fee, kvb))
}
