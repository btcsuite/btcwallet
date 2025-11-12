package btcunit

import (
	"math"
	"math/big"
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
			rate:         SatPerVByte{big.NewRat(1, 1)},
			expectedVB:   SatPerVByte{big.NewRat(1, 1)},
			expectedKVB:  SatPerKVByte{big.NewRat(1000, 1)},
			expectedKW:   SatPerKWeight{big.NewRat(250, 1)},
			expectedSats: 1,
		},
		{
			name:         "1000 sat/kvb",
			rate:         SatPerKVByte{big.NewRat(1000, 1)},
			expectedVB:   SatPerVByte{big.NewRat(1, 1)},
			expectedKVB:  SatPerKVByte{big.NewRat(1000, 1)},
			expectedKW:   SatPerKWeight{big.NewRat(250, 1)},
			expectedSats: 1000,
		},
		{
			name:         "250 sat/kw",
			rate:         SatPerKWeight{big.NewRat(250, 1)},
			expectedVB:   SatPerVByte{big.NewRat(1, 1)},
			expectedKVB:  SatPerKVByte{big.NewRat(1000, 1)},
			expectedKW:   SatPerKWeight{big.NewRat(250, 1)},
			expectedSats: 250,
		},
		{
			name:         "0.11 sat/vb",
			rate:         SatPerVByte{big.NewRat(11, 100)},
			expectedVB:   SatPerVByte{big.NewRat(11, 100)},
			expectedKVB:  SatPerKVByte{big.NewRat(110, 1)},
			expectedKW:   SatPerKWeight{big.NewRat(11000, 400)},
			expectedSats: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			switch r := tc.rate.(type) {
			case SatPerVByte:
				require.True(t, tc.expectedVB.Equal(r))
				require.True(t, tc.expectedKVB.Equal(
					r.FeePerKVByte()),
				)
				require.True(t, tc.expectedKW.Equal(
					r.FeePerKWeight()),
				)

				// The expected sats is the floor of the fee
				// rate.
				floor := new(big.Int).Div(r.Num(), r.Denom())
				require.Equal(
					t, tc.expectedSats,
					btcutil.Amount(floor.Int64()),
				)

			case SatPerKVByte:
				require.True(t, tc.expectedVB.Equal(
					r.FeePerKWeight().FeePerVByte()),
				)
				require.True(t, tc.expectedKVB.Equal(r))
				require.True(t, tc.expectedKW.Equal(
					r.FeePerKWeight()),
				)
				floor := new(big.Int).Div(r.Num(), r.Denom())
				require.Equal(
					t, tc.expectedSats,
					btcutil.Amount(floor.Int64()),
				)

			case SatPerKWeight:
				require.True(t, tc.expectedVB.Equal(
					r.FeePerVByte()),
				)
				require.True(t, tc.expectedKVB.Equal(
					r.FeePerKVByte()),
				)
				require.True(t, tc.expectedKW.Equal(r))
				floor := new(big.Int).Div(r.Num(), r.Denom())
				require.Equal(
					t, tc.expectedSats,
					btcutil.Amount(floor.Int64()),
				)
			}
		})
	}
}

// TestFeeRateComparisons tests the comparison methods of the fee rate types.
func TestFeeRateComparisons(t *testing.T) {
	t.Parallel()

	// Create a set of fee rates to compare.
	r1 := SatPerVByte{big.NewRat(1, 1)}
	r2 := SatPerVByte{big.NewRat(2, 1)}
	r3 := SatPerVByte{big.NewRat(1, 1)}

	// Test Equal.
	require.True(t, r1.Equal(r3))
	require.False(t, r1.Equal(r2))

	// Test GreaterThan.
	require.True(t, r2.GreaterThan(r1))
	require.False(t, r1.GreaterThan(r2))
	require.False(t, r1.GreaterThan(r3))

	// Test LessThan.
	require.True(t, r1.LessThan(r2))
	require.False(t, r2.LessThan(r1))
	require.False(t, r1.LessThan(r3))

	// Test GreaterThanOrEqual.
	require.True(t, r2.GreaterThanOrEqual(r1))
	require.True(t, r1.GreaterThanOrEqual(r3))
	require.False(t, r1.GreaterThanOrEqual(r2))

	// Test LessThanOrEqual.
	require.True(t, r1.LessThanOrEqual(r2))
	require.True(t, r1.LessThanOrEqual(r3))
	require.False(t, r2.LessThanOrEqual(r1))
}

// TestFeeForWeightRoundUp checks that the FeeForWeightRoundUp method correctly
// rounds up the fee for a given weight.
func TestFeeForWeightRoundUp(t *testing.T) {
	t.Parallel()

	feeRate := SatPerVByte{big.NewRat(1, 1)}.FeePerKWeight()
	txWeight := NewWeightUnit(674) // 674 weight units is 168.5 vb.

	require.EqualValues(t, 168, feeRate.FeeForWeight(txWeight))
	require.EqualValues(t, 169, feeRate.FeeForWeightRoundUp(txWeight))
}

// TestNewFeeRateConstructors checks that the New* fee rate constructors work
// as expected.
func TestNewFeeRateConstructors(t *testing.T) {
	t.Parallel()

	// Test NewSatPerKWeight.
	fee := btcutil.Amount(1000)
	wu := NewWeightUnit(1000)
	expectedRate := SatPerKWeight{big.NewRat(1000, 1)}
	require.Zero(
		t, expectedRate.Cmp(NewSatPerKWeight(fee, wu).Rat),
	)

	// Test NewSatPerVByte.
	vb := NewVByte(250)
	expectedRateVB := SatPerVByte{big.NewRat(4, 1)}
	require.Zero(
		t, expectedRateVB.Cmp(NewSatPerVByte(fee, vb).Rat),
	)

	// Test NewSatPerKVByte.
	kvb := NewVByte(1)
	expectedRateKVB := SatPerKVByte{big.NewRat(1000000, 1)}
	require.Zero(
		t, expectedRateKVB.Cmp(NewSatPerKVByte(fee, kvb).Rat),
	)
}

// TestStringer tests the stringer methods of the fee rate types.
func TestStringer(t *testing.T) {
	t.Parallel()

	// Create a set of fee rates to test.
	r1 := SatPerVByte{big.NewRat(1, 1)}
	r2 := SatPerKVByte{big.NewRat(1000, 1)}
	r3 := SatPerKWeight{big.NewRat(250, 1)}

	// Test String.
	require.Equal(t, "1.00 sat/vb", r1.String())
	require.Equal(t, "1000.00 sat/kvb", r2.String())
	require.Equal(t, "250.00 sat/kw", r3.String())
}

// TestFeeRateComparisonsKVB tests the comparison methods of the SatPerKVByte
// type.
func TestFeeRateComparisonsKVB(t *testing.T) {
	t.Parallel()

	// Create a set of fee rates to compare.
	r1 := SatPerKVByte{big.NewRat(1, 1)}
	r2 := SatPerKVByte{big.NewRat(2, 1)}
	r3 := SatPerKVByte{big.NewRat(1, 1)}

	// Test Equal.
	require.True(t, r1.Equal(r3))
	require.False(t, r1.Equal(r2))

	// Test GreaterThan.
	require.True(t, r2.GreaterThan(r1))
	require.False(t, r1.GreaterThan(r2))
	require.False(t, r1.GreaterThan(r3))

	// Test LessThan.
	require.True(t, r1.LessThan(r2))
	require.False(t, r2.LessThan(r1))
	require.False(t, r1.LessThan(r3))

	// Test GreaterThanOrEqual.
	require.True(t, r2.GreaterThanOrEqual(r1))
	require.True(t, r1.GreaterThanOrEqual(r3))
	require.False(t, r1.GreaterThanOrEqual(r2))

	// Test LessThanOrEqual.
	require.True(t, r1.LessThanOrEqual(r2))
	require.True(t, r1.LessThanOrEqual(r3))
	require.False(t, r2.LessThanOrEqual(r1))
}

// TestFeeRateComparisonsKW tests the comparison methods of the SatPerKWeight
// type.
func TestFeeRateComparisonsKW(t *testing.T) {
	t.Parallel()

	// Create a set of fee rates to compare.
	r1 := SatPerKWeight{big.NewRat(1, 1)}
	r2 := SatPerKWeight{big.NewRat(2, 1)}
	r3 := SatPerKWeight{big.NewRat(1, 1)}

	// Test Equal.
	require.True(t, r1.Equal(r3))
	require.False(t, r1.Equal(r2))

	// Test GreaterThan.
	require.True(t, r2.GreaterThan(r1))
	require.False(t, r1.GreaterThan(r2))
	require.False(t, r1.GreaterThan(r3))

	// Test LessThan.
	require.True(t, r1.LessThan(r2))
	require.False(t, r2.LessThan(r1))
	require.False(t, r1.LessThan(r3))

	// Test GreaterThanOrEqual.
	require.True(t, r2.GreaterThanOrEqual(r1))
	require.True(t, r1.GreaterThanOrEqual(r3))
	require.False(t, r1.GreaterThanOrEqual(r2))

	// Test LessThanOrEqual.
	require.True(t, r1.LessThanOrEqual(r2))
	require.True(t, r1.LessThanOrEqual(r3))
	require.False(t, r2.LessThanOrEqual(r1))
}

// TestFeeForSize tests the FeeForVSize and FeeForVByte methods.
func TestFeeForSize(t *testing.T) {
	t.Parallel()

	// Create a set of fee rates to test.
	r1 := SatPerKVByte{big.NewRat(1000, 1)}
	r2 := SatPerKWeight{big.NewRat(250, 1)}

	// Test FeeForVSize.
	require.Equal(t, btcutil.Amount(250), r1.FeeForVSize(NewVByte(250)))

	// Test FeeForVByte.
	require.Equal(t, btcutil.Amount(250), r2.FeeForVByte(NewVByte(250)))
}

// TestNewFeeRateConstructorsZero tests the New* fee rate constructors with
// zero values.
func TestNewFeeRateConstructorsZero(t *testing.T) {
	t.Parallel()

	// Test NewSatPerKWeight with zero weight.
	fee := btcutil.Amount(1000)
	wu := NewWeightUnit(0)
	expectedRate := SatPerKWeight{big.NewRat(0, 1)}
	require.Zero(
		t, expectedRate.Cmp(NewSatPerKWeight(fee, wu).Rat),
	)

	// Test NewSatPerVByte with zero vbytes.
	vb := NewVByte(0)
	expectedRateVB := SatPerVByte{big.NewRat(0, 1)}
	require.Zero(
		t, expectedRateVB.Cmp(NewSatPerVByte(fee, vb).Rat),
	)

	// Test NewSatPerKVByte with zero kvbytes.
	kvb := NewVByte(0)
	expectedRateKVB := SatPerKVByte{big.NewRat(0, 1)}
	require.Zero(
		t, expectedRateKVB.Cmp(NewSatPerKVByte(fee, kvb).Rat),
	)
}

// TestSafeUint64ToInt64Overflow tests the overflow condition in
// safeUint64ToInt64 through the New* constructors.
func TestSafeUint64ToInt64Overflow(t *testing.T) {
	t.Parallel()

	fee := btcutil.Amount(1)
	overflowVByte := NewVByte(math.MaxInt64 + 1)

	// Test NewSatPerVByte with an overflowing vbyte value.
	// The denominator should be capped at math.MaxInt64.
	rateVB := NewSatPerVByte(fee, overflowVByte)
	expectedDenom := big.NewInt(math.MaxInt64)
	require.Zero(t, expectedDenom.Cmp(rateVB.Denom()))

	// Test NewSatPerKVByte with an overflowing kvb value.
	// The denominator should be capped at math.MaxInt64.
	rateKVB := NewSatPerKVByte(fee, overflowVByte)
	require.Zero(t, expectedDenom.Cmp(rateKVB.Denom()))

	// Test NewSatPerKWeight with an overflowing weight unit value.
	overflowWU := NewWeightUnit(math.MaxInt64 + 1)
	rateKW := NewSatPerKWeight(fee, overflowWU)
	require.Zero(t, expectedDenom.Cmp(rateKW.Denom()))
}
