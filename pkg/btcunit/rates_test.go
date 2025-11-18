package btcunit

import (
	"math"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
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
			rate:         NewSatPerVByte(1, NewVByte(1)),
			expectedVB:   NewSatPerVByte(1, NewVByte(1)),
			expectedKVB:  NewSatPerKVByte(1000, NewKVByte(1)),
			expectedKW:   NewSatPerKWeight(250, NewKWeightUnit(1)),
			expectedSats: 250,
		},
		{
			name:         "1000 sat/kvb",
			rate:         NewSatPerKVByte(1000, NewKVByte(1)),
			expectedVB:   NewSatPerVByte(1, NewVByte(1)),
			expectedKVB:  NewSatPerKVByte(1000, NewKVByte(1)),
			expectedKW:   NewSatPerKWeight(250, NewKWeightUnit(1)),
			expectedSats: 250,
		},
		{
			name:         "250 sat/kw",
			rate:         NewSatPerKWeight(250, NewKWeightUnit(1)),
			expectedVB:   NewSatPerVByte(1, NewVByte(1)),
			expectedKVB:  NewSatPerKVByte(1000, NewKVByte(1)),
			expectedKW:   NewSatPerKWeight(250, NewKWeightUnit(1)),
			expectedSats: 250,
		},
		{
			name:        "0.11 sat/vb",
			rate:        NewSatPerVByte(11, NewVByte(100)),
			expectedVB:  NewSatPerVByte(11, NewVByte(100)),
			expectedKVB: NewSatPerKVByte(110, NewKVByte(1)),
			expectedKW: NewSatPerKWeight(
				27500, NewKWeightUnit(1000),
			),
			expectedSats: 27,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			switch r := tc.rate.(type) {
			case SatPerVByte:
				require.True(t, tc.expectedVB.equal(
					r.ToSatPerVByte().baseFeeRate,
				))
				require.True(t, tc.expectedKVB.equal(
					r.ToSatPerKVByte().baseFeeRate,
				))
				require.True(t, tc.expectedKW.equal(
					r.ToSatPerKWeight().baseFeeRate,
				))

				// Calculate the floor of the fee rate.
				floor := big.NewInt(0)
				floor.Div(
					r.satsPerKWU.Num(),
					r.satsPerKWU.Denom(),
				)
				require.Equal(
					t, tc.expectedSats,
					btcutil.Amount(floor.Int64()),
				)

			case SatPerKVByte:
				require.True(t, tc.expectedVB.equal(
					r.ToSatPerVByte().baseFeeRate,
				))
				require.True(
					t, tc.expectedKVB.equal(r.baseFeeRate),
				)
				require.True(t, tc.expectedKW.equal(
					r.ToSatPerKWeight().baseFeeRate,
				))

				// Calculate the floor of the fee rate.
				floor := big.NewInt(0)
				floor.Div(
					r.satsPerKWU.Num(),
					r.satsPerKWU.Denom(),
				)
				require.Equal(
					t, tc.expectedSats,
					btcutil.Amount(floor.Int64()),
				)

			case SatPerKWeight:
				require.True(t,
					tc.expectedVB.equal(
						r.ToSatPerVByte().baseFeeRate,
					),
				)
				require.True(t, tc.expectedKVB.equal(
					r.ToSatPerKVByte().baseFeeRate,
				))
				require.True(
					t, tc.expectedKW.equal(r.baseFeeRate),
				)

				// Calculate the floor of the fee rate.
				floor := big.NewInt(0)
				floor.Div(
					r.satsPerKWU.Num(),
					r.satsPerKWU.Denom(),
				)
				require.Equal(
					t, tc.expectedSats,
					btcutil.Amount(floor.Int64()),
				)
			}
		})
	}
}

// TestFeeRateComparisonsVB tests the comparison methods of the SatPerVByte
// type.
func TestFeeRateComparisonsVB(t *testing.T) {
	t.Parallel()

	// Create a set of fee rates to compare.
	r1 := NewSatPerVByte(1, NewVByte(1))
	r2 := NewSatPerVByte(2, NewVByte(1))
	r3 := NewSatPerVByte(1, NewVByte(1))

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

	feeRate := NewSatPerVByte(1, NewVByte(1)).ToSatPerKWeight()
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
	expectedRate := NewSatPerKWeight(1000, NewKWeightUnit(1))
	require.Zero(
		t, expectedRate.satsPerKWU.Cmp(
			NewSatPerKWeight(fee, wu.ToKWU()).satsPerKWU,
		),
	)

	// Test NewSatPerVByte.
	vb := NewVByte(250)
	expectedRateVB := NewSatPerVByte(4, NewVByte(1))
	require.Zero(
		t, expectedRateVB.satsPerKWU.Cmp(
			NewSatPerVByte(fee, vb).satsPerKWU,
		),
	)

	// Test NewSatPerKVByte.
	kvb := NewKVByte(1)
	expectedRateKVB := NewSatPerKVByte(1000, NewKVByte(1))
	require.Zero(
		t, expectedRateKVB.satsPerKWU.Cmp(
			NewSatPerKVByte(fee, kvb).satsPerKWU,
		),
	)
}

// TestStringer tests the stringer methods of the fee rate types.
func TestStringer(t *testing.T) {
	t.Parallel()

	// Create a set of fee rates to test.
	r1 := NewSatPerVByte(1, NewVByte(1))
	r2 := NewSatPerKVByte(1000, NewKVByte(1))
	r3 := NewSatPerKWeight(250, NewKWeightUnit(1))

	// Test String.
	require.Equal(t, "1.000 sat/vb", r1.String())
	require.Equal(t, "1000.000 sat/kvb", r2.String())
	require.Equal(t, "250.000 sat/kw", r3.String())
}

// TestFeeRateComparisonsKVB tests the comparison methods of the SatPerKVByte
// type.
func TestFeeRateComparisonsKVB(t *testing.T) {
	t.Parallel()

	// Create a set of fee rates to compare.
	r1 := NewSatPerKVByte(1, NewKVByte(1))
	r2 := NewSatPerKVByte(2, NewKVByte(1))
	r3 := NewSatPerKVByte(1, NewKVByte(1))

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
	r1 := NewSatPerKWeight(1, NewKWeightUnit(1))
	r2 := NewSatPerKWeight(2, NewKWeightUnit(1))
	r3 := NewSatPerKWeight(1, NewKWeightUnit(1))

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
	// r1: 1000 sat/kvb = 1000 sat / 1000 vbyte = 1 sat/vbyte.
	// Since 1 vbyte = 4 weight units, this is 1 sat / 4 wu = 0.25 sat/wu.
	// In canonical units: 0.25 * 1000 = 250 sat/kwu.
	r1 := NewSatPerKVByte(1000, NewKVByte(1))

	// r2: 250 sat/kwu. This matches r1.
	r2 := NewSatPerKWeight(250, NewKWeightUnit(1))

	// r3: 1 sat/vbyte.
	// 1 sat / 4 wu = 0.25 sat/wu = 250 sat/kwu.
	// All three rates are equivalent.
	r3 := NewSatPerVByte(1, NewVByte(1))

	// Test FeeForVByte with r1 (1000 sat/kvb).
	// Size: 250 vbytes.
	// Fee: 250 vbytes * 1 sat/vbyte = 250 sats.
	require.Equal(t, btcutil.Amount(250), r1.FeeForVByte(NewVByte(250)))

	// Test FeeForVByte with r2 (250 sat/kwu).
	// Size: 250 vbytes = 1000 weight units.
	// Rate: 250 sat/1000 wu = 0.25 sat/wu.
	// Fee: 1000 wu * 0.25 sat/wu = 250 sats.
	require.Equal(t, btcutil.Amount(250), r2.FeeForVByte(NewVByte(250)))

	// Test FeeForVByte with SatPerVByte.
	// Size: 1000 vbytes.
	// Rate: 1 sat/vbyte.
	// Fee: 1000 sats.
	require.Equal(t, btcutil.Amount(1000), r3.FeeForVByte(NewVByte(1000)))

	// Test FeeForKVByte with SatPerVByte.
	// Size: 1 kvb = 1000 vbytes.
	// Rate: 1 sat/vbyte.
	// Fee: 1000 sats.
	require.Equal(t, btcutil.Amount(1000), r3.FeeForKVByte(NewKVByte(1)))

	// Test FeeForWeight with SatPerVByte.
	// Size: 1000 weight units.
	// Rate: 1 sat/vbyte = 0.25 sat/wu.
	// Fee: 1000 * 0.25 = 250 sats.
	require.Equal(t, btcutil.Amount(250),
		r3.FeeForWeight(NewWeightUnit(1000)))

	// Test ToSatPerVByte with SatPerKVByte.
	// 1000 sat/kvb should equal 1 sat/vbyte.
	require.True(t, r3.Equal(r1.ToSatPerVByte()))

	// Test FeeForKVByte with SatPerKVByte.
	// Size: 1 kvb.
	// Rate: 1000 sat/kvb.
	// Fee: 1000 sats.
	require.Equal(t, btcutil.Amount(1000), r1.FeeForKVByte(NewKVByte(1)))

	// Test FeeForWeight with SatPerKVByte.
	// Size: 1000 weight units.
	// Rate: 1000 sat/kvb = 0.25 sat/wu.
	// Fee: 1000 * 0.25 = 250 sats.
	require.Equal(t, btcutil.Amount(250),
		r1.FeeForWeight(NewWeightUnit(1000)))

	// Test FeeForKVByte with SatPerKWeight.
	// Size: 1 kvb = 1000 vbytes = 4000 weight units.
	// Rate: 250 sat/kwu = 0.25 sat/wu.
	// Fee: 4000 * 0.25 = 1000 sats.
	require.Equal(t, btcutil.Amount(1000), r2.FeeForKVByte(NewKVByte(1)))

	// Test FeeForKWeight with SatPerKWeight.
	// Size: 1 kwu = 1000 weight units.
	// Rate: 250 sat/kwu = 0.25 sat/wu.
	// Fee: 1000 * 0.25 = 250 sats.
	require.Equal(t, btcutil.Amount(250),
		r2.FeeForKWeight(NewKWeightUnit(1)))
}

// TestNewFeeRateConstructorsZero tests the New* fee rate constructors with
// zero values.
func TestNewFeeRateConstructorsZero(t *testing.T) {
	t.Parallel()

	// Test NewSatPerKWeight with zero weight.
	fee := btcutil.Amount(1000)
	kwu := NewKWeightUnit(0)
	expectedRate := NewSatPerKWeight(0, NewKWeightUnit(1))
	require.Zero(
		t, expectedRate.satsPerKWU.Cmp(
			NewSatPerKWeight(fee, kwu).satsPerKWU,
		),
	)

	// Test NewSatPerVByte with zero vbytes.
	vb := NewVByte(0)
	expectedRateVB := NewSatPerVByte(0, NewVByte(1))
	require.Zero(
		t, expectedRateVB.satsPerKWU.Cmp(
			NewSatPerVByte(fee, vb).satsPerKWU,
		),
	)

	// Test NewSatPerKVByte with zero kvbytes.
	kvb := NewKVByte(0)
	expectedRateKVB := NewSatPerKVByte(0, NewKVByte(1))
	require.Zero(
		t, expectedRateKVB.satsPerKWU.Cmp(
			NewSatPerKVByte(fee, kvb).satsPerKWU,
		),
	)

	// Test zero constants.
	require.True(t, ZeroSatPerVByte.Equal(
		NewSatPerVByte(0, NewVByte(1)),
	))
	require.True(t, ZeroSatPerKVByte.Equal(
		NewSatPerKVByte(0, NewKVByte(1)),
	))
	require.True(t, ZeroSatPerKWeight.Equal(
		NewSatPerKWeight(0, NewKWeightUnit(1)),
	))

	require.Equal(t, "0.000 sat/vb", ZeroSatPerVByte.String())
	require.Equal(t, "0.000 sat/kvb", ZeroSatPerKVByte.String())
	require.Equal(t, "0.000 sat/kw", ZeroSatPerKWeight.String())
}

// TestSafeUint64ToInt64Overflow tests the overflow condition in
// safeUint64ToInt64 through the New* constructors.
func TestSafeUint64ToInt64Overflow(t *testing.T) {
	t.Parallel()

	fee := btcutil.Amount(1)

	// Test NewSatPerVByte with an overflowing vbyte value.
	// The denominator should be capped at math.MaxInt64.
	// We manually construct the VByte to ensure wu > MaxInt64 without
	// overflowing the constructor's internal multiplication.
	overflowVByte := VByte{baseUnit{wu: math.MaxInt64 + 1}}
	expectedDenom := big.NewInt(math.MaxInt64)

	rateVB := NewSatPerVByte(fee, overflowVByte)
	require.Zero(t, expectedDenom.Cmp(rateVB.satsPerKWU.Denom()))

	// Test NewSatPerKVByte with an overflowing kvb value.
	// The denominator should be capped at math.MaxInt64.
	overflowKVByte := KVByte{baseUnit{wu: math.MaxInt64 + 1}}
	rateKVB := NewSatPerKVByte(fee, overflowKVByte)
	require.Zero(t, expectedDenom.Cmp(rateKVB.satsPerKWU.Denom()))

	// Test NewSatPerKWeight with an overflowing weight unit value.
	overflowWU := KWeightUnit{baseUnit{wu: math.MaxInt64 + 1}}
	rateKW := NewSatPerKWeight(fee, overflowWU)
	require.Zero(t, expectedDenom.Cmp(rateKW.satsPerKWU.Denom()))
}
