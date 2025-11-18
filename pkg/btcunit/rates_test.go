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
		expectedW    SatPerWeight
		expectedSats btcutil.Amount
	}{
		{
			name:         "1 sat/vb",
			rate:         NewSatPerVByte(1),
			expectedVB:   NewSatPerVByte(1),
			expectedKVB:  NewSatPerKVByte(1000),
			expectedKW:   NewSatPerKWeight(250),
			expectedW:    CalcSatPerWeight(1, NewWeightUnit(4)),
			expectedSats: 250,
		},
		{
			name:         "1000 sat/kvb",
			rate:         NewSatPerKVByte(1000),
			expectedVB:   NewSatPerVByte(1),
			expectedKVB:  NewSatPerKVByte(1000),
			expectedKW:   NewSatPerKWeight(250),
			expectedW:    CalcSatPerWeight(1, NewWeightUnit(4)),
			expectedSats: 250,
		},
		{
			name:         "250 sat/kw",
			rate:         NewSatPerKWeight(250),
			expectedVB:   NewSatPerVByte(1),
			expectedKVB:  NewSatPerKVByte(1000),
			expectedKW:   NewSatPerKWeight(250),
			expectedW:    CalcSatPerWeight(1, NewWeightUnit(4)),
			expectedSats: 250,
		},
		{
			name:         "0.25 sat/wu",
			rate:         CalcSatPerWeight(1, NewWeightUnit(4)),
			expectedVB:   NewSatPerVByte(1),
			expectedKVB:  NewSatPerKVByte(1000),
			expectedKW:   NewSatPerKWeight(250),
			expectedW:    CalcSatPerWeight(1, NewWeightUnit(4)),
			expectedSats: 250,
		},
		{
			name:         "0.11 sat/vb",
			rate:         CalcSatPerVByte(11, NewVByte(100)),
			expectedVB:   CalcSatPerVByte(11, NewVByte(100)),
			expectedKVB:  NewSatPerKVByte(110),
			expectedKW:   CalcSatPerKWeight(55, NewKWeightUnit(2)),
			expectedW:    CalcSatPerWeight(11, NewWeightUnit(400)),
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
				require.True(t, tc.expectedW.equal(
					r.ToSatPerWeight().baseFeeRate,
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
				require.True(t, tc.expectedW.equal(
					r.ToSatPerWeight().baseFeeRate,
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
				require.True(t, tc.expectedW.equal(
					r.ToSatPerWeight().baseFeeRate,
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

			case SatPerWeight:
				require.True(t, tc.expectedVB.equal(
					r.ToSatPerVByte().baseFeeRate,
				))
				require.True(t, tc.expectedKVB.equal(
					r.ToSatPerKVByte().baseFeeRate,
				))
				require.True(t, tc.expectedKW.equal(
					r.ToSatPerKWeight().baseFeeRate,
				))
				require.True(
					t, tc.expectedW.equal(r.baseFeeRate),
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
	r1 := NewSatPerVByte(1)
	r2 := NewSatPerVByte(2)
	r3 := NewSatPerVByte(1)

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

	feeRate := NewSatPerVByte(1).ToSatPerKWeight()
	txWeight := NewWeightUnit(674) // 674 weight units is 168.5 vb.

	require.EqualValues(t, 168, feeRate.FeeForWeight(txWeight))
	require.EqualValues(t, 169, feeRate.FeeForWeightRoundUp(txWeight))
}

// TestNewFeeRateConstructors checks that the New* and Calc* fee rate
// constructors work as expected.
func TestNewFeeRateConstructors(t *testing.T) {
	t.Parallel()

	// Test CalcSatPerKWeight.
	fee := btcutil.Amount(1000)
	wu := NewWeightUnit(1000)
	expectedRate := NewSatPerKWeight(1000)
	require.Zero(
		t, expectedRate.satsPerKWU.Cmp(
			CalcSatPerKWeight(fee, wu.ToKWU()).satsPerKWU,
		),
	)

	// Test CalcSatPerWeight.
	expectedRateW := NewSatPerWeight(1000)
	require.Zero(
		t, expectedRateW.satsPerKWU.Cmp(
			CalcSatPerWeight(fee, NewWeightUnit(1)).satsPerKWU,
		),
	)

	// Test CalcSatPerVByte.
	vb := NewVByte(250)
	expectedRateVB := NewSatPerVByte(4)
	require.Zero(
		t, expectedRateVB.satsPerKWU.Cmp(
			CalcSatPerVByte(fee, vb).satsPerKWU,
		),
	)

	// Test CalcSatPerKVByte.
	kvb := NewKVByte(1)
	expectedRateKVB := NewSatPerKVByte(1000)
	require.Zero(
		t, expectedRateKVB.satsPerKWU.Cmp(
			CalcSatPerKVByte(fee, kvb).satsPerKWU,
		),
	)
}

// TestStringer tests the stringer methods of the fee rate types.
func TestStringer(t *testing.T) {
	t.Parallel()

	// Create a set of fee rates to test.
	r1 := NewSatPerVByte(1)
	r2 := NewSatPerKVByte(1000)
	r3 := NewSatPerKWeight(250)
	r4 := CalcSatPerWeight(1, NewWeightUnit(4)) // 0.25 sat/wu

	// Test String.
	require.Equal(t, "1.000 sat/vb", r1.String())
	require.Equal(t, "1000.000 sat/kvb", r2.String())
	require.Equal(t, "250.000 sat/kw", r3.String())
	require.Equal(t, "0.250 sat/wu", r4.String())
}

// TestFeeRateComparisonsKVB tests the comparison methods of the SatPerKVByte
// type.
func TestFeeRateComparisonsKVB(t *testing.T) {
	t.Parallel()

	// Create a set of fee rates to compare.
	r1 := NewSatPerKVByte(1)
	r2 := NewSatPerKVByte(2)
	r3 := NewSatPerKVByte(1)

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
	r1 := NewSatPerKWeight(1)
	r2 := NewSatPerKWeight(2)
	r3 := NewSatPerKWeight(1)

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

// TestFeeRateComparisonsW tests the comparison methods of the SatPerWeight
// type.
func TestFeeRateComparisonsW(t *testing.T) {
	t.Parallel()

	// Create a set of fee rates to compare.
	r1 := NewSatPerWeight(1)
	r2 := NewSatPerWeight(2)
	r3 := NewSatPerWeight(1)

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
	r1 := NewSatPerKVByte(1000)

	// r2: 250 sat/kwu. This matches r1.
	r2 := NewSatPerKWeight(250)

	// r3: 1 sat/vbyte.
	r3 := NewSatPerVByte(1)

	// r4: 0.25 sat/wu.
	// 0.25 sat/wu * 1000 = 250 sat/kwu.
	r4 := CalcSatPerWeight(1, NewWeightUnit(4))

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

	// Test FeeForWeight with SatPerWeight.
	// Size: 1000 weight units.
	// Rate: 0.25 sat/wu.
	// Fee: 1000 * 0.25 = 250 sats.
	require.Equal(t, btcutil.Amount(250),
		r4.FeeForWeight(NewWeightUnit(1000)))

	// Test ToSatPerWeight with SatPerVByte.
	// 1 sat/vbyte should equal 0.25 sat/wu.
	require.True(t, r4.Equal(r3.ToSatPerWeight()))
}

// TestNewFeeRateConstructorsZero tests the New* fee rate constructors with
// zero values.
func TestNewFeeRateConstructorsZero(t *testing.T) {
	t.Parallel()

	// Test CalcSatPerKWeight with zero weight.
	fee := btcutil.Amount(1000)
	kwu := NewKWeightUnit(0)
	expectedRate := NewSatPerKWeight(0)
	require.Zero(
		t, expectedRate.satsPerKWU.Cmp(
			CalcSatPerKWeight(fee, kwu).satsPerKWU,
		),
	)

	// Test CalcSatPerVByte with zero vbytes.
	vb := NewVByte(0)
	expectedRateVB := NewSatPerVByte(0)
	require.Zero(
		t, expectedRateVB.satsPerKWU.Cmp(
			CalcSatPerVByte(fee, vb).satsPerKWU,
		),
	)

	// Test CalcSatPerKVByte with zero kvbytes.
	kvb := NewKVByte(0)
	expectedRateKVB := NewSatPerKVByte(0)
	require.Zero(
		t, expectedRateKVB.satsPerKWU.Cmp(
			CalcSatPerKVByte(fee, kvb).satsPerKWU,
		),
	)

	// Test CalcSatPerWeight with zero weight units.
	wu := NewWeightUnit(0)
	expectedRateW := NewSatPerWeight(0)
	require.Zero(
		t, expectedRateW.satsPerKWU.Cmp(
			CalcSatPerWeight(fee, wu).satsPerKWU,
		),
	)

	// Test zero constants.
	require.True(t, ZeroSatPerVByte.Equal(NewSatPerVByte(0)))
	require.True(t, ZeroSatPerKVByte.Equal(NewSatPerKVByte(0)))
	require.True(t, ZeroSatPerKWeight.Equal(NewSatPerKWeight(0)))
	require.True(t, ZeroSatPerWeight.Equal(NewSatPerWeight(0)))

	require.Equal(t, "0.000 sat/vb", ZeroSatPerVByte.String())
	require.Equal(t, "0.000 sat/kvb", ZeroSatPerKVByte.String())
	require.Equal(t, "0.000 sat/kw", ZeroSatPerKWeight.String())
	require.Equal(t, "0.000 sat/wu", ZeroSatPerWeight.String())
}

// TestSafeUint64ToInt64Overflow tests the overflow condition in
// safeUint64ToInt64 through the New* constructors.
func TestSafeUint64ToInt64Overflow(t *testing.T) {
	t.Parallel()

	fee := btcutil.Amount(1)

	// Test CalcSatPerVByte with an overflowing vbyte value.
	// The denominator should be capped at math.MaxInt64.
	// We manually construct the VByte to ensure wu > MaxInt64 without
	// overflowing the constructor's internal multiplication.
	overflowVByte := VByte{baseUnit{wu: math.MaxInt64 + 1}}
	expectedDenom := big.NewInt(math.MaxInt64)

	rateVB := CalcSatPerVByte(fee, overflowVByte)
	require.Zero(t, expectedDenom.Cmp(rateVB.satsPerKWU.Denom()))

	// Test CalcSatPerKVByte with an overflowing kvb value.
	// The denominator should be capped at math.MaxInt64.
	overflowKVByte := KVByte{baseUnit{wu: math.MaxInt64 + 1}}
	rateKVB := CalcSatPerKVByte(fee, overflowKVByte)
	require.Zero(t, expectedDenom.Cmp(rateKVB.satsPerKWU.Denom()))

	// Test CalcSatPerKWeight with an overflowing weight unit value.
	overflowWU := KWeightUnit{baseUnit{wu: math.MaxInt64 + 1}}
	rateKW := CalcSatPerKWeight(fee, overflowWU)
	require.Zero(t, expectedDenom.Cmp(rateKW.satsPerKWU.Denom()))

	// Test CalcSatPerWeight with an overflowing weight unit value.
	overflowWeight := WeightUnit{baseUnit{wu: math.MaxInt64 + 1}}
	rateW := CalcSatPerWeight(fee, overflowWeight)
	require.Zero(t, expectedDenom.Cmp(rateW.satsPerKWU.Denom()))
}

// TestVal checks that the Val method returns the correct integer fee rate.
func TestVal(t *testing.T) {
	t.Parallel()

	// Test SatPerKVByte.Val().
	rateKVB := NewSatPerKVByte(1000)
	require.Equal(t, btcutil.Amount(1000), rateKVB.Val())

	// Test SatPerKWeight.Val().
	rateKW := NewSatPerKWeight(250)
	require.Equal(t, btcutil.Amount(250), rateKW.Val())
}

// TestRatePrecision checks that baseFeeRate preserves precision for
// non-integer rates (e.g., repeating decimals) during conversions and fee
// calculations for all rate units.
func TestRatePrecision(t *testing.T) {
	t.Parallel()

	// We choose a test payload size of 12,000 weight units.
	// This specific number is chosen because it is cleanly divisible by
	// all unit factors, allowing us to pass exact integer amounts to all
	// FeeFor... methods.
	//
	// 12,000 wu = 12 kwu
	// 12,000 wu = 3,000 vb
	// 12,000 wu = 3 kvb
	const (
		payloadWU  = 12000
		payloadKWU = 12
		payloadVB  = 3000
		payloadKVB = 3
	)

	// expectedFee is always 1 satoshi because we define the rate in each
	// test case as (1 sat / payload_size).
	const expectedFee = btcutil.Amount(1)

	// 1. Test SatPerWeight.
	// Rate: 1 sat / 12,000 wu = 0.0000833... sat/wu.
	t.Run("SatPerWeight", func(t *testing.T) {
		t.Parallel()

		rate := CalcSatPerWeight(1, NewWeightUnit(payloadWU))

		// The rate 0.0000833... rounds to 0.000 when displayed with 3
		// decimal places, but the internal precision is preserved.
		require.Equal(t, "0.000 sat/wu", rate.String())
		require.Equal(t, expectedFee,
			rate.FeeForWeight(NewWeightUnit(payloadWU)))

		// Convert to SatPerKWeight.
		// Rate: 1 sat / 12 kwu = 0.0833... sat/kw.
		kw := rate.ToSatPerKWeight()
		require.Equal(t, "0.083 sat/kw", kw.String())
		require.Equal(t, expectedFee,
			kw.FeeForKWeight(NewKWeightUnit(payloadKWU)))

		// Convert to SatPerVByte.
		// Rate: 1 sat / 3,000 vb = 0.00033... sat/vb.
		// This rounds to 0.000 at 3 decimals.
		vb := rate.ToSatPerVByte()
		require.Equal(t, "0.000 sat/vb", vb.String())
		require.Equal(t, expectedFee,
			vb.FeeForVByte(NewVByte(payloadVB)))

		// Convert to SatPerKVByte.
		// Rate: 1 sat / 3 kvb = 0.333... sat/kvb.
		kvb := rate.ToSatPerKVByte()
		require.Equal(t, "0.333 sat/kvb", kvb.String())
		require.Equal(t, expectedFee,
			kvb.FeeForKVByte(NewKVByte(payloadKVB)))
	})

	// 2. Test SatPerKWeight.
	// Rate: 1 sat / 12 kwu = 0.0833... sat/kw.
	t.Run("SatPerKWeight", func(t *testing.T) {
		t.Parallel()

		rate := CalcSatPerKWeight(1, NewKWeightUnit(payloadKWU))
		require.Equal(t, "0.083 sat/kw", rate.String())
		require.Equal(t, expectedFee,
			rate.FeeForKWeight(NewKWeightUnit(payloadKWU)))

		// Convert to SatPerWeight.
		// Rate: 1 sat / 12,000 wu = 0.0000833... sat/wu.
		// Rounds to 0.000.
		w := rate.ToSatPerWeight()
		require.Equal(t, "0.000 sat/wu", w.String())
		require.Equal(t, expectedFee,
			w.FeeForWeight(NewWeightUnit(payloadWU)))

		// Convert to SatPerVByte.
		// Rate: 1 sat / 3,000 vb = 0.00033... sat/vb.
		// Rounds to 0.000.
		vb := rate.ToSatPerVByte()
		require.Equal(t, "0.000 sat/vb", vb.String())
		require.Equal(t, expectedFee,
			vb.FeeForVByte(NewVByte(payloadVB)))

		// Convert to SatPerKVByte.
		// Rate: 1 sat / 3 kvb = 0.333... sat/kvb.
		kvb := rate.ToSatPerKVByte()
		require.Equal(t, "0.333 sat/kvb", kvb.String())
		require.Equal(t, expectedFee,
			kvb.FeeForKVByte(NewKVByte(payloadKVB)))
	})

	// 3. Test SatPerVByte.
	// Rate: 1 sat / 3,000 vb = 0.00033... sat/vb.
	t.Run("SatPerVByte", func(t *testing.T) {
		t.Parallel()

		rate := CalcSatPerVByte(1, NewVByte(payloadVB))
		// Rounds to 0.000 at 3 decimals.
		require.Equal(t, "0.000 sat/vb", rate.String())
		require.Equal(t, expectedFee,
			rate.FeeForVByte(NewVByte(payloadVB)))

		// Convert to SatPerKVByte.
		// Rate: 1 sat / 3 kvb = 0.333... sat/kvb.
		kvb := rate.ToSatPerKVByte()
		require.Equal(t, "0.333 sat/kvb", kvb.String())
		require.Equal(t, expectedFee,
			kvb.FeeForKVByte(NewKVByte(payloadKVB)))

		// Convert to SatPerKWeight.
		// Rate: 1 sat / 12 kwu = 0.0833... sat/kw.
		kw := rate.ToSatPerKWeight()
		require.Equal(t, "0.083 sat/kw", kw.String())
		require.Equal(t, expectedFee,
			kw.FeeForKWeight(NewKWeightUnit(payloadKWU)))

		// Convert to SatPerWeight.
		// Rate: 1 sat / 12,000 wu = 0.0000833... sat/wu.
		// Rounds to 0.000.
		w := rate.ToSatPerWeight()
		require.Equal(t, "0.000 sat/wu", w.String())
		require.Equal(t, expectedFee,
			w.FeeForWeight(NewWeightUnit(payloadWU)))
	})

	// 4. Test SatPerKVByte.
	// Rate: 1 sat / 3 kvb = 0.333... sat/kvb.
	t.Run("SatPerKVByte", func(t *testing.T) {
		t.Parallel()

		rate := CalcSatPerKVByte(1, NewKVByte(payloadKVB))
		require.Equal(t, "0.333 sat/kvb", rate.String())
		require.Equal(t, expectedFee,
			rate.FeeForKVByte(NewKVByte(payloadKVB)))

		// Convert to SatPerVByte.
		// Rate: 1 sat / 3,000 vb = 0.00033... sat/vb.
		// Rounds to 0.000.
		vb := rate.ToSatPerVByte()
		require.Equal(t, "0.000 sat/vb", vb.String())
		require.Equal(t, expectedFee,
			vb.FeeForVByte(NewVByte(payloadVB)))

		// Convert to SatPerKWeight.
		// Rate: 1 sat / 12 kwu = 0.0833... sat/kw.
		kw := rate.ToSatPerKWeight()
		require.Equal(t, "0.083 sat/kw", kw.String())
		require.Equal(t, expectedFee,
			kw.FeeForKWeight(NewKWeightUnit(payloadKWU)))

		// Convert to SatPerWeight.
		// Rate: 1 sat / 12,000 wu = 0.0000833... sat/wu.
		// Rounds to 0.000.
		w := rate.ToSatPerWeight()
		require.Equal(t, "0.000 sat/wu", w.String())
		require.Equal(t, expectedFee,
			w.FeeForWeight(NewWeightUnit(payloadWU)))
	})
}
