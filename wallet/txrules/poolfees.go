// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txrules

import (
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/decred/dcrd/blockchain"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrutil"
)

// maxPoolFeeRate is the maximum value of the pool fee
const maxPoolFeeRate = 10000.0

// IsValidPoolFeeRate tests to see if a pool fee is a valid percentage from
// 0.01% to 100.00%.
func IsValidPoolFeeRate(feeRate float64) error {
	poolFeeRateTest := feeRate * 100
	poolFeeRateTest = math.Floor(poolFeeRateTest)
	if poolFeeRateTest <= 0.0 || poolFeeRateTest > maxPoolFeeRate {
		return fmt.Errorf("invalid pool fee %v, pool fee "+
			"must be between 0.01 and 100.00", feeRate)
	}

	return nil
}

var subsidyCache *blockchain.SubsidyCache
var initSubsidyCacheOnce sync.Once

// StakePoolTicketFee determines the stake pool ticket fee for a given ticket
// from the passed percentage. Pool fee as a percentage is truncated from 0.01%
// to 100.00%. This all must be done with integers, so bear with the big.Int
// usage below.
//
// See the included doc.go of this package for more information about the
// calculation of this fee.
func StakePoolTicketFee(stakeDiff dcrutil.Amount, relayFee dcrutil.Amount,
	height int32, poolFee float64, params *chaincfg.Params) dcrutil.Amount {
	// Shift the decimal two places, e.g. 1.00%
	// to 100. This assumes that the proportion
	// is already multiplied by 100 to give a
	// percentage, thus making the entirety
	// be a multiplication by 10000.
	poolFeeAbs := math.Floor(poolFee * 100.0)
	poolFeeInt := int64(poolFeeAbs)

	// Subsidy is fetched from the blockchain package, then
	// pushed forward a number of adjustment periods for
	// compensation in gradual subsidy decay. Recall that
	// the average time to claiming 50% of the tickets as
	// votes is the approximately the same as the ticket
	// pool size (params.TicketPoolSize), so take the
	// ceiling of the ticket pool size divided by the
	// reduction interval.
	adjs := int(math.Ceil(float64(params.TicketPoolSize) /
		float64(params.ReductionInterval)))
	initSubsidyCacheOnce.Do(func() {
		subsidyCache = blockchain.NewSubsidyCache(int64(height), params)
	})
	subsidy := blockchain.CalcStakeVoteSubsidy(subsidyCache, int64(height),
		params)
	for i := 0; i < adjs; i++ {
		subsidy *= 100
		subsidy /= 101
	}

	// The numerator is (p*10000*s*(v+z)) << 64.
	shift := uint(64)
	s := new(big.Int).SetInt64(subsidy)
	v := new(big.Int).SetInt64(int64(stakeDiff))
	z := new(big.Int).SetInt64(int64(relayFee))
	num := new(big.Int).SetInt64(poolFeeInt)
	num.Mul(num, s)
	vPlusZ := new(big.Int).Add(v, z)
	num.Mul(num, vPlusZ)
	num.Lsh(num, shift)

	// The denominator is 10000*(s+v).
	// The extra 10000 above cancels out.
	den := new(big.Int).Set(s)
	den.Add(den, v)
	den.Mul(den, new(big.Int).SetInt64(10000))

	// Divide and shift back.
	num.Div(num, den)
	num.Rsh(num, shift)

	return dcrutil.Amount(num.Int64())
}
