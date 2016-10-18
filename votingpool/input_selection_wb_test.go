// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package votingpool

import (
	"bytes"
	"reflect"
	"sort"
	"testing"

	"github.com/jadeblaquiere/ctcd/chaincfg/chainhash"
	"github.com/jadeblaquiere/ctcd/wire"
	"github.com/jadeblaquiere/ctcutil"
	"github.com/jadeblaquiere/ctcwallet/wtxmgr"
)

var (
	// random small number of satoshis used as dustThreshold
	dustThreshold btcutil.Amount = 1e4
)

func TestGetEligibleInputs(t *testing.T) {
	tearDown, pool, store := TstCreatePoolAndTxStore(t)
	defer tearDown()

	series := []TstSeriesDef{
		{ReqSigs: 2, PubKeys: TstPubKeys[1:4], SeriesID: 1},
		{ReqSigs: 2, PubKeys: TstPubKeys[3:6], SeriesID: 2},
	}
	TstCreateSeries(t, pool, series)
	scripts := append(
		getPKScriptsForAddressRange(t, pool, 1, 0, 2, 0, 4),
		getPKScriptsForAddressRange(t, pool, 2, 0, 2, 0, 6)...)

	// Create two eligible inputs locked to each of the PKScripts above.
	expNoEligibleInputs := 2 * len(scripts)
	eligibleAmounts := []int64{int64(dustThreshold + 1), int64(dustThreshold + 1)}
	var inputs []wtxmgr.Credit
	for i := 0; i < len(scripts); i++ {
		created := TstCreateCreditsOnStore(t, store, scripts[i], eligibleAmounts)
		inputs = append(inputs, created...)
	}

	startAddr := TstNewWithdrawalAddress(t, pool, 1, 0, 0)
	lastSeriesID := uint32(2)
	currentBlock := int32(TstInputsBlock + eligibleInputMinConfirmations + 1)
	var eligibles []credit
	var err error
	TstRunWithManagerUnlocked(t, pool.Manager(), func() {
		eligibles, err = pool.getEligibleInputs(
			store, *startAddr, lastSeriesID, dustThreshold, int32(currentBlock),
			eligibleInputMinConfirmations)
	})
	if err != nil {
		t.Fatal("InputSelection failed:", err)
	}

	// Check we got the expected number of eligible inputs.
	if len(eligibles) != expNoEligibleInputs {
		t.Fatalf("Wrong number of eligible inputs returned. Got: %d, want: %d.",
			len(eligibles), expNoEligibleInputs)
	}

	// Check that the returned eligibles are reverse sorted by address.
	if !sort.IsSorted(sort.Reverse(byAddress(eligibles))) {
		t.Fatal("Eligible inputs are not sorted.")
	}

	// Check that all credits are unique
	checkUniqueness(t, eligibles)
}

func TestNextAddrWithVaryingHighestIndices(t *testing.T) {
	tearDown, mgr, pool := TstCreatePool(t)
	defer tearDown()

	series := []TstSeriesDef{
		{ReqSigs: 2, PubKeys: TstPubKeys[1:4], SeriesID: 1},
	}
	TstCreateSeries(t, pool, series)
	stopSeriesID := uint32(2)

	// Populate the used addr DB for branch 0 and indices ranging from 0 to 2.
	TstEnsureUsedAddr(t, pool, 1, Branch(0), 2)

	// Populate the used addr DB for branch 1 and indices ranging from 0 to 1.
	TstEnsureUsedAddr(t, pool, 1, Branch(1), 1)

	// Start with the address for branch==0, index==1.
	addr := TstNewWithdrawalAddress(t, pool, 1, 0, 1)

	var err error
	// The first call to nextAddr() should give us the address for branch==1
	// and index==1.
	TstRunWithManagerUnlocked(t, mgr, func() {
		addr, err = nextAddr(pool, addr.seriesID, addr.branch, addr.index, stopSeriesID)
	})
	if err != nil {
		t.Fatalf("Failed to get next address: %v", err)
	}
	checkWithdrawalAddressMatches(t, addr, 1, Branch(1), 1)

	// The next call should give us the address for branch==0, index==2 since
	// there are no used addresses for branch==2.
	TstRunWithManagerUnlocked(t, mgr, func() {
		addr, err = nextAddr(pool, addr.seriesID, addr.branch, addr.index, stopSeriesID)
	})
	if err != nil {
		t.Fatalf("Failed to get next address: %v", err)
	}
	checkWithdrawalAddressMatches(t, addr, 1, Branch(0), 2)

	// Since the last addr for branch==1 was the one with index==1, a subsequent
	// call will return nil.
	TstRunWithManagerUnlocked(t, mgr, func() {
		addr, err = nextAddr(pool, addr.seriesID, addr.branch, addr.index, stopSeriesID)
	})
	if err != nil {
		t.Fatalf("Failed to get next address: %v", err)
	}
	if addr != nil {
		t.Fatalf("Wrong next addr; got '%s', want 'nil'", addr.addrIdentifier())
	}
}

func TestNextAddr(t *testing.T) {
	tearDown, mgr, pool := TstCreatePool(t)
	defer tearDown()

	series := []TstSeriesDef{
		{ReqSigs: 2, PubKeys: TstPubKeys[1:4], SeriesID: 1},
		{ReqSigs: 2, PubKeys: TstPubKeys[3:6], SeriesID: 2},
	}
	TstCreateSeries(t, pool, series)
	stopSeriesID := uint32(3)

	lastIdx := Index(10)
	// Populate used addresses DB with entries for seriesID==1, branch==0..3,
	// idx==0..10.
	for _, i := range []int{0, 1, 2, 3} {
		TstEnsureUsedAddr(t, pool, 1, Branch(i), lastIdx)
	}
	addr := TstNewWithdrawalAddress(t, pool, 1, 0, lastIdx-1)
	var err error
	// nextAddr() first increments just the branch, which ranges from 0 to 3
	// here (because our series has 3 public keys).
	for _, i := range []int{1, 2, 3} {
		TstRunWithManagerUnlocked(t, mgr, func() {
			addr, err = nextAddr(pool, addr.seriesID, addr.branch, addr.index, stopSeriesID)
		})
		if err != nil {
			t.Fatalf("Failed to get next address: %v", err)
		}
		checkWithdrawalAddressMatches(t, addr, 1, Branch(i), lastIdx-1)
	}

	// The last nextAddr() above gave us the addr with branch=3,
	// idx=lastIdx-1, so the next 4 calls should give us the addresses with
	// branch=[0-3] and idx=lastIdx.
	for _, i := range []int{0, 1, 2, 3} {
		TstRunWithManagerUnlocked(t, mgr, func() {
			addr, err = nextAddr(pool, addr.seriesID, addr.branch, addr.index, stopSeriesID)
		})
		if err != nil {
			t.Fatalf("Failed to get next address: %v", err)
		}
		checkWithdrawalAddressMatches(t, addr, 1, Branch(i), lastIdx)
	}

	// Populate used addresses DB with entries for seriesID==2, branch==0..3,
	// idx==0..10.
	for _, i := range []int{0, 1, 2, 3} {
		TstEnsureUsedAddr(t, pool, 2, Branch(i), lastIdx)
	}
	// Now we've gone through all the available branch/idx combinations, so
	// we should move to the next series and start again with branch=0, idx=0.
	for _, i := range []int{0, 1, 2, 3} {
		TstRunWithManagerUnlocked(t, mgr, func() {
			addr, err = nextAddr(pool, addr.seriesID, addr.branch, addr.index, stopSeriesID)
		})
		if err != nil {
			t.Fatalf("Failed to get next address: %v", err)
		}
		checkWithdrawalAddressMatches(t, addr, 2, Branch(i), 0)
	}

	// Finally check that nextAddr() returns nil when we've reached the last
	// available address before stopSeriesID.
	addr = TstNewWithdrawalAddress(t, pool, 2, 3, lastIdx)
	TstRunWithManagerUnlocked(t, mgr, func() {
		addr, err = nextAddr(pool, addr.seriesID, addr.branch, addr.index, stopSeriesID)
	})
	if err != nil {
		t.Fatalf("Failed to get next address: %v", err)
	}
	if addr != nil {
		t.Fatalf("Wrong WithdrawalAddress; got %s, want nil", addr.addrIdentifier())
	}
}

func TestEligibleInputsAreEligible(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	var chainHeight int32 = 1000
	_, credits := TstCreateCreditsOnNewSeries(t, pool, []int64{int64(dustThreshold)})
	c := credits[0]
	// Make sure credit is old enough to pass the minConf check.
	c.BlockMeta.Height = int32(eligibleInputMinConfirmations)

	if !pool.isCreditEligible(c, eligibleInputMinConfirmations, chainHeight, dustThreshold) {
		t.Errorf("Input is not eligible and it should be.")
	}
}

func TestNonEligibleInputsAreNotEligible(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	var chainHeight int32 = 1000
	_, credits := TstCreateCreditsOnNewSeries(t, pool, []int64{int64(dustThreshold - 1)})
	c := credits[0]
	// Make sure credit is old enough to pass the minConf check.
	c.BlockMeta.Height = int32(eligibleInputMinConfirmations)

	// Check that credit below dustThreshold is rejected.
	if pool.isCreditEligible(c, eligibleInputMinConfirmations, chainHeight, dustThreshold) {
		t.Errorf("Input is eligible and it should not be.")
	}

	// Check that a credit with not enough confirmations is rejected.
	_, credits = TstCreateCreditsOnNewSeries(t, pool, []int64{int64(dustThreshold)})
	c = credits[0]
	// The calculation of if it has been confirmed does this: chainheigt - bh +
	// 1 >= target, which is quite weird, but the reason why I need to put 902
	// is *that* makes 1000 - 902 +1 = 99 >= 100 false
	c.BlockMeta.Height = int32(902)
	if pool.isCreditEligible(c, eligibleInputMinConfirmations, chainHeight, dustThreshold) {
		t.Errorf("Input is eligible and it should not be.")
	}
}

func TestCreditSortingByAddress(t *testing.T) {
	teardown, _, pool := TstCreatePool(t)
	defer teardown()

	series := []TstSeriesDef{
		{ReqSigs: 2, PubKeys: TstPubKeys[1:4], SeriesID: 1},
		{ReqSigs: 2, PubKeys: TstPubKeys[3:6], SeriesID: 2},
	}
	TstCreateSeries(t, pool, series)

	shaHash0 := bytes.Repeat([]byte{0}, 32)
	shaHash1 := bytes.Repeat([]byte{1}, 32)
	shaHash2 := bytes.Repeat([]byte{2}, 32)
	c0 := newDummyCredit(t, pool, 1, 0, 0, shaHash0, 0)
	c1 := newDummyCredit(t, pool, 1, 0, 0, shaHash0, 1)
	c2 := newDummyCredit(t, pool, 1, 0, 0, shaHash1, 0)
	c3 := newDummyCredit(t, pool, 1, 0, 0, shaHash2, 0)
	c4 := newDummyCredit(t, pool, 1, 0, 1, shaHash0, 0)
	c5 := newDummyCredit(t, pool, 1, 1, 0, shaHash0, 0)
	c6 := newDummyCredit(t, pool, 2, 0, 0, shaHash0, 0)

	randomCredits := [][]credit{
		[]credit{c6, c5, c4, c3, c2, c1, c0},
		[]credit{c2, c1, c0, c6, c5, c4, c3},
		[]credit{c6, c4, c5, c2, c3, c0, c1},
	}

	want := []credit{c0, c1, c2, c3, c4, c5, c6}

	for _, random := range randomCredits {
		sort.Sort(byAddress(random))
		got := random

		if len(got) != len(want) {
			t.Fatalf("Sorted credit slice size wrong: Got: %d, want: %d",
				len(got), len(want))
		}

		for idx := 0; idx < len(want); idx++ {
			if !reflect.DeepEqual(got[idx], want[idx]) {
				t.Errorf("Wrong output index. Got: %v, want: %v",
					got[idx], want[idx])
			}
		}
	}
}

// newDummyCredit creates a new credit with the given hash and outpointIdx,
// locked to the votingpool address identified by the given
// series/index/branch.
func newDummyCredit(t *testing.T, pool *Pool, series uint32, index Index, branch Branch,
	txHash []byte, outpointIdx uint32) credit {
	var hash chainhash.Hash
	if err := hash.SetBytes(txHash); err != nil {
		t.Fatal(err)
	}
	// Ensure the address defined by the given series/branch/index is present on
	// the set of used addresses as that's a requirement of WithdrawalAddress.
	TstEnsureUsedAddr(t, pool, series, branch, index)
	addr := TstNewWithdrawalAddress(t, pool, series, branch, index)
	c := wtxmgr.Credit{
		OutPoint: wire.OutPoint{
			Hash:  hash,
			Index: outpointIdx,
		},
	}
	return newCredit(c, *addr)
}

func checkUniqueness(t *testing.T, credits byAddress) {
	type uniq struct {
		series      uint32
		branch      Branch
		index       Index
		hash        chainhash.Hash
		outputIndex uint32
	}

	uniqMap := make(map[uniq]bool)
	for _, c := range credits {
		u := uniq{
			series:      c.addr.SeriesID(),
			branch:      c.addr.Branch(),
			index:       c.addr.Index(),
			hash:        c.OutPoint.Hash,
			outputIndex: c.OutPoint.Index,
		}
		if _, exists := uniqMap[u]; exists {
			t.Fatalf("Duplicate found: %v", u)
		} else {
			uniqMap[u] = true
		}
	}
}

func getPKScriptsForAddressRange(t *testing.T, pool *Pool, seriesID uint32,
	startBranch, stopBranch Branch, startIdx, stopIdx Index) [][]byte {
	var pkScripts [][]byte
	for idx := startIdx; idx <= stopIdx; idx++ {
		for branch := startBranch; branch <= stopBranch; branch++ {
			pkScripts = append(pkScripts, TstCreatePkScript(t, pool, seriesID, branch, idx))
		}
	}
	return pkScripts
}

func checkWithdrawalAddressMatches(t *testing.T, addr *WithdrawalAddress, seriesID uint32,
	branch Branch, index Index) {
	if addr.SeriesID() != seriesID {
		t.Fatalf("Wrong seriesID; got %d, want %d", addr.SeriesID(), seriesID)
	}
	if addr.Branch() != branch {
		t.Fatalf("Wrong branch; got %d, want %d", addr.Branch(), branch)
	}
	if addr.Index() != index {
		t.Fatalf("Wrong index; got %d, want %d", addr.Index(), index)
	}
}
