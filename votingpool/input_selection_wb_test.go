/*
 * Copyright (c) 2015 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package votingpool

import (
	"bytes"
	"reflect"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/txstore"
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
	var inputs []txstore.Credit
	for i := 0; i < len(scripts); i++ {
		txIndex := int(i) + 1
		created := TstCreateInputsOnBlock(t, store, txIndex, scripts[i], eligibleAmounts)
		inputs = append(inputs, created...)
	}

	startAddr := TstNewWithdrawalAddress(t, pool, 1, 0, 0)
	lastSeriesID := uint32(2)
	currentBlock := int32(TstInputsBlock + eligibleInputMinConfirmations + 1)
	var eligibles []Credit
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

	// Check that the returned eligibles are sorted by address.
	if !sort.IsSorted(byAddress(eligibles)) {
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
	tearDown, pool, store := TstCreatePoolAndTxStore(t)
	defer tearDown()
	seriesID := uint32(1)
	branch := Branch(0)
	index := Index(0)

	// create the series
	series := []TstSeriesDef{{ReqSigs: 3, PubKeys: TstPubKeys[1:6], SeriesID: seriesID}}
	TstCreateSeries(t, pool, series)

	// Create the input.
	pkScript := TstCreatePkScript(t, pool, seriesID, branch, index)
	var chainHeight int32 = 1000
	c := TstCreateInputs(t, store, pkScript, []int64{int64(dustThreshold)})[0]

	// Make sure credits is old enough to pass the minConf check.
	c.BlockHeight = int32(eligibleInputMinConfirmations)

	if !pool.isCreditEligible(c, eligibleInputMinConfirmations, chainHeight, dustThreshold) {
		t.Errorf("Input is not eligible and it should be.")
	}
}

func TestNonEligibleInputsAreNotEligible(t *testing.T) {
	tearDown, pool, store1 := TstCreatePoolAndTxStore(t)
	store2, storeTearDown2 := TstCreateTxStore(t)
	defer tearDown()
	defer storeTearDown2()
	seriesID := uint32(1)
	branch := Branch(0)
	index := Index(0)

	// create the series
	series := []TstSeriesDef{{ReqSigs: 3, PubKeys: TstPubKeys[1:6], SeriesID: seriesID}}
	TstCreateSeries(t, pool, series)

	pkScript := TstCreatePkScript(t, pool, seriesID, branch, index)
	var chainHeight int32 = 1000

	// Check that credit below dustThreshold is rejected.
	c1 := TstCreateInputs(t, store1, pkScript, []int64{int64(dustThreshold - 1)})[0]
	c1.BlockHeight = int32(100) // make sure it has enough confirmations.
	if pool.isCreditEligible(c1, eligibleInputMinConfirmations, chainHeight, dustThreshold) {
		t.Errorf("Input is eligible and it should not be.")
	}

	// Check that a credit with not enough confirmations is rejected.
	c2 := TstCreateInputs(t, store2, pkScript, []int64{int64(dustThreshold)})[0]
	// the calculation of if it has been confirmed does this:
	// chainheigt - bh + 1 >= target, which is quite weird, but the
	// reason why I need to put 902 as *that* makes 1000 - 902 +1 = 99 >=
	// 100 false
	c2.BlockHeight = int32(902)
	if pool.isCreditEligible(c2, eligibleInputMinConfirmations, chainHeight, dustThreshold) {
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
	c0 := TstNewFakeCredit(t, pool, 1, 0, 0, shaHash0, 0)
	c1 := TstNewFakeCredit(t, pool, 1, 0, 0, shaHash0, 1)
	c2 := TstNewFakeCredit(t, pool, 1, 0, 0, shaHash1, 0)
	c3 := TstNewFakeCredit(t, pool, 1, 0, 0, shaHash2, 0)
	c4 := TstNewFakeCredit(t, pool, 1, 0, 1, shaHash0, 0)
	c5 := TstNewFakeCredit(t, pool, 1, 1, 0, shaHash0, 0)
	c6 := TstNewFakeCredit(t, pool, 2, 0, 0, shaHash0, 0)

	randomCredits := [][]Credit{
		[]Credit{c6, c5, c4, c3, c2, c1, c0},
		[]Credit{c2, c1, c0, c6, c5, c4, c3},
		[]Credit{c6, c4, c5, c2, c3, c0, c1},
	}

	want := []Credit{c0, c1, c2, c3, c4, c5, c6}

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

// TstFakeCredit is a structure implementing the Credit interface used to test
// the byAddress sorting. It exists because to test the sorting properly we need
// to be able to set the Credit's TxSha and OutputIndex.
type TstFakeCredit struct {
	addr        WithdrawalAddress
	txSha       *wire.ShaHash
	outputIndex uint32
	amount      btcutil.Amount
}

func (c *TstFakeCredit) String() string             { return "" }
func (c *TstFakeCredit) TxSha() *wire.ShaHash       { return c.txSha }
func (c *TstFakeCredit) OutputIndex() uint32        { return c.outputIndex }
func (c *TstFakeCredit) Address() WithdrawalAddress { return c.addr }
func (c *TstFakeCredit) Amount() btcutil.Amount     { return c.amount }
func (c *TstFakeCredit) TxOut() *wire.TxOut         { return nil }
func (c *TstFakeCredit) OutPoint() *wire.OutPoint {
	return &wire.OutPoint{Hash: *c.txSha, Index: c.outputIndex}
}

func TstNewFakeCredit(t *testing.T, pool *Pool, series uint32, index Index, branch Branch,
	txSha []byte, outputIdx int) *TstFakeCredit {
	var hash wire.ShaHash
	if err := hash.SetBytes(txSha); err != nil {
		t.Fatal(err)
	}
	// Ensure the address defined by the given series/branch/index is present on
	// the set of used addresses as that's a requirement of WithdrawalAddress.
	TstEnsureUsedAddr(t, pool, series, branch, index)
	addr := TstNewWithdrawalAddress(t, pool, series, branch, index)
	return &TstFakeCredit{
		addr:        *addr,
		txSha:       &hash,
		outputIndex: uint32(outputIdx),
	}
}

// Compile time check that TstFakeCredit implements the
// Credit interface.
var _ Credit = (*TstFakeCredit)(nil)

func checkUniqueness(t *testing.T, credits byAddress) {
	type uniq struct {
		series      uint32
		branch      Branch
		index       Index
		hash        wire.ShaHash
		outputIndex uint32
	}

	uniqMap := make(map[uniq]bool)
	for _, c := range credits {
		u := uniq{
			series:      c.Address().SeriesID(),
			branch:      c.Address().Branch(),
			index:       c.Address().Index(),
			hash:        *c.TxSha(),
			outputIndex: c.OutputIndex(),
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
