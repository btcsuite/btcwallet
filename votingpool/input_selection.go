/*
 * Copyright (c) 2015-2016 The btcsuite developers
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
	"fmt"
	"sort"

	"github.com/jadeblaquiere/ctcd/chaincfg"
	"github.com/jadeblaquiere/ctcd/txscript"
	"github.com/jadeblaquiere/ctcutil"
	"github.com/jadeblaquiere/ctcwallet/wtxmgr"
)

const eligibleInputMinConfirmations = 100

// credit is an abstraction over wtxmgr.Credit used in the construction of
// voting pool withdrawal transactions.
type credit struct {
	wtxmgr.Credit
	addr WithdrawalAddress
}

func newCredit(c wtxmgr.Credit, addr WithdrawalAddress) credit {
	return credit{Credit: c, addr: addr}
}

func (c *credit) String() string {
	return fmt.Sprintf("credit of %v locked to %v", c.Amount, c.addr)
}

// byAddress defines the methods needed to satisify sort.Interface to sort a
// slice of credits by their address.
type byAddress []credit

func (c byAddress) Len() int      { return len(c) }
func (c byAddress) Swap(i, j int) { c[i], c[j] = c[j], c[i] }

// Less returns true if the element at positions i is smaller than the
// element at position j. The 'smaller-than' relation is defined to be
// the lexicographic ordering defined on the tuple (SeriesID, Index,
// Branch, TxSha, OutputIndex).
func (c byAddress) Less(i, j int) bool {
	iAddr := c[i].addr
	jAddr := c[j].addr
	if iAddr.seriesID < jAddr.seriesID {
		return true
	}
	if iAddr.seriesID > jAddr.seriesID {
		return false
	}

	// The seriesID are equal, so compare index.
	if iAddr.index < jAddr.index {
		return true
	}
	if iAddr.index > jAddr.index {
		return false
	}

	// The seriesID and index are equal, so compare branch.
	if iAddr.branch < jAddr.branch {
		return true
	}
	if iAddr.branch > jAddr.branch {
		return false
	}

	// The seriesID, index, and branch are equal, so compare hash.
	txidComparison := bytes.Compare(c[i].OutPoint.Hash[:], c[j].OutPoint.Hash[:])
	if txidComparison < 0 {
		return true
	}
	if txidComparison > 0 {
		return false
	}

	// The seriesID, index, branch, and hash are equal, so compare output
	// index.
	return c[i].OutPoint.Index < c[j].OutPoint.Index
}

// getEligibleInputs returns eligible inputs with addresses between startAddress
// and the last used address of lastSeriesID. They're reverse ordered based on
// their address.
func (p *Pool) getEligibleInputs(store *wtxmgr.Store, startAddress WithdrawalAddress,
	lastSeriesID uint32, dustThreshold btcutil.Amount, chainHeight int32,
	minConf int) ([]credit, error) {

	if p.Series(lastSeriesID) == nil {
		str := fmt.Sprintf("lastSeriesID (%d) does not exist", lastSeriesID)
		return nil, newError(ErrSeriesNotExists, str, nil)
	}
	unspents, err := store.UnspentOutputs()
	if err != nil {
		return nil, newError(ErrInputSelection, "failed to get unspent outputs", err)
	}
	addrMap, err := groupCreditsByAddr(unspents, p.manager.ChainParams())
	if err != nil {
		return nil, err
	}
	var inputs []credit
	address := startAddress
	for {
		log.Debugf("Looking for eligible inputs at address %v", address.addrIdentifier())
		if candidates, ok := addrMap[address.addr.EncodeAddress()]; ok {
			var eligibles []credit
			for _, c := range candidates {
				candidate := newCredit(c, address)
				if p.isCreditEligible(candidate, minConf, chainHeight, dustThreshold) {
					eligibles = append(eligibles, candidate)
				}
			}
			inputs = append(inputs, eligibles...)
		}
		nAddr, err := nextAddr(p, address.seriesID, address.branch, address.index, lastSeriesID+1)
		if err != nil {
			return nil, newError(ErrInputSelection, "failed to get next withdrawal address", err)
		} else if nAddr == nil {
			log.Debugf("getEligibleInputs: reached last addr, stopping")
			break
		}
		address = *nAddr
	}
	sort.Sort(sort.Reverse(byAddress(inputs)))
	return inputs, nil
}

// nextAddr returns the next WithdrawalAddress according to the input selection
// rules: http://opentransactions.org/wiki/index.php/Input_Selection_Algorithm_(voting_pools)
// It returns nil if the new address' seriesID is >= stopSeriesID.
func nextAddr(p *Pool, seriesID uint32, branch Branch, index Index, stopSeriesID uint32) (
	*WithdrawalAddress, error) {
	series := p.Series(seriesID)
	if series == nil {
		return nil, newError(ErrSeriesNotExists, fmt.Sprintf("unknown seriesID: %d", seriesID), nil)
	}
	branch++
	if int(branch) > len(series.publicKeys) {
		highestIdx, err := p.highestUsedSeriesIndex(seriesID)
		if err != nil {
			return nil, err
		}
		if index > highestIdx {
			seriesID++
			log.Debugf("nextAddr(): reached last branch (%d) and highest used index (%d), "+
				"moving on to next series (%d)", branch, index, seriesID)
			index = 0
		} else {
			index++
		}
		branch = 0
	}

	if seriesID >= stopSeriesID {
		return nil, nil
	}

	addr, err := p.WithdrawalAddress(seriesID, branch, index)
	if err != nil && err.(Error).ErrorCode == ErrWithdrawFromUnusedAddr {
		// The used indices will vary between branches so sometimes we'll try to
		// get a WithdrawalAddress that hasn't been used before, and in such
		// cases we just need to move on to the next one.
		log.Debugf("nextAddr(): skipping addr (series #%d, branch #%d, index #%d) as it hasn't "+
			"been used before", seriesID, branch, index)
		return nextAddr(p, seriesID, branch, index, stopSeriesID)
	}
	return addr, err
}

// highestUsedSeriesIndex returns the highest index among all of this Pool's
// used addresses for the given seriesID. It returns 0 if there are no used
// addresses with the given seriesID.
func (p *Pool) highestUsedSeriesIndex(seriesID uint32) (Index, error) {
	maxIdx := Index(0)
	series := p.Series(seriesID)
	if series == nil {
		return maxIdx,
			newError(ErrSeriesNotExists, fmt.Sprintf("unknown seriesID: %d", seriesID), nil)
	}
	for i := range series.publicKeys {
		idx, err := p.highestUsedIndexFor(seriesID, Branch(i))
		if err != nil {
			return Index(0), err
		}
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	return maxIdx, nil
}

// groupCreditsByAddr converts a slice of credits to a map from the string
// representation of an encoded address to the unspent outputs associated with
// that address.
func groupCreditsByAddr(credits []wtxmgr.Credit, chainParams *chaincfg.Params) (
	map[string][]wtxmgr.Credit, error) {
	addrMap := make(map[string][]wtxmgr.Credit)
	for _, c := range credits {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(c.PkScript, chainParams)
		if err != nil {
			return nil, newError(ErrInputSelection, "failed to obtain input address", err)
		}
		// As our credits are all P2SH we should never have more than one
		// address per credit, so let's error out if that assumption is
		// violated.
		if len(addrs) != 1 {
			return nil, newError(ErrInputSelection, "input doesn't have exactly one address", nil)
		}
		encAddr := addrs[0].EncodeAddress()
		if v, ok := addrMap[encAddr]; ok {
			addrMap[encAddr] = append(v, c)
		} else {
			addrMap[encAddr] = []wtxmgr.Credit{c}
		}
	}

	return addrMap, nil
}

// isCreditEligible tests a given credit for eligibilty with respect
// to number of confirmations, the dust threshold and that it is not
// the charter output.
func (p *Pool) isCreditEligible(c credit, minConf int, chainHeight int32,
	dustThreshold btcutil.Amount) bool {
	if c.Amount < dustThreshold {
		return false
	}
	if confirms(c.BlockMeta.Block.Height, chainHeight) < int32(minConf) {
		return false
	}
	if p.isCharterOutput(c) {
		return false
	}

	return true
}

// isCharterOutput - TODO: In order to determine this, we need the txid
// and the output index of the current charter output, which we don't have yet.
func (p *Pool) isCharterOutput(c credit) bool {
	return false
}

// confirms returns the number of confirmations for a transaction in a block at
// height txHeight (or -1 for an unconfirmed tx) given the chain height
// curHeight.
func confirms(txHeight, curHeight int32) int32 {
	switch {
	case txHeight == -1, txHeight > curHeight:
		return 0
	default:
		return curHeight - txHeight + 1
	}
}
