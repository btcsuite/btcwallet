/*
 * Copyright (c) 2013-2016 The btcsuite developers
 * Copyright (c) 2015 The Decred developers
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

package wallet

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/btcsuite/btclog"

	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/chain"
	"github.com/decred/dcrwallet/waddrmgr"
)

// finalScanLength is the final length of accounts to scan for the
// function below.
var finalAcctScanLength = 50

// acctSeekWidth is the number of addresses for both internal and external
// branches to scan to determine whether or not an account exists and should
// be rescanned. This is the tolerance for account gaps as well.
var acctSeekWidth uint32 = 5

// accountIsUsed
func (w *Wallet) accountIsUsed(account uint32, chainClient *chain.RPCClient) bool {
	// Search external branch then internal branch for a used
	// address. We need to set the address function to use based
	// on whether or not this is the initial sync. The function
	// AddressDerivedFromCointype is able to see addresses that
	// exists in accounts that have not yet been created, while
	// AddressDerivedFromDbAcct can not.
	addrFunc := w.Manager.AddressDerivedFromDbAcct
	if w.resyncAccounts {
		addrFunc = w.Manager.AddressDerivedFromCointype
	}

	for branch := uint32(0); branch < 2; branch++ {
		for i := uint32(0); i < acctSeekWidth; i++ {
			addr, err := addrFunc(i, account, branch)
			// Skip erroneous keys, which happen rarely.
			if err != nil {
				continue
			}

			exists, err := chainClient.ExistsAddress(addr)
			if err != nil {
				return false
			}
			if exists {
				return true
			}
		}
	}

	return false
}

// bisectLastAcctIndex is a helper function for searching through accounts to
// find the last used account. It uses logarithmic scanning to determine if
// an account has been used.
func (w *Wallet) bisectLastAcctIndex(hi, low int) int {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return 0
	}

	offset := low
	for i := hi - low - 1; i > 0; i /= 2 {
		if i+offset+int(acctSeekWidth) < waddrmgr.MaxAddressesPerAccount {
			for j := i + offset + int(addrSeekWidth); j >= i+offset; j-- {
				if w.accountIsUsed(uint32(j), chainClient) {
					return i + offset
				}
			}
		} else {
			if w.accountIsUsed(uint32(i+offset), chainClient) {
				return i + offset
			}
		}
	}

	return 0
}

// findAcctEnd is a helper function for searching for the last used account by
// logarithmic scanning of the account indexes.
func (w *Wallet) findAcctEnd(start, stop int) int {
	indexStart := w.bisectLastAcctIndex(stop, start)
	indexLast := 0
	for {
		indexLastStored := indexStart
		low := indexLastStored
		hi := indexLast + ((indexStart - indexLast) * 2) + 1
		indexStart = w.bisectLastAcctIndex(hi, low)
		indexLast = indexLastStored

		if indexStart == 0 {
			break
		}
	}

	return indexLast
}

// scanAccountIndex identifies the last used address in an HD keychain of public
// keys. It returns the index of the last used key, along with the address of
// this key.
func (w *Wallet) scanAccountIndex(start int, end int) (uint32, error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return 0, err
	}

	// Find the last used account. Scan from it to the end in case there was a
	// gap from that position, which is possible. Then, return the account
	// in that position.
	lastUsed := w.findAcctEnd(start, end)
	if lastUsed != 0 {
		for i := lastUsed + finalAcctScanLength; i >= lastUsed; i-- {
			if w.accountIsUsed(uint32(i), chainClient) {
				return uint32(i), nil
			}
		}
	}

	// We can't find any used addresses. The account is
	// unused.
	return 0, nil
}

// finalScanLength is the final length of keys to scan for the
// function below.
var finalAddrScanLength = 750

// debugScanLength is the final length of keys to scan past the
// last index returned from the logarithmic scanning function
// when creating the debug string of used addresses.
var debugAddrScanLength = 3500

// addrSeekWidth is the number of new addresses to generate and add to the
// address manager when trying to sync up a wallet to the main chain. This
// is the maximum gap introduced by a resyncing as well, and should be less
// than finalScanLength above.
// TODO Optimize the scanning so that rather than overshooting the end address,
// you instead step through addresses incrementally until reaching idx so that
// you don't reach a gap. This can be done by keeping track of where the current
// cursor is and adding addresses in big chunks until you hit the end.
var addrSeekWidth uint32 = 20

// bisectLastAddrIndex is a helper function for search through addresses.
func (w *Wallet) bisectLastAddrIndex(hi, low int, account uint32,
	branch uint32) int {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return 0
	}

	offset := low
	for i := hi - low - 1; i > 0; i /= 2 {
		if i+offset+int(addrSeekWidth) < waddrmgr.MaxAddressesPerAccount {
			for j := i + offset + int(addrSeekWidth); j >= i+offset; j-- {
				addr, err := w.Manager.AddressDerivedFromDbAcct(uint32(j),
					account, branch)
				// Skip erroneous keys, which happen rarely.
				if err != nil {
					continue
				}

				exists, err := chainClient.ExistsAddress(addr)
				if err != nil {
					return 0
				}
				if exists {
					return i + offset
				}
			}
		} else {
			addr, err := w.Manager.AddressDerivedFromDbAcct(uint32(i+offset),
				account, branch)
			// Skip erroneous keys, which happen rarely.
			if err != nil {
				continue
			}
			exists, err := chainClient.ExistsAddress(addr)
			if err != nil {
				return 0
			}
			if exists {
				return i + offset
			}
		}
	}

	return 0
}

// findEnd is a helper function for searching for used addresses.
func (w *Wallet) findAddrEnd(start, stop int, account uint32, branch uint32) int {
	indexStart := w.bisectLastAddrIndex(stop, start, account, branch)
	indexLast := 0
	for {
		indexLastStored := indexStart
		low := indexLastStored
		hi := indexLast + ((indexStart - indexLast) * 2) + 1
		indexStart = w.bisectLastAddrIndex(hi, low, account, branch)
		indexLast = indexLastStored

		if indexStart == 0 {
			break
		}
	}

	return indexLast
}

// debugAccountAddrGapsString is a debug function that prints a graphical outlook
// of address usage to a string, from the perspective of the daemon.
func debugAccountAddrGapsString(scanBackFrom int, account uint32, branch uint32,
	w *Wallet) (string, error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	str := fmt.Sprintf("Begin debug address scan scanning backwards from "+
		"idx %v, account %v, branch %v\n", scanBackFrom, account, branch)
	buf.WriteString(str)
	firstUsedIndex := 0
	for i := scanBackFrom; i > 0; i-- {
		addr, err := w.Manager.AddressDerivedFromDbAcct(uint32(i), account,
			branch)
		// Skip erroneous keys.
		if err != nil {
			continue
		}

		exists, err := chainClient.ExistsAddress(addr)
		if err != nil {
			return "", fmt.Errorf("failed to access chain server: %v",
				err.Error())
		}

		if exists {
			firstUsedIndex = i
			break
		}
	}

	str = fmt.Sprintf("Last used index found: %v\n", firstUsedIndex)
	buf.WriteString(str)

	batchSize := 50
	batches := (firstUsedIndex / batchSize) + 1
	lastBatchSize := 0
	if firstUsedIndex%batchSize != 0 {
		lastBatchSize = firstUsedIndex - ((batches - 1) * batchSize)
	}

	for i := 0; i < batches; i++ {
		str = fmt.Sprintf("%8v", i*batchSize)
		buf.WriteString(str)

		start := i * batchSize
		end := (i + 1) * batchSize
		if i == batches-1 {
			// Nothing to do because last batch empty.
			if lastBatchSize == 0 {
				break
			}
			end = (i*batchSize + lastBatchSize) + 1
		}

		for j := start; j < end; j++ {
			if j%10 == 0 {
				buf.WriteString("  ")
			}

			char := "_"
			addr, err := w.Manager.AddressDerivedFromDbAcct(uint32(j),
				account, branch)
			if err != nil {
				char = "X"
			}

			exists, err := chainClient.ExistsAddress(addr)
			if err != nil {
				return "", fmt.Errorf("failed to access chain server: %v",
					err.Error())
			}
			if exists {
				char = "#"
			}

			buf.WriteString(char)
		}

		buf.WriteString("\n")
	}

	return buf.String(), nil
}

// scanAddressIndex identifies the last used address in an HD keychain of public
// keys. It returns the index of the last used key, along with the address of
// this key.
func (w *Wallet) scanAddressIndex(start int, end int, account uint32,
	branch uint32) (uint32, dcrutil.Address, error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return 0, nil, err
	}

	// Find the last used address. Scan from it to the end in case there was a
	// gap from that position, which is possible. Then, return the address
	// in that position.
	lastUsed := w.findAddrEnd(start, end, account, branch)

	// If debug is on, do an exhaustive check and a graphical printout
	// of what the used addresses currently look like.
	if log.Level() == btclog.DebugLvl || log.Level() == btclog.TraceLvl {
		dbgStr, err := debugAccountAddrGapsString(lastUsed+debugAddrScanLength,
			account, branch, w)
		if err != nil {
			log.Debugf("Failed to debug address gaps for account %v, "+
				"branch %v: %v", account, branch, err)
		} else {
			log.Debugf("%v", dbgStr)
		}
	}

	if lastUsed != 0 {
		for i := lastUsed + finalAddrScanLength; i >= lastUsed; i-- {
			addr, err := w.Manager.AddressDerivedFromDbAcct(uint32(i),
				account, branch)
			// Skip erroneous keys.
			if err != nil {
				continue
			}

			exists, err := chainClient.ExistsAddress(addr)
			if err != nil {
				return 0, nil, fmt.Errorf("failed to access chain server: %v",
					err.Error())
			}

			if exists {
				lastUsed = i
				break
			}
		}

		addr, err := w.Manager.AddressDerivedFromDbAcct(uint32(lastUsed),
			account, branch)
		if err != nil {
			return 0, nil, err
		}
		return uint32(lastUsed), addr, nil
	}

	// In the case that 0 was returned as the last used address,
	// make sure the the 0th address was not used. If it was,
	// return this address to let the caller know that this
	// 0th address was used.
	if lastUsed == 0 {
		addr, err := w.Manager.AddressDerivedFromDbAcct(0,
			account, branch)
		// Skip erroneous keys.
		if err != nil {
			return 0, nil, err
		}

		exists, err := chainClient.ExistsAddress(addr)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to access chain server: %v",
				err.Error())
		}

		if exists {
			return 0, addr, nil
		}
	}

	// We can't find any used addresses for this account's
	// branch.
	return 0, nil, nil
}

// rescanActiveAddresses accesses the daemon to discover all the addresses that
// have been used by an HD keychain stemming from this wallet in the default
// account.
func (w *Wallet) rescanActiveAddresses() error {
	log.Infof("Beginning a rescan of active addresses using the daemon. " +
		"This may take a while.")

	// Start by rescanning the accounts and determining what the
	// current account index is. This scan should only ever be
	// performed if we're restoring our wallet from seed.
	lastAcct := uint32(0)
	var err error
	if w.resyncAccounts {
		min := 0
		max := waddrmgr.MaxAccountNum
		lastAcct, err = w.scanAccountIndex(min, max)
		if err != nil {
			return err
		}
	}

	lastAcctMgr, err := w.Manager.LastAccount()
	if err != nil {
		return err
	}

	// The address manager is not synced (wallet has been restored
	// from seed?). In this case, spawn the accounts in the address
	// manager first. The accounts are named by their respective
	// index number, as strings.
	if lastAcctMgr < lastAcct {
		for i := lastAcctMgr + 1; i <= lastAcct; i++ {
			_, err := w.Manager.NewAccount(strconv.Itoa(int(i)))
			if err != nil {
				return err
			}
		}
	}

	// The account manager has a greater index than the rescan.
	// It is likely that the end user created a new account but
	// did not use it yet. Rescan it anyway so that the address
	// pool is created.
	if lastAcctMgr > lastAcct {
		lastAcct = lastAcctMgr
	}

	log.Infof("The last used account was %v. Beginning a rescan for "+
		"all active addresses in known accounts.", lastAcct)

	// Rescan addresses for the both the internal and external
	// branches of the account. Insert a new address pool for
	// the respective account and initialize it.
	for acct := uint32(0); acct <= lastAcct; acct++ {
		var extIdx, intIdx uint32
		min := 0
		max := waddrmgr.MaxAddressesPerAccount

		// Do this for both external (0) and internal (1) branches.
		for branch := uint32(0); branch < 2; branch++ {
			idx, lastAddr, err := w.scanAddressIndex(min, max, acct, branch)
			if err != nil {
				return err
			}

			// If the account is unused, buffer the initial address pool
			// by syncing the address manager upstream.
			unusedAcct := (lastAddr == nil)
			if unusedAcct {
				_, err := w.Manager.SyncAccountToAddrIndex(acct,
					addressPoolBuffer, branch)
				if err != nil {
					return fmt.Errorf("failed to create initial waddrmgr "+
						"address buffer for the address pool, "+
						"account %v, branch %v: %s", acct, branch,
						err.Error())
				}
			}

			branchString := "external"
			if branch == waddrmgr.InternalBranch {
				branchString = "internal"
			}

			// Fetch the address pool index for this account and
			// branch from the database meta bucket.
			isInternal := branch == waddrmgr.InternalBranch
			oldIdx, err := w.Manager.NextToUseAddrPoolIndex(isInternal, acct)
			unexpectedError := false
			if err != nil {
				mErr, ok := err.(waddrmgr.ManagerError)
				if !ok {
					unexpectedError = true
				} else {
					// Skip errors where the account's address index
					// has not been store. For this case, oldIdx will
					// be the special case 0 which will always be
					// skipped in the initialization step below.
					if mErr.ErrorCode != waddrmgr.ErrMetaPoolIdxNoExist {
						unexpectedError = true
					}
				}
				if unexpectedError {
					return fmt.Errorf("got unexpected error trying to "+
						"retrieve last known addr index for acct %v, "+
						"%s branch: %v", acct, branchString, err)
				}
			}

			// If the stored index is further along than the sync-to
			// index determined by the contents of daemon's addrindex,
			// use it to initialize the address pool instead.
			nextToUseIdx := idx
			if !unusedAcct {
				nextToUseIdx++
			}
			if oldIdx > nextToUseIdx {
				nextToUseIdx = oldIdx
			}
			nextToUseAddr, err := w.Manager.AddressDerivedFromDbAcct(
				nextToUseIdx, acct, branch)
			if err != nil {
				return fmt.Errorf("failed to derive next address for "+
					"account %v, branch %v: %s", acct, branch,
					err.Error())
			}

			// Save these for the address pool startup later.
			if isInternal {
				intIdx = nextToUseIdx
			} else {
				extIdx = nextToUseIdx
			}

			// Synchronize the account manager to our address index plus
			// an extra chunk of addresses that are used as a buffer
			// in the address pool.
			_, err = w.Manager.SyncAccountToAddrIndex(acct,
				nextToUseIdx+addressPoolBuffer, branch)
			if err != nil {
				// A ErrSyncToIndex error indicates that we're already
				// synced to beyond the end of the account in the
				// waddrmgr.
				errWaddrmgr, ok := err.(waddrmgr.ManagerError)
				if !ok || errWaddrmgr.ErrorCode != waddrmgr.ErrSyncToIndex {
					return fmt.Errorf("couldn't sync %s addresses in "+
						"address manager: %v", branchString, err.Error())
				}
			}

			// Set the next address in the waddrmgr database so that the
			// address pool can synchronize properly after.
			err = w.Manager.StoreNextToUseAddress(isInternal, acct, nextToUseIdx)
			if err != nil {
				log.Errorf("Failed to store next to use pool idx for "+
					"%s pool in the manager on init sync: %v",
					branchString, err.Error())
			}

			log.Infof("Successfully synchronized the address manager to "+
				"%s address %v (key index %v) for account %v",
				branchString,
				nextToUseAddr.String(),
				nextToUseIdx,
				acct)
		}

		pool, err := newAddressPools(acct, intIdx, extIdx, w)
		if err != nil {
			return err
		}

		w.addrPools[acct] = pool
	}

	log.Infof("Successfully synchronized wallet accounts to account "+
		"number %v.", lastAcct)

	return nil
}
