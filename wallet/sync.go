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
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/btcsuite/btclog"

	"github.com/decred/bitset"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrutil/hdkeychain"
	"github.com/decred/dcrwallet/chain"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/walletdb"
)

const (
	// finalScanLength is the final length of accounts to scan for the function
	// below.
	finalAcctScanLength = 50

	// acctSeekWidth is the number of addresses for both internal and external
	// branches to scan to determine whether or not an account exists and should
	// be rescanned. This is the tolerance for account gaps as well.
	acctSeekWidth = 5

	// debugScanLength is the final length of keys to scan past the
	// last index returned from the logarithmic scanning function
	// when creating the debug string of used addresses.
	debugAddrScanLength = 3500

	// addrSeekWidth is the number of new addresses to generate and add to the
	// address manager when trying to sync up a wallet to the main chain. This
	// is the maximum gap introduced by a resyncing as well, and should be less
	// than finalScanLength above.
	//
	// TODO Optimize the scanning so that rather than overshooting the end
	// address, you instead step through addresses incrementally until reaching
	// idx so that you don't reach a gap. This can be done by keeping track of
	// where the current cursor is and adding addresses in big chunks until you
	// hit the end.
	addrSeekWidth = 20
)

type discoveryContext struct {
	chainClient *chain.RPCClient
	deriveAddr  func(ns walletdb.ReadBucket, index uint32, account uint32, branch uint32) (dcrutil.Address, error)
}

// accountIsUsed checks if an account has ever been used by scanning the
// first acctSeekWidth many addresses for usage.
func (w *Wallet) accountIsUsed(ctx *discoveryContext, account uint32) (bool, error) {
	for branch := uint32(0); branch < 2; branch++ {
		for i := uint32(0); i < acctSeekWidth; i++ {
			var addr dcrutil.Address
			err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
				addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
				var err error
				addr, err = ctx.deriveAddr(addrmgrNs, i, account, branch)
				return err
			})
			// Skip erroneous keys, which happen rarely.
			if e, ok := err.(waddrmgr.ManagerError); ok && e.Err == hdkeychain.ErrInvalidChild {
				continue
			}
			if err != nil {
				return false, err
			}

			exists, err := ctx.chainClient.ExistsAddress(addr)
			if err != nil {
				return false, err
			}
			if exists {
				return true, nil
			}
		}
	}

	return false, nil
}

// bisectLastAcctIndex is a helper function for searching through accounts to
// find the last used account. It uses logarithmic scanning to determine if
// an account has been used.
func (w *Wallet) bisectLastAcctIndex(ctx *discoveryContext, hi, low uint32) (uint32, error) {
	offset := low
	for i := hi - low - 1; i > 0; i /= 2 {
		if i+offset+acctSeekWidth < waddrmgr.MaxAddressesPerAccount {
			for j := i + offset + addrSeekWidth; j >= i+offset; j-- {
				used, err := w.accountIsUsed(ctx, j)
				if err != nil {
					return 0, err
				}
				if used {
					return i + offset, nil
				}
			}
		} else {
			used, err := w.accountIsUsed(ctx, i+offset)
			if err != nil {
				return 0, err
			}
			if used {
				return i + offset, nil
			}
		}
	}

	return 0, nil
}

// findAcctEnd is a helper function for searching for the last used account by
// logarithmic scanning of the account indexes.
func (w *Wallet) findAcctEnd(ctx *discoveryContext, start, stop uint32) (uint32, error) {
	indexStart, err := w.bisectLastAcctIndex(ctx, stop, start)
	if err != nil {
		return 0, err
	}
	var indexLast uint32
	for {
		indexLastStored := indexStart
		low := indexLastStored
		hi := indexLast + ((indexStart - indexLast) * 2) + 1
		indexStart, err = w.bisectLastAcctIndex(ctx, hi, low)
		if err != nil {
			return 0, err
		}
		indexLast = indexLastStored

		if indexStart == 0 {
			break
		}
	}

	return indexLast, nil
}

// scanAccountIndex identifies the last used address in an HD keychain of public
// keys. It returns the index of the last used key, along with the address of
// this key.
func (w *Wallet) scanAccountIndex(ctx *discoveryContext, start, end uint32) (uint32, error) {
	// Find the last used account. Scan from it to the end in case there was a
	// gap from that position, which is possible. Then, return the account
	// in that position.
	lastUsed, err := w.findAcctEnd(ctx, start, end)
	if err != nil {
		return 0, err
	}
	if lastUsed != 0 {
		for i := lastUsed + finalAcctScanLength; i >= lastUsed; i-- {
			used, err := w.accountIsUsed(ctx, i)
			if err != nil {
				return 0, err
			}
			if used {
				return i, nil
			}
		}
	}

	// We can't find any used addresses. The account is
	// unused.
	return 0, nil
}

// scanAddressRange scans backwards from end to start many addresses in the
// account branch, and return the first index that is found on the blockchain.
// If the address doesn't exist, false is returned as the first argument.
func (w *Wallet) scanAddressRange(ctx *discoveryContext,
	account uint32, branch uint32, start, end uint32) (bool, uint32, error) {

	var addresses []dcrutil.Address
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error
		addresses, err = w.Manager.AddressesDerivedFromDbAcct(addrmgrNs,
			start, end+1, account, branch)
		return err
	})
	if err != nil {
		return false, 0, err
	}

	// Whether or not the addresses exist is encoded as a binary
	// bitset.
	exists, err := ctx.chainClient.ExistsAddresses(addresses)
	if err != nil {
		return false, 0, err
	}
	existsB, err := hex.DecodeString(exists)
	if err != nil {
		return false, 0, err
	}
	set := bitset.Bytes(existsB)

	// Prevent a panic when an empty message is passed as a response.
	if len(set) == 0 {
		return false, 0, nil
	}

	// Scan backwards and return if we find an address exists.
	idx := end
	itr := len(addresses) - 1
	for idx >= start {
		// If the address exists in the mempool or blockchain according
		// to the bit set returned, return this index.
		if set.Get(itr) {
			return true, idx, nil
		}

		itr--
		idx--
	}

	return false, 0, nil
}

// bisectLastAddrIndex is a helper function for search through addresses.
func (w *Wallet) bisectLastAddrIndex(ctx *discoveryContext, hi, low uint32,
	account uint32, branch uint32) (uint32, error) {

	// Logarithmically scan address indexes to find the last used
	// address index. Each time the algorithm receives an end point,
	// scans a chunk of addresses at the end point, and if no
	// addresses are found, divides the address index by two and
	// repeats until it finds the last used index.
	offset := low
	for i := hi - low - 1; i > 0; i /= 2 {
		if i+offset+addrSeekWidth < waddrmgr.MaxAddressesPerAccount {
			start := i + offset
			end := i + offset + addrSeekWidth
			exists, idx, err := w.scanAddressRange(ctx, account, branch, start, end)
			// Skip erroneous keys, which happen rarely. Don't skip
			// other errors.
			if e, ok := err.(waddrmgr.ManagerError); ok && e.Err == hdkeychain.ErrInvalidChild {
				continue
			}
			if err != nil {
				return 0, err
			}
			if exists {
				return idx, nil
			}
		} else {
			var addr dcrutil.Address
			err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
				addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
				var err error
				addr, err = w.Manager.AddressDerivedFromDbAcct(addrmgrNs,
					i+offset, account, branch)
				return err
			})
			// Skip erroneous keys, which happen rarely.
			if err != nil {
				continue
			}

			exists, err := ctx.chainClient.ExistsAddress(addr)
			if err != nil {
				return 0, err
			}
			if exists {
				return i + offset, nil
			}
		}
	}

	return 0, nil
}

// findEnd is a helper function for searching for used addresses.
func (w *Wallet) findAddrEnd(ctx *discoveryContext, start, stop uint32,
	account uint32, branch uint32) (uint32, error) {

	indexStart, err := w.bisectLastAddrIndex(ctx, stop, start, account, branch)
	if err != nil {
		return 0, err
	}
	var indexLast uint32
	for {
		indexLastStored := indexStart
		low := indexLastStored
		hi := indexLast + ((indexStart - indexLast) * 2) + 1
		indexStart, err = w.bisectLastAddrIndex(ctx, hi, low, account, branch)
		if err != nil {
			return 0, err
		}
		indexLast = indexLastStored

		if indexStart == 0 {
			break
		}
	}

	return indexLast, nil
}

// debugAccountAddrGapsString is a debug function that prints a graphical outlook
// of address usage to a string, from the perspective of the daemon.
func debugAccountAddrGapsString(chainClient *chain.RPCClient, scanBackFrom uint32,
	account uint32, branch uint32, w *Wallet) (string, error) {

	var buf bytes.Buffer
	str := fmt.Sprintf("Begin debug address scan scanning backwards from "+
		"idx %v, account %v, branch %v\n", scanBackFrom, account, branch)
	buf.WriteString(str)
	var firstUsedIndex uint32
	for i := scanBackFrom; i > 0; i-- {
		var addr dcrutil.Address
		err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			var err error
			addr, err = w.Manager.AddressDerivedFromDbAcct(addrmgrNs,
				i, account, branch)
			return err
		})
		// Skip erroneous keys.
		if err != nil {
			continue
		}

		exists, err := chainClient.ExistsAddress(addr)
		if err != nil {
			return "", fmt.Errorf("failed to access chain server: %v",
				err)
		}

		if exists {
			firstUsedIndex = i
			break
		}
	}

	str = fmt.Sprintf("Last used index found: %v\n", firstUsedIndex)
	buf.WriteString(str)

	var batchSize uint32 = 50
	batches := (firstUsedIndex / batchSize) + 1
	var lastBatchSize uint32
	if firstUsedIndex%batchSize != 0 {
		lastBatchSize = firstUsedIndex - ((batches - 1) * batchSize)
	}

	for i := uint32(0); i < batches; i++ {
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
			var addr dcrutil.Address
			err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
				addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
				var err error
				addr, err = w.Manager.AddressDerivedFromDbAcct(addrmgrNs,
					j, account, branch)
				return err
			})
			if err != nil {
				char = "X"
			}

			exists, err := chainClient.ExistsAddress(addr)
			if err != nil {
				return "", fmt.Errorf("failed to access chain server: %v",
					err)
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
func (w *Wallet) scanAddressIndex(ctx *discoveryContext, start, end uint32,
	account uint32, branch uint32) (uint32, dcrutil.Address, error) {

	// Find the last used address. Scan from it to the end in case there was a
	// gap from that position, which is possible. Then, return the address
	// in that position.
	lastUsed, err := w.findAddrEnd(ctx, start, end, account, branch)
	if err != nil {
		return 0, nil, err
	}

	// If debug is on, do an exhaustive check and a graphical printout
	// of what the used addresses currently look like.
	if log.Level() <= btclog.DebugLvl {
		dbgStr, err := debugAccountAddrGapsString(ctx.chainClient,
			lastUsed+debugAddrScanLength, account, branch, w)
		if err != nil {
			log.Debugf("Failed to debug address gaps for account %v, "+
				"branch %v: %v", account, branch, err)
		} else {
			log.Debugf("%v", dbgStr)
		}
	}

	// If there was a last used index, do an exhaustive final scan that
	// reexamines the last used addresses and ensures that the final index
	// we have found is correct.
	if lastUsed != 0 {
		start := lastUsed
		end := lastUsed + uint32(w.addrIdxScanLen)
		exists, idx, err := w.scanAddressRange(ctx, account, branch, start, end)
		if err != nil {
			return 0, nil, err
		}

		if exists {
			lastUsed = idx
			var addr dcrutil.Address
			err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
				addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
				var err error
				addr, err = w.Manager.AddressDerivedFromDbAcct(addrmgrNs,
					lastUsed, account, branch)
				return err
			})
			if err != nil {
				return 0, nil, err
			}
			return lastUsed, addr, nil
		}
	}

	// In the case that 0 was returned as the last used address,
	// make sure the the 0th address was not used. If it was,
	// return this address to let the caller know that this
	// 0th address was used.
	if lastUsed == 0 {
		var addr dcrutil.Address
		err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			var err error
			addr, err = w.Manager.AddressDerivedFromDbAcct(addrmgrNs, 0,
				account, branch)
			return err
		})
		// Skip erroneous keys.
		if err != nil {
			return 0, nil, err
		}

		exists, err := ctx.chainClient.ExistsAddress(addr)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to access chain server: %v",
				err)
		}

		if exists {
			return 0, addr, nil
		}
	}

	// We can't find any used addresses for this account's
	// branch.
	return 0, nil, nil
}

// DiscoverActiveAddresses accesses the consensus RPC server to discover all the
// addresses that have been used by an HD keychain stemming from this wallet. If
// discoverAccts is true, used accounts will be discovered as well.  This
// feature requires the wallet to be unlocked in order to derive hardened
// account extended pubkeys.
//
// A transaction filter (re)load and rescan should be performed after discovery.
//
// BUG(jrick): This function reassigns address pools, and if called multiple
// times it would not be unlikely to see address reuse due to losing the address
// pool's derivation index.  I am punting on this for now.  In the future,
// address pools should be removed and all derivation should be done solely by
// waddrmgr.  Use with caution.
func (w *Wallet) DiscoverActiveAddresses(chainClient *chain.RPCClient, discoverAccts bool) error {
	log.Infof("Beginning a rescan of active addresses using the daemon. " +
		"This may take a while.")

	// Search external branch then internal branch for a used address. We need
	// to set the address function to use based on whether or not this is the
	// initial sync. The function AddressDerivedFromCointype is able to see
	// addresses that exists in accounts that have not yet been created, while
	// AddressDerivedFromDbAcct can not.
	derive := w.Manager.AddressDerivedFromDbAcct
	if discoverAccts {
		derive = w.Manager.AddressDerivedFromCointype
	}

	ctx := &discoveryContext{chainClient: chainClient, deriveAddr: derive}

	// Start by rescanning the accounts and determining what the
	// current account index is. This scan should only ever be
	// performed if we're restoring our wallet from seed.
	var lastAcct uint32
	if w.initiallyUnlocked {
		var err error
		lastAcct, err = w.scanAccountIndex(ctx, 0, waddrmgr.MaxAccountNum)
		if err != nil {
			return err
		}
	}

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		lastAcctMgr, err := w.Manager.LastAccount(addrmgrNs)
		if err != nil {
			return err
		}

		// The address manager is not synced (wallet has been restored
		// from seed?). In this case, spawn the accounts in the address
		// manager first. The accounts are named by their respective
		// index number, as strings.
		if lastAcctMgr < lastAcct {
			for i := lastAcctMgr + 1; i <= lastAcct; i++ {
				_, err := w.Manager.NewAccount(
					addrmgrNs, strconv.Itoa(int(i)))
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
		return nil
	})
	if err != nil {
		return err
	}

	log.Infof("The last used account was %v. Beginning a rescan for "+
		"all active addresses in known accounts.", lastAcct)

	// Rescan addresses for the both the internal and external
	// branches of the account. Insert a new address pool for
	// the respective account and initialize it.
	for acct := uint32(0); acct <= lastAcct; acct++ {
		var extIdx, intIdx uint32

		// Do this for both external (0) and internal (1) branches.
		for branch := uint32(0); branch < 2; branch++ {
			idx, lastAddr, err := w.scanAddressIndex(ctx, 0,
				waddrmgr.MaxAddressesPerAccount, acct, branch)
			if err != nil {
				return err
			}

			err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
				addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

				// If the account is unused, buffer the initial address pool
				// by syncing the address manager upstream.
				unusedAcct := (lastAddr == nil)
				if unusedAcct {
					_, err := w.Manager.SyncAccountToAddrIndex(
						addrmgrNs, acct, addressPoolBuffer, branch)
					if err != nil {
						// A ErrSyncToIndex error indicates that we're already
						// synced to beyond the end of the account in the
						// waddrmgr.
						errWaddrmgr, ok := err.(waddrmgr.ManagerError)
						if !ok || errWaddrmgr.ErrorCode != waddrmgr.ErrSyncToIndex {
							return fmt.Errorf("failed to create initial waddrmgr "+
								"address buffer for the address pool, "+
								"account %v, branch %v: %v", acct, branch,
								err)
						}
					}
				}

				branchString := "external"
				if branch == waddrmgr.InternalBranch {
					branchString = "internal"
				}

				// Fetch the address pool index for this account and
				// branch from the database meta bucket.
				isInternal := branch == waddrmgr.InternalBranch
				oldIdx, err := w.Manager.NextToUseAddrPoolIndex(
					addrmgrNs, isInternal, acct)
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
					addrmgrNs, nextToUseIdx, acct, branch)
				if err != nil {
					return fmt.Errorf("failed to derive next address for "+
						"account %v, branch %v: %v", acct, branch,
						err)
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
				_, err = w.Manager.SyncAccountToAddrIndex(addrmgrNs,
					acct, nextToUseIdx+addressPoolBuffer, branch)
				if err != nil {
					// A ErrSyncToIndex error indicates that we're already
					// synced to beyond the end of the account in the
					// waddrmgr.
					errWaddrmgr, ok := err.(waddrmgr.ManagerError)
					if !ok || errWaddrmgr.ErrorCode != waddrmgr.ErrSyncToIndex {
						return fmt.Errorf("couldn't sync %s addresses in "+
							"address manager: %v", branchString, err)
					}
				}

				// Set the next address in the waddrmgr database so that the
				// address pool can synchronize properly after.
				err = w.Manager.StoreNextToUseAddress(
					addrmgrNs, isInternal, acct, nextToUseIdx)
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
				return nil
			})
			if err != nil {
				return err
			}
		}

		pool, err := newAddressPools(acct, intIdx, extIdx, w)
		if err != nil {
			return err
		}

		w.addrPoolsMtx.Lock()
		w.addrPools[acct] = pool
		w.addrPoolsMtx.Unlock()
	}

	log.Infof("Successfully synchronized wallet accounts to account "+
		"number %v.", lastAcct)

	return nil
}
