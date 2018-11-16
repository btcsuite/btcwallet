// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

func (w *Wallet) handleChainNotifications() {
	defer w.wg.Done()

	chainClient, err := w.requireChainClient()
	if err != nil {
		log.Errorf("handleChainNotifications called without RPC client")
		return
	}

	sync := func(w *Wallet, birthdayStamp *waddrmgr.BlockStamp) {
		// At the moment there is no recourse if the rescan fails for
		// some reason, however, the wallet will not be marked synced
		// and many methods will error early since the wallet is known
		// to be out of date.
		err := w.syncWithChain(birthdayStamp)
		if err != nil && !w.ShuttingDown() {
			log.Warnf("Unable to synchronize wallet to chain: %v", err)
		}
	}

	catchUpHashes := func(w *Wallet, client chain.Interface,
		height int32) error {
		// TODO(aakselrod): There's a race conditon here, which
		// happens when a reorg occurs between the
		// rescanProgress notification and the last GetBlockHash
		// call. The solution when using btcd is to make btcd
		// send blockconnected notifications with each block
		// the way Neutrino does, and get rid of the loop. The
		// other alternative is to check the final hash and,
		// if it doesn't match the original hash returned by
		// the notification, to roll back and restart the
		// rescan.
		log.Infof("Catching up block hashes to height %d, this"+
			" might take a while", height)
		err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

			startBlock := w.Manager.SyncedTo()

			for i := startBlock.Height + 1; i <= height; i++ {
				hash, err := client.GetBlockHash(int64(i))
				if err != nil {
					return err
				}
				header, err := chainClient.GetBlockHeader(hash)
				if err != nil {
					return err
				}

				bs := waddrmgr.BlockStamp{
					Height:    i,
					Hash:      *hash,
					Timestamp: header.Timestamp,
				}
				err = w.Manager.SetSyncedTo(ns, &bs)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			log.Errorf("Failed to update address manager "+
				"sync state for height %d: %v", height, err)
		}

		log.Info("Done catching up block hashes")
		return err
	}

	for {
		select {
		case n, ok := <-chainClient.Notifications():
			if !ok {
				return
			}

			var notificationName string
			var err error
			switch n := n.(type) {
			case chain.ClientConnected:
				// Before attempting to sync with our backend,
				// we'll make sure that our birthday block has
				// been set correctly to potentially prevent
				// missing relevant events.
				birthdayBlock, err := w.birthdaySanityCheck()
				if err != nil {
					err := fmt.Errorf("unable to sanity "+
						"check wallet birthday block: %v",
						err)
					log.Error(err)
					panic(err)
				}

				go sync(w, birthdayBlock)
			case chain.BlockConnected:
				err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
					return w.connectBlock(tx, wtxmgr.BlockMeta(n))
				})
				notificationName = "blockconnected"
			case chain.BlockDisconnected:
				err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
					return w.disconnectBlock(tx, wtxmgr.BlockMeta(n))
				})
				notificationName = "blockdisconnected"
			case chain.RelevantTx:
				err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
					return w.addRelevantTx(tx, n.TxRecord, n.Block)
				})
				notificationName = "recvtx/redeemingtx"
			case chain.FilteredBlockConnected:
				// Atomically update for the whole block.
				if len(n.RelevantTxs) > 0 {
					err = walletdb.Update(w.db, func(
						tx walletdb.ReadWriteTx) error {
						var err error
						for _, rec := range n.RelevantTxs {
							err = w.addRelevantTx(tx, rec,
								n.Block)
							if err != nil {
								return err
							}
						}
						return nil
					})
				}
				notificationName = "filteredblockconnected"

			// The following require some database maintenance, but also
			// need to be reported to the wallet's rescan goroutine.
			case *chain.RescanProgress:
				err = catchUpHashes(w, chainClient, n.Height)
				notificationName = "rescanprogress"
				select {
				case w.rescanNotifications <- n:
				case <-w.quitChan():
					return
				}
			case *chain.RescanFinished:
				err = catchUpHashes(w, chainClient, n.Height)
				notificationName = "rescanprogress"
				w.SetChainSynced(true)
				select {
				case w.rescanNotifications <- n:
				case <-w.quitChan():
					return
				}
			}
			if err != nil {
				// On out-of-sync blockconnected notifications, only
				// send a debug message.
				errStr := "Failed to process consensus server " +
					"notification (name: `%s`, detail: `%v`)"
				if notificationName == "blockconnected" &&
					strings.Contains(err.Error(),
						"couldn't get hash from database") {
					log.Debugf(errStr, notificationName, err)
				} else {
					log.Errorf(errStr, notificationName, err)
				}
			}
		case <-w.quit:
			return
		}
	}
}

// connectBlock handles a chain server notification by marking a wallet
// that's currently in-sync with the chain server as being synced up to
// the passed block.
func (w *Wallet) connectBlock(dbtx walletdb.ReadWriteTx, b wtxmgr.BlockMeta) error {
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

	bs := waddrmgr.BlockStamp{
		Height:    b.Height,
		Hash:      b.Hash,
		Timestamp: b.Time,
	}
	err := w.Manager.SetSyncedTo(addrmgrNs, &bs)
	if err != nil {
		return err
	}

	// Notify interested clients of the connected block.
	//
	// TODO: move all notifications outside of the database transaction.
	w.NtfnServer.notifyAttachedBlock(dbtx, &b)
	return nil
}

// disconnectBlock handles a chain server reorganize by rolling back all
// block history from the reorged block for a wallet in-sync with the chain
// server.
func (w *Wallet) disconnectBlock(dbtx walletdb.ReadWriteTx, b wtxmgr.BlockMeta) error {
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	if !w.ChainSynced() {
		return nil
	}

	// Disconnect the removed block and all blocks after it if we know about
	// the disconnected block. Otherwise, the block is in the future.
	if b.Height <= w.Manager.SyncedTo().Height {
		hash, err := w.Manager.BlockHash(addrmgrNs, b.Height)
		if err != nil {
			return err
		}
		if bytes.Equal(hash[:], b.Hash[:]) {
			bs := waddrmgr.BlockStamp{
				Height: b.Height - 1,
			}
			hash, err = w.Manager.BlockHash(addrmgrNs, bs.Height)
			if err != nil {
				return err
			}
			b.Hash = *hash

			client := w.ChainClient()
			header, err := client.GetBlockHeader(hash)
			if err != nil {
				return err
			}

			bs.Timestamp = header.Timestamp
			err = w.Manager.SetSyncedTo(addrmgrNs, &bs)
			if err != nil {
				return err
			}

			err = w.TxStore.Rollback(txmgrNs, b.Height)
			if err != nil {
				return err
			}
		}
	}

	// Notify interested clients of the disconnected block.
	w.NtfnServer.notifyDetachedBlock(&b.Hash)

	return nil
}

func (w *Wallet) addRelevantTx(dbtx walletdb.ReadWriteTx, rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta) error {
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	// At the moment all notified transactions are assumed to actually be
	// relevant.  This assumption will not hold true when SPV support is
	// added, but until then, simply insert the transaction because there
	// should either be one or more relevant inputs or outputs.
	err := w.TxStore.InsertTx(txmgrNs, rec, block)
	if err != nil {
		return err
	}

	// Check every output to determine whether it is controlled by a wallet
	// key.  If so, mark the output as a credit.
	for i, output := range rec.MsgTx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript,
			w.chainParams)
		if err != nil {
			// Non-standard outputs are skipped.
			continue
		}
		for _, addr := range addrs {
			ma, err := w.Manager.Address(addrmgrNs, addr)
			if err == nil {
				// TODO: Credits should be added with the
				// account they belong to, so wtxmgr is able to
				// track per-account balances.
				err = w.TxStore.AddCredit(txmgrNs, rec, block, uint32(i),
					ma.Internal())
				if err != nil {
					return err
				}
				err = w.Manager.MarkUsed(addrmgrNs, addr)
				if err != nil {
					return err
				}
				log.Debugf("Marked address %v used", addr)
				continue
			}

			// Missing addresses are skipped.  Other errors should
			// be propagated.
			if !waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
				return err
			}
		}
	}

	// Send notification of mined or unmined transaction to any interested
	// clients.
	//
	// TODO: Avoid the extra db hits.
	if block == nil {
		details, err := w.TxStore.UniqueTxDetails(txmgrNs, &rec.Hash, nil)
		if err != nil {
			log.Errorf("Cannot query transaction details for notification: %v", err)
		}

		// It's possible that the transaction was not found within the
		// wallet's set of unconfirmed transactions due to it already
		// being confirmed, so we'll avoid notifying it.
		//
		// TODO(wilmer): ideally we should find the culprit to why we're
		// receiving an additional unconfirmed chain.RelevantTx
		// notification from the chain backend.
		if details != nil {
			w.NtfnServer.notifyUnminedTransaction(dbtx, details)
		}
	} else {
		details, err := w.TxStore.UniqueTxDetails(txmgrNs, &rec.Hash, &block.Block)
		if err != nil {
			log.Errorf("Cannot query transaction details for notification: %v", err)
		}

		// We'll only notify the transaction if it was found within the
		// wallet's set of confirmed transactions.
		if details != nil {
			w.NtfnServer.notifyMinedTransaction(dbtx, details, block)
		}
	}

	return nil
}

// birthdaySanityCheck is a helper function that ensures our birthday block
// correctly reflects the birthday timestamp within a reasonable timestamp
// delta. It will be run after the wallet establishes its connection with the
// backend, but before it begins syncing.  This is done as the second part to
// the wallet's address manager migration where we populate the birthday block
// to ensure we do not miss any relevant events throughout rescans.
func (w *Wallet) birthdaySanityCheck() (*waddrmgr.BlockStamp, error) {
	// We'll start by acquiring our chain backend client as we'll be
	// querying it for blocks.
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// We'll then fetch our wallet's birthday timestamp and block.
	var (
		birthdayTimestamp     = w.Manager.Birthday()
		birthdayBlock         waddrmgr.BlockStamp
		birthdayBlockVerified bool
	)
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		var err error
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		birthdayBlock, birthdayBlockVerified, err = w.Manager.BirthdayBlock(ns)
		return err
	})

	switch {
	// If our wallet's birthday block has not been set yet, then this is our
	// initial sync, so we'll defer setting it until then.
	case waddrmgr.IsError(err, waddrmgr.ErrBirthdayBlockNotSet):
		return nil, nil

	// Otherwise, we'll return the error if there was one.
	case err != nil:
		return nil, err
	}

	// If the birthday block has already been verified to be correct, we can
	// exit our sanity check to prevent potentially fetching a better
	// candidate.
	if birthdayBlockVerified {
		log.Debugf("Birthday block has already been verified: "+
			"height=%d, hash=%v", birthdayBlock.Height,
			birthdayBlock.Hash)

		return &birthdayBlock, nil
	}

	log.Debugf("Starting sanity check for the wallet's birthday block "+
		"from: height=%d, hash=%v", birthdayBlock.Height,
		birthdayBlock.Hash)

	// Now, we'll need to determine if our block correctly reflects our
	// timestamp. To do so, we'll fetch the block header and check its
	// timestamp in the event that the birthday block's timestamp was not
	// set (this is possible if it was set through the migration, since we
	// do not store block timestamps).
	candidate := birthdayBlock
	header, err := chainClient.GetBlockHeader(&candidate.Hash)
	if err != nil {
		return nil, fmt.Errorf("unable to get header for block hash "+
			"%v: %v", candidate.Hash, err)
	}
	candidate.Timestamp = header.Timestamp

	// We'll go back a day worth of blocks in the chain until we find a
	// block whose timestamp is below our birthday timestamp.
	heightDelta := int32(144)
	for birthdayTimestamp.Before(candidate.Timestamp) {
		// If the birthday block has reached genesis, then we can exit
		// our search as there exists no data before this point.
		if candidate.Height == 0 {
			break
		}

		// To prevent requesting blocks out of range, we'll use a lower
		// bound of the first block in the chain.
		newCandidateHeight := int64(candidate.Height - heightDelta)
		if newCandidateHeight < 0 {
			newCandidateHeight = 0
		}

		// Then, we'll fetch the current candidate's hash and header to
		// determine if it is valid.
		hash, err := chainClient.GetBlockHash(newCandidateHeight)
		if err != nil {
			return nil, fmt.Errorf("unable to get block hash for "+
				"height %d: %v", candidate.Height, err)
		}
		header, err := chainClient.GetBlockHeader(hash)
		if err != nil {
			return nil, fmt.Errorf("unable to get header for "+
				"block hash %v: %v", candidate.Hash, err)
		}

		candidate.Hash = *hash
		candidate.Timestamp = header.Timestamp

		log.Debugf("Checking next birthday block candidate: "+
			"height=%d, hash=%v, timestamp=%v",
			candidate.Height, candidate.Hash,
			candidate.Timestamp)
	}

	// To ensure we have a reasonable birthday block, we'll make sure it
	// respects our birthday timestamp and it is within a reasonable delta.
	// The birthday has already been adjusted to two days in the past of the
	// actual birthday, so we'll make our expected delta to be within two
	// hours of it to account for the network-adjusted time and prevent
	// fetching more unnecessary blocks.
	_, bestHeight, err := chainClient.GetBestBlock()
	if err != nil {
		return nil, err
	}
	timestampDelta := birthdayTimestamp.Sub(candidate.Timestamp)
	for timestampDelta > 2*time.Hour {
		// We'll determine the height for our next candidate and make
		// sure it is not out of range. If it is, we'll lower our height
		// delta until finding a height within range.
		newHeight := candidate.Height + heightDelta
		if newHeight > bestHeight {
			heightDelta /= 2

			// If we've exhausted all of our possible options at a
			// later height, then we can assume the current birthday
			// block is our best estimate.
			if heightDelta == 0 {
				break
			}

			continue
		}

		// We'll fetch the header for the next candidate and compare its
		// timestamp.
		hash, err := chainClient.GetBlockHash(int64(newHeight))
		if err != nil {
			return nil, fmt.Errorf("unable to get block hash for "+
				"height %d: %v", candidate.Height, err)
		}
		header, err := chainClient.GetBlockHeader(hash)
		if err != nil {
			return nil, fmt.Errorf("unable to get header for "+
				"block hash %v: %v", hash, err)
		}

		log.Debugf("Checking next birthday block candidate: "+
			"height=%d, hash=%v, timestamp=%v", newHeight, hash,
			header.Timestamp)

		// If this block has exceeded our birthday timestamp, we'll look
		// for the next candidate with a lower height delta.
		if birthdayTimestamp.Before(header.Timestamp) {
			heightDelta /= 2

			// If we've exhausted all of our possible options at a
			// later height, then we can assume the current birthday
			// block is our best estimate.
			if heightDelta == 0 {
				break
			}

			continue
		}

		// Otherwise, this is a valid candidate, so we'll check to see
		// if it meets our expected timestamp delta.
		candidate.Hash = *hash
		candidate.Height = newHeight
		candidate.Timestamp = header.Timestamp
		timestampDelta = birthdayTimestamp.Sub(header.Timestamp)
	}

	// At this point, we've found a new, better candidate, so we'll write it
	// to disk.
	log.Debugf("Found a new valid wallet birthday block: height=%d, hash=%v",
		candidate.Height, candidate.Hash)

	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		err := w.Manager.SetBirthdayBlock(ns, candidate, true)
		if err != nil {
			return err
		}
		return w.Manager.SetSyncedTo(ns, &candidate)
	})
	if err != nil {
		return nil, err
	}

	return &candidate, nil
}
