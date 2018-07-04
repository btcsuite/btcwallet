// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"strings"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

func (w *Wallet) handleChainNotifications() {
	chainClient, err := w.requireChainClient()
	if err != nil {
		log.Errorf("handleChainNotifications called without RPC client")
		w.wg.Done()
		return
	}

	sync := func(w *Wallet) {
		// At the moment there is no recourse if the rescan fails for
		// some reason, however, the wallet will not be marked synced
		// and many methods will error early since the wallet is known
		// to be out of date.
		err := w.syncWithChain()
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

	for n := range chainClient.Notifications() {
		var notificationName string
		var err error
		switch n := n.(type) {
		case chain.ClientConnected:
			go sync(w)
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
	}
	w.wg.Done()
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
		} else {
			w.NtfnServer.notifyUnminedTransaction(dbtx, details)
		}
	} else {
		details, err := w.TxStore.UniqueTxDetails(txmgrNs, &rec.Hash, &block.Block)
		if err != nil {
			log.Errorf("Cannot query transaction details for notification: %v", err)
		} else {
			w.NtfnServer.notifyMinedTransaction(dbtx, details, block)
		}
	}

	return nil
}
