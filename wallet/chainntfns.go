// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"

	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcwallet/chain"
	"github.com/roasbeef/btcwallet/waddrmgr"
	"github.com/roasbeef/btcwallet/walletdb"
	"github.com/roasbeef/btcwallet/wtxmgr"
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

		// The following are handled by the wallet's rescan
		// goroutines, so just pass them there.
		case *chain.RescanProgress, *chain.RescanFinished:
			w.rescanNotifications <- n
		}
		if err != nil {
			log.Errorf("Failed to process consensus server notification "+
				"(name: `%s`, detail: `%v`)", notificationName, err)
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
		Height: b.Height,
		Hash:   b.Hash,
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
			log.Errorf("Cannot query transaction details for notifiation: %v", err)
		} else {
			w.NtfnServer.notifyUnminedTransaction(dbtx, details)
		}
	} else {
		details, err := w.TxStore.UniqueTxDetails(txmgrNs, &rec.Hash, &block.Block)
		if err != nil {
			log.Errorf("Cannot query transaction details for notifiation: %v", err)
		} else {
			w.NtfnServer.notifyMinedTransaction(dbtx, details, block)
		}
	}

	return nil
}
