/*
 * Copyright (c) 2013, 2014 Conformal Systems LLC <info@conformal.com>
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

package main

import (
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/chain"
	"github.com/conformal/btcwallet/keystore"
	"github.com/conformal/btcwallet/txstore"
)

func (w *Wallet) handleChainNotifications() {
	for n := range w.chainSvr.Notifications() {
		var err error
		switch n := n.(type) {
		case chain.ClientConnected:
			w.notifyChainServerConnected(true)
		case chain.BlockConnected:
			w.connectBlock(keystore.BlockStamp(n))
		case chain.BlockDisconnected:
			w.disconnectBlock(keystore.BlockStamp(n))
		case chain.RecvTx:
			err = w.addReceivedTx(n.Tx, n.Block)
		case chain.RedeemingTx:
			err = w.addRedeemingTx(n.Tx, n.Block)

		// The following are handled by the wallet's rescan
		// goroutines, so just pass them there.
		case *chain.RescanProgress, *chain.RescanFinished:
			w.rescanNotifications <- n
		}
		if err != nil {
			log.Errorf("Cannot handle chain server "+
				"notification: %v", err)
		}
	}
	w.wg.Done()
}

// connectBlock handles a chain server notification by marking a wallet
// that's currently in-sync with the chain server as being synced up to
// the passed block.
func (w *Wallet) connectBlock(bs keystore.BlockStamp) {
	if !w.ChainSynced() {
		return
	}

	w.KeyStore.SetSyncedWith(&bs)
	w.KeyStore.MarkDirty()
	w.notifyConnectedBlock(bs)

	w.notifyBalances(bs.Height)
}

// disconnectBlock handles a chain server reorganize by rolling back all
// block history from the reorged block for a wallet in-sync with the chain
// server.
func (w *Wallet) disconnectBlock(bs keystore.BlockStamp) {
	if !w.ChainSynced() {
		return
	}

	// Disconnect the last seen block from the keystore if it
	// matches the removed block.
	iter := w.KeyStore.NewIterateRecentBlocks()
	if iter != nil && *iter.BlockStamp().Hash == *bs.Hash {
		if iter.Prev() {
			prev := iter.BlockStamp()
			w.KeyStore.SetSyncedWith(&prev)
		} else {
			w.KeyStore.SetSyncedWith(nil)
		}
		w.KeyStore.MarkDirty()
	}
	w.notifyDisconnectedBlock(bs)

	w.notifyBalances(bs.Height - 1)
}

func (w *Wallet) addReceivedTx(tx *btcutil.Tx, block *txstore.Block) error {
	// For every output, if it pays to a wallet address, insert the
	// transaction into the store (possibly moving it from unconfirmed to
	// confirmed), and add a credit record if one does not already exist.
	var txr *txstore.TxRecord
	txInserted := false
	for txOutIdx, txOut := range tx.MsgTx().TxOut {
		// Errors don't matter here.  If addrs is nil, the range below
		// does nothing.
		_, addrs, _, _ := btcscript.ExtractPkScriptAddrs(txOut.PkScript,
			activeNet.Params)
		insert := false
		for _, addr := range addrs {
			_, err := w.KeyStore.Address(addr)
			if err == nil {
				insert = true
				break
			}
		}
		if insert {
			if !txInserted {
				var err error
				txr, err = w.TxStore.InsertTx(tx, block)
				if err != nil {
					return err
				}
				// InsertTx may have moved a previous unmined
				// tx, so mark the entire store as dirty.
				w.TxStore.MarkDirty()
				txInserted = true
			}
			if txr.HasCredit(txOutIdx) {
				continue
			}
			_, err := txr.AddCredit(uint32(txOutIdx), false)
			if err != nil {
				return err
			}
			w.TxStore.MarkDirty()
		}
	}

	bs, err := w.chainSvr.BlockStamp()
	if err == nil {
		w.notifyBalances(bs.Height)
	}

	return nil
}

// addRedeemingTx inserts the notified spending transaction as a debit and
// schedules the transaction store for a future file write.
func (w *Wallet) addRedeemingTx(tx *btcutil.Tx, block *txstore.Block) error {
	txr, err := w.TxStore.InsertTx(tx, block)
	if err != nil {
		return err
	}
	if _, err := txr.AddDebits(); err != nil {
		return err
	}
	w.KeyStore.MarkDirty()

	bs, err := w.chainSvr.BlockStamp()
	if err == nil {
		w.notifyBalances(bs.Height)
	}

	return nil
}

func (w *Wallet) notifyBalances(curHeight int32) {
	// Don't notify unless wallet is synced to the chain server.
	if !w.ChainSynced() {
		return
	}

	// Notify any potential changes to the balance.
	confirmed, err := w.TxStore.Balance(1, curHeight)
	if err != nil {
		log.Errorf("Cannot determine 1-conf balance: %v", err)
		return
	}
	w.notifyConfirmedBalance(confirmed)
	unconfirmed, err := w.TxStore.Balance(0, curHeight)
	if err != nil {
		log.Errorf("Cannot determine 0-conf balance: %v", err)
		return
	}
	w.notifyUnconfirmedBalance(unconfirmed - confirmed)
}
