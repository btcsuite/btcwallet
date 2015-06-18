/*
 * Copyright (c) 2013-2015 The btcsuite developers
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
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

func (w *Wallet) handleChainNotifications() {
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

	for n := range w.chainSvr.Notifications() {
		var err error
		switch n := n.(type) {
		case chain.ClientConnected:
			go sync(w)
		case chain.BlockConnected:
			w.connectBlock(wtxmgr.BlockMeta(n))
		case chain.BlockDisconnected:
			err = w.disconnectBlock(wtxmgr.BlockMeta(n))
		case chain.RelevantTx:
			err = w.addRelevantTx(n.TxRecord, n.Block)

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
func (w *Wallet) connectBlock(b wtxmgr.BlockMeta) {
	if !w.ChainSynced() {
		return
	}

	bs := waddrmgr.BlockStamp{
		Height: b.Height,
		Hash:   b.Hash,
	}
	if err := w.Manager.SetSyncedTo(&bs); err != nil {
		log.Errorf("Failed to update address manager sync state in "+
			"connect block for hash %v (height %d): %v", b.Hash,
			b.Height, err)
	}
	w.notifyConnectedBlock(b)

	w.notifyBalances(bs.Height)
}

// disconnectBlock handles a chain server reorganize by rolling back all
// block history from the reorged block for a wallet in-sync with the chain
// server.
func (w *Wallet) disconnectBlock(b wtxmgr.BlockMeta) error {
	if !w.ChainSynced() {
		return nil
	}

	// Disconnect the last seen block from the manager if it matches the
	// removed block.
	iter := w.Manager.NewIterateRecentBlocks()
	if iter != nil && iter.BlockStamp().Hash == b.Hash {
		if iter.Prev() {
			prev := iter.BlockStamp()
			w.Manager.SetSyncedTo(&prev)
			err := w.TxStore.Rollback(prev.Height + 1)
			if err != nil {
				return err
			}
		} else {
			// The reorg is farther back than the recently-seen list
			// of blocks has recorded, so set it to unsynced which
			// will in turn lead to a rescan from either the
			// earliest blockstamp the addresses in the manager are
			// known to have been created.
			w.Manager.SetSyncedTo(nil)
			// Rollback everything but the genesis block.
			err := w.TxStore.Rollback(1)
			if err != nil {
				return err
			}
		}
	}

	w.notifyDisconnectedBlock(b)
	w.notifyBalances(b.Height - 1)

	return nil
}

func (w *Wallet) addRelevantTx(rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta) error {
	// TODO: The transaction store and address manager need to be updated
	// together, but each operate under different namespaces and are changed
	// under new transactions.  This is not error safe as we lose
	// transaction semantics.
	//
	// I'm unsure of the best way to solve this.  Some possible solutions
	// and drawbacks:
	//
	//   1. Open write transactions here and pass the handle to every
	//      waddrmr and wtxmgr method.  This complicates the caller code
	//      everywhere, however.
	//
	//   2. Move the wtxmgr namespace into the waddrmgr namespace, likely
	//      under its own bucket.  This entire function can then be moved
	//      into the waddrmgr package, which updates the nested wtxmgr.
	//      This removes some of separation between the components.
	//
	//   3. Use multiple wtxmgrs, one for each account, nested in the
	//      waddrmgr namespace.  This still provides some sort of logical
	//      separation (transaction handling remains in another package, and
	//      is simply used by waddrmgr), but may result in duplicate
	//      transactions being saved if they are relevant to multiple
	//      accounts.
	//
	//   4. Store wtxmgr-related details under the waddrmgr namespace, but
	//      solve the drawback of #3 by splitting wtxmgr to save entire
	//      transaction records globally for all accounts, with
	//      credit/debit/balance tracking per account.  Each account would
	//      also save the relevant transaction hashes and block incidence so
	//      the full transaction can be loaded from the waddrmgr
	//      transactions bucket.  This currently seems like the best
	//      solution.

	// At the moment all notified transactions are assumed to actually be
	// relevant.  This assumption will not hold true when SPV support is
	// added, but until then, simply insert the transaction because there
	// should either be one or more relevant inputs or outputs.
	err := w.TxStore.InsertTx(rec, block)
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
			ma, err := w.Manager.Address(addr)
			if err == nil {
				// TODO: Credits should be added with the
				// account they belong to, so wtxmgr is able to
				// track per-account balances.
				err = w.TxStore.AddCredit(rec, block, uint32(i),
					ma.Internal())
				if err != nil {
					return err
				}
				err = w.Manager.MarkUsed(addr)
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

	// TODO: Notify connected clients of the added transaction.

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
