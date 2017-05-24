// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

func (s *Session) handleChainNotifications() {
	defer s.Wallet.wg.Done()
	
	sync := func(s *Session) {
		// At the moment there is no recourse if the rescan fails for
		// some reason, however, the wallet will not be marked synced
		// and many methods will error early since the wallet is known
		// to be out of date.
		err := s.syncWithChain()
		if err != nil && !s.ShuttingDown() {
			log.Warnf("Unable to synchronize wallet to chain: %v", err)
		}
	}

	notifications := s.chainClient.Notifications()
	for {
		select {
		// If the wallet session is closed, end the function.
		case <-s.quit:
			return
		case n, ok := <-notifications:
			if !ok {
				// If the notification channel is closed, turn off the wallet.
				s.Stop()
				return
			}

			var err error
			switch n := n.(type) {
			case chain.ClientConnected:
				go sync(s)
			case chain.BlockConnected:
				s.connectBlock(wtxmgr.BlockMeta(n))
			case chain.BlockDisconnected:
				err = s.disconnectBlock(wtxmgr.BlockMeta(n))
			case chain.RelevantTx:
				err = s.Wallet.addRelevantTx(n.TxRecord, n.Block)

			// The following are handled by the wallet's rescan
			// goroutines, so just pass them there.
			case *chain.RescanProgress, *chain.RescanFinished:
				s.Wallet.rescanNotifications <- n
			}
			if err != nil {
				log.Errorf("Cannot handle chain server "+
					"notification: %v", err)
			}
		}
	}
}

// connectBlock handles a chain server notification by marking a wallet
// that's currently in-sync with the chain server as being synced up to
// the passed block.
func (s *Session) connectBlock(b wtxmgr.BlockMeta) {
	bs := waddrmgr.BlockStamp{
		Height: b.Height,
		Hash:   b.Hash,
	}
	if err := s.Wallet.Manager.SetSyncedTo(&bs); err != nil {
		log.Errorf("Failed to update address manager sync state in "+
			"connect block for hash %v (height %d): %v", b.Hash,
			b.Height, err)
	}

	// Notify interested clients of the connected block.
	s.Wallet.NtfnServer.notifyAttachedBlock(s, &b)
}

// disconnectBlock handles a chain server reorganize by rolling back all
// block history from the reorged block for a wallet in-sync with the chain
// server.
func (s *Session) disconnectBlock(b wtxmgr.BlockMeta) error {
	if !s.ChainSynced() {
		return nil
	}

	// Disconnect the last seen block from the manager if it matches the
	// removed block.
	iter := s.Wallet.Manager.NewIterateRecentBlocks()
	if iter != nil && iter.BlockStamp().Hash == b.Hash {
		if iter.Prev() {
			prev := iter.BlockStamp()
			s.Wallet.Manager.SetSyncedTo(&prev)
			err := s.Wallet.TxStore.Rollback(prev.Height + 1)
			if err != nil {
				return err
			}
		} else {
			// The reorg is farther back than the recently-seen list
			// of blocks has recorded, so set it to unsynced which
			// will in turn lead to a rescan from either the
			// earliest blockstamp the addresses in the manager are
			// known to have been created.
			s.Wallet.Manager.SetSyncedTo(nil)
			// Rollback everything but the genesis block.
			err := s.Wallet.TxStore.Rollback(1)
			if err != nil {
				return err
			}
		}
	}

	// Notify interested clients of the disconnected block.
	s.Wallet.NtfnServer.notifyDetachedBlock(&b.Hash)

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

	// Send notification of mined or unmined transaction to any interested
	// clients.
	//
	// TODO: Avoid the extra db hits.
	if block == nil {
		details, err := w.TxStore.UniqueTxDetails(&rec.Hash, nil)
		if err != nil {
			log.Errorf("Cannot query transaction details for notifiation: %v", err)
		} else {
			w.NtfnServer.notifyUnminedTransaction(w, details)
		}
	} else {
		details, err := w.TxStore.UniqueTxDetails(&rec.Hash, &block.Block)
		if err != nil {
			log.Errorf("Cannot query transaction details for notifiation: %v", err)
		} else {
			w.NtfnServer.notifyMinedTransaction(w, details, block)
		}
	}

	return nil
}
