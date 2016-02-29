/*
 * Copyright (c) 2013-2015 The btcsuite developers
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
	"github.com/decred/dcrd/wire"
)

// attemptToRepairInconsistencies is called when there is some issue indicated
// with the wtxmgr database. This function should do absolutely nothing if the
// wallet is consistent, but will otherwise try to repair the wallet and make
// it continue to be functional even in the result of some unknown database
// failing.
func (w *Wallet) attemptToRepairInconsistencies() error {
	if !w.automaticRepair {
		log.Warnf("Inconsistencies have been found in the wallet database! " +
			"You may wish to recreate your wallet from seed or try automatic " +
			"repair. To enable automatic repair, turn on the" +
			" --automaticrepair flag.")
		return nil
	}

	chainClient, err := w.requireChainClient()
	if err != nil {
		return err
	}

	log.Warnf("Inconsistencies have been found in the wallet database! To " +
		"ensure smooth operation, they are being corrected. However, it is " +
		"recommended that you restore your wallet from seed to ensure that " +
		"your wallet is consistent and has all owned outputs.")

	log.Warnf("Removing orphan unspent outputs. This may take a while. Do not " +
		"shut down wallet at this time.")
	utxos, err := w.TxStore.RepairInconsistencies()
	if err != nil {
		return err
	}

	var toDelete []*wire.OutPoint
	for _, utxo := range utxos {
		_, err := chainClient.GetRawTransaction(&utxo.Hash)
		if err != nil {
			toDelete = append(toDelete, utxo)
		}
	}
	err = w.TxStore.DeleteUnspent(toDelete)
	if err != nil {
		return err
	}

	topBlockStamp := w.Manager.SyncedTo()
	err = w.TxStore.RepairMinedBalance(topBlockStamp.Height)
	if err != nil {
		return err
	}

	log.Infof("Wallet consistency repair complete. If errors are still being " +
		"returned or owned outputs are missing, try restoring the wallet " +
		"from the seed.")
	return nil
}
