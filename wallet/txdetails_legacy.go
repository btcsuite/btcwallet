// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// fetchTxDetails fetches the tx details for the given tx hash from the wallet's
// legacy tx store.
//
// NOTE: This helper remains for callers outside tx_reader.go, such as the PSBT
// manager, while tx_reader itself migrates to db.Store-backed detail reads.
// TODO(yy): Remove this helper once the remaining legacy callers, including the
// PSBT manager, no longer depend on wtxmgr.TxDetails.
func (w *Wallet) fetchTxDetails(txHash *chainhash.Hash) (*wtxmgr.TxDetails,
	error) {

	var txDetails *wtxmgr.TxDetails

	err := walletdb.View(w.cfg.DB, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		var err error

		txDetails, err = w.txStore.TxDetails(txmgrNs, txHash)
		if err != nil {
			return fmt.Errorf("failed to fetch tx details: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to view wallet db: %w", err)
	}

	if txDetails == nil {
		return nil, ErrTxNotFound
	}

	return txDetails, nil
}
