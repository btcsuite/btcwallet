// Copyright (c) 2016 The Decred developers
// Copyright (c) 2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcd/chainhash/v2"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

type unstableAPI struct {
	w *Wallet
}

// UnstableAPI exposes additional unstable public APIs for a Wallet.  These APIs
// may be changed or removed at any time.  Currently this type exists to ease
// the transition (particularly for the legacy JSON-RPC server) from using
// exported manager packages to a unified wallet package that exposes all
// functionality by itself.  New code should not be written using this API.
func UnstableAPI(w *Wallet) unstableAPI { // nolint:golint
	return unstableAPI{w}
}

// TxDetails returns transaction details under a single Store view transaction.
func (u unstableAPI) TxDetails(
	txHash *chainhash.Hash) (*wtxmgr.TxDetails, error) {

	var details *wtxmgr.TxDetails

	err := u.w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {

			var err error
			details, err = tx.Tx().TxDetails(txHash)
			return err
		}, func() {
			details = nil
		})

	return details, err
}

// RangeTransactions visits transaction details under a single Store view
// transaction. The caller callback runs only after the read succeeds so SQL
// transaction retries cannot replay caller side effects.
func (u unstableAPI) RangeTransactions(begin, end int32,
	visit func([]wtxmgr.TxDetails) (bool, error)) error {

	var batches [][]wtxmgr.TxDetails
	err := u.w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			return tx.Tx().RangeTransactions(
				begin, end,
				func(details []wtxmgr.TxDetails) (bool, error) {
					batch := append([]wtxmgr.TxDetails(nil), details...)
					batches = append(batches, batch)

					return false, nil
				},
			)
		}, func() {
			batches = nil
		},
	)
	if err != nil {
		return err
	}

	for _, batch := range batches {
		stop, err := visit(batch)
		if err != nil || stop {
			return err
		}
	}

	return nil
}
