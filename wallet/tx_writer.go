// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/walletdb"
)

// TxWriter provides an interface for updating wallet txns.
type TxWriter interface {
	// LabelTx adds a label to a tx. If a label already exists, it will be
	// overwritten.
	LabelTx(ctx context.Context, hash chainhash.Hash, label string) error
}

// A compile time check to ensure that Wallet implements the interface.
var _ TxWriter = (*Wallet)(nil)

// LabelTx adds a label to a tx. If a label already exists, it will be
// overwritten.
func (w *Wallet) LabelTx(_ context.Context,
	hash chainhash.Hash, label string) error {

	err := walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
		txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

		// Check that the transaction is known to the wallet.
		details, err := w.txStore.TxDetails(txmgrNs, &hash)
		if err != nil {
			return fmt.Errorf("failed to get tx details: %w", err)
		}

		if details == nil {
			return ErrTxNotFound
		}

		err = w.txStore.PutTxLabel(txmgrNs, hash, label)
		if err != nil {
			return fmt.Errorf("failed to put tx label: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to update wallet db: %w", err)
	}

	return nil
}
