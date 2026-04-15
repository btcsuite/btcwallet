// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
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
func (w *Wallet) LabelTx(ctx context.Context,
	hash chainhash.Hash, label string) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	err = w.store.UpdateTx(ctx, db.UpdateTxParams{
		WalletID: w.id,
		Txid:     hash,
		Label:    &label,
	})
	if err != nil {
		if errors.Is(err, db.ErrTxNotFound) {
			return fmt.Errorf("update tx label: %w", ErrTxNotFound)
		}

		return fmt.Errorf("update tx label: %w", err)
	}

	return nil
}
