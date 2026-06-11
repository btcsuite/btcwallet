// Package wallet provides the implementation of a Bitcoin wallet.
//
// TODO(yy): This file will be removed once the Store implementation is
// finished.
package wallet

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

// DBPutPassphrase updates the wallet's public or private passphrases.
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `UpdateWallet` instead.
func (w *Wallet) DBPutPassphrase(_ context.Context,
	req ChangePassphraseRequest) error {

	db := w.legacyStore.DB()

	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		if req.ChangePublic {
			err := w.addrStore.ChangePassphrase(
				addrmgrNs, req.PublicOld, req.PublicNew,
				false, &waddrmgr.DefaultScryptOptions,
			)
			if err != nil {
				return fmt.Errorf("change public passphrase: "+
					"%w", err)
			}
		}

		if req.ChangePrivate {
			err := w.addrStore.ChangePassphrase(
				addrmgrNs, req.PrivateOld,
				req.PrivateNew, true,
				&waddrmgr.DefaultScryptOptions,
			)
			if err != nil {
				return fmt.Errorf("change private passphrase: "+
					"%w", err)
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	return nil
}
