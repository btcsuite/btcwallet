// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

// NewAccount creates the next account and returns its account number. The name
// must be unique under the kep scope. In order to support automatic seed
// restoring, new accounts may not be created when all of the previous 100
// accounts have no transaction history (this is a deviation from the BIP0044
// spec, which allows no unused account gaps).
func (w *Wallet) NewAccount(_ context.Context, scope waddrmgr.KeyScope,
	name string) (uint32, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return 0, err
	}

	// Validate that the scope manager can add this new account.
	err = manager.CanAddAccount()
	if err != nil {
		return 0, err
	}

	var (
		accountIndex uint32
	)
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		// Create a new account under the current key scope.
		accountID, err := manager.NewAccount(addrmgrNs, name)
		accountIndex = accountID

		return err
	})

	return accountIndex, err
}
