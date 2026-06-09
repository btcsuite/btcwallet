// Package wallet provides the implementation of a Bitcoin wallet.
//
// TODO(yy): This file will be removed once the Store implementation is
// finished.
package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/walletdb/migration"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// ErrMissingAddressManager is returned when the address manager namespace
	// is missing from the database.
	ErrMissingAddressManager = errors.New("missing address manager namespace")

	// ErrMissingTxManager is returned when the transaction manager namespace is
	// missing from the database.
	ErrMissingTxManager = errors.New("missing transaction manager namespace")
)

// DBCreateWallet initializes the database structure for a new wallet.
func DBCreateWallet(cfg Config, params CreateWalletParams,
	rootKey *hdkeychain.ExtendedKey) error {

	err := walletdb.Update(cfg.DB, func(tx walletdb.ReadWriteTx) error {
		// Create the top-level bucket for the address manager.
		addrMgrNs, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return fmt.Errorf("create addr mgr bucket: %w", err)
		}

		// Create the top-level bucket for the transaction manager.
		txMgrNs, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if err != nil {
			return fmt.Errorf("create tx mgr bucket: %w", err)
		}

		// Initialize the address manager in the database. This sets up
		// the master keys and the initial account structure.
		err = waddrmgr.Create(
			addrMgrNs, rootKey, params.PubPassphrase, params.PrivatePassphrase,
			cfg.ChainParams, nil, params.Birthday,
		)
		if err != nil {
			return fmt.Errorf("create addr mgr: %w", err)
		}

		// Initialize the transaction manager in the database.
		err = wtxmgr.Create(txMgrNs)
		if err != nil {
			return fmt.Errorf("create tx mgr: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	return nil
}

// DBLoadWallet initializes the database and returns the address and transaction
// managers.
func DBLoadWallet(cfg Config) (*waddrmgr.Manager, *wtxmgr.Store, error) {
	var (
		addrMgr *waddrmgr.Manager
		txMgr   *wtxmgr.Store
	)

	// Before attempting to open the wallet, we'll check if there are any
	// database upgrades for us to proceed. We'll also create our references
	// to the address and transaction managers, as they are backed by the
	// database.
	err := walletdb.Update(cfg.DB, func(tx walletdb.ReadWriteTx) error {
		addrMgrBucket := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if addrMgrBucket == nil {
			return ErrMissingAddressManager
		}

		txMgrBucket := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if txMgrBucket == nil {
			return ErrMissingTxManager
		}

		addrMgrUpgrader := waddrmgr.NewMigrationManager(addrMgrBucket)
		txMgrUpgrader := wtxmgr.NewMigrationManager(txMgrBucket)

		err := migration.Upgrade(txMgrUpgrader, addrMgrUpgrader)
		if err != nil {
			return fmt.Errorf("failed to upgrade database: %w", err)
		}

		addrMgr, err = waddrmgr.Open(
			addrMgrBucket, cfg.PubPassphrase, cfg.ChainParams,
		)
		if err != nil {
			return fmt.Errorf("failed to open address manager: %w", err)
		}

		txMgr, err = wtxmgr.Open(txMgrBucket, cfg.ChainParams)
		if err != nil {
			return fmt.Errorf("failed to open transaction manager: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load wallet: %w", err)
	}

	return addrMgr, txMgr, nil
}

// DBPutPassphrase updates the wallet's public or private passphrases.
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `UpdateWallet` instead.
func (w *Wallet) DBPutPassphrase(_ context.Context,
	req ChangePassphraseRequest) error {

	err := walletdb.Update(w.cfg.DB, func(tx walletdb.ReadWriteTx) error {
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
