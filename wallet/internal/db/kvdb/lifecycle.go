package kvdb

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/walletdb/migration"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// CreateWalletRequest holds the per-wallet inputs for initializing a kvdb
// wallet. It is operation data rather than configuration: the database, chain
// parameters and public passphrase live on Config.
type CreateWalletRequest struct {
	// RootKey is the optional root extended key used to initialize
	// waddrmgr. A nil key creates a watch-only wallet.
	RootKey *hdkeychain.ExtendedKey

	// PrivatePassphrase protects the private keys and script bodies.
	PrivatePassphrase []byte

	// Birthday is the wallet birthday persisted in waddrmgr.
	Birthday time.Time
}

// CreateWallet initializes the walletdb bucket structure for a new wallet on
// the already-open database in cfg, in a single transaction.
func CreateWallet(cfg Config, req CreateWalletRequest) error {
	err := walletdb.Update(cfg.DB, func(tx walletdb.ReadWriteTx) error {
		addrMgrNs, err := tx.CreateTopLevelBucket(waddrmgr.NamespaceKey)
		if err != nil {
			return fmt.Errorf("create addr mgr bucket: %w", err)
		}

		txMgrNs, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if err != nil {
			return fmt.Errorf("create tx mgr bucket: %w", err)
		}

		// The public passphrase is the create credential and lives on
		// Config, the same carrier a later Open reads it from.
		err = waddrmgr.Create(
			addrMgrNs, req.RootKey, cfg.PubPassphrase,
			req.PrivatePassphrase, cfg.ChainParams, nil,
			req.Birthday,
		)
		if err != nil {
			return fmt.Errorf("create addr mgr: %w", err)
		}

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

// OpenStore upgrades and opens the legacy managers on the already-open database
// in cfg and returns the Store adapter over them.
//
// The address manager is returned alongside the Store because it holds live key
// state the caller must close before closing the database; the Store itself
// owns nothing beyond the handles it was given.
func OpenStore(cfg Config) (*Store, *waddrmgr.Manager, error) {
	var (
		addrMgr *waddrmgr.Manager
		txMgr   *wtxmgr.Store
	)

	err := walletdb.Update(cfg.DB, func(tx walletdb.ReadWriteTx) error {
		addrMgrBucket := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if addrMgrBucket == nil {
			return errMissingAddrmgrNamespace
		}

		txMgrBucket := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if txMgrBucket == nil {
			return errMissingTxmgrNamespace
		}

		err := migration.Upgrade(
			waddrmgr.NewMigrationManager(addrMgrBucket),
			wtxmgr.NewMigrationManager(txMgrBucket),
		)
		if err != nil {
			return fmt.Errorf("failed to upgrade database: %w", err)
		}

		addrMgr, err = waddrmgr.Open(
			addrMgrBucket, cfg.PubPassphrase, cfg.ChainParams,
		)
		if err != nil {
			return fmt.Errorf("failed to open address "+
				"manager: %w", err)
		}

		txMgr, err = wtxmgr.Open(txMgrBucket, cfg.ChainParams)
		if err != nil {
			return fmt.Errorf("failed to open transaction "+
				"manager: %w", err)
		}

		return nil
	})
	if err != nil {
		// An address manager opened before the failure holds decrypted
		// key state and scoped managers in memory. Nothing else has a
		// reference to it yet, so release it here rather than leaking it
		// for the process lifetime; a commit failure also rolls the
		// transaction back, so there is no half-open manager to keep.
		if addrMgr != nil {
			addrMgr.Close()
		}

		return nil, nil, fmt.Errorf("failed to load wallet: %w", err)
	}

	return NewStore(cfg.DB, txMgr, addrMgr), addrMgr, nil
}
