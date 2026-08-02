package wallet

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// defaultWalletDBDirPerm is the permission applied to database directories
// created by a Manager backend.
const defaultWalletDBDirPerm = 0o700

// managerBackend owns the database used by a Manager and resolves the storage
// dependencies needed to assemble a Wallet.
type managerBackend interface {
	// create initializes and opens a wallet on the backend.
	create(ctx context.Context, cfg Config, params CreateWalletParams,
		rootKey *hdkeychain.ExtendedKey) (*walletData, error)

	// load opens an existing wallet on the backend.
	load(ctx context.Context, cfg Config) (*walletData, error)

	// close releases the database and any live managers owned by the backend.
	close() error
}

// walletData is the immutable storage data needed to assemble a Wallet. It
// owns no resources; the managerBackend that returned it remains their owner.
type walletData struct {
	id                uint32
	store             db.Store
	addressStore      waddrmgr.AddrStore
	transactionStore  wtxmgr.TxStore
	vault             keyvault.Vault
	masterFingerprint uint32
	isWatchOnly       bool
}

// masterFingerprint parses a runtime wallet's master HD public key and returns
// its BIP32 fingerprint. Wallets without a persisted master public key use the
// zero fingerprint.
func masterFingerprint(info *db.WalletInfo) (uint32, error) {
	if info == nil || len(info.MasterPubKey) == 0 {
		return 0, nil
	}

	extKey, err := hdkeychain.NewKeyFromString(string(info.MasterPubKey))
	if err != nil {
		return 0, fmt.Errorf("parse master HD pubkey: %w", err)
	}

	fingerprint, err := masterKeyFingerprint(extKey)
	if err != nil {
		return 0, fmt.Errorf("master fingerprint: %w", err)
	}

	return fingerprint, nil
}
