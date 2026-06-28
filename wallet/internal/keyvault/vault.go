package keyvault

import (
	"errors"
	"sync"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

var (
	// errUnexpectedState reports that the vault is in an unexpected state,
	// which may indicate a programming error or data corruption. Normal
	// operation should not return this error, and that's why it's unexported.
	errUnexpectedState = errors.New("unexpected state")
)

// WalletVault adapts db.Store wallet secret storage to the wallet key-vault
// boundary.
type WalletVault struct {
	// store is the underlying durable persistence layer for the wallets.
	store db.Store

	// walletID is the wallet row id that this vault is scoped to.
	walletID uint32

	// mtx guards concurrent access.
	mtx sync.Mutex

	// unlockedState holds sensitive runtime secret material that is only
	// available when the vault is unlocked.
	unlockedState *unlockedState
}

// unlockedState holds sensitive runtime secret material.
type unlockedState struct {
	// cryptoKeyPrivate is the key used to encrypt and decrypt private material.
	cryptoKeyPrivate snacl.CryptoKey

	// cryptoKeyScript is the key used to encrypt and decrypt script material.
	cryptoKeyScript snacl.CryptoKey

	// hdRootKey is the master HD extended key for the wallet, which can derive
	// all sub scopes, accounts, addresses, and keys.
	hdRootKey *hdkeychain.ExtendedKey
}

// Ensure WalletVault implements keyvault.Vault.
var _ Vault = (*WalletVault)(nil)

// NewDBVault creates a key-vault bridge scoped to one wallet row.
func NewDBVault(store db.Store, walletID uint32) *WalletVault {
	return &WalletVault{
		store:    store,
		walletID: walletID,
	}
}

// zero clears the runtime secret material held by the unlocked state.
func (s *unlockedState) zero() {
	if s == nil {
		return
	}

	s.cryptoKeyPrivate.Zero()
	s.cryptoKeyScript.Zero()

	if s.hdRootKey != nil {
		s.hdRootKey.Zero()
		s.hdRootKey = nil
	}
}
