package keyvault

import (
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// errWalletVaultNotImplemented marks wallet vault methods whose runtime state is
// not available through db.Store yet.
var errWalletVaultNotImplemented = errors.New("wallet vault method not implemented")

// errUnexpectedState reports that the vault is in an unexpected state,
// which may indicate a programming error or data corruption. Normal
// operation should not return this error, and that's why it's unexported.
var errUnexpectedState = errors.New("unexpected state")

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

// Ensure WalletVault implements Vault.
var _ Vault = (*WalletVault)(nil)

// NewWalletVault creates a key-vault bridge scoped to one wallet row.
func NewWalletVault(store db.Store, walletID uint32) *WalletVault {
	return &WalletVault{
		store:    store,
		walletID: walletID,
	}
}

// Decrypt is not implemented yet.
// TODO(gus): implement it.
func (v *WalletVault) Decrypt(_ waddrmgr.CryptoKeyType, _ []byte) ([]byte, error) {
	return nil, v.notImplemented("Decrypt")
}

// notImplemented returns a scoped error for wallet vault methods that are still
// awaiting DB-backed runtime crypto support.
func (v *WalletVault) notImplemented(method string) error {
	return fmt.Errorf("wallet %d wallet vault %s: %w", v.walletID, method,
		errWalletVaultNotImplemented)
}

// zero clears the runtime secret material held by the unlocked state.
func (s *unlockedState) zero() {
	if s == nil {
		return
	}

	// Clear sensitive key bytes in place. Dropping this struct only removes Go
	// references; it does not guarantee when heap memory containing
	// spend-capable secrets will be overwritten.
	s.cryptoKeyPrivate.Zero()
	s.cryptoKeyScript.Zero()

	if s.hdRootKey != nil {
		s.hdRootKey.Zero()
		s.hdRootKey = nil
	}
}
