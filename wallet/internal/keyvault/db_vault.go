package keyvault

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// errDBVaultNotImplemented marks db vault methods whose runtime state is not
// available through db.Store yet.
var errDBVaultNotImplemented = errors.New("db vault method not implemented")

// DBVault adapts db.Store wallet secret storage to the wallet key-vault
// boundary.
type DBVault struct {
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

// Ensure DBVault implements keyvault.Vault.
var _ Vault = (*DBVault)(nil)

// NewDBVault creates a key-vault bridge scoped to one wallet row.
func NewDBVault(store db.Store, walletID uint32) *DBVault {
	return &DBVault{
		store:    store,
		walletID: walletID,
	}
}

// Unlock is not implemented yet.
// TODO(gus): implement it.
func (v *DBVault) Unlock(_ context.Context, _ []byte) error {
	return v.notImplemented("Unlock")
}

// Lock is not implemented yet.
// TODO(gus): implement it.
func (v *DBVault) Lock() {}

// Encrypt is not implemented yet.
// TODO(gus): implement it.
func (v *DBVault) Encrypt(_ waddrmgr.CryptoKeyType, _ []byte) ([]byte, error) {
	return nil, v.notImplemented("Encrypt")
}

// Decrypt  is not implemented yet.
// TODO(gus): implement it.
func (v *DBVault) Decrypt(_ waddrmgr.CryptoKeyType, _ []byte) ([]byte, error) {
	return nil, v.notImplemented("Decrypt")
}

// RefreshPrivatePassphrase is not implemented yet.
// TODO(gus): implement it.
func (v *DBVault) RefreshPrivatePassphrase(_ []byte) error {
	return v.notImplemented("RefreshPrivatePassphrase")
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

// notImplemented returns a scoped error for db vault methods that are still
// awaiting DB-backed runtime crypto support.
func (v *DBVault) notImplemented(method string) error {
	return fmt.Errorf("wallet %d db vault %s: %w", v.walletID, method,
		errDBVaultNotImplemented)
}
