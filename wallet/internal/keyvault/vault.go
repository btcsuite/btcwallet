package keyvault

import (
	"context"
	"errors"
	"fmt"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// errWalletVaultNotImplemented marks wallet vault methods whose runtime state is not
// available through db.Store yet.
var errWalletVaultNotImplemented = errors.New("wallet vault method not implemented")

// WalletVault adapts db.Store wallet secret storage to the wallet key-vault
// boundary.
type WalletVault struct {
	// store is the underlying durable persistence layer for the wallets.
	store db.Store

	// walletID is the wallet row id that this vault is scoped to.
	walletID uint32
}

// Ensure WalletVault implements keyvault.Vault.
var _ Vault = (*WalletVault)(nil)

// NewWalletVault creates a key-vault bridge scoped to one wallet row.
func NewWalletVault(store db.Store, walletID uint32) *WalletVault {
	return &WalletVault{
		store:    store,
		walletID: walletID,
	}
}

// Unlock is not implemented yet.
// TODO(gus): implement it.
func (v *WalletVault) Unlock(_ context.Context, _ []byte) error {
	return v.notImplemented("Unlock")
}

// Lock is not implemented yet.
// TODO(gus): implement it.
func (v *WalletVault) Lock() {}

// IsLocked is not implemented yet.
// TODO(gus): implement it.
func (v *WalletVault) IsLocked() bool {
	return true
}

// Encrypt is not implemented yet.
// TODO(gus): implement it.
func (v *WalletVault) Encrypt(_ waddrmgr.CryptoKeyType, _ []byte) ([]byte, error) {
	return nil, v.notImplemented("Encrypt")
}

// Decrypt  is not implemented yet.
// TODO(gus): implement it.
func (v *WalletVault) Decrypt(_ waddrmgr.CryptoKeyType, _ []byte) ([]byte, error) {
	return nil, v.notImplemented("Decrypt")
}

// ChangePassphrase is not implemented yet.
// TODO(gus): implement it.
func (v *WalletVault) ChangePassphrase(_ context.Context, _ []byte) error {
	return v.notImplemented("ChangePassphrase")
}

// notImplemented returns a scoped error for wallet vault methods that are still
// awaiting DB-backed runtime crypto support.
func (v *WalletVault) notImplemented(method string) error {
	return fmt.Errorf("wallet %d wallet vault %s: %w", v.walletID, method,
		errWalletVaultNotImplemented)
}
