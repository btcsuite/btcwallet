package kvdb

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
	"github.com/btcsuite/btcwallet/walletdb"
)

// LegacyManagerVault adapts the legacy address manager to keyvault.Vault.
type LegacyManagerVault struct {
	db  walletdb.DB
	mgr *waddrmgr.Manager
}

// Compile-time assertion that LegacyManagerVault satisfies keyvault.Vault.
var _ keyvault.Vault = (*LegacyManagerVault)(nil)

// NewLegacyManagerVault creates a Vault backed by a legacy walletdb address
// manager.
func NewLegacyManagerVault(db walletdb.DB,
	mgr *waddrmgr.Manager) *LegacyManagerVault {

	return &LegacyManagerVault{
		db:  db,
		mgr: mgr,
	}
}

// Unlock authenticates the private passphrase through the legacy address
// manager.
//
// The timeout is ignored: the legacy address manager has no auto-lock timer of
// its own, so the wallet controller keeps owning the auto-lock schedule. The
// vault only forwards the unlock to the underlying manager.
func (v *LegacyManagerVault) Unlock(ctx context.Context, passphrase []byte,
	_ time.Duration) error {

	err := checkContext(ctx)
	if err != nil {
		return err
	}

	err = walletdb.View(v.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		return v.mgr.Unlock(ns, passphrase)
	})
	if err != nil {
		return fmt.Errorf("view: %w", err)
	}

	return nil
}

// Lock clears any cached secret key material from the legacy address manager.
//
// Lock is idempotent: an already-locked manager returns waddrmgr.ErrLocked,
// which is swallowed. Any other failure is only logged because the
// keyvault.Vault contract gives Lock no way to surface an error.
func (v *LegacyManagerVault) Lock() {
	err := v.mgr.Lock()
	if err != nil && !waddrmgr.IsError(err, waddrmgr.ErrLocked) {
		log.Errorf("LegacyManagerVault lock manager: %v", err)
	}
}

// IsLocked reports whether the legacy address manager is currently locked.
func (v *LegacyManagerVault) IsLocked() bool {
	return v.mgr.IsLocked()
}

// Encrypt encrypts plaintext key material through the legacy address manager.
func (v *LegacyManagerVault) Encrypt(keyType waddrmgr.CryptoKeyType,
	plaintext []byte) ([]byte, error) {

	ciphertext, err := v.mgr.Encrypt(keyType, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	return ciphertext, nil
}

// Decrypt decrypts ciphertext key material through the legacy address manager.
func (v *LegacyManagerVault) Decrypt(keyType waddrmgr.CryptoKeyType,
	ciphertext []byte) ([]byte, error) {

	plaintext, err := v.mgr.Decrypt(keyType, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// RefreshPrivatePassphrase is a no-op for the legacy address manager.
//
// The legacy manager rotates its in-memory crypto state in place while it
// applies a private passphrase change, so there is no separate vault-owned
// runtime state left to refresh afterwards.
func (v *LegacyManagerVault) RefreshPrivatePassphrase(_ []byte) error {
	return nil
}

// checkContext returns ctx.Err when the context is already canceled.
func checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()

	default:
		return nil
	}
}
