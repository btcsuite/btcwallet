// Package keyvault defines the encryption boundary for wallet key material.
package keyvault

import (
	"context"
	"errors"

	"github.com/btcsuite/btcwallet/waddrmgr"
)

// ErrInvalidPassphrase reports that the provided vault passphrase is wrong.
var ErrInvalidPassphrase = errors.New("invalid vault passphrase")

// ErrVaultUnlocked reports that an unlock operation was attempted while the
// vault was already unlocked.
var ErrVaultUnlocked = errors.New("vault is already unlocked")

// Vault manages the lock lifecycle and cryptographic operations for wallet key
// material.
type Vault interface {
	// Unlock unlocks the vault with the provided passphrase.
	//
	// If the passphrase is invalid, or the unlock operation fails, the vault
	// must remain locked. If Unlock is called while the vault is already
	// unlocked, it must return ErrVaultUnlocked without validating the provided
	// passphrase.
	Unlock(ctx context.Context, passphrase []byte) error

	// Lock locks the vault and erases secret material from memory. Lock is
	// idempotent.
	Lock()

	// IsLocked reports whether the vault is currently locked.
	IsLocked() bool

	// Encrypt encrypts plaintext key material with the selected crypto key
	// type.
	Encrypt(keyType waddrmgr.CryptoKeyType, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext key material with the selected crypto key
	// type.
	Decrypt(keyType waddrmgr.CryptoKeyType, ciphertext []byte) ([]byte, error)

	// ChangePassphrase rotates persisted wallet secrets to the provided new
	// private passphrase. The vault must already be unlocked when this method
	// is called.
	ChangePassphrase(ctx context.Context, newPassphrase []byte) error
}
