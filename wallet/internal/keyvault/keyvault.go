// Package keyvault defines the encryption boundary for wallet key material.
package keyvault

import (
	"context"
	"errors"

	"github.com/btcsuite/btcwallet/waddrmgr"
)

// ErrInvalidPassphrase reports that the provided vault passphrase is wrong.
var ErrInvalidPassphrase = errors.New("invalid vault passphrase")

// Vault manages the lock lifecycle and cryptographic operations for wallet key
// material.
type Vault interface {
	// Unlock unlocks the vault with the provided passphrase.
	//
	// If the passphrase is invalid, or the unlock operation fails, the vault
	// must remain locked. If Unlock is called while the vault is already
	// unlocked, it must be a no-op and must not validate the provided
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

	// RefreshPrivatePassphrase refreshes vault owned runtime passphrase and
	// crypto state after a successful private passphrase rotation.
	//
	// The vault must still be unlocked with the new passphrase when this method
	// is called.
	RefreshPrivatePassphrase(ctx context.Context, passphrase []byte) error
}
