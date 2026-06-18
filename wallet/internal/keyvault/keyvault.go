// Package keyvault defines the encryption boundary for wallet key material.
package keyvault

import (
	"context"
	"errors"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
)

// defaultVaultUnlockTimeout is the default duration that a vault remains
// unlocked after a successful Unlock.
const defaultVaultUnlockTimeout = 10 * time.Minute

// ErrInvalidPassphrase reports that the provided vault passphrase is wrong.
var ErrInvalidPassphrase = errors.New("invalid vault passphrase")

// ErrVaultLocked reports that an operation requiring unlocked runtime state
// was attempted while the vault was locked.
var ErrVaultLocked = errors.New("vault is locked")

// Vault manages the lock lifecycle and cryptographic operations for wallet key
// material.
type Vault interface {
	// Unlock unlocks the vault with the provided passphrase and applies the
	// requested automatic lock timeout.
	//
	// A zero timeout uses the implementation's default timeout.
	// A negative timeout disables automatic locking until Lock is called.
	// A positive timeout schedules Lock to run after that duration.
	//
	// A successful Unlock replaces any previously scheduled lock. An invalid
	// passphrase must leave the vault locked.
	Unlock(ctx context.Context, passphrase []byte, timeout time.Duration) error

	// Lock locks the vault, clears any pending automatic lock, and erases
	// secret material from memory. Lock is idempotent.
	Lock()

	// IsLocked reports whether the vault is currently locked.
	IsLocked() bool

	// Encrypt encrypts plaintext key material with the selected crypto key
	// type.
	Encrypt(keyType waddrmgr.CryptoKeyType, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext key material with the selected crypto key
	// type.
	Decrypt(keyType waddrmgr.CryptoKeyType, ciphertext []byte) ([]byte, error)

	// RefreshPrivatePassphrase rotates persisted wallet secrets to the provided
	// new private passphrase. The vault must already be unlocked when this
	// method is called.
	RefreshPrivatePassphrase(ctx context.Context, passphrase []byte) error
}
