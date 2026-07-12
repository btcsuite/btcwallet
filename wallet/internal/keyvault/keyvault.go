// Package keyvault defines the encryption boundary for wallet key material.
package keyvault

import (
	"context"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/signing"
)

// ErrInvalidPassphrase reports that the provided vault passphrase is wrong.
var ErrInvalidPassphrase = errors.New("invalid vault passphrase")

// ErrVaultLocked reports that an operation requiring unlocked runtime state
// was attempted while the vault was locked.
var ErrVaultLocked = errors.New("vault is locked")

// ErrVaultUnlocked reports that an unlock operation was attempted while the
// vault was already unlocked.
var ErrVaultUnlocked = errors.New("vault is already unlocked")

// ErrVaultKeyOpsUnimplemented reports that the vault does not yet implement
// key derivation or signing operations.
var ErrVaultKeyOpsUnimplemented = errors.New(
	"vault key operations are unimplemented",
)

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

	// DerivePubKey derives the public key for the provided key locator.
	//
	// The caller provides a wallet key locator, and the vault returns the
	// corresponding public key without exposing private key material. The vault
	// must already be unlocked; implementations must return ErrVaultLocked if
	// called while locked.
	DerivePubKey(ctx context.Context,
		keyLocator signing.KeyLocator) (*btcec.PublicKey, error)

	// Sign signs the caller-computed 32-byte digest for the located key using
	// the primitive signing mode described by req.
	//
	// The caller is responsible for digest construction, sighash selection,
	// signature serialization, transaction assembly, and any appended sighash
	// byte. Signing requests do not carry transactions, PSBTs, scripts,
	// witnesses, sighash types, or Taproot tree data. The vault must already be
	// unlocked; implementations must return ErrVaultLocked if called while
	// locked.
	Sign(ctx context.Context, req signing.Request) (signing.Signature, error)
}
