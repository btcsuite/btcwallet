// Package keyvault defines the encryption boundary for wallet key material.
package keyvault

import (
	"context"
	"errors"

	"github.com/btcsuite/btcwallet/waddrmgr"
)

// ErrInvalidPassphrase reports that the provided vault passphrase is wrong.
var ErrInvalidPassphrase = errors.New("invalid vault passphrase")

// ErrVaultLocked reports that an operation requiring unlocked runtime state
// was attempted while the vault was locked.
var ErrVaultLocked = errors.New("vault is locked")

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

	// ChangePassphrase re-wraps the persisted wallet secrets according to
	// params.
	//
	// Implementations validate the whole request before reading or
	// mutating any secret, so a request an implementation cannot serve in
	// full changes nothing.
	//
	// The rotation preserves the vault's original locked/unlocked state: an
	// unlocked vault stays unlocked with its runtime keys unchanged, and a
	// locked vault leaves no decrypted state behind. The old passphrase is
	// required even while locked, because a locked vault holds no decrypted
	// keys and must re-derive the old master key from the persisted
	// parameters before re-wrapping under the new one.
	ChangePassphrase(ctx context.Context,
		params ChangePassphraseParams) error
}

// ErrPublicPassphraseUnsupported reports that a backend was asked to rotate a
// public passphrase it does not have. SQL wallets protect all key material
// under one passphrase; only the legacy kvdb format keeps a separate public
// half.
var ErrPublicPassphraseUnsupported = errors.New(
	"public passphrase rotation unsupported",
)

// ChangePassphraseParams contains the passphrase halves to rotate.
//
// The two halves are independent because the legacy kvdb format protects
// public metadata and private key material under separate passphrases and can
// rotate either or both in one transaction. A non-nil old passphrase selects
// that half; this preserves a non-nil empty passphrase as a valid request.
type ChangePassphraseParams struct {
	// PublicOld and PublicNew contain the old and new public passphrases. A
	// non-nil PublicOld requests their rotation.
	//
	// Deprecated: only the legacy kvdb format has a separate public
	// passphrase. Remove these fields with kvdb support.
	PublicOld []byte
	PublicNew []byte

	// PrivateOld and PrivateNew contain the old and new private passphrases.
	// A non-nil PrivateOld requests their rotation.
	PrivateOld []byte
	PrivateNew []byte
}
