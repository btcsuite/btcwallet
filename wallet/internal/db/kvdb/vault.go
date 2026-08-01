package kvdb

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
	"github.com/btcsuite/btcwallet/walletdb"
)

// LegacyWalletVault adapts the legacy address manager to keyvault.Vault.
type LegacyWalletVault struct {
	db  walletdb.DB
	mgr *waddrmgr.Manager
}

// Compile-time assertion that LegacyWalletVault satisfies keyvault.Vault.
var _ keyvault.Vault = (*LegacyWalletVault)(nil)

// NewLegacyWalletVault creates a Vault backed by a legacy walletdb address
// manager.
func NewLegacyWalletVault(db walletdb.DB,
	mgr *waddrmgr.Manager) *LegacyWalletVault {

	return &LegacyWalletVault{
		db:  db,
		mgr: mgr,
	}
}

// Unlock authenticates the private passphrase through the legacy address
// manager.
func (v *LegacyWalletVault) Unlock(ctx context.Context,
	passphrase []byte) error {

	err := checkContext(ctx)
	if err != nil {
		return err
	}

	// Honor the Vault contract: unlocking an already-unlocked vault must
	// return ErrVaultUnlocked without re-validating the passphrase.
	if !v.mgr.IsLocked() {
		return keyvault.ErrVaultUnlocked
	}

	err = walletdb.View(v.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		return v.mgr.Unlock(ns, passphrase)
	})
	if err != nil {
		return fmt.Errorf("view: %w", translateVaultErr(err))
	}

	return nil
}

// Lock clears any cached secret key material from the legacy address manager.
//
// Lock is idempotent and has nothing to surface for the no-op cases: an
// already-locked manager returns waddrmgr.ErrLocked and a watch-only manager
// returns waddrmgr.ErrWatchingOnly (it holds no private material to clear).
// Both are swallowed. Any other failure is only logged because the
// keyvault.Vault contract gives Lock no way to surface an error.
func (v *LegacyWalletVault) Lock() {
	err := v.mgr.Lock()
	switch {
	case err == nil:

	case waddrmgr.IsError(err, waddrmgr.ErrLocked):

	case waddrmgr.IsError(err, waddrmgr.ErrWatchingOnly):

	default:
		log.Errorf("LegacyWalletVault lock manager: %v", err)
	}
}

// IsLocked reports whether the legacy address manager is currently locked.
func (v *LegacyWalletVault) IsLocked() bool {
	return v.mgr.IsLocked()
}

// Encrypt encrypts key material under the requested legacy crypto-key class.
func (v *LegacyWalletVault) Encrypt(keyType waddrmgr.CryptoKeyType,
	plaintext []byte) ([]byte, error) {

	return v.crypt(v.mgr.Encrypt, keyType, plaintext, "encrypt")
}

// Decrypt decrypts key material under the requested legacy crypto-key class.
func (v *LegacyWalletVault) Decrypt(keyType waddrmgr.CryptoKeyType,
	ciphertext []byte) ([]byte, error) {

	return v.crypt(v.mgr.Decrypt, keyType, ciphertext, "decrypt")
}

// crypt forwards a cipher operation to the address manager and maps its
// sentinels onto the keyvault ones. The crypto-key class stays a caller
// argument here: the legacy format records per script row which key protects
// it, so the adapter cannot pick one for the whole manager.
func (v *LegacyWalletVault) crypt(op func(waddrmgr.CryptoKeyType,
	[]byte) ([]byte, error), keyType waddrmgr.CryptoKeyType, in []byte,
	what string) ([]byte, error) {

	out, err := op(keyType, in)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, translateVaultErr(err))
	}

	return out, nil
}

// ChangePassphrase re-wraps the address manager's key material inside a single
// walletdb transaction.
//
// The legacy dual layout keeps public metadata and private key material under
// separate passphrases, so a request may rotate either half or both. Both are
// applied in the same transaction to preserve the base API's atomicity.
// Validation and the row writes belong to the address manager, so this works
// whether or not the manager is unlocked. The manager applies the new material
// to its own in-memory state; this adapter neither observes nor reorders that.
//
//nolint:staticcheck // Implements the legacy kvdb dual-passphrase format.
func (v *LegacyWalletVault) ChangePassphrase(ctx context.Context,
	params keyvault.ChangePassphraseParams) error {

	// Bail before the walletdb access and the expensive scrypt derivation
	// when the request is already canceled.
	err := checkContext(ctx)
	if err != nil {
		return err
	}

	changePublic := params.PublicOld != nil

	changePrivate := params.PrivateOld != nil
	if !changePublic && !changePrivate {
		return nil
	}

	err = walletdb.Update(v.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		if changePublic {
			err := v.mgr.ChangePassphrase(
				ns, params.PublicOld, params.PublicNew, false,
				&waddrmgr.DefaultScryptOptions,
			)
			if err != nil {
				return err
			}
		}

		if changePrivate {
			err := v.mgr.ChangePassphrase(
				ns, params.PrivateOld, params.PrivateNew, true,
				&waddrmgr.DefaultScryptOptions,
			)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("update: %w", translateVaultErr(err))
	}

	return nil
}

// translateVaultErr maps the waddrmgr sentinels an adapter method can surface
// onto their keyvault.Vault equivalents, so callers handle a keyvault.Vault
// backed by the legacy manager the same way they handle WalletVault. A wrong
// passphrase (waddrmgr.ErrWrongPassphrase) becomes
// keyvault.ErrInvalidPassphrase and a locked/watch-only crypto-key access
// (waddrmgr.ErrLocked) becomes keyvault.ErrVaultLocked, matching what
// WalletVault returns for those cases. Any other error is returned unchanged.
func translateVaultErr(err error) error {
	switch {
	case waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase):
		return keyvault.ErrInvalidPassphrase

	case waddrmgr.IsError(err, waddrmgr.ErrLocked):
		return keyvault.ErrVaultLocked

	default:
		return err
	}
}
