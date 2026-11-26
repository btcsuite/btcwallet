package keyvault

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/signing"
)

// PubKey returns the public key of the selected private key. See Vault for
// the lock and cleanup contract.
func (v *WalletVault) PubKey(ctx context.Context,
	sel signing.KeySelector) (*btcec.PublicKey, error) {

	var pub *btcec.PublicKey

	err := v.useKey(ctx, sel, func(key *btcec.PrivateKey) error {
		pub = key.PubKey()

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("wallet %d vault PubKey: %w", v.walletID,
			err)
	}

	return pub, nil
}

// useKey resolves the selected private key and runs use with it under the
// vault guard.
//
// It refuses an invalid selector, then returns ErrVaultLocked for a locked
// vault, both before the Store read. The read runs without the guard, so a
// Lock can still land before the guard is taken; the guarded phase checks the
// lock again. use is vault code, not caller code: it must not keep the key,
// call the Store or call another vault method. Every secret is cleared before
// useKey returns or panics.
func (v *WalletVault) useKey(ctx context.Context, sel signing.KeySelector,
	use func(*btcec.PrivateKey) error) error {

	err := signing.ValidateKeySelector(sel)
	if err != nil {
		return err
	}

	// Read the lock state directly, as DecryptScript does: vault code
	// does not call the vault's own public methods.
	v.mtx.Lock()
	locked := v.unlockedState == nil
	v.mtx.Unlock()

	if locked {
		return ErrVaultLocked
	}

	ciphertext, toKey, err := LoadEncryptedKey(ctx, v.store, v.walletID, sel)

	// The vault owns the encrypted copy from the Store, so clear it on
	// every path.
	defer clear(ciphertext)

	if err != nil {
		return err
	}

	return v.useDecryptedKey(
		ciphertext, (*snacl.CryptoKey).Decrypt, toKey, use,
	)
}

// useDecryptedKey owns the guarded phase after lookup: it decrypts ciphertext,
// turns the plaintext into the private key with toKey and runs use with it.
// decrypt, toKey and use are vault-owned; none may retain a key or access the
// Store. The plaintext and the key are cleared before it returns or panics.
func (v *WalletVault) useDecryptedKey(ciphertext []byte,
	decrypt accountDecryptor,
	toKey func([]byte) (*btcec.PrivateKey, error),
	use func(*btcec.PrivateKey) error) error {

	v.mtx.Lock()
	defer v.mtx.Unlock()

	if v.unlockedState == nil {
		return ErrVaultLocked
	}

	cryptoKey, err := v.selectUnlockedCryptoKey(waddrmgr.CKTPrivate)
	if err != nil {
		return err
	}

	plaintext, err := decrypt(cryptoKey, ciphertext)
	defer clear(plaintext)

	if err != nil {
		return fmt.Errorf("decrypt private key: %w", err)
	}

	key, err := toKey(plaintext)
	if err != nil {
		return err
	}
	defer key.Zero()

	return use(key)
}

// LoadEncryptedKey reads the encrypted private key that sel names. It returns
// that ciphertext and a function that turns its decrypted plaintext into the
// private key: the account child at the selector's derivation path for a
// DerivedKey, the raw key for an ImportedKey. A key without private material
// returns ErrNoPrivateKey; see loadEncryptedImportedKey for how a missing
// import is reported. A selector that signing.ValidateKeySelector refuses, such
// as an import without a script, returns signing.ErrInvalidKeySelector without
// a Store read. The caller owns and clears the returned ciphertext, must zero
// the key the function returns, and must not hold a vault guard.
//
// TODO(gus): unexport once kvdb support is removed.
func LoadEncryptedKey(ctx context.Context, store db.Store, walletID uint32,
	sel signing.KeySelector) ([]byte,
	func([]byte) (*btcec.PrivateKey, error), error) {

	err := signing.ValidateKeySelector(sel)
	if err != nil {
		return nil, nil, err
	}

	switch s := sel.(type) {
	case signing.DerivedKey:
		ciphertext, err := loadEncryptedAccountKey(
			ctx, store, walletID, s,
		)
		if err != nil {
			return nil, nil, err
		}

		toKey := func(accountPriv []byte) (*btcec.PrivateKey, error) {
			return DeriveAccountChildKey(
				accountPriv, s.DerivationPath,
			)
		}

		return ciphertext, toKey, nil

	case signing.ImportedKey:
		ciphertext, err := loadEncryptedImportedKey(
			ctx, store, walletID, s,
		)
		if err != nil {
			return nil, nil, err
		}

		return ciphertext, parseImportedKey, nil

	default:
		return nil, nil, fmt.Errorf("%w: unsupported selector %T",
			signing.ErrInvalidKeySelector, sel)
	}
}

// loadEncryptedAccountKey reads the encrypted extended private key of the
// account that key names. It returns ErrNoPrivateKey when the account has no
// private key. Whatever the Store returns is cleared on an error.
func loadEncryptedAccountKey(ctx context.Context, store db.Store,
	walletID uint32, key signing.DerivedKey) ([]byte, error) {

	secret, err := store.GetAccountSecret(ctx, db.GetAccountSecretQuery{
		WalletID:      walletID,
		Scope:         db.KeyScope(key.KeyScope),
		AccountNumber: key.DerivationPath.InternalAccount,
	})
	if err != nil {
		if secret != nil {
			clear(secret.EncryptedPrivateKey)
		}

		return nil, fmt.Errorf("get account secret: %w", err)
	}

	if len(secret.EncryptedPrivateKey) == 0 {
		return nil, ErrNoPrivateKey
	}

	return secret.EncryptedPrivateKey, nil
}

// loadEncryptedImportedKey reads the encrypted raw private key imported for
// key's script pubkey. The encrypted script copy is always cleared, and
// whatever the Store returns is cleared on an error.
//
// A script the Store holds without a private key returns ErrNoPrivateKey. The
// Store reports a watch-only import as db.ErrSecretNotFound, which is wrapped
// as ErrNoPrivateKey too. kvdb also reports a script it does not know as
// db.ErrSecretNotFound, so a missing kvdb import returns ErrNoPrivateKey, as
// wallet.resolveImportedAddrPrivKey treats it; no extra address read
// separates the two. The SQL Store's db.ErrAddressNotFound for an unknown
// script keeps its identity.
func loadEncryptedImportedKey(ctx context.Context, store db.Store,
	walletID uint32, key signing.ImportedKey) ([]byte, error) {

	secret, err := store.GetAddressSecret(ctx, db.GetAddressSecretQuery{
		WalletID:     walletID,
		ScriptPubKey: key.ScriptPubKey,
	})
	if err != nil {
		clearAddressSecret(secret)

		if errors.Is(err, db.ErrSecretNotFound) {
			return nil, fmt.Errorf("%w: %w", ErrNoPrivateKey, err)
		}

		return nil, fmt.Errorf("get address secret: %w", err)
	}

	// Only the private key is used. Clear the script copy.
	clear(secret.EncryptedScript)

	if len(secret.EncryptedPrivKey) == 0 {
		return nil, ErrNoPrivateKey
	}

	return secret.EncryptedPrivKey, nil
}

// parseImportedKey turns a decrypted imported raw key into the private key. It
// refuses a key that is not 32 bytes, is not below the group order or is zero.
// The caller keeps ownership of plaintext and must zero the returned key; the
// intermediate scalar is zeroed on every path.
func parseImportedKey(plaintext []byte) (*btcec.PrivateKey, error) {
	if len(plaintext) != btcec.PrivKeyBytesLen {
		return nil, fmt.Errorf("imported private key has %d bytes: %w",
			len(plaintext), errUnexpectedState)
	}

	var scalar btcec.ModNScalar
	defer scalar.Zero()

	overflow := scalar.SetByteSlice(plaintext)
	if overflow || scalar.IsZero() {
		return nil, fmt.Errorf("imported private key is out of range: "+
			"%w", errUnexpectedState)
	}

	return btcec.PrivKeyFromScalar(&scalar), nil
}
