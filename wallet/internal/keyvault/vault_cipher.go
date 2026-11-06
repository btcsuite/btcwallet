package keyvault

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// errUnsupportedCryptoKeyType is returned when a crypto key type is not
// supported for the requested operation.
var errUnsupportedCryptoKeyType = errors.New("unsupported crypto key type")

// Encrypt encrypts plaintext with the selected unlocked runtime crypto key.
func (v *WalletVault) Encrypt(keyType waddrmgr.CryptoKeyType,
	plaintext []byte) ([]byte, error) {

	v.mtx.Lock()
	defer v.mtx.Unlock()

	if v.unlockedState == nil {
		return nil, fmt.Errorf("wallet %d vault Encrypt: %w", v.walletID,
			ErrVaultLocked)
	}

	cryptoKey, err := v.selectUnlockedCryptoKey(keyType)
	if err != nil {
		return nil, fmt.Errorf("wallet %d vault Encrypt: %w", v.walletID, err)
	}

	ciphertext, err := cryptoKey.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("wallet %d vault Encrypt: encrypt: %w",
			v.walletID, err)
	}

	return ciphertext, nil
}

// Decrypt decrypts ciphertext with the selected unlocked runtime crypto key.
func (v *WalletVault) Decrypt(keyType waddrmgr.CryptoKeyType,
	ciphertext []byte) ([]byte, error) {

	v.mtx.Lock()
	defer v.mtx.Unlock()

	if v.unlockedState == nil {
		return nil, fmt.Errorf("wallet %d vault Decrypt: %w", v.walletID,
			ErrVaultLocked)
	}

	cryptoKey, err := v.selectUnlockedCryptoKey(keyType)
	if err != nil {
		return nil, fmt.Errorf("wallet %d vault Decrypt: %w", v.walletID, err)
	}

	plaintext, err := cryptoKey.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("wallet %d vault Decrypt: decrypt: %w",
			v.walletID, err)
	}

	return plaintext, nil
}

// selectUnlockedCryptoKey returns a crypto key available in unlockedState.
func (v *WalletVault) selectUnlockedCryptoKey(
	keyType waddrmgr.CryptoKeyType) (*snacl.CryptoKey, error) {

	switch keyType {
	case waddrmgr.CKTPrivate:
		if v.watchOnly {
			return nil, fmt.Errorf("private crypto key: %w",
				errUnsupportedCryptoKeyType)
		}

		return &v.unlockedState.cryptoKeyPrivate, nil
	case waddrmgr.CKTScript, waddrmgr.CKTPublic:
		// A SQL wallet derives one key per class from a single
		// passphrase and has no separate public crypto key. The legacy
		// format kept one so that non-secret script rows stayed
		// readable while locked, and the retained taproot script import
		// still asks for that class; map it onto the script key so the
		// import works and its ciphertext is recorded as script-key
		// material.
		return &v.unlockedState.cryptoKeyScript, nil
	default:
		return nil, fmt.Errorf("%d: %w", keyType, errUnsupportedCryptoKeyType)
	}
}

// DecryptScript returns a caller-owned copy of the plaintext script stored for
// scriptPubKey. See Vault for the full contract.
func (v *WalletVault) DecryptScript(ctx context.Context,
	scriptPubKey []byte) ([]byte, error) {

	// Resolve the selector through the Store before taking the guard. The
	// guard must never wait for a Store transaction.
	secret, err := v.store.GetAddressSecret(ctx, db.GetAddressSecretQuery{
		WalletID:     v.walletID,
		ScriptPubKey: scriptPubKey,
	})

	// The vault owns the returned encrypted copy, so clear it on every
	// path, including a panic further down.
	defer clearAddressSecret(secret)

	switch {
	case errors.Is(err, db.ErrSecretNotFound),
		errors.Is(err, db.ErrAddressNotFound):

		return nil, fmt.Errorf("wallet %d vault DecryptScript: %w",
			v.walletID, ErrScriptNotFound)

	case err != nil:
		return nil, fmt.Errorf("wallet %d vault DecryptScript: get "+
			"address secret: %w", v.walletID, err)
	}

	if len(secret.EncryptedScript) == 0 {
		return nil, fmt.Errorf("wallet %d vault DecryptScript: %w",
			v.walletID, ErrScriptNotFound)
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	if v.unlockedState == nil {
		return nil, fmt.Errorf("wallet %d vault DecryptScript: %w",
			v.walletID, ErrVaultLocked)
	}

	// SQL writes every script under the script key. The persisted
	// ScriptIsSecret flag only carries meaning for kvdb rows.
	cryptoKey, err := v.selectUnlockedCryptoKey(waddrmgr.CKTScript)
	if err != nil {
		return nil, fmt.Errorf("wallet %d vault DecryptScript: %w",
			v.walletID, err)
	}

	// Decryption allocates new plaintext that the vault keeps no reference
	// to, so the successful result is already the caller's copy.
	script, err := cryptoKey.Decrypt(secret.EncryptedScript)
	if err != nil {
		return nil, fmt.Errorf("wallet %d vault DecryptScript: decrypt "+
			"script: %w", v.walletID, err)
	}

	return script, nil
}

// clearAddressSecret clears the encrypted bytes of an address secret that the
// vault read from the Store.
func clearAddressSecret(secret *db.AddressSecret) {
	if secret == nil {
		return
	}

	clear(secret.EncryptedPrivKey)
	clear(secret.EncryptedScript)
}
