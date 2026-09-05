package keyvault

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
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
