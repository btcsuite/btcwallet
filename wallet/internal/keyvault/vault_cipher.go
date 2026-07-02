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

// selectUnlockedCryptoKey returns a crypto key available in unlockedState.
func (v *WalletVault) selectUnlockedCryptoKey(
	keyType waddrmgr.CryptoKeyType) (*snacl.CryptoKey, error) {

	switch keyType {
	case waddrmgr.CKTPrivate:
		return &v.unlockedState.cryptoKeyPrivate, nil
	case waddrmgr.CKTScript:
		return &v.unlockedState.cryptoKeyScript, nil
	case waddrmgr.CKTPublic:
		return nil, fmt.Errorf("public crypto key: %w",
			errUnsupportedCryptoKeyType)
	default:
		return nil, fmt.Errorf("%d: %w", keyType, errUnsupportedCryptoKeyType)
	}
}
