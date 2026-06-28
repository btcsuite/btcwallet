package keyvault

import (
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
)

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
