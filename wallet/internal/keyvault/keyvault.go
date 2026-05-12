// Package keyvault defines the wallet key-material encryption boundary.
package keyvault

import "github.com/btcsuite/btcwallet/waddrmgr"

// Vault provides encryption and decryption for wallet key material.
type Vault interface {
	// Encrypt encrypts plaintext key material with the selected key type.
	Encrypt(keyType waddrmgr.CryptoKeyType, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext key material with the selected key type.
	Decrypt(keyType waddrmgr.CryptoKeyType, ciphertext []byte) ([]byte, error)
}

// A compile-time assertion to ensure the legacy address manager satisfies the
// keyvault boundary.
var _ Vault = (*waddrmgr.Manager)(nil)
