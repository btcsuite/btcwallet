package keyvault

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// CreateWalletSecrets generates the initial encrypted secret material for a new
// wallet, mirroring the genesis waddrmgr.Create performs for the legacy
// backend. It derives a master private key from privatePassphrase, generates
// fresh script (and, for spendable wallets, private) crypto keys, encrypts
// them, and — for a spendable wallet — encrypts the master HD private key
// under the private crypto key. The result is the db.WalletSecrets the store
// persists and that WalletVault.Unlock later reproduces via
// decryptWalletSecrets.
//
// A watch-only wallet holds no signing material, so only the script crypto key
// is produced and hdRootKey is ignored (it may be nil). A spendable wallet
// requires a non-nil hdRootKey.
//
// The returned secrets contain only ciphertext. Every plaintext buffer this
// function controls is zeroed before returning; the one copy it cannot wipe is
// the immutable string hdRootKey.String() returns, which Go keeps read-only on
// the heap until it is garbage collected.
func CreateWalletSecrets(privatePassphrase []byte,
	hdRootKey *hdkeychain.ExtendedKey, watchOnly bool) (*db.WalletSecrets,
	error) {

	// Derive the master private key from the passphrase using the default
	// scrypt parameters. NewSecretKey generates a fresh salt and derives
	// the key; Marshal persists the parameters (salt + N/R/P), not the key
	// itself, so Unlock can re-derive it from the same passphrase.
	masterKey, err := snacl.NewSecretKey(
		&privatePassphrase, snacl.DefaultN, snacl.DefaultR,
		snacl.DefaultP,
	)
	if err != nil {
		return nil, fmt.Errorf("new master private key: %w", err)
	}
	defer masterKey.Zero()

	// Every wallet, watch-only included, protects scripts with a script
	// crypto key encrypted under the master key.
	cryptoKeyScript, err := snacl.GenerateCryptoKey()
	if err != nil {
		return nil, fmt.Errorf("generate crypto key script: %w", err)
	}
	defer cryptoKeyScript.Zero()

	encryptedCryptoKeyScript, err := masterKey.Encrypt(cryptoKeyScript[:])
	if err != nil {
		return nil, fmt.Errorf("encrypt crypto key script: %w", err)
	}

	secrets := &db.WalletSecrets{
		MasterPrivParams:         masterKey.Marshal(),
		EncryptedCryptoScriptKey: encryptedCryptoKeyScript,
	}

	// A watch-only wallet has no private signing material, so the script
	// key is all it needs.
	if watchOnly {
		return secrets, nil
	}

	if hdRootKey == nil {
		return nil, fmt.Errorf("%w: spendable wallet requires an HD root key",
			errUnexpectedState)
	}

	// A spendable wallet additionally holds a private crypto key protecting
	// private material, plus the master HD private key encrypted under it.
	cryptoKeyPrivate, err := snacl.GenerateCryptoKey()
	if err != nil {
		return nil, fmt.Errorf("generate crypto key private: %w", err)
	}
	defer cryptoKeyPrivate.Zero()

	encryptedCryptoKeyPrivate, err := masterKey.Encrypt(cryptoKeyPrivate[:])
	if err != nil {
		return nil, fmt.Errorf("encrypt crypto key private: %w", err)
	}

	// hdRootKey.String() returns an immutable plaintext xprv; that string
	// copy cannot be wiped, but the byte buffer we hand to Encrypt can, so
	// zero it once the ciphertext is produced.
	hdRootKeyBytes := []byte(hdRootKey.String())
	defer clear(hdRootKeyBytes)

	encryptedMasterHDPrivKey, err := cryptoKeyPrivate.Encrypt(
		hdRootKeyBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("encrypt master HD private key: %w", err)
	}

	secrets.EncryptedCryptoPrivKey = encryptedCryptoKeyPrivate
	secrets.EncryptedMasterHdPrivKey = encryptedMasterHDPrivKey

	return secrets, nil
}
