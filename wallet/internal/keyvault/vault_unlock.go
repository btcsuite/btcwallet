package keyvault

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// Unlock loads wallet secrets from the store and decrypts them into runtime
// state using the provided private passphrase. If the vault is already
// unlocked, Unlock is a no-op and does not validate the passphrase.
func (v *WalletVault) Unlock(ctx context.Context, passphrase []byte) error {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	if v.unlockedState != nil {
		return nil
	}

	secrets, err := v.store.GetWalletSecrets(ctx, v.walletID)
	if err != nil {
		return fmt.Errorf("wallet %d vault Unlock: get secrets: %w",
			v.walletID, err)
	}

	state, err := decryptWalletSecrets(secrets, passphrase)
	if err != nil {
		return fmt.Errorf("wallet %d vault Unlock: decrypt secrets: %w",
			v.walletID, err)
	}

	// After a successful unlockedState construction, clear any existing runtime
	// state before referencing the new state.
	v.clearRuntimeAndLock()
	v.unlockedState = state

	return nil
}

// decryptWalletSecrets decrypts persisted wallet secrets into runtime state.
//
// TODO(gus): wrap with secret.Do from golang 1.26+. There are functions that
// actually leaks a lot of information in memory while waiting GC, like
// hdkeychain.NewKeyFromString.
func decryptWalletSecrets(secrets *db.WalletSecrets,
	passphrase []byte) (*unlockedState, error) {

	if secrets == nil {
		// this error is not expected to happen.
		return nil, fmt.Errorf("missing wallet secrets: %w", errUnexpectedState)
	}

	var masterPrivateKey snacl.SecretKey

	// first, we need to load the key parameter from stored secrets.
	err := masterPrivateKey.Unmarshal(secrets.MasterPrivParams)
	if err != nil {
		return nil, fmt.Errorf("unmarshal master private parameters: %w", err)
	}
	defer masterPrivateKey.Zero()

	// with the parameters loaded, we can derive the master cryptographic key
	// from the passphrase and check for invalid passphrase errors.
	err = deriveMasterPrivateKey(&masterPrivateKey, passphrase)
	if err != nil {
		return nil, err
	}

	// with the master key, we can start decrypting the other encrypted keys,
	// including the master HD private key that can spend coins.
	state := &unlockedState{}

	clearState := true
	defer func() {
		if clearState {
			state.zero()
		}
	}()

	state.cryptoKeyPrivate, err = decryptCryptoKey(
		&masterPrivateKey, secrets.EncryptedCryptoPrivKey,
	)
	if err != nil {
		return nil, fmt.Errorf("crypto key private: %w", err)
	}

	state.cryptoKeyScript, err = decryptCryptoKey(
		&masterPrivateKey, secrets.EncryptedCryptoScriptKey,
	)
	if err != nil {
		return nil, fmt.Errorf("crypto key script: %w", err)
	}

	if len(secrets.EncryptedMasterHdPrivKey) == 0 {
		clearState = false
		return state, nil
	}

	decryptedHDPrivate, decryptErr := state.cryptoKeyPrivate.Decrypt(
		secrets.EncryptedMasterHdPrivKey,
	)
	if decryptErr != nil {
		return nil, fmt.Errorf("decrypt master HD private key: %w: %w",
			errUnexpectedState, decryptErr)
	}
	defer clear(decryptedHDPrivate)

	state.hdRootKey, err = hdkeychain.NewKeyFromString(
		string(decryptedHDPrivate),
	)
	if err != nil {
		return nil, fmt.Errorf("parse master HD private key: %w", err)
	}

	clearState = false

	return state, nil
}

// deriveMasterPrivateKey derives the master private key from the passphrase
// and maps invalid passwords to ErrInvalidPassphrase.
func deriveMasterPrivateKey(masterPrivateKey *snacl.SecretKey,
	passphrase []byte) error {

	err := masterPrivateKey.DeriveKey(&passphrase)
	if err == nil {
		return nil
	}

	if errors.Is(err, snacl.ErrInvalidPassword) {
		return fmt.Errorf("derive master private key: %w", ErrInvalidPassphrase)
	}

	return fmt.Errorf("derive master private key: %w", err)
}

// decryptCryptoKey decrypts and validates a fixed-size runtime crypto key.
func decryptCryptoKey(masterPrivateKey *snacl.SecretKey,
	ciphertext []byte) (snacl.CryptoKey, error) {

	decryptedKey, err := masterPrivateKey.Decrypt(ciphertext)
	defer clear(decryptedKey)

	if err != nil {
		return snacl.CryptoKey{}, fmt.Errorf("decrypt CryptoKey: %w: %w",
			errUnexpectedState, err)
	}

	if len(decryptedKey) != snacl.KeySize {
		return snacl.CryptoKey{}, fmt.Errorf("decrypt CryptoKey expected %d"+
			" bytes, got %d: %w", snacl.KeySize, len(decryptedKey),
			errUnexpectedState)
	}

	var cryptoKey snacl.CryptoKey
	copy(cryptoKey[:], decryptedKey)

	return cryptoKey, nil
}
