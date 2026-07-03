package keyvault

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// Lock locks the vault erasing runtime secret material from memory.
func (v *WalletVault) Lock() {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	v.clearRuntimeAndLock()
}

// clearRuntimeAndLock clears unlocked state, locking the vault.
//
// This method must be called with v.mtx held.
func (v *WalletVault) clearRuntimeAndLock() {
	if v.unlockedState != nil {
		// Zero runtime secrets before dropping references. Waiting for GC would
		// leave spend-capable key material readable in heap memory until an
		// implementation-dependent collection cycle.
		v.unlockedState.zero()
		v.unlockedState = nil
	}
}

// IsLocked reports whether the vault currently has unlocked runtime state.
func (v *WalletVault) IsLocked() bool {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	return v.unlockedState == nil
}

// Unlock loads wallet secrets from the store and decrypts them into runtime
// state using the provided private passphrase. If the vault is already
// unlocked, Unlock returns ErrVaultUnlocked and does not validate the
// passphrase.
func (v *WalletVault) Unlock(ctx context.Context, passphrase []byte) error {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	if v.unlockedState != nil {
		return fmt.Errorf("wallet %d vault Unlock: %w", v.walletID,
			ErrVaultUnlocked)
	}

	secrets, err := v.store.GetWalletSecrets(ctx, v.walletID)
	if err != nil {
		return fmt.Errorf("wallet %d vault Unlock: get secrets: %w",
			v.walletID, err)
	}

	state, err := decryptWalletSecrets(secrets, passphrase, v.watchOnly)
	if err != nil {
		return fmt.Errorf("wallet %d vault Unlock: decrypt secrets: %w",
			v.walletID, err)
	}

	v.unlockedState = state

	return nil
}

// decryptWalletSecrets decrypts persisted wallet secrets into runtime state.
//
// TODO(gus): wrap with secret.Do from golang 1.26+. There are functions that
// actually leaks a lot of information in memory while waiting GC, like
// hdkeychain.NewKeyFromString.
func decryptWalletSecrets(secrets *db.WalletSecrets, passphrase []byte,
	watchOnly bool) (*unlockedState, error) {

	if secrets == nil {
		// This error is not expected to happen.
		return nil, fmt.Errorf("missing wallet secrets: %w", errUnexpectedState)
	}

	var masterPrivateKey snacl.SecretKey

	// First, we need to load the key parameter from stored secrets.
	err := masterPrivateKey.Unmarshal(secrets.MasterPrivParams)
	if err != nil {
		return nil, fmt.Errorf("unmarshal master private parameters: %w", err)
	}
	defer masterPrivateKey.Zero()

	// With the parameters loaded, we can derive the master cryptographic key
	// from the passphrase and check for invalid passphrase errors.
	err = deriveMasterPrivateKey(&masterPrivateKey, passphrase)
	if err != nil {
		return nil, err
	}

	if watchOnly {
		return decryptWatchOnlyWalletSecrets(&masterPrivateKey, secrets)
	}

	return decryptSpendableWalletSecrets(&masterPrivateKey, secrets)
}

// decryptWatchOnlyWalletSecrets decrypts watch-only secret material.
func decryptWatchOnlyWalletSecrets(masterPrivateKey *snacl.SecretKey,
	secrets *db.WalletSecrets) (*unlockedState, error) {

	cryptoKeyScript, err := decryptCryptoKey(
		masterPrivateKey, secrets.EncryptedCryptoScriptKey,
	)
	if err != nil {
		return nil, fmt.Errorf("crypto key script: %w", err)
	}
	defer cryptoKeyScript.Zero()

	return &unlockedState{
		cryptoKeyScript: cryptoKeyScript,
	}, nil
}

// decryptSpendableWalletSecrets decrypts spendable secret material.
func decryptSpendableWalletSecrets(masterPrivateKey *snacl.SecretKey,
	secrets *db.WalletSecrets) (*unlockedState, error) {

	cryptoKeyPrivate, err := decryptCryptoKey(
		masterPrivateKey, secrets.EncryptedCryptoPrivKey,
	)
	if err != nil {
		return nil, fmt.Errorf("crypto key private: %w", err)
	}
	defer cryptoKeyPrivate.Zero()

	if len(secrets.EncryptedMasterHdPrivKey) == 0 {
		return nil, fmt.Errorf("missing master HD private key: %w",
			errUnexpectedState)
	}

	cryptoKeyScript, err := decryptCryptoKey(
		masterPrivateKey, secrets.EncryptedCryptoScriptKey,
	)
	if err != nil {
		return nil, fmt.Errorf("crypto key script: %w", err)
	}
	defer cryptoKeyScript.Zero()

	decryptedHDPrivate, decryptErr := cryptoKeyPrivate.Decrypt(
		secrets.EncryptedMasterHdPrivKey,
	)
	if decryptErr != nil {
		return nil, fmt.Errorf("decrypt master HD private key: %w: %w",
			errUnexpectedState, decryptErr)
	}
	defer clear(decryptedHDPrivate)

	hdRootKey, err := hdkeychain.NewKeyFromString(
		string(decryptedHDPrivate),
	)
	if err != nil {
		return nil, fmt.Errorf("parse master HD private key: %w", err)
	}

	state := &unlockedState{
		cryptoKeyPrivate: cryptoKeyPrivate,
		cryptoKeyScript:  cryptoKeyScript,

		// Transfer HD root key pointer ownership to state so we do not zero it.
		hdRootKey: hdRootKey,
	}

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

// ChangePassphrase rotates persisted wallet secrets to the new private
// passphrase and keeps the existing unlocked runtime state unchanged.
func (v *WalletVault) ChangePassphrase(ctx context.Context,
	newPassphrase []byte) error {

	v.mtx.Lock()
	defer v.mtx.Unlock()

	if v.unlockedState == nil {
		return fmt.Errorf("wallet %d vault ChangePassphrase: %w",
			v.walletID, ErrVaultLocked)
	}

	secrets, err := v.store.GetWalletSecrets(ctx, v.walletID)
	if err != nil {
		return fmt.Errorf("wallet %d vault ChangePassphrase: "+
			"get secrets: %w", v.walletID, err)
	}

	updateParams, err := v.makeRotatedWalletSecrets(secrets, newPassphrase)
	if err != nil {
		return fmt.Errorf("wallet %d vault ChangePassphrase: "+
			"rotate secrets: %w", v.walletID, err)
	}

	// Validate that the rotated secrets derive the same runtime keys before
	// persisting them. This prevents storing secrets that would leave the vault
	// unable to reproduce its current key material.
	//
	// This should only fail if there is a bug in this rotation path or in the
	// underlying cryptographic implementation.
	err = v.validateRotatedWalletSecrets(updateParams, newPassphrase)
	if err != nil {
		return fmt.Errorf("wallet %d vault ChangePassphrase: "+
			"validate rotated secrets: %w", v.walletID, err)
	}

	err = v.store.UpdateWalletSecrets(ctx, updateParams)
	if err != nil {
		return fmt.Errorf("wallet %d vault ChangePassphrase: "+
			"update secrets: %w", v.walletID, err)
	}

	return nil
}

// validateRotatedWalletSecrets confirms rotated persisted secrets decrypt with
// the new passphrase to the same runtime keys already held in memory.
func (v *WalletVault) validateRotatedWalletSecrets(
	params db.UpdateWalletSecretsParams, passphrase []byte) error {

	updatedSecrets := db.WalletSecrets{
		MasterPrivParams:         params.MasterPrivParams,
		EncryptedCryptoPrivKey:   params.EncryptedCryptoPrivKey,
		EncryptedCryptoScriptKey: params.EncryptedCryptoScriptKey,
		EncryptedMasterHdPrivKey: params.EncryptedMasterHdPrivKey,
	}

	validatedState, err := decryptWalletSecrets(
		&updatedSecrets, passphrase, v.watchOnly,
	)
	if err != nil {
		return fmt.Errorf("decrypt rotated secrets: %w", err)
	}
	defer validatedState.zero()

	if !unlockedStateEqual(v.unlockedState, validatedState) {
		return fmt.Errorf("rotated secrets changed runtime keys: %w",
			errUnexpectedState)
	}

	return nil
}

// unlockedStateEqual reports whether two unlocked states hold equal runtime
// keys.
func unlockedStateEqual(a, b *unlockedState) bool {
	if a == nil || b == nil {
		return a == b
	}

	if !bytes.Equal(a.cryptoKeyPrivate[:], b.cryptoKeyPrivate[:]) {
		return false
	}

	if !bytes.Equal(a.cryptoKeyScript[:], b.cryptoKeyScript[:]) {
		return false
	}

	if a.hdRootKey == nil || b.hdRootKey == nil {
		return a.hdRootKey == b.hdRootKey
	}

	return a.hdRootKey.String() == b.hdRootKey.String()
}

// makeRotatedWalletSecrets creates a persisted wallet secret update encrypted
// with a new private passphrase from the currently unlocked runtime state.
//
// TODO(gus): wrap this with secret.Do from Go 1.26+ to avoid
// leaking HD private key string material while waiting for GC.
func (v *WalletVault) makeRotatedWalletSecrets(secrets *db.WalletSecrets,
	newPassphrase []byte) (db.UpdateWalletSecretsParams, error) {

	if secrets == nil {
		return db.UpdateWalletSecretsParams{},
			fmt.Errorf("missing wallet secrets: %w", errUnexpectedState)
	}

	// First, we need to load the old key parameters to be able to derive the
	// new key.
	var currentMasterPrivateKey snacl.SecretKey

	err := currentMasterPrivateKey.Unmarshal(secrets.MasterPrivParams)
	if err != nil {
		return db.UpdateWalletSecretsParams{}, fmt.Errorf(
			"unmarshal master private parameters: %w", err,
		)
	}
	defer currentMasterPrivateKey.Zero()

	keyParams := currentMasterPrivateKey.Parameters

	// Second, generate the new key.
	newMasterPrivateKey, err := snacl.NewSecretKey(
		&newPassphrase, keyParams.N, keyParams.R, keyParams.P,
	)
	if err != nil {
		return db.UpdateWalletSecretsParams{},
			fmt.Errorf("new master private key: %w", err)
	}
	defer newMasterPrivateKey.Zero()

	if v.watchOnly {
		encryptedCryptoKeyScript, scriptErr := newMasterPrivateKey.Encrypt(
			v.unlockedState.cryptoKeyScript[:],
		)
		if scriptErr != nil {
			return db.UpdateWalletSecretsParams{},
				fmt.Errorf("encrypt crypto key script: %w", scriptErr)
		}

		return db.UpdateWalletSecretsParams{
			WalletID:                 v.walletID,
			MasterPrivParams:         newMasterPrivateKey.Marshal(),
			EncryptedCryptoScriptKey: encryptedCryptoKeyScript,
		}, nil
	}

	encryptedCryptoKeyPrivate, err := newMasterPrivateKey.Encrypt(
		v.unlockedState.cryptoKeyPrivate[:],
	)
	if err != nil {
		return db.UpdateWalletSecretsParams{},
			fmt.Errorf("encrypt crypto key private: %w", err)
	}

	encryptedCryptoKeyScript, err := newMasterPrivateKey.Encrypt(
		v.unlockedState.cryptoKeyScript[:],
	)
	if err != nil {
		return db.UpdateWalletSecretsParams{},
			fmt.Errorf("encrypt crypto key script: %w", err)
	}

	return db.UpdateWalletSecretsParams{
		WalletID:                 v.walletID,
		MasterPrivParams:         newMasterPrivateKey.Marshal(),
		EncryptedCryptoPrivKey:   encryptedCryptoKeyPrivate,
		EncryptedCryptoScriptKey: encryptedCryptoKeyScript,
		EncryptedMasterHdPrivKey: secrets.EncryptedMasterHdPrivKey,
	}, nil
}
