package keyvault

import (
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

// ChangePassphrase re-wraps the persisted wallet secrets from oldPassphrase to
// newPassphrase. It preserves the vault's original locked/unlocked state: the
// runtime keys held while unlocked are never touched, and a locked vault leaves
// no decrypted state behind because the rotation reads and re-encrypts only the
// persisted ciphertext.
func (v *WalletVault) ChangePassphrase(ctx context.Context,
	params ChangePassphraseParams) error {

	err := params.Validate()
	if err != nil {
		return fmt.Errorf("wallet %d vault ChangePassphrase: %w",
			v.walletID, err)
	}

	// Validate before touching any secret. A SQL wallet has no public
	// passphrase, so a request naming one cannot be served in full and must
	// leave the persisted state untouched rather than rotating the private
	// half and then reporting failure.
	if params.PublicOld != nil {
		return fmt.Errorf("wallet %d vault ChangePassphrase: %w",
			v.walletID, ErrPublicPassphraseUnsupported)
	}

	oldPassphrase, newPassphrase := params.PrivateOld, params.PrivateNew

	// Hold the lock for the whole rotation so it serializes against
	// Lock/Unlock/Encrypt/Decrypt. The rotation itself never reads or
	// writes v.unlockedState, so the vault's locked/unlocked state is
	// preserved regardless of the outcome.
	v.mtx.Lock()
	defer v.mtx.Unlock()

	secrets, err := v.store.GetWalletSecrets(ctx, v.walletID)
	if err != nil {
		return fmt.Errorf("wallet %d vault ChangePassphrase: "+
			"get secrets: %w", v.walletID, err)
	}

	updateParams, err := v.makeRotatedWalletSecrets(
		secrets, oldPassphrase, newPassphrase,
	)
	if err != nil {
		return fmt.Errorf("wallet %d vault ChangePassphrase: "+
			"rotate secrets: %w", v.walletID, err)
	}

	err = v.store.UpdateWalletSecrets(ctx, updateParams)
	if err != nil {
		return fmt.Errorf("wallet %d vault ChangePassphrase: "+
			"update secrets: %w", v.walletID, err)
	}

	return nil
}

// makeRotatedWalletSecrets validates the old private passphrase and re-encrypts
// the persisted crypto keys under a master key derived from the new
// passphrase. It mirrors CreateWalletSecrets: it derives the old master key
// from the stored parameters (which validates oldPassphrase against the stored
// digest), decrypts the persisted crypto key blobs with it, and re-encrypts
// them under a freshly salted master key derived from newPassphrase. The master
// HD private key ciphertext is carried forward unchanged because it is
// encrypted under the crypto private key, not the passphrase.
//
// A wrong oldPassphrase is reported as ErrInvalidPassphrase and no persisted
// state is mutated. This does not read v.unlockedState, so it works whether the
// vault is locked or unlocked.
//
// TODO(gus): wrap this with secret.Do from Go 1.26+ to avoid leaking decrypted
// key material while waiting for GC.
func (v *WalletVault) makeRotatedWalletSecrets(secrets *db.WalletSecrets,
	oldPassphrase, newPassphrase []byte) (db.UpdateWalletSecretsParams,
	error) {

	if secrets == nil {
		return db.UpdateWalletSecretsParams{},
			fmt.Errorf("missing wallet secrets: %w", errUnexpectedState)
	}

	// Derive the old master private key from the stored parameters.
	// DeriveKey validates oldPassphrase against the stored digest, so a
	// wrong passphrase is rejected here before any secret material is
	// touched.
	var oldMasterPrivateKey snacl.SecretKey

	err := oldMasterPrivateKey.Unmarshal(secrets.MasterPrivParams)
	if err != nil {
		return db.UpdateWalletSecretsParams{}, fmt.Errorf(
			"unmarshal master private parameters: %w", err,
		)
	}
	defer oldMasterPrivateKey.Zero()

	err = deriveMasterPrivateKey(&oldMasterPrivateKey, oldPassphrase)
	if err != nil {
		return db.UpdateWalletSecretsParams{}, err
	}

	keyParams := oldMasterPrivateKey.Parameters

	// Derive a new master private key from the new passphrase. NewSecretKey
	// generates a fresh salt; the scrypt cost parameters are preserved.
	newMasterPrivateKey, err := snacl.NewSecretKey(
		&newPassphrase, keyParams.N, keyParams.R, keyParams.P,
	)
	if err != nil {
		return db.UpdateWalletSecretsParams{},
			fmt.Errorf("new master private key: %w", err)
	}
	defer newMasterPrivateKey.Zero()

	// Re-encrypt the script crypto key under the new master key. Every
	// wallet, watch-only included, holds a script crypto key.
	encryptedCryptoKeyScript, err := reEncryptCryptoKey(
		&oldMasterPrivateKey, newMasterPrivateKey,
		secrets.EncryptedCryptoScriptKey,
	)
	if err != nil {
		return db.UpdateWalletSecretsParams{},
			fmt.Errorf("re-encrypt crypto key script: %w", err)
	}

	// A watch-only wallet has no private crypto key or HD root material, so
	// the script key is all it needs.
	if v.watchOnly {
		return db.UpdateWalletSecretsParams{
			WalletID:                 v.walletID,
			MasterPrivParams:         newMasterPrivateKey.Marshal(),
			EncryptedCryptoScriptKey: encryptedCryptoKeyScript,
		}, nil
	}

	// Re-encrypt the private crypto key under the new master key.
	// Decrypting it with the old master key also confirms oldPassphrase can
	// reproduce the spendable key material, beyond the digest check
	// performed above.
	encryptedCryptoKeyPrivate, err := reEncryptCryptoKey(
		&oldMasterPrivateKey, newMasterPrivateKey,
		secrets.EncryptedCryptoPrivKey,
	)
	if err != nil {
		return db.UpdateWalletSecretsParams{},
			fmt.Errorf("re-encrypt crypto key private: %w", err)
	}

	// The HD-root ciphertext is encrypted under the crypto private key, not
	// the passphrase, so it is carried forward unchanged. Validate that it
	// still decrypts and parses under that key before persisting it, so a
	// corrupt or mismatched root cannot let rotation report success while
	// stranding the wallet: after rotation, unlock recovers the HD root the
	// same way and must not be the first place the corruption surfaces.
	err = validateCarriedHDRoot(
		&oldMasterPrivateKey, secrets.EncryptedCryptoPrivKey,
		secrets.EncryptedMasterHdPrivKey,
	)
	if err != nil {
		return db.UpdateWalletSecretsParams{},
			fmt.Errorf("validate carried HD root: %w", err)
	}

	return db.UpdateWalletSecretsParams{
		WalletID:                 v.walletID,
		MasterPrivParams:         newMasterPrivateKey.Marshal(),
		EncryptedCryptoPrivKey:   encryptedCryptoKeyPrivate,
		EncryptedCryptoScriptKey: encryptedCryptoKeyScript,

		// The master HD private key is encrypted under the crypto
		// private key, not the passphrase, so its ciphertext is carried
		// forward unchanged.
		EncryptedMasterHdPrivKey: secrets.EncryptedMasterHdPrivKey,
	}, nil
}

// validateCarriedHDRoot confirms the carried HD-root ciphertext is recoverable
// before a passphrase rotation persists it. It decrypts the crypto private key
// with the (already validated) old master key, uses it to decrypt the HD-root
// ciphertext, and parses the result as an extended key. Rotation preserves the
// crypto private key plaintext, so a root that recovers here also recovers
// under the newly re-encrypted crypto private key. Any failure is reported as
// errUnexpectedState.
func validateCarriedHDRoot(oldMasterKey *snacl.SecretKey,
	encryptedCryptoKeyPrivate, encryptedHDRoot []byte) error {

	cryptoKeyPrivate, err := decryptCryptoKey(
		oldMasterKey, encryptedCryptoKeyPrivate,
	)
	if err != nil {
		return fmt.Errorf("crypto key private: %w", err)
	}
	defer cryptoKeyPrivate.Zero()

	if len(encryptedHDRoot) == 0 {
		return fmt.Errorf("missing master HD private key: %w",
			errUnexpectedState)
	}

	decryptedHDRoot, err := cryptoKeyPrivate.Decrypt(encryptedHDRoot)
	if err != nil {
		return fmt.Errorf("decrypt master HD private key: %w: %w",
			errUnexpectedState, err)
	}
	defer clear(decryptedHDRoot)

	hdRootKey, err := hdkeychain.NewKeyFromString(string(decryptedHDRoot))
	if err != nil {
		return fmt.Errorf("parse master HD private key: %w: %w",
			errUnexpectedState, err)
	}

	// The parsed key is only used to confirm the ciphertext is recoverable;
	// zero it immediately since validation keeps no runtime state.
	hdRootKey.Zero()

	return nil
}

// reEncryptCryptoKey decrypts a persisted crypto key blob with the old master
// key and re-encrypts it under the new master key, zeroing the decrypted
// plaintext before returning. It validates that the decrypted key has the
// expected size.
func reEncryptCryptoKey(oldMasterKey, newMasterKey *snacl.SecretKey,
	ciphertext []byte) ([]byte, error) {

	decrypted, err := oldMasterKey.Decrypt(ciphertext)
	defer clear(decrypted)

	if err != nil {
		return nil, fmt.Errorf("decrypt crypto key: %w: %w",
			errUnexpectedState, err)
	}

	if len(decrypted) != snacl.KeySize {
		return nil, fmt.Errorf("decrypt crypto key expected %d bytes, "+
			"got %d: %w", snacl.KeySize, len(decrypted),
			errUnexpectedState)
	}

	reEncrypted, err := newMasterKey.Encrypt(decrypted)
	if err != nil {
		return nil, fmt.Errorf("encrypt crypto key: %w", err)
	}

	return reEncrypted, nil
}
