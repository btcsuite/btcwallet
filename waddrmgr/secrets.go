// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/internal/zero"
	"github.com/btcsuite/btcwallet/snacl"
)

// This file provides the minimal, backend-neutral secret core of an address
// manager: the crypto-key hierarchy and per-account key material, expressed
// against the neutral store types (ManagerState, KeyScopeState, AccountState)
// rather than a walletdb bucket. It is what the Stage 3 SQL wallet lifecycle
// uses in place of a fully bucket-bound Manager to create secrets outside a
// write transaction and to obtain an account's extended key for derivation.
//
// It reuses the exact snacl and crypto-key primitives the live Manager uses
// (newSecretKey, newCryptoKey, deriveCoinTypeKey, deriveAccountKey, cryptoKey),
// so the material it produces is byte-identical to a wallet created through
// Create and opened through Open. It deliberately covers only the crypto core:
// the in-memory ManagedAddress cache, the deriveOnUnlock queue, disk read-back
// verification, and runtime account creation from the master HD key remain with
// the full Manager.

// ScopeSecrets is the prepared durable state for one key scope and its default
// account, produced outside any write transaction so the caller can commit it
// through the runtime store.
type ScopeSecrets struct {
	// State is the durable key-scope state, with its encrypted coin-type
	// keys and no allocated account (LastAccount is NoAccountAllocated).
	State KeyScopeState

	// Account is the durable state for the scope's default account (number
	// zero), with its encrypted extended keys.
	Account AccountState
}

// WalletSecrets is the prepared durable state of a freshly created wallet: the
// address manager's root state plus one default scope entry per requested key
// scope. It is produced by PrepareWalletSecrets outside any write transaction.
type WalletSecrets struct {
	// Manager is the durable root address-manager state, carrying the master
	// key parameters and the encrypted crypto and master-HD keys.
	Manager ManagerState

	// Scopes are the prepared default scopes, one per requested key scope,
	// each with its encrypted coin-type keys and default account.
	Scopes []ScopeSecrets
}

// PrepareWalletSecrets generates the address manager's crypto-key hierarchy
// and the coin-type and default-account keys for each requested scope,
// returning the prepared durable state ready to be committed through the
// runtime store. It mirrors the secret-generation half of Create but never
// touches a database, so the key derivation and encryption happen entirely
// outside the write transaction, matching the Stage 3
// prepare-outside-then-commit contract.
//
// rootKey is the wallet's BIP0032 master node; a nil root key is rejected
// because this minimal path does not create watch-only wallets. The returned
// material is byte-identical to what Create would persist for the same inputs.
//
//nolint:cyclop // A linear generate-and-encrypt sequence mirroring Create.
func PrepareWalletSecrets(rootKey *hdkeychain.ExtendedKey, pubPassphrase,
	privPassphrase []byte, config *ScryptOptions,
	scopes []KeyScope) (*WalletSecrets, error) {

	if rootKey == nil {
		return nil, managerError(ErrWatchingOnly, "a root key is "+
			"required to prepare wallet secrets", nil)
	}

	if len(privPassphrase) == 0 {
		return nil, managerError(ErrEmptyPassphrase,
			"private passphrase may not be empty", nil)
	}

	if config == nil {
		config = &DefaultScryptOptions
	}

	// Generate the master keys that protect the crypto keys, then the crypto
	// keys that protect the actual key material.
	masterKeyPub, err := newSecretKey(&pubPassphrase, config)
	if err != nil {
		return nil, managerError(ErrCrypto,
			"failed to derive master public key", err)
	}
	defer masterKeyPub.Zero()

	masterKeyPriv, err := newSecretKey(&privPassphrase, config)
	if err != nil {
		return nil, managerError(ErrCrypto,
			"failed to derive master private key", err)
	}
	defer masterKeyPriv.Zero()

	cryptoKeyPub, err := newCryptoKey()
	if err != nil {
		return nil, managerError(ErrCrypto,
			"failed to generate crypto public key", err)
	}
	defer cryptoKeyPub.Zero()

	cryptoKeyPriv, err := newCryptoKey()
	if err != nil {
		return nil, managerError(ErrCrypto,
			"failed to generate crypto private key", err)
	}
	defer cryptoKeyPriv.Zero()

	cryptoKeyScript, err := newCryptoKey()
	if err != nil {
		return nil, managerError(ErrCrypto,
			"failed to generate crypto script key", err)
	}
	defer cryptoKeyScript.Zero()

	manager, err := buildManagerState(
		rootKey, masterKeyPub, masterKeyPriv, cryptoKeyPub, cryptoKeyPriv,
		cryptoKeyScript,
	)
	if err != nil {
		return nil, err
	}

	secrets := &WalletSecrets{Manager: manager}

	// Derive and encrypt the coin-type and default-account keys for each
	// requested scope.
	for _, scope := range scopes {
		scopeSecrets, err := prepareScopeSecrets(
			rootKey, scope, cryptoKeyPub, cryptoKeyPriv,
		)
		if err != nil {
			return nil, err
		}

		secrets.Scopes = append(secrets.Scopes, scopeSecrets)
	}

	return secrets, nil
}

// buildManagerState encrypts the crypto keys with their master keys and the
// root master HD keys with the crypto keys, then assembles the durable manager
// root state. It mirrors the crypto-key and master-HD-key persistence half of
// Create.
func buildManagerState(rootKey *hdkeychain.ExtendedKey, masterKeyPub,
	masterKeyPriv *snacl.SecretKey, cryptoKeyPub, cryptoKeyPriv,
	cryptoKeyScript EncryptorDecryptor) (ManagerState, error) {

	// Encrypt the crypto keys with their associated master keys.
	cryptoKeyPubEnc, err := masterKeyPub.Encrypt(cryptoKeyPub.Bytes())
	if err != nil {
		return ManagerState{}, managerError(ErrCrypto,
			"failed to encrypt crypto public key", err)
	}

	cryptoKeyPrivEnc, err := masterKeyPriv.Encrypt(cryptoKeyPriv.Bytes())
	if err != nil {
		return ManagerState{}, managerError(ErrCrypto,
			"failed to encrypt crypto private key", err)
	}

	cryptoKeyScriptEnc, err := masterKeyPriv.Encrypt(cryptoKeyScript.Bytes())
	if err != nil {
		return ManagerState{}, managerError(ErrCrypto,
			"failed to encrypt crypto script key", err)
	}

	// Encrypt the root master HD keys so additional scoped managers can be
	// created later, exactly as Create does.
	rootPubKey, err := rootKey.Neuter()
	if err != nil {
		return ManagerState{}, managerError(ErrKeyChain,
			"failed to neuter master extended key", err)
	}

	masterHDPrivEnc, err := cryptoKeyPriv.Encrypt([]byte(rootKey.String()))
	if err != nil {
		return ManagerState{}, managerError(ErrCrypto,
			"failed to encrypt master HD private key", err)
	}

	masterHDPubEnc, err := cryptoKeyPub.Encrypt([]byte(rootPubKey.String()))
	if err != nil {
		return ManagerState{}, managerError(ErrCrypto,
			"failed to encrypt master HD public key", err)
	}

	return ManagerState{
		Version:                  LatestMgrVersion,
		CreatedAt:                time.Now(),
		WatchOnly:                false,
		MasterPubParams:          masterKeyPub.Marshal(),
		MasterPrivParams:         masterKeyPriv.Marshal(),
		EncryptedCryptoPubKey:    cryptoKeyPubEnc,
		EncryptedCryptoPrivKey:   cryptoKeyPrivEnc,
		EncryptedCryptoScriptKey: cryptoKeyScriptEnc,
		EncryptedMasterHDPubKey:  masterHDPubEnc,
		EncryptedMasterHDPrivKey: masterHDPrivEnc,
	}, nil
}

// prepareScopeSecrets derives the coin-type key and the default account key for
// one scope, encrypts them with the crypto keys, and returns the prepared
// durable scope and account state. It mirrors createManagerKeyScope for the
// default account only; the imported-address account is a Phase 2A2 concern.
//
//nolint:cyclop // A linear derive-and-encrypt sequence mirroring Create.
func prepareScopeSecrets(rootKey *hdkeychain.ExtendedKey, scope KeyScope,
	cryptoKeyPub, cryptoKeyPriv EncryptorDecryptor) (ScopeSecrets, error) {

	schema, ok := ScopeAddrMap[scope]
	if !ok {
		return ScopeSecrets{}, managerError(ErrScopeNotFound, fmt.Sprintf(
			"no default address schema for scope %v", scope), nil)
	}

	coinTypeKeyPriv, err := deriveCoinTypeKey(rootKey, scope)
	if err != nil {
		return ScopeSecrets{}, managerError(ErrKeyChain,
			"failed to derive cointype extended key", err)
	}
	defer coinTypeKeyPriv.Zero()

	acctKeyPriv, err := deriveAccountKey(coinTypeKeyPriv, 0)
	if err != nil {
		return ScopeSecrets{}, managerError(ErrKeyChain,
			"failed to derive account 0 extended key", err)
	}
	defer acctKeyPriv.Zero()

	// Ensure the branch keys are derivable, matching Create's seed check.
	if err := checkBranchKeys(acctKeyPriv); err != nil {
		return ScopeSecrets{}, managerError(ErrKeyChain,
			"account 0 branch keys are not derivable", err)
	}

	acctKeyPub, err := acctKeyPriv.Neuter()
	if err != nil {
		return ScopeSecrets{}, managerError(ErrKeyChain,
			"failed to neuter account 0 key", err)
	}

	coinTypeKeyPub, err := coinTypeKeyPriv.Neuter()
	if err != nil {
		return ScopeSecrets{}, managerError(ErrKeyChain,
			"failed to neuter cointype key", err)
	}

	coinTypePubEnc, err := cryptoKeyPub.Encrypt(
		[]byte(coinTypeKeyPub.String()),
	)
	if err != nil {
		return ScopeSecrets{}, managerError(ErrCrypto,
			"failed to encrypt cointype public key", err)
	}

	coinTypePrivEnc, err := cryptoKeyPriv.Encrypt(
		[]byte(coinTypeKeyPriv.String()),
	)
	if err != nil {
		return ScopeSecrets{}, managerError(ErrCrypto,
			"failed to encrypt cointype private key", err)
	}

	acctPubEnc, err := cryptoKeyPub.Encrypt([]byte(acctKeyPub.String()))
	if err != nil {
		return ScopeSecrets{}, managerError(ErrCrypto,
			"failed to encrypt account 0 public key", err)
	}

	acctPrivEnc, err := cryptoKeyPriv.Encrypt([]byte(acctKeyPriv.String()))
	if err != nil {
		return ScopeSecrets{}, managerError(ErrCrypto,
			"failed to encrypt account 0 private key", err)
	}

	return ScopeSecrets{
		State: KeyScopeState{
			Scope:                scope,
			AddrSchema:           schema,
			EncryptedCoinPubKey:  coinTypePubEnc,
			EncryptedCoinPrivKey: coinTypePrivEnc,
			LastAccount:          NoAccountAllocated,
		},
		Account: AccountState{
			Scope:            scope,
			Account:          DefaultAccountNum,
			Type:             AccountDefault,
			Name:             defaultAccountName,
			EncryptedPubKey:  acctPubEnc,
			EncryptedPrivKey: acctPrivEnc,
		},
	}, nil
}

// ManagerKeyring is the minimal, in-memory secret core of an address manager
// reconstructed from durable ManagerState. It holds the crypto-key hierarchy
// and can decrypt a stored account extended key for address derivation. It is
// the loaded/unlocked-manager stand-in the Stage 3 SQL wallet lifecycle uses in
// place of a fully bucket-bound Manager.
//
// Like the live Manager it starts locked: the public crypto key is available
// immediately (so public account keys decrypt), while the private crypto key is
// derived only on Unlock. It is not safe for concurrent use; the SQL wallet
// serializes access through the runtime mutation gate.
type ManagerKeyring struct {
	chainParams *chaincfg.Params
	watchOnly   bool
	locked      bool

	// masterKeyPub is derived from the public passphrase at open time and is
	// used to decrypt the public crypto key. masterKeyPriv holds only its
	// parameters until Unlock derives it from the private passphrase.
	masterKeyPub  *snacl.SecretKey
	masterKeyPriv *snacl.SecretKey

	// cryptoKeyPub protects public key material and is always available.
	cryptoKeyPub EncryptorDecryptor

	// cryptoKeyPriv protects private key material and is zeroed until Unlock.
	cryptoKeyPrivEncrypted []byte
	cryptoKeyPriv          EncryptorDecryptor

	// cryptoKeyScript protects script material and is zeroed until Unlock.
	cryptoKeyScriptEncrypted []byte
	cryptoKeyScript          EncryptorDecryptor
}

// OpenManagerKeyring reconstructs the secret core from durable manager state
// and the public passphrase, mirroring the crypto half of loadManager. It
// derives the public master key, decrypts the public crypto key, and retains
// the private master-key parameters and encrypted private crypto keys so a
// later Unlock can derive the private material. The keyring starts locked.
func OpenManagerKeyring(state ManagerState, pubPassphrase []byte,
	chainParams *chaincfg.Params) (*ManagerKeyring, error) {

	masterKeyPub := &snacl.SecretKey{}
	if err := masterKeyPub.Unmarshal(state.MasterPubParams); err != nil {
		return nil, managerError(ErrCrypto,
			"failed to unmarshal master public key", err)
	}

	if err := masterKeyPub.DeriveKey(&pubPassphrase); err != nil {
		return nil, managerError(ErrWrongPassphrase,
			"invalid passphrase for master public key", nil)
	}

	// Use the master public key to decrypt the crypto public key.
	cryptoKeyPub := &cryptoKey{}
	pubCT, err := masterKeyPub.Decrypt(state.EncryptedCryptoPubKey)
	if err != nil {
		return nil, managerError(ErrCrypto,
			"failed to decrypt crypto public key", err)
	}
	cryptoKeyPub.CopyBytes(pubCT)
	zero.Bytes(pubCT)

	// Retain the private master-key parameters so Unlock can derive them.
	masterKeyPriv := &snacl.SecretKey{}
	if !state.WatchOnly {
		err := masterKeyPriv.Unmarshal(state.MasterPrivParams)
		if err != nil {
			return nil, managerError(ErrCrypto,
				"failed to unmarshal master private key", err)
		}
	}

	return &ManagerKeyring{
		chainParams:              chainParams,
		watchOnly:                state.WatchOnly,
		locked:                   true,
		masterKeyPub:             masterKeyPub,
		masterKeyPriv:            masterKeyPriv,
		cryptoKeyPub:             cryptoKeyPub,
		cryptoKeyPrivEncrypted:   state.EncryptedCryptoPrivKey,
		cryptoKeyPriv:            &cryptoKey{},
		cryptoKeyScriptEncrypted: state.EncryptedCryptoScriptKey,
		cryptoKeyScript:          &cryptoKey{},
	}, nil
}

// Unlock derives the private master key from the private passphrase and
// decrypts the private and script crypto keys, mirroring the crypto half of the
// Manager's Unlock. After it returns the account private keys become available.
// A watch-only keyring cannot be unlocked.
func (k *ManagerKeyring) Unlock(privPassphrase []byte) error {
	if k.watchOnly {
		return managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	if err := k.masterKeyPriv.DeriveKey(&privPassphrase); err != nil {
		k.Lock()

		return managerError(ErrWrongPassphrase,
			"invalid passphrase for master private key", nil)
	}

	privCT, err := k.masterKeyPriv.Decrypt(k.cryptoKeyPrivEncrypted)
	if err != nil {
		k.Lock()

		return managerError(ErrCrypto,
			"failed to decrypt crypto private key", err)
	}
	k.cryptoKeyPriv.CopyBytes(privCT)
	zero.Bytes(privCT)

	scriptCT, err := k.masterKeyPriv.Decrypt(k.cryptoKeyScriptEncrypted)
	if err != nil {
		k.Lock()

		return managerError(ErrCrypto,
			"failed to decrypt crypto script key", err)
	}
	k.cryptoKeyScript.CopyBytes(scriptCT)
	zero.Bytes(scriptCT)

	k.locked = false

	return nil
}

// Lock zeroes the private key material, returning the keyring to its locked
// state. Public key material remains available so public account keys still
// decrypt.
func (k *ManagerKeyring) Lock() {
	k.cryptoKeyScript.Zero()
	k.cryptoKeyPriv.Zero()
	k.masterKeyPriv.Zero()
	k.locked = true
}

// Close zeroes all in-memory secret material, including the public crypto key.
func (k *ManagerKeyring) Close() {
	k.Lock()
	k.cryptoKeyPub.Zero()
	k.masterKeyPub.Zero()
}

// IsLocked reports whether the private key material has not been derived yet.
func (k *ManagerKeyring) IsLocked() bool {
	return k.locked
}

// WatchOnly reports whether the keyring holds no private key material.
func (k *ManagerKeyring) WatchOnly() bool {
	return k.watchOnly
}

// AccountKey decrypts the extended key for one account from its durable state.
// It returns the private extended key when the keyring is unlocked and the
// account has private material, otherwise the public extended key, mirroring
// the key selection in loadAccountInfo. Address derivation uses only the child
// public keys, so the public account key is enough to derive addresses for a
// locked or watch-only account.
func (k *ManagerKeyring) AccountKey(account AccountState) (
	*hdkeychain.ExtendedKey, error) {

	if !k.locked && !k.watchOnly && len(account.EncryptedPrivKey) != 0 {
		key, err := k.decryptKey(k.cryptoKeyPriv, account.EncryptedPrivKey)
		if err != nil {
			return nil, managerError(ErrCrypto, fmt.Sprintf("failed to "+
				"decrypt account %d private key", account.Account),
				err)
		}

		return key, nil
	}

	if len(account.EncryptedPubKey) == 0 {
		return nil, managerError(ErrCrypto, fmt.Sprintf("account %d has "+
			"no public key material", account.Account), nil)
	}

	key, err := k.decryptKey(k.cryptoKeyPub, account.EncryptedPubKey)
	if err != nil {
		return nil, managerError(ErrCrypto, fmt.Sprintf("failed to "+
			"decrypt account %d public key", account.Account), err)
	}

	return key, nil
}

// decryptKey decrypts an encrypted extended key with the given crypto key and
// parses it back into an extended key, zeroing the intermediate plaintext.
func (k *ManagerKeyring) decryptKey(cryptoKey EncryptorDecryptor,
	encrypted []byte) (*hdkeychain.ExtendedKey, error) {

	serialized, err := cryptoKey.Decrypt(encrypted)
	if err != nil {
		return nil, err
	}

	key, err := hdkeychain.NewKeyFromString(string(serialized))
	zero.Bytes(serialized)
	if err != nil {
		return nil, err
	}

	key.SetNet(k.chainParams)

	return key, nil
}
