// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/internal/zero"
	"github.com/btcsuite/btcwallet/walletdb"
)

// AllocateDerivedAccountNumber advances the per-scope lastAccount counter and
// returns the next derived account number. Watch-only wallets are rejected.
func (s *ScopedKeyManager) AllocateDerivedAccountNumber(
	ns walletdb.ReadWriteBucket) (uint32, error) {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.rootManager.WatchOnly() {
		return 0, managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	return s.advanceLastAccountLocked(ns)
}

// PutDerivedAccountWithKeys persists a derived account row using the
// caller-supplied account material. The plaintext public key is encrypted
// with cryptoKeyPub; the supplied encryptedPrivKey is persisted as-is.
//
// Must run inside the same walletdb.Update transaction as
// AllocateDerivedAccountNumber.
func (s *ScopedKeyManager) PutDerivedAccountWithKeys(
	ns walletdb.ReadWriteBucket, account uint32, name string,
	plaintextPubKey []byte, encryptedPrivKey []byte) error {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.rootManager.WatchOnly() {
		return managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	err := ValidateAccountName(name)
	if err != nil {
		return err
	}

	_, lookupErr := s.lookupAccount(ns, name)
	if lookupErr == nil {
		return managerError(
			ErrDuplicateAccount,
			"account with the same name already exists", nil,
		)
	}

	pubKeyEncrypted, err := s.rootManager.cryptoKeyPub.Encrypt(
		plaintextPubKey,
	)
	if err != nil {
		return managerError(
			ErrCrypto, "failed to encrypt public key for account",
			err,
		)
	}

	err = putDefaultAccountInfo(
		ns, &s.scope, account, pubKeyEncrypted, encryptedPrivKey,
		0, 0, name,
	)
	if err != nil {
		return err
	}

	_, err = s.loadAccountInfo(ns, account)

	return err
}

// DeriveAccountKeys derives the account-level extended public key and
// encrypted private key for an already allocated derived account number.
// It uses the scoped coin-type private key, so it continues to work after
// Manager.NeuterRootKey has deleted the master HD private key.
func (s *ScopedKeyManager) DeriveAccountKeys(ns walletdb.ReadBucket,
	account uint32) ([]byte, []byte, error) {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.rootManager.WatchOnly() {
		return nil, nil, managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	if s.rootManager.IsLocked() {
		return nil, nil, managerError(ErrLocked, errLocked, nil)
	}

	_, coinTypePrivEnc, err := fetchCoinTypeKeys(ns, &s.scope)
	if err != nil {
		return nil, nil, err
	}

	serializedKeyPriv, err := s.rootManager.cryptoKeyPriv.Decrypt(
		coinTypePrivEnc,
	)
	if err != nil {
		str := "failed to decrypt cointype serialized private key"
		return nil, nil, managerError(ErrLocked, str, err)
	}

	coinTypeKeyPriv, err := hdkeychain.NewKeyFromString(
		string(serializedKeyPriv),
	)
	zero.Bytes(serializedKeyPriv)

	if err != nil {
		str := "failed to create cointype extended private key"
		return nil, nil, managerError(ErrKeyChain, str, err)
	}

	defer coinTypeKeyPriv.Zero()

	acctKeyPriv, err := deriveAccountKey(coinTypeKeyPriv, account)
	if err != nil {
		if IsError(err, ErrAccountNumTooHigh) {
			return nil, nil, err
		}

		str := "failed to convert private key for account"

		return nil, nil, managerError(ErrKeyChain, str, err)
	}
	defer acctKeyPriv.Zero()

	acctKeyPub, err := acctKeyPriv.Neuter()
	if err != nil {
		str := "failed to convert public key for account"
		return nil, nil, managerError(ErrKeyChain, str, err)
	}

	serializedPrivKey := []byte(acctKeyPriv.String())
	defer zero.Bytes(serializedPrivKey)

	acctPrivEnc, err := s.rootManager.cryptoKeyPriv.Encrypt(
		serializedPrivKey,
	)
	if err != nil {
		str := "failed to encrypt private key for account"
		return nil, nil, managerError(ErrCrypto, str, err)
	}

	return []byte(acctKeyPub.String()), acctPrivEnc, nil
}

// AllocateImportedAccountNumber advances the per-scope lastAccount counter
// and returns the next account number for an imported (watch-only) account.
// Imported accounts share the per-scope counter with derived accounts; this
// entrypoint exists so the kvdb adapter can split the legacy
// NewAccountWatchingOnly flow into pure DB steps.
func (s *ScopedKeyManager) AllocateImportedAccountNumber(
	ns walletdb.ReadWriteBucket) (uint32, error) {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.advanceLastAccountLocked(ns)
}

// PutWatchOnlyAccountWithKeys persists a new imported (watch-only) account
// row using the caller-supplied account-level extended public key. The
// pubkey is encrypted with cryptoKeyPub before storage.
//
// Must run inside the same walletdb.Update transaction as
// AllocateImportedAccountNumber.
func (s *ScopedKeyManager) PutWatchOnlyAccountWithKeys(
	ns walletdb.ReadWriteBucket, account uint32, name string,
	pubKey *hdkeychain.ExtendedKey, masterKeyFingerprint uint32,
	addrSchema *ScopeAddrSchema) error {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	err := ValidateAccountName(name)
	if err != nil {
		return err
	}

	_, lookupErr := s.lookupAccount(ns, name)
	if lookupErr == nil {
		return managerError(
			ErrDuplicateAccount,
			"account with the same name already exists", nil,
		)
	}

	pubKeyEncrypted, err := s.rootManager.cryptoKeyPub.Encrypt(
		[]byte(pubKey.String()),
	)
	if err != nil {
		return managerError(
			ErrCrypto, "failed to encrypt public key for account",
			err,
		)
	}

	err = putWatchOnlyAccountInfo(
		ns, &s.scope, account, pubKeyEncrypted, masterKeyFingerprint,
		0, 0, name, addrSchema,
	)
	if err != nil {
		return err
	}

	_, err = s.loadAccountInfo(ns, account)

	return err
}

// advanceLastAccountLocked advances the per-scope lastAccount counter and
// returns the next account number. It is the shared body for the derived
// and imported allocators and assumes the caller already holds s.mtx and
// has performed any wallet-mode preconditions (e.g. watch-only rejection
// on the derived path).
func (s *ScopedKeyManager) advanceLastAccountLocked(
	ns walletdb.ReadWriteBucket) (uint32, error) {

	account, err := fetchLastAccount(ns, &s.scope)
	if err != nil {
		return 0, err
	}

	account++

	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return 0, err
	}

	err = putLastAccount(ns, &s.scope, account)
	if err != nil {
		return 0, err
	}

	return account, nil
}
