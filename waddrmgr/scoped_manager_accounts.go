// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
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
