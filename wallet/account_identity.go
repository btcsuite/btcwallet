// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"

	"github.com/btcsuite/btcwallet/waddrmgr"
)

var errInvalidAccountSelector = errors.New(
	"exactly one of account name or account number must be provided",
)

// AccountNumber is the BIP44 account index within a key scope. A nil pointer
// means the account has no BIP44 number, while a non-nil zero identifies
// account zero.
type AccountNumber uint32

// MasterFingerprint is the BIP32 master key fingerprint. A nil pointer means
// the fingerprint is absent, while a non-nil zero is a present-zero
// fingerprint.
type MasterFingerprint uint32

// AccountSelector identifies an account by its portable wallet semantics.
// Callers construct selectors with NewAccountSelectorByName or
// NewAccountSelectorByNumber.
type AccountSelector struct {
	keyScope      waddrmgr.KeyScope
	accountName   *string
	accountNumber *AccountNumber
}

// NewAccountSelectorByName identifies an account by its key scope and name.
func NewAccountSelectorByName(keyScope waddrmgr.KeyScope,
	accountName string) AccountSelector {

	return AccountSelector{
		keyScope:    keyScope,
		accountName: &accountName,
	}
}

// NewAccountSelectorByNumber identifies a wallet-derived account by its key
// scope and BIP44 account number.
func NewAccountSelectorByNumber(keyScope waddrmgr.KeyScope,
	accountNumber AccountNumber) AccountSelector {

	return AccountSelector{
		keyScope:      keyScope,
		accountNumber: &accountNumber,
	}
}

// validate verifies that exactly one account identity is set. Scope support
// and account existence are resolved by the consuming operation.
func (s AccountSelector) validate() error {
	if (s.accountName == nil) == (s.accountNumber == nil) {
		return errInvalidAccountSelector
	}

	return nil
}
