// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// AccountInfo describes the public, wallet-owned snapshot of an account. Its
// pointer and byte-slice fields are owned by the result and may be mutated by
// the caller without affecting Store state or another result.
type AccountInfo struct {
	// AccountNumber is the BIP44 account index used for a derived account. A
	// nil pointer means the account has no BIP44 number, while a non-nil zero
	// identifies account zero.
	AccountNumber *AccountNumber

	// AccountName is the human-readable name of the account.
	AccountName string

	// IsImported reports whether the account was imported rather than
	// derived from the wallet seed.
	IsImported bool

	// ExternalKeyCount is the number of external keys derived for the
	// account.
	ExternalKeyCount uint32

	// InternalKeyCount is the number of internal change keys derived for the
	// account.
	InternalKeyCount uint32

	// ImportedKeyCount is the number of individually imported keys reported
	// for legacy account stores.
	ImportedKeyCount uint32

	// ConfirmedBalance is the account balance from confirmed transactions.
	ConfirmedBalance btcutil.Amount

	// UnconfirmedBalance is the account balance from unconfirmed
	// transactions.
	UnconfirmedBalance btcutil.Amount

	// IsWatchOnly reports the wallet-level watch-only state associated with
	// the account snapshot.
	IsWatchOnly bool

	// CreatedAt is the time the account was created. A zero time means the
	// backing Store does not know the creation time.
	CreatedAt time.Time

	// KeyScope identifies the account's BIP43 purpose and BIP44 coin type.
	KeyScope waddrmgr.KeyScope

	// AddrSchema is the effective external and internal address schema for
	// the account.
	AddrSchema waddrmgr.ScopeAddrSchema

	// PublicKey is the serialized account-level extended public key when the
	// wallet knows that public material.
	PublicKey []byte

	// MasterKeyFingerprint is the BIP32 root fingerprint associated with the
	// account public key. A nil pointer means it is absent, while a non-nil
	// zero is a present-zero fingerprint.
	MasterKeyFingerprint *MasterFingerprint
}
