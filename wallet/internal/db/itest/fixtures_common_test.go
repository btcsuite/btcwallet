//go:build itest

package itest

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// CreateWalletParamsFixture creates test parameters for wallet creation.
func CreateWalletParamsFixture(name string) db.CreateWalletParams {
	return db.CreateWalletParams{
		Name:                     name,
		IsImported:               false,
		ManagerVersion:           1,
		IsWatchOnly:              false,
		EncryptedMasterPrivKey:   RandomBytes(32),
		MasterPubKey:             RandomBytes(32),
		MasterKeyPrivParams:      RandomBytes(16),
		EncryptedCryptoPrivKey:   RandomBytes(32),
		EncryptedCryptoScriptKey: RandomBytes(32),
	}
}

// CreateImportedWalletParams creates test parameters for an imported wallet.
func CreateImportedWalletParams(name string) db.CreateWalletParams {
	params := CreateWalletParamsFixture(name)
	params.IsImported = true

	return params
}

// CreateWatchOnlyWalletParams creates test parameters for a watch-only wallet.
func CreateWatchOnlyWalletParams(name string) db.CreateWalletParams {
	params := CreateWalletParamsFixture(name)
	params.IsWatchOnly = true
	params.EncryptedMasterPrivKey = nil
	params.MasterKeyPrivParams = nil
	params.EncryptedCryptoPrivKey = nil
	params.EncryptedCryptoScriptKey = nil

	return params
}

// RandomBytes generates random bytes for test data.
func RandomBytes(n int) []byte {
	b := make([]byte, n)

	_, err := rand.Read(b)
	if err != nil {
		// This should never happen.
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}

	return b
}

// RandomHash generates a random chainhash.Hash for testing.
func RandomHash() chainhash.Hash {
	var h chainhash.Hash

	_, err := rand.Read(h[:])
	if err != nil {
		// This should never happen.
		panic(fmt.Sprintf("failed to generate random hash: %v", err))
	}

	return h
}

// NewBlockFixture creates a new Block with the provided height, current time,
// and random hash.
func NewBlockFixture(height uint32) db.Block {
	hash := RandomHash()
	timestamp := time.Now().UTC()

	return db.Block{
		Hash:      hash,
		Height:    height,
		Timestamp: timestamp,
	}
}

// AccountTestCase defines a reusable account fixture for tests. It provides
// a unified way to describe both derived and imported accounts across all
// standard key scopes.
type AccountTestCase struct {
	// Name is the account name to use in tests.
	Name string

	// Scope is the key scope for the account.
	Scope db.KeyScope

	// Origin indicates whether the account is derived or imported.
	Origin db.AccountOrigin

	// IsWatchOnly indicates whether the account is watch-only (has no private
	// key material).
	IsWatchOnly bool
}

// DerivedAccountCases contains derived account fixtures across all standard
// key scopes, with multiple accounts per scope.
var DerivedAccountCases = []AccountTestCase{
	{
		Name:   "derived-bip84-default",
		Scope:  db.KeyScopeBIP0084,
		Origin: db.DerivedAccount,
	},
	{
		Name:   "derived-bip84-savings",
		Scope:  db.KeyScopeBIP0084,
		Origin: db.DerivedAccount,
	},
	{
		Name:   "derived-bip86-default",
		Scope:  db.KeyScopeBIP0086,
		Origin: db.DerivedAccount,
	},
	{
		Name:   "derived-bip86-savings",
		Scope:  db.KeyScopeBIP0086,
		Origin: db.DerivedAccount,
	},
	{
		Name:   "derived-bip44-default",
		Scope:  db.KeyScopeBIP0044,
		Origin: db.DerivedAccount,
	},
	{
		Name:   "derived-bip44-savings",
		Scope:  db.KeyScopeBIP0044,
		Origin: db.DerivedAccount,
	},
	{
		Name:   "derived-bip49-default",
		Scope:  db.KeyScopeBIP0049Plus,
		Origin: db.DerivedAccount,
	},
	{
		Name:   "derived-bip49-savings",
		Scope:  db.KeyScopeBIP0049Plus,
		Origin: db.DerivedAccount,
	},
}

// ImportedAccountCases contains imported account fixtures (with private keys)
// across multiple key scopes.
var ImportedAccountCases = []AccountTestCase{
	{
		Name:   "imported-bip84-main",
		Scope:  db.KeyScopeBIP0084,
		Origin: db.ImportedAccount,
	},
	{
		Name:   "imported-bip84-hardware",
		Scope:  db.KeyScopeBIP0084,
		Origin: db.ImportedAccount,
	},
	{
		Name:   "imported-bip86-main",
		Scope:  db.KeyScopeBIP0086,
		Origin: db.ImportedAccount,
	},
	{
		Name:   "imported-bip86-hardware",
		Scope:  db.KeyScopeBIP0086,
		Origin: db.ImportedAccount,
	},
	{
		Name:   "imported-bip44-legacy",
		Scope:  db.KeyScopeBIP0044,
		Origin: db.ImportedAccount,
	},
}

// PublicOnlyImportedAccountCases contains imported account fixtures without
// private keys across multiple key scopes. These fixtures exercise public-only
// (xpub) account creation without accidentally generating private key material.
var PublicOnlyImportedAccountCases = []AccountTestCase{
	{
		Name:        "xpub-bip84-cold",
		Scope:       db.KeyScopeBIP0084,
		Origin:      db.ImportedAccount,
		IsWatchOnly: true,
	},
	{
		Name:        "xpub-bip84-monitor",
		Scope:       db.KeyScopeBIP0084,
		Origin:      db.ImportedAccount,
		IsWatchOnly: true,
	},
	{
		Name:        "xpub-bip86-cold",
		Scope:       db.KeyScopeBIP0086,
		Origin:      db.ImportedAccount,
		IsWatchOnly: true,
	},
	{
		Name:        "xpub-bip86-monitor",
		Scope:       db.KeyScopeBIP0086,
		Origin:      db.ImportedAccount,
		IsWatchOnly: true,
	},
}

// AllAccountCases combines all account test cases (derived, imported with
// private keys, and public-only imported) into a single slice.
var AllAccountCases = append(
	append(DerivedAccountCases, ImportedAccountCases...),
	PublicOnlyImportedAccountCases...,
)

// AllImportedAccountCases combines imported account cases (with and without
// private keys).
var AllImportedAccountCases = append(
	ImportedAccountCases, PublicOnlyImportedAccountCases...,
)

// DerivedParams converts the test case to CreateDerivedAccountParams.
func (tc AccountTestCase) DerivedParams(
	walletID uint32) db.CreateDerivedAccountParams {

	return db.CreateDerivedAccountParams{
		WalletID: walletID,
		Scope:    tc.Scope,
		Name:     tc.Name,
	}
}

// SpendableDeriveFn returns a fake AccountDerivationFunc that synthesizes a
// minimal DerivedAccountData for spendable-wallet test cases. It mirrors what
// the wallet manager will pass in production: a public key, encrypted private
// key, and a deterministic master-key fingerprint.
func SpendableDeriveFn() db.AccountDerivationFunc {
	return func(_ context.Context, _ db.KeyScope, _ uint32,
		walletIsWatchOnly bool) (*db.DerivedAccountData, error) {

		data := &db.DerivedAccountData{
			PublicKey:            RandomBytes(33),
			MasterKeyFingerprint: 0xC0DEC0DE,
		}
		if !walletIsWatchOnly {
			data.EncryptedPrivateKey = RandomBytes(48)
		}

		return data, nil
	}
}

// ImportedParams converts the test case to CreateImportedAccountParams.
// IsWatchOnly controls whether EncryptedPrivateKey is populated.
func (tc AccountTestCase) ImportedParams(
	walletID uint32) db.CreateImportedAccountParams {

	params := db.CreateImportedAccountParams{
		WalletID:          walletID,
		Name:              tc.Name,
		Scope:             tc.Scope,
		MasterFingerprint: 12345,
		PublicKey:         RandomBytes(32),
	}

	if !tc.IsWatchOnly {
		params.EncryptedPrivateKey = RandomBytes(32)
	}

	return params
}

// FilterAccountsByScope returns a slice of AccountTestCases filtered by the
// given key scope.
func FilterAccountsByScope(scope db.KeyScope) []AccountTestCase {
	var filtered []AccountTestCase

	for _, tc := range AllAccountCases {
		if tc.Scope == scope {
			filtered = append(filtered, tc)
		}
	}

	return filtered
}
