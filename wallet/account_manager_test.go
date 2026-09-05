// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestAccountInfoFromStore verifies SQL and modern kvdb snapshots map every
// public semantic field without exposing Store identity. The fixtures cover
// absent, present-zero, and present-nonzero optional values, including a stale
// derived fingerprint that must be replaced by the Wallet-cached value.
func TestAccountInfoFromStore(t *testing.T) {
	t.Parallel()

	var (
		storeAccountID        = uint32(91)
		storeAccountZero      = uint32(0)
		storeAccountSeven     = uint32(7)
		storeFingerprintZero  = uint32(0)
		storeFingerprintStale = uint32(0xfedcba98)
		publicAccountZero     = AccountNumber(0)
		publicAccountSeven    = AccountNumber(7)
		publicFingerprintZero = MasterFingerprint(0)
		publicFingerprintSet  = MasterFingerprint(0x01020304)
	)

	createdAt := time.Date(
		2026, time.August, 15, 9, 30, 0, 0, time.UTC,
	)
	tests := []struct {
		name              string
		walletFingerprint uint32
		store             db.AccountInfo
		want              AccountInfo
	}{
		{
			name: "sql present zero optionals",
			store: db.AccountInfo{
				AccountID:          &storeAccountID,
				AccountNumber:      &storeAccountZero,
				AccountName:        "sql derived",
				ExternalKeyCount:   2,
				InternalKeyCount:   3,
				ImportedKeyCount:   4,
				ConfirmedBalance:   btcutil.Amount(5),
				UnconfirmedBalance: btcutil.Amount(6),
				IsWatchOnly:        true,
				CreatedAt:          createdAt,
				KeyScope:           db.KeyScope{Purpose: 49, Coin: 0},
				AddrSchema: db.ScopeAddrSchema{
					ExternalAddrType: db.NestedWitnessPubKey,
					InternalAddrType: db.WitnessPubKey,
				},
				PublicKey:            []byte{7, 8, 9},
				MasterKeyFingerprint: &storeFingerprintZero,
			},
			want: AccountInfo{
				AccountNumber:      &publicAccountZero,
				AccountName:        "sql derived",
				ExternalKeyCount:   2,
				InternalKeyCount:   3,
				ImportedKeyCount:   4,
				ConfirmedBalance:   btcutil.Amount(5),
				UnconfirmedBalance: btcutil.Amount(6),
				IsWatchOnly:        true,
				CreatedAt:          createdAt,
				KeyScope:           waddrmgr.KeyScope{Purpose: 49, Coin: 0},
				AddrSchema: waddrmgr.ScopeAddrSchema{
					ExternalAddrType: waddrmgr.NestedWitnessPubKey,
					InternalAddrType: waddrmgr.WitnessPubKey,
				},
				PublicKey:            []byte{7, 8, 9},
				MasterKeyFingerprint: &publicFingerprintZero,
			},
		},
		{
			name: "modern kvdb absent optionals",
			store: db.AccountInfo{
				AccountID:          &storeAccountID,
				AccountName:        "imported",
				IsImported:         true,
				ExternalKeyCount:   10,
				InternalKeyCount:   11,
				ImportedKeyCount:   12,
				ConfirmedBalance:   btcutil.Amount(13),
				UnconfirmedBalance: btcutil.Amount(14),
				CreatedAt:          createdAt.Add(time.Hour),
				KeyScope:           db.KeyScope{Purpose: 84, Coin: 1},
				AddrSchema: db.ScopeAddrSchema{
					ExternalAddrType: db.WitnessPubKey,
					InternalAddrType: db.WitnessPubKey,
				},
			},
			want: AccountInfo{
				AccountName:        "imported",
				IsImported:         true,
				ExternalKeyCount:   10,
				InternalKeyCount:   11,
				ImportedKeyCount:   12,
				ConfirmedBalance:   btcutil.Amount(13),
				UnconfirmedBalance: btcutil.Amount(14),
				CreatedAt:          createdAt.Add(time.Hour),
				KeyScope:           waddrmgr.KeyScope{Purpose: 84, Coin: 1},
				AddrSchema: waddrmgr.ScopeAddrSchema{
					ExternalAddrType: waddrmgr.WitnessPubKey,
					InternalAddrType: waddrmgr.WitnessPubKey,
				},
			},
		},
		{
			name:              "modern kvdb ignores stale fingerprint",
			walletFingerprint: uint32(publicFingerprintSet),
			store: db.AccountInfo{
				AccountID:          &storeAccountID,
				AccountNumber:      &storeAccountSeven,
				AccountName:        "kvdb derived",
				ExternalKeyCount:   15,
				InternalKeyCount:   16,
				ImportedKeyCount:   17,
				ConfirmedBalance:   btcutil.Amount(18),
				UnconfirmedBalance: btcutil.Amount(19),
				IsWatchOnly:        true,
				CreatedAt:          createdAt.Add(2 * time.Hour),
				KeyScope:           db.KeyScope{Purpose: 86, Coin: 1},
				AddrSchema: db.ScopeAddrSchema{
					ExternalAddrType: db.TaprootPubKey,
					InternalAddrType: db.TaprootPubKey,
				},
				PublicKey:            []byte{20, 21, 22},
				MasterKeyFingerprint: &storeFingerprintStale,
			},
			want: AccountInfo{
				AccountNumber:      &publicAccountSeven,
				AccountName:        "kvdb derived",
				ExternalKeyCount:   15,
				InternalKeyCount:   16,
				ImportedKeyCount:   17,
				ConfirmedBalance:   btcutil.Amount(18),
				UnconfirmedBalance: btcutil.Amount(19),
				IsWatchOnly:        true,
				CreatedAt:          createdAt.Add(2 * time.Hour),
				KeyScope:           waddrmgr.KeyScope{Purpose: 86, Coin: 1},
				AddrSchema: waddrmgr.ScopeAddrSchema{
					ExternalAddrType: waddrmgr.TaprootPubKey,
					InternalAddrType: waddrmgr.TaprootPubKey,
				},
				PublicKey:            []byte{20, 21, 22},
				MasterKeyFingerprint: &publicFingerprintSet,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			w := &Wallet{masterFingerprint: test.walletFingerprint}
			got, err := w.accountInfoFromStore(&test.store)
			require.NoError(t, err)
			require.Equal(t, test.want, *got)
		})
	}
}

// TestAccountInfoFromStoreCopiesMutableFields verifies independently converted
// results do not alias Store-owned optionals or public-key bytes.
func TestAccountInfoFromStoreCopiesMutableFields(t *testing.T) {
	t.Parallel()

	accountNumber := uint32(2)
	fingerprint := uint32(3)
	store := db.AccountInfo{
		AccountNumber: &accountNumber,
		IsImported:    true,
		AddrSchema: db.ScopeAddrSchema{
			ExternalAddrType: db.WitnessPubKey,
			InternalAddrType: db.WitnessPubKey,
		},
		PublicKey:            []byte{4, 5, 6},
		MasterKeyFingerprint: &fingerprint,
	}
	w := &Wallet{}

	first, err := w.accountInfoFromStore(&store)
	require.NoError(t, err)
	second, err := w.accountInfoFromStore(&store)
	require.NoError(t, err)

	*first.AccountNumber = AccountNumber(20)
	*first.MasterKeyFingerprint = MasterFingerprint(30)
	first.PublicKey[0] = 40

	require.Equal(t, uint32(2), *store.AccountNumber)
	require.Equal(t, uint32(3), *store.MasterKeyFingerprint)
	require.Equal(t, []byte{4, 5, 6}, store.PublicKey)
	require.Equal(t, AccountNumber(2), *second.AccountNumber)
	require.Equal(t, MasterFingerprint(3), *second.MasterKeyFingerprint)
	require.Equal(t, []byte{4, 5, 6}, second.PublicKey)
}

// TestAccountInfoFromStoreRejectsInvalidSchema verifies a malformed Store
// schema fails conversion instead of producing a partial public result.
func TestAccountInfoFromStoreRejectsInvalidSchema(t *testing.T) {
	t.Parallel()

	store := db.AccountInfo{AddrSchema: db.ScopeAddrSchema{
		ExternalAddrType: db.Anchor,
		InternalAddrType: db.WitnessPubKey,
	}}

	got, err := (&Wallet{}).accountInfoFromStore(&store)
	require.ErrorContains(t, err, "external account address schema")
	require.Nil(t, got)
}

// stubAccountDeriveFn holds the master-key material the test wallet's
// buildAccountDeriveFn path consumes.
type stubAccountDeriveFn struct {
	encryptedSeed        []byte
	plaintextMasterKey   []byte
	masterKey            *hdkeychain.ExtendedKey
	masterKeyFingerprint uint32
}

// newStubAccountDeriveFn builds a deterministic master key + the byte
// strings the GetEncryptedHDSeed/Decrypt mocks return.
func newStubAccountDeriveFn(t *testing.T) stubAccountDeriveFn {
	t.Helper()

	masterKey, err := hdkeychain.NewMaster(fixedTestSeed(), &chainParams)
	require.NoError(t, err)

	fingerprint, err := masterKeyFingerprint(masterKey)
	require.NoError(t, err)

	plaintext := []byte(masterKey.String())
	encrypted := append([]byte("enc:"), plaintext...)

	return stubAccountDeriveFn{
		encryptedSeed:        encrypted,
		plaintextMasterKey:   plaintext,
		masterKey:            masterKey,
		masterKeyFingerprint: fingerprint,
	}
}

// expectAccountDeriveSetup wires the mock expectations the new wallet
// NewAccount path performs before invoking w.store.CreateDerivedAccount.
// Decrypt returns a fresh copy so the wallet's post-parse zero.Bytes call
// does not corrupt the shared stub across multiple invocations.
func expectAccountDeriveSetup(t *testing.T, deps *mockWalletDeps,
	stub stubAccountDeriveFn) {

	t.Helper()

	deps.vault.On("IsLocked").Return(false).Once()
	deps.store.On("GetEncryptedHDSeed", mock.Anything, uint32(0)).
		Return(append([]byte(nil), stub.encryptedSeed...), nil).Once()
	deps.vault.On("Decrypt", waddrmgr.CKTPrivate,
		mock.Anything).Return(
		append([]byte(nil), stub.plaintextMasterKey...), nil,
	).Once()
}

// expectAccountNameAvailable wires the read-only lookup that proves a public
// account mutation may proceed to its Store write.
func expectAccountNameAvailable(deps *mockWalletDeps,
	scope waddrmgr.KeyScope, name string) {

	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID:    0,
		Scope:       db.KeyScope(scope),
		Name:        &name,
		SkipBalance: true,
	}).Return((*db.AccountInfo)(nil), db.ErrAccountNotFound).Once()
}

// hardenedKey converts a plain BIP32 child index to its hardened
// counterpart by adding hdkeychain.HardenedKeyStart.
func hardenedKey(key uint32) uint32 {
	return key + hdkeychain.HardenedKeyStart
}

// deriveAcctPubKey walks the supplied hardened BIP32 path under root
// using the scope's Purpose+Coin prefix, then returns the public
// (Neuter'd) extended key of the resulting account.
func deriveAcctPubKey(t *testing.T, root *hdkeychain.ExtendedKey,
	scope waddrmgr.KeyScope, paths ...uint32) *hdkeychain.ExtendedKey {

	t.Helper()

	path := []uint32{hardenedKey(scope.Purpose), hardenedKey(scope.Coin)}
	path = append(path, paths...)

	var (
		currentKey = root
		err        error
	)
	for _, pathPart := range path {
		currentKey, err = currentKey.Derive(pathPart)
		require.NoError(t, err)
	}

	// The Neuter() method checks the version and doesn't know any
	// non-standard methods. We need to convert them to standard, neuter,
	// then convert them back with the target extended public key version.
	pubVersionBytes := make([]byte, 4)
	copy(pubVersionBytes, chainParams.HDPublicKeyID[:])

	switch {
	case strings.HasPrefix(root.String(), "uprv"):
		binary.BigEndian.PutUint32(pubVersionBytes, uint32(
			waddrmgr.HDVersionTestNetBIP0049,
		))

	case strings.HasPrefix(root.String(), "vprv"):
		binary.BigEndian.PutUint32(pubVersionBytes, uint32(
			waddrmgr.HDVersionTestNetBIP0084,
		))
	}

	currentKey, err = currentKey.CloneWithVersion(
		chainParams.HDPrivateKeyID[:],
	)
	require.NoError(t, err)
	currentKey, err = currentKey.Neuter()
	require.NoError(t, err)
	currentKey, err = currentKey.CloneWithVersion(pubVersionBytes)
	require.NoError(t, err)

	return currentKey
}

const (
	// testAccountName is a constant for the account name used in the tests.
	testAccountName = "test"
)

// TestPropertiesToAccountInfoLockedDerivedNotMisclassified verifies that a
// locked derived account is not classified as an imported account.
func TestPropertiesToAccountInfoLockedDerivedNotMisclassified(t *testing.T) {
	t.Parallel()

	const masterFingerprint uint32 = 0xDEADBEEF

	info := propertiesToAccountInfo(&waddrmgr.AccountProperties{
		AccountNumber: 7,
		AccountName:   "locked derived",
		IsWatchOnly:   true,
	}, 123, false, false, masterFingerprint)

	require.NotNil(t, info.AccountNumber)
	require.Equal(t, uint32(7), *info.AccountNumber)
	require.False(t, info.IsImported)
	require.False(t, info.IsWatchOnly)
	require.NotNil(t, info.MasterKeyFingerprint)
	require.Equal(t, masterFingerprint, *info.MasterKeyFingerprint)
}

// TestValidateExtendedPubKeyNil verifies that a nil account key is rejected
// with an error instead of panicking.
func TestValidateExtendedPubKeyNil(t *testing.T) {
	t.Parallel()

	err := validateExtendedPubKey(nil, true, &chaincfg.MainNetParams)
	require.ErrorIs(t, err, ErrInvalidAccountKey)
}

// TestPropertiesToAccountInfoImportedClassifiedAndMasked verifies that an
// imported account keeps imported-only account-info semantics.
func TestPropertiesToAccountInfoImportedClassifiedAndMasked(t *testing.T) {
	t.Parallel()

	const importedFingerprint uint32 = 12345

	info := propertiesToAccountInfo(&waddrmgr.AccountProperties{
		AccountNumber:        7,
		AccountName:          "imported",
		IsWatchOnly:          true,
		MasterKeyFingerprint: importedFingerprint,
	}, 123, true, false, 0xDEADBEEF)

	require.Nil(t, info.AccountNumber)
	require.True(t, info.IsImported)
	require.True(t, info.IsWatchOnly)
	require.Nil(t, info.MasterKeyFingerprint)
}

// TestListAccounts verifies ListAccounts returns account snapshots with the
// wallet-level derived-account master fingerprint applied.
func TestListAccounts(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	// Seed a non-zero cached master fingerprint so the derived-account
	// override path in listAccountInfos produces an observable value on
	// each entry.
	const masterFP uint32 = 0xDEADBEEF

	w.masterFingerprint = masterFP
	accountNumber := uint32(0)

	bip84 := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}

	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 0,
	}).Return([]db.AccountInfo{
		{
			AccountNumber: &accountNumber,
			AccountName:   "default",
			KeyScope:      bip84,
		},
	}, nil).Once()

	accounts, err := w.ListAccounts(t.Context())
	require.NoError(t, err)

	require.Len(t, accounts, 1)
	require.Equal(t, "default", accounts[0].AccountName)
	require.NotNil(t, accounts[0].MasterKeyFingerprint)
	require.Equal(t, MasterFingerprint(masterFP),
		*accounts[0].MasterKeyFingerprint)
}

// TestListAccountsByScope verifies the scope filter narrows the query.
func TestListAccountsByScope(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	accountNumber := uint32(0)

	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 0,
		Scope:    &dbScope,
	}).Return([]db.AccountInfo{
		{
			AccountNumber: &accountNumber,
			AccountName:   "default",
			KeyScope:      dbScope,
		},
	}, nil).Once()

	accounts, err := w.ListAccountsByScope(t.Context(), scope)
	require.NoError(t, err)
	require.Len(t, accounts, 1)
}

// TestListAccountsByScopeUnknownScope verifies that a scope the wallet does not
// know is reported as a bad request through the boundary, without leaking the
// store sentinel behind it.
func TestListAccountsByScopeUnknownScope(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet whose Store rejects an unknown scope.
	w, deps := createStartedWalletWithMocks(t)

	scope := waddrmgr.KeyScope{Purpose: 123, Coin: 456}
	dbScope := db.KeyScope(scope)
	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 0,
		Scope:    &dbScope,
	}).Return(nil, db.ErrUnknownKeyScope).Once()

	// Act: list accounts under the unknown scope.
	_, err := w.ListAccountsByScope(t.Context(), scope)

	// Assert: the public invalid-parameter identity replaces the Store error.
	require.ErrorIs(t, err, ErrInvalidParam)
	require.NotErrorIs(t, err, db.ErrUnknownKeyScope)
	deps.store.AssertExpectations(t)
}

// TestListAccountsByName verifies the name filter narrows the query.
func TestListAccountsByName(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	name := testAccountName
	dbScope := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}
	accountNumber := uint32(1)

	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 0,
		Name:     &name,
	}).Return([]db.AccountInfo{
		{
			AccountNumber: &accountNumber,
			AccountName:   testAccountName,
			KeyScope:      dbScope,
		},
	}, nil).Once()

	accounts, err := w.ListAccountsByName(t.Context(), testAccountName)
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	require.Equal(t, testAccountName, accounts[0].AccountName)
}

// TestListAccountsByNameIncludesImportedPseudoAccount verifies that the
// AccountInfo read surface keeps waddrmgr's legacy imported-address
// pseudo-account queryable by name.
func TestListAccountsByNameIncludesImportedPseudoAccount(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	name := waddrmgr.ImportedAddrAccountName

	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 0,
		Name:     &name,
	}).Return([]db.AccountInfo{
		{
			AccountName:      waddrmgr.ImportedAddrAccountName,
			IsImported:       true,
			KeyScope:         dbScope,
			ImportedKeyCount: 2,
		},
	}, nil).Once()

	accounts, err := w.ListAccountsByName(t.Context(), name)
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	require.Equal(t, waddrmgr.ImportedAddrAccountName,
		accounts[0].AccountName)
	require.True(t, accounts[0].IsImported)
	require.Nil(t, accounts[0].AccountNumber)
	require.Equal(t, uint32(2), accounts[0].ImportedKeyCount)
}

// TestListAccountsByNameNoMatch verifies the store-backed API returns an empty
// list when the account name is absent.
func TestListAccountsByNameNoMatch(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	name := "non-existent"
	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 0,
		Name:     &name,
	}).Return([]db.AccountInfo(nil), nil).Once()

	accounts, err := w.ListAccountsByName(t.Context(), name)
	require.NoError(t, err)
	require.Empty(t, accounts)
}

// TestGetAccount verifies GetAccount returns the snapshot from a single
// cache.GetAccount read, using the balance attached to that snapshot.
func TestGetAccount(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	// Seed a non-zero cached master fingerprint so the
	// derived-account override path produces an observable value.
	// The mocked store deliberately returns an absent fingerprint,
	// matching a legacy derived row with no kvdb side-bucket entry,
	// so the wallet-level fallback surfaces the value to the caller.
	const masterFP uint32 = 0xDEADBEEF

	w.masterFingerprint = masterFP

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	name := testAccountName
	accountNumber := uint32(1)

	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID: 0,
		Scope:    dbScope,
		Name:     &name,
	}).Return(&db.AccountInfo{
		AccountNumber:      &accountNumber,
		AccountName:        name,
		KeyScope:           dbScope,
		ConfirmedBalance:   100,
		UnconfirmedBalance: 23,
	}, nil).Once()

	info, err := w.GetAccount(t.Context(), scope, name)
	require.NoError(t, err)
	require.NotNil(t, info.AccountNumber)
	require.Equal(t, AccountNumber(1), *info.AccountNumber)
	require.Equal(t, name, info.AccountName)
	require.Equal(t, btcutil.Amount(100), info.ConfirmedBalance)
	require.Equal(t, btcutil.Amount(23), info.UnconfirmedBalance)
	require.NotNil(t, info.MasterKeyFingerprint)
	require.Equal(t, MasterFingerprint(masterFP),
		*info.MasterKeyFingerprint)
}

// TestGetAccountIncludesImportedPseudoAccount verifies that the AccountInfo
// read surface keeps waddrmgr's legacy imported-address pseudo-account
// queryable by name.
func TestGetAccountIncludesImportedPseudoAccount(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	name := waddrmgr.ImportedAddrAccountName

	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID: 0,
		Scope:    dbScope,
		Name:     &name,
	}).Return(&db.AccountInfo{
		AccountName:      waddrmgr.ImportedAddrAccountName,
		IsImported:       true,
		KeyScope:         dbScope,
		ImportedKeyCount: 3,
	}, nil).Once()

	account, err := w.GetAccount(
		t.Context(), scope, name,
	)
	require.NoError(t, err)
	require.Equal(t, waddrmgr.ImportedAddrAccountName, account.AccountName)
	require.True(t, account.IsImported)
	require.Nil(t, account.AccountNumber)
	require.Equal(t, uint32(3), account.ImportedKeyCount)
}

// TestNewAccount verifies NewAccount routes through
// w.store.CreateDerivedAccount.
func TestNewAccount(t *testing.T) {
	t.Parallel()

	// Arrange: an unlocked wallet with an available account name and valid
	// derivation material.
	w, deps := createStartedWalletWithMocks(t)
	stub := newStubAccountDeriveFn(t)
	w.masterFingerprint = stub.masterKeyFingerprint

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	accountNumber := uint32(1)

	expectAccountNameAvailable(deps, scope, testAccountName)
	expectAccountDeriveSetup(t, deps, stub)
	deps.store.On("CreateDerivedAccount", mock.Anything,
		db.CreateDerivedAccountParams{
			WalletID: 0,
			Scope:    dbScope,
			Name:     testAccountName,
		}, mock.Anything).Return(
		&db.AccountInfo{
			AccountNumber: &accountNumber,
			AccountName:   testAccountName,
			KeyScope:      dbScope,
		}, nil,
	).Once()

	// Act: create the next account in the scope.
	account, err := w.NewAccount(t.Context(), scope, testAccountName)

	// Assert: the account result contains the allocated number and canonical
	// master fingerprint, and every required dependency call occurred.
	require.NoError(t, err)
	require.NotNil(t, account.AccountNumber)
	require.Equal(t, AccountNumber(1), *account.AccountNumber)
	require.NotNil(t, account.MasterKeyFingerprint)
	require.Equal(t, MasterFingerprint(stub.masterKeyFingerprint),
		*account.MasterKeyFingerprint)
	deps.store.AssertExpectations(t)
	deps.vault.AssertExpectations(t)
}

// TestNewAccountMissingHDSeedDefersToStore verifies that neutered-root kvdb
// wallets can let the store fall back to scoped coin-type key derivation.
func TestNewAccountMissingHDSeedDefersToStore(t *testing.T) {
	t.Parallel()

	// Arrange: an unlocked wallet whose root seed is absent, allowing the
	// legacy Store callback to derive from its scoped key instead.
	w, deps := createStartedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	accountNumber := uint32(1)

	deps.vault.On("IsLocked").Return(false).Once()
	expectAccountNameAvailable(deps, scope, testAccountName)
	deps.store.On("GetEncryptedHDSeed", mock.Anything, uint32(0)).
		Return(nil, db.ErrSecretNotFound).Once()
	deps.store.On("CreateDerivedAccount", mock.Anything,
		db.CreateDerivedAccountParams{
			WalletID: 0,
			Scope:    dbScope,
			Name:     testAccountName,
		}, mock.MatchedBy(func(deriveFn db.AccountDerivationFunc) bool {
			if deriveFn == nil {
				return false
			}

			derived, err := deriveFn(t.Context(), dbScope, 1, false)

			return derived == nil && errors.Is(err, db.ErrSecretNotFound)
		})).Return(&db.AccountInfo{
		AccountNumber: &accountNumber,
		AccountName:   testAccountName,
		KeyScope:      dbScope,
	}, nil).Once()

	// Act: create an account through the deferred derivation path.
	account, err := w.NewAccount(t.Context(), scope, testAccountName)

	// Assert: the Store-provided result is returned and all expected admission
	// and derivation calls occurred.
	require.NoError(t, err)
	require.NotNil(t, account.AccountNumber)
	require.Equal(t, AccountNumber(1), *account.AccountNumber)
	deps.store.AssertExpectations(t)
	deps.vault.AssertExpectations(t)
}

// TestRenameAccount verifies RenameAccount routes through
// w.store.RenameAccount with the correct params and reports a missing
// account through the wallet-owned ErrAccountNotFound.
func TestRenameAccount(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet with an available replacement name.
	w, deps := createStartedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}

	expectAccountNameAvailable(deps, scope, "renamed")
	deps.store.On("RenameAccount", mock.Anything, db.RenameAccountParams{
		WalletID: 0,
		Scope:    dbScope,
		OldName:  testAccountName,
		NewName:  "renamed",
	}).Return(nil).Once()

	// Act: rename the account to the available name.
	err := w.RenameAccount(t.Context(), scope, testAccountName, "renamed")

	// Assert: the Store accepted the exact rename request.
	require.NoError(t, err)
	deps.store.AssertExpectations(t)
}

// TestAccountManagerErrTranslation verifies the mapping the AccountManager
// boundary applies: which store, legacy waddrmgr, and vault failures become
// which wallet-owned sentinel, and that no internal error identity survives
// the translation.
func TestAccountManagerErrTranslation(t *testing.T) {
	t.Parallel()

	conn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	_, err = conn.ExecContext(t.Context(), `
		CREATE TABLE accounts (
			wallet_id INTEGER, scope_id INTEGER, account_name TEXT,
			UNIQUE(wallet_id, scope_id, account_name)
		);
		INSERT INTO accounts VALUES (1, 1, 'taken');
	`)
	require.NoError(t, err)
	_, duplicateErr := conn.ExecContext(
		t.Context(), "INSERT INTO accounts VALUES (1, 1, 'taken')",
	)
	require.Error(t, duplicateErr)

	tests := []struct {
		name   string
		inject error

		// want is the sentinel the boundary must report, or nil when
		// the outcome has no stable identity in the contract.
		want error

		// passthrough marks an identity that belongs to the caller
		// rather than to a backend, so it must survive unchanged.
		passthrough bool
	}{{
		name:   "store account not found",
		inject: db.ErrAccountNotFound,
		want:   ErrAccountNotFound,
	}, {
		name:   "wrapped store account not found",
		inject: fmt.Errorf("rename account: %w", db.ErrAccountNotFound),
		want:   ErrAccountNotFound,
	}, {
		name:   "store key scope not found",
		inject: db.ErrKeyScopeNotFound,
		want:   ErrAccountNotFound,
	}, {
		name: "legacy account not found",
		inject: waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrAccountNotFound,
		},
		want: ErrAccountNotFound,
	}, {
		// The legacy backend wraps every manager error for context, so
		// the boundary must unwrap rather than type-assert.
		name: "wrapped legacy account not found",
		inject: fmt.Errorf("waddrmgr: %w", waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrAccountNotFound,
		}),
		want: ErrAccountNotFound,
	}, {
		name: "legacy scope not found",
		inject: waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrScopeNotFound,
		},
		want: ErrAccountNotFound,
	}, {
		name:   "store account already exists",
		inject: duplicateErr,
		want:   ErrAccountAlreadyExists,
	}, {
		name:   "wrapped store account already exists",
		inject: fmt.Errorf("insert account: %w", duplicateErr),
		want:   ErrAccountAlreadyExists,
	}, {
		name: "legacy duplicate account",
		inject: waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrDuplicateAccount,
		},
		want: ErrAccountAlreadyExists,
	}, {
		name: "wrapped legacy duplicate account",
		inject: fmt.Errorf("waddrmgr: %w", waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrDuplicateAccount,
		}),
		want: ErrAccountAlreadyExists,
	}, {
		name:   "watch-only import violation",
		inject: db.ErrWatchOnlyViolation,
		want:   ErrAccountOperationUnsupported,
	}, {
		name:   "spendable sql import needs private key",
		inject: db.ErrSpendableWalletNeedsAccountPrivKey,
		want:   ErrAccountOperationUnsupported,
	}, {
		name: "legacy watching only",
		inject: waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrWatchingOnly,
		},
		want: ErrAccountOperationUnsupported,
	}, {
		name:   "store account range exhausted",
		inject: db.ErrMaxAccountNumberReached,
		want:   ErrAccountDerivationExhausted,
	}, {
		name: "legacy account number too high",
		inject: waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrAccountNumTooHigh,
		},
		want: ErrAccountDerivationExhausted,
	}, {
		name: "legacy locked",
		inject: waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrLocked,
		},
		want: ErrStateForbidden,
	}, {
		name:   "store missing account name",
		inject: db.ErrMissingAccountName,
		want:   ErrInvalidParam,
	}, {
		name:   "store missing account public key",
		inject: db.ErrMissingAccountPublicKey,
		want:   ErrInvalidParam,
	}, {
		name:   "store missing field",
		inject: db.ErrMissingField,
		want:   ErrInvalidParam,
	}, {
		name:   "store invalid parameter",
		inject: db.ErrInvalidParam,
		want:   ErrInvalidParam,
	}, {
		name:   "store reserved account name",
		inject: db.ErrReservedAccountName,
		want:   ErrInvalidParam,
	}, {
		name:   "store unknown key scope",
		inject: db.ErrUnknownKeyScope,
		want:   ErrInvalidParam,
	}, {
		name:   "store invalid account selector",
		inject: db.ErrInvalidAccountQuery,
		want:   ErrInvalidParam,
	}, {
		name: "legacy invalid account",
		inject: waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrInvalidAccount,
		},
		want: ErrInvalidParam,
	}, {
		name:   "unexpected backend error",
		inject: errors.New("backend exploded"),
		want:   nil,
	}, {
		name:        "context cancelled",
		inject:      context.Canceled,
		want:        context.Canceled,
		passthrough: true,
	}, {
		name:        "context deadline exceeded",
		inject:      context.DeadlineExceeded,
		want:        context.DeadlineExceeded,
		passthrough: true,
	}, {
		name:   "wrapped context cancelled",
		inject: fmt.Errorf("store: %w", context.Canceled),
		want:   context.Canceled,
	}, {
		name:   "wrapped context deadline exceeded",
		inject: fmt.Errorf("store: %w", context.DeadlineExceeded),
		want:   context.DeadlineExceeded,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			injected := tc.inject
			w, deps := createStartedWalletWithMocks(t)
			scope := waddrmgr.KeyScopeBIP0084
			var err error
			switch {
			case errors.Is(tc.want, ErrAccountNotFound):
				deps.store.On("GetAccount", mock.Anything,
					mock.Anything).Return(
					(*db.AccountInfo)(nil), injected,
				).Once()
				_, err = w.GetAccount(t.Context(), scope, testAccountName)

			case errors.Is(tc.want, ErrInvalidParam),
				errors.Is(tc.want, ErrAccountOperationUnsupported):

				key, fp := importAccountTestKey(t, 84)
				expectAccountNameAvailable(deps, scope, testAccountName)
				deps.store.On("CreateImportedAccount", mock.Anything,
					mock.Anything).Return(
					(*db.AccountInfo)(nil), injected,
				).Once()
				_, err = w.ImportAccount(
					t.Context(), testAccountName, key, fp,
					waddrmgr.WitnessPubKey, false,
				)

			default:
				stub := newStubAccountDeriveFn(t)
				w.masterFingerprint = stub.masterKeyFingerprint
				expectAccountNameAvailable(deps, scope, testAccountName)
				expectAccountDeriveSetup(t, deps, stub)
				deps.store.On("CreateDerivedAccount", mock.Anything,
					mock.Anything, mock.Anything).Return(
					(*db.AccountInfo)(nil), injected,
				).Once()
				_, err = w.NewAccount(t.Context(), scope, testAccountName)
			}
			deps.store.AssertExpectations(t)
			deps.vault.AssertExpectations(t)

			// Assert: the named sentinel is reported, the
			// diagnostic text is preserved, and no internal
			// identity survives.
			require.Error(t, err)
			require.ErrorContains(t, err, injected.Error())

			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
			}

			if tc.passthrough {
				require.Equal(t, injected, err)
				return
			}

			for _, sentinel := range accountSentinels() {
				if !errors.Is(tc.want, sentinel) {
					require.NotErrorIs(t, err, sentinel)
				}
			}

			require.NotErrorIs(t, err, injected)

			var mErr waddrmgr.ManagerError
			require.NotErrorAs(t, err, &mErr,
				"waddrmgr identity crossed the boundary")
		})
	}
}

// TestAccountManagerErrCancellationScrubsBackendIdentity verifies caller-owned
// cancellation remains matchable without carrying an internal Store identity
// through the public boundary.
func TestAccountManagerErrCancellationScrubsBackendIdentity(t *testing.T) {
	t.Parallel()

	// Arrange: a combined failure containing both caller cancellation and a
	// Store-owned account result.
	injected := errors.Join(context.Canceled, db.ErrAccountNotFound)

	// Act: translate the combined failure at the AccountManager boundary.
	err := accountManagerErr(injected)

	// Assert: cancellation remains public while the Store identity is removed.
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, db.ErrAccountNotFound)
	require.ErrorContains(t, err, db.ErrAccountNotFound.Error())
}

// accountSentinels returns every stable error identity the AccountManager
// contract names, so a test can assert that an unnamed outcome matches none of
// them.
func accountSentinels() []error {
	return []error{
		ErrAccountNotFound, ErrAccountAlreadyExists,
		ErrAccountOperationUnsupported, ErrAccountDerivationExhausted,
		ErrInvalidParam, ErrInvalidAccountKey, ErrStateForbidden,
	}
}

// TestAccountManagerErrNil verifies the boundary leaves a successful call
// alone.
func TestAccountManagerErrNil(t *testing.T) {
	t.Parallel()

	// Arrange: a store call that succeeded.
	var storeErr error

	// Act: translate it at the AccountManager boundary.
	err := accountManagerErr(storeErr)

	// Assert: success stays success.
	require.NoError(t, err)
}

// TestNewAccountTranslatesStoreError verifies NewAccount routes its store
// failure through the boundary instead of returning it unchanged.
func TestNewAccountTranslatesStoreError(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet whose account store rejects the insert
	// with the legacy duplicate-account error.
	w, deps := createStartedWalletWithMocks(t)
	stub := newStubAccountDeriveFn(t)
	w.masterFingerprint = stub.masterKeyFingerprint

	expectAccountNameAvailable(
		deps, waddrmgr.KeyScopeBIP0084, testAccountName,
	)
	expectAccountDeriveSetup(t, deps, stub)
	deps.store.On("CreateDerivedAccount", mock.Anything, mock.Anything,
		mock.Anything).Return((*db.AccountInfo)(nil),
		waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrDuplicateAccount,
		}).Once()

	// Act: create an account whose name is already taken.
	account, err := w.NewAccount(
		t.Context(), waddrmgr.KeyScopeBIP0084, testAccountName,
	)

	// Assert: the wallet sentinel is reported, the legacy identity is not,
	// and the store saw exactly the calls set up above.
	require.Nil(t, account)
	require.ErrorIs(t, err, ErrAccountAlreadyExists)

	var mErr waddrmgr.ManagerError
	require.NotErrorAs(t, err, &mErr)

	deps.store.AssertExpectations(t)
	deps.vault.AssertExpectations(t)
}

// TestRenameAccountTranslatesStoreError verifies RenameAccount reports an
// absent source through the wallet-owned identity after name preflight passes.
func TestRenameAccountTranslatesStoreError(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet with an available replacement name whose source
	// account does not exist.
	w, deps := createStartedWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0084
	expectAccountNameAvailable(deps, scope, "renamed")
	deps.store.On("RenameAccount", mock.Anything, db.RenameAccountParams{
		WalletID: 0,
		Scope:    db.KeyScope(scope),
		OldName:  "missing",
		NewName:  "renamed",
	}).Return(db.ErrAccountNotFound).Once()

	// Act: rename the missing account.
	err := w.RenameAccount(t.Context(), scope, "missing", "renamed")

	// Assert: the wallet identity is public, the Store identity is scrubbed,
	// and both expected Store calls occurred.
	require.ErrorIs(t, err, ErrAccountNotFound)
	require.NotErrorIs(t, err, db.ErrAccountNotFound)
	deps.store.AssertExpectations(t)
}

// TestGetAccountTranslatesStoreError verifies GetAccount reports a missing
// account through the wallet-owned sentinel.
func TestGetAccountTranslatesStoreError(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet whose account read finds no row.
	w, deps := createStartedWalletWithMocks(t)
	deps.store.On("GetAccount", mock.Anything, mock.Anything).
		Return((*db.AccountInfo)(nil), db.ErrAccountNotFound).Once()

	// Act: read an account that is not in the store.
	account, err := w.GetAccount(
		t.Context(), waddrmgr.KeyScopeBIP0084, testAccountName,
	)

	// Assert: the wallet sentinel is reported and the store sentinel stops
	// at the boundary.
	require.Nil(t, account)
	require.ErrorIs(t, err, ErrAccountNotFound)
	require.NotErrorIs(t, err, db.ErrAccountNotFound)

	deps.store.AssertExpectations(t)
}

// TestListAccountsTranslatesStoreError verifies the query surface crosses the
// same boundary as the mutations.
func TestListAccountsTranslatesStoreError(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet whose account listing fails on a key scope
	// the wallet does not know.
	w, deps := createStartedWalletWithMocks(t)
	deps.store.On("ListAccounts", mock.Anything, mock.Anything).
		Return([]db.AccountInfo(nil), db.ErrUnknownKeyScope).Once()

	// Act: list every account in the wallet.
	accounts, err := w.ListAccounts(t.Context())

	// Assert: the request is reported as invalid and the store sentinel
	// stops at the boundary.
	require.Nil(t, accounts)
	require.ErrorIs(t, err, ErrInvalidParam)
	require.NotErrorIs(t, err, db.ErrUnknownKeyScope)

	deps.store.AssertExpectations(t)
}

// TestImportAccountTranslatesStoreError verifies an import refused by the
// store's watch-only invariant reports as an unsupported operation.
func TestImportAccountTranslatesStoreError(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet whose store refuses the imported account.
	w, deps := createStartedWalletWithMocks(t)
	acctPubKey, masterFP := importAccountTestKey(t, 84)

	expectAccountNameAvailable(
		deps, waddrmgr.KeyScopeBIP0084, testAccountName,
	)
	deps.store.On("CreateImportedAccount", mock.Anything, mock.Anything).
		Return((*db.AccountInfo)(nil),
			db.ErrSpendableWalletNeedsAccountPrivKey).Once()

	// Act: import an account the store will not accept.
	account, err := w.ImportAccount(
		t.Context(), testAccountName, acctPubKey, masterFP,
		waddrmgr.WitnessPubKey, false,
	)

	// Assert: the wallet sentinel is reported and the store sentinel stops
	// at the boundary.
	require.Nil(t, account)
	require.ErrorIs(t, err, ErrAccountOperationUnsupported)
	require.NotErrorIs(t, err, db.ErrSpendableWalletNeedsAccountPrivKey)

	deps.store.AssertExpectations(t)
}

// TestImportAccountInternalPreservesStoreError verifies the Manager-owned
// initial-account path does not inherit the public AccountManager translation.
func TestImportAccountInternalPreservesStoreError(t *testing.T) {
	t.Parallel()

	// Arrange: an internal import whose Store write returns a db identity.
	w, deps := createStartedWalletWithMocks(t)
	acctPubKey, masterFP := importAccountTestKey(t, 84)

	deps.store.On("CreateImportedAccount", mock.Anything, mock.Anything).
		Return((*db.AccountInfo)(nil), db.ErrWatchOnlyViolation).Once()

	// Act: import through the Manager-owned initialization path.
	account, err := w.importAccountInternal(
		t.Context(), testAccountName, acctPubKey, masterFP,
		waddrmgr.WitnessPubKey, false,
	)

	// Assert: the internal call retains the Store identity for its caller.
	require.Nil(t, account)
	require.ErrorIs(t, err, db.ErrWatchOnlyViolation)
	require.NotErrorIs(t, err, ErrAccountOperationUnsupported)
	deps.store.AssertExpectations(t)
}

// TestImportAccountTranslatesInvalidRequest verifies request-shape failures
// produced while deriving the imported account scope cross the public boundary
// as wallet-owned invalid parameters.
func TestImportAccountTranslatesInvalidRequest(t *testing.T) {
	t.Parallel()

	// Arrange: a BIP84 account key paired with an incompatible address type.
	w, deps := createStartedWalletWithMocks(t)
	acctPubKey, masterFP := importAccountTestKey(t, 84)

	// Act: import the key with a legacy pay-to-pubkey-hash address type.
	account, err := w.ImportAccount(
		t.Context(), testAccountName, acctPubKey, masterFP,
		waddrmgr.PubKeyHash, false,
	)

	// Assert: the request is invalid and no Store operation begins.
	require.Nil(t, account)
	require.ErrorIs(t, err, ErrInvalidParam)
	deps.store.AssertNotCalled(t, "GetAccount", mock.Anything, mock.Anything)
	deps.store.AssertNotCalled(t, "CreateImportedAccount", mock.Anything,
		mock.Anything)
	deps.store.AssertExpectations(t)
}

// TestImportAccountPreservesInvalidAccountKey verifies key-material validation
// retains its existing wallet-owned identity at the public boundary.
func TestImportAccountPreservesInvalidAccountKey(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet and a missing imported account key.
	w, deps := createStartedWalletWithMocks(t)

	// Act: attempt an import without key material.
	account, err := w.ImportAccount(
		t.Context(), testAccountName, nil, 0, waddrmgr.WitnessPubKey, false,
	)

	// Assert: the key-specific identity survives and no Store operation begins.
	require.Nil(t, account)
	require.ErrorIs(t, err, ErrInvalidAccountKey)
	require.NotErrorIs(t, err, ErrInvalidParam)
	deps.store.AssertNotCalled(t, "GetAccount", mock.Anything, mock.Anything)
	deps.store.AssertNotCalled(t, "CreateImportedAccount", mock.Anything,
		mock.Anything)
	deps.store.AssertExpectations(t)
}

// TestNewAccountAlreadyLockedForbidden verifies a locked Wallet rejects account
// creation before encrypted seed or Vault preparation begins.
func TestNewAccountAlreadyLockedForbidden(t *testing.T) {
	t.Parallel()

	// Arrange: a started spendable wallet whose Vault is already locked.
	w, deps := createStartedWalletWithMocks(t)
	deps.vault.On("IsLocked").Return(true).Once()

	// Act: create an account while the Wallet is already locked.
	account, err := w.NewAccount(
		t.Context(), waddrmgr.KeyScopeBIP0084, testAccountName,
	)

	// Assert: admission fails before encrypted seed, Vault, or account Store
	// preparation begins.
	require.Nil(t, account)
	require.ErrorIs(t, err, ErrStateForbidden)
	deps.store.AssertNotCalled(t, "GetEncryptedHDSeed", mock.Anything,
		mock.Anything)
	deps.vault.AssertNotCalled(t, "Decrypt", mock.Anything, mock.Anything)
	deps.store.AssertNotCalled(t, "CreateDerivedAccount", mock.Anything,
		mock.Anything, mock.Anything)
	deps.store.AssertExpectations(t)
	deps.vault.AssertExpectations(t)
}

// TestNewAccountVaultLockedForbidden verifies a Vault lock that races with
// account preparation surfaces as ErrStateForbidden without leaking the Vault
// sentinel.
func TestNewAccountVaultLockedForbidden(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet whose vault refuses to decrypt the master
	// HD private key because it is locked.
	w, deps := createStartedWalletWithMocks(t)
	stub := newStubAccountDeriveFn(t)

	deps.vault.On("IsLocked").Return(false).Once()
	expectAccountNameAvailable(
		deps, waddrmgr.KeyScopeBIP0084, testAccountName,
	)
	deps.store.On("GetEncryptedHDSeed", mock.Anything, uint32(0)).
		Return(append([]byte(nil), stub.encryptedSeed...), nil).Once()
	deps.vault.On("Decrypt", waddrmgr.CKTPrivate, mock.Anything).
		Return([]byte(nil), keyvault.ErrVaultLocked).Once()

	// Act: create an account while the vault is locked.
	account, err := w.NewAccount(
		t.Context(), waddrmgr.KeyScopeBIP0084, testAccountName,
	)

	// Assert: the lock is reported as a forbidden state, the vault
	// identity does not escape, and no account row was attempted.
	require.Nil(t, account)
	require.ErrorIs(t, err, ErrStateForbidden)
	require.NotErrorIs(t, err, keyvault.ErrVaultLocked)

	deps.store.AssertNotCalled(t, "CreateDerivedAccount", mock.Anything,
		mock.Anything, mock.Anything)
	deps.store.AssertExpectations(t)
	deps.vault.AssertExpectations(t)
}

// TestNewAccountWatchOnlyUnsupported verifies that a watch-only wallet is
// refused before the store is reached, and that the derivation callback keeps
// refusing on its own so a backend that reaches it cannot derive either.
func TestNewAccountWatchOnlyUnsupported(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet holding no master HD private key.
	w, deps := createStartedWalletWithMocks(t)
	w.isWatchOnly = true

	scope := waddrmgr.KeyScopeBIP0084
	expectAccountNameAvailable(deps, scope, testAccountName)

	// Act: create a derived account on the watch-only wallet.
	account, err := w.NewAccount(t.Context(), scope, testAccountName)

	// Assert: the refusal is reported as unsupported, the internal
	// derivation sentinel does not escape, and the store is never asked.
	require.Nil(t, account)
	require.ErrorIs(t, err, ErrAccountOperationUnsupported)
	require.NotErrorIs(t, err, errWatchOnlyAccountDerivation)

	deps.store.AssertNotCalled(t, "CreateDerivedAccount", mock.Anything,
		mock.Anything, mock.Anything)
	deps.store.AssertExpectations(t)
}

// TestNewAccountWatchOnlyPrecedence verifies that the watch-only refusal does
// not outrank the answers that come before it. The refusal short-circuits the
// store, so cancellation and request-shape rules have to be settled by
// NewAccount itself or they would be lost.
func TestNewAccountWatchOnlyPrecedence(t *testing.T) {
	t.Parallel()

	scope := waddrmgr.KeyScopeBIP0084

	t.Run("cancelled context outranks unsupported", func(t *testing.T) {
		t.Parallel()

		// Arrange: a watch-only wallet and a caller that already gave
		// up on the request.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		// Act: create an account with the cancelled context.
		account, err := w.NewAccount(ctx, scope, testAccountName)

		// Assert: the caller hears about its own cancellation rather
		// than about the wallet's mode, and nothing was attempted.
		require.Nil(t, account)
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, ErrAccountOperationUnsupported)

		deps.store.AssertExpectations(t)
	})

	t.Run("invalid name outranks unsupported", func(t *testing.T) {
		t.Parallel()

		names := []struct {
			name        string
			accountName string
		}{
			{name: "empty", accountName: ""},
			{
				name:        "reserved",
				accountName: waddrmgr.ImportedAddrAccountName,
			},
		}

		for _, tc := range names {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				// Arrange: a watch-only wallet and a name the
				// account-name rules reject.
				w, deps := createStartedWalletWithMocks(t)
				w.isWatchOnly = true

				// Act: create an account under that name.
				account, err := w.NewAccount(
					t.Context(), scope, tc.accountName,
				)

				// Assert: the malformed request is reported as
				// such, not as a mode refusal, and nothing was
				// attempted.
				require.Nil(t, account)
				require.ErrorIs(t, err, ErrInvalidParam)
				require.NotErrorIs(
					t, err, ErrAccountOperationUnsupported,
				)

				deps.store.AssertExpectations(t)
			})
		}
	})

	t.Run("occupied name outranks unsupported", func(t *testing.T) {
		t.Parallel()

		// Arrange: a watch-only wallet whose requested name already exists.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		dbScope := db.KeyScope(scope)
		accountName := testAccountName
		deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
			WalletID:    0,
			Scope:       dbScope,
			Name:        &accountName,
			SkipBalance: true,
		}).Return(&db.AccountInfo{AccountName: testAccountName}, nil).Once()

		// Act: request a watch-only account under the occupied name.
		account, err := w.NewAccount(t.Context(), scope, testAccountName)

		// Assert: the stable name conflict wins and no mutation is attempted.
		require.Nil(t, account)
		require.ErrorIs(t, err, ErrAccountAlreadyExists)
		require.NotErrorIs(t, err, ErrAccountOperationUnsupported)
		deps.store.AssertNotCalled(t, "CreateDerivedAccount", mock.Anything,
			mock.Anything, mock.Anything)
		deps.store.AssertExpectations(t)
	})
}

// TestAccountManagerOccupiedNamePrecedesMutation verifies each public account
// mutation resolves a conflicting target name before invoking its Store write.
func TestAccountManagerOccupiedNamePrecedesMutation(t *testing.T) {
	t.Parallel()

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope(scope)

	t.Run("new account", func(t *testing.T) {
		t.Parallel()

		// Arrange: an unlocked wallet whose requested name is occupied.
		w, deps := createStartedWalletWithMocks(t)
		deps.vault.On("IsLocked").Return(false).Once()

		accountName := testAccountName
		deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
			WalletID:    0,
			Scope:       dbScope,
			Name:        &accountName,
			SkipBalance: true,
		}).Return(&db.AccountInfo{AccountName: testAccountName}, nil).Once()

		// Act: create an account under the occupied name.
		account, err := w.NewAccount(t.Context(), scope, testAccountName)

		// Assert: the conflict is stable and no preparation or write begins.
		require.Nil(t, account)
		require.ErrorIs(t, err, ErrAccountAlreadyExists)
		deps.store.AssertNotCalled(t, "GetEncryptedHDSeed", mock.Anything,
			mock.Anything)
		deps.store.AssertNotCalled(t, "CreateDerivedAccount", mock.Anything,
			mock.Anything, mock.Anything)
		deps.store.AssertExpectations(t)
		deps.vault.AssertExpectations(t)
	})

	t.Run("import account", func(t *testing.T) {
		t.Parallel()

		// Arrange: a valid account key whose derived scope already contains the
		// requested name.
		w, deps := createStartedWalletWithMocks(t)
		acctPubKey, masterFP := importAccountTestKey(t, 84)
		accountName := testAccountName
		deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
			WalletID:    0,
			Scope:       dbScope,
			Name:        &accountName,
			SkipBalance: true,
		}).Return(&db.AccountInfo{AccountName: testAccountName}, nil).Once()

		// Act: import the valid key under the occupied name.
		account, err := w.ImportAccount(
			t.Context(), testAccountName, acctPubKey, masterFP,
			waddrmgr.WitnessPubKey, false,
		)

		// Assert: the conflict is returned before the Store import starts.
		require.Nil(t, account)
		require.ErrorIs(t, err, ErrAccountAlreadyExists)
		deps.store.AssertNotCalled(t, "CreateImportedAccount", mock.Anything,
			mock.Anything)
		deps.store.AssertExpectations(t)
	})

	t.Run("rename account", func(t *testing.T) {
		t.Parallel()

		// Arrange: the requested replacement name already exists in the same
		// scope.
		w, deps := createStartedWalletWithMocks(t)
		newName := "occupied"
		deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
			WalletID:    0,
			Scope:       dbScope,
			Name:        &newName,
			SkipBalance: true,
		}).Return(&db.AccountInfo{AccountName: newName}, nil).Once()

		// Act: rename an account onto the occupied name.
		err := w.RenameAccount(t.Context(), scope, testAccountName, newName)

		// Assert: the conflict is returned before the rename write starts.
		require.ErrorIs(t, err, ErrAccountAlreadyExists)
		deps.store.AssertNotCalled(t, "RenameAccount", mock.Anything,
			mock.Anything)
		deps.store.AssertExpectations(t)
	})
}

// TestRenameAccountInvalidName verifies that the locally validated name rules
// also cross the boundary as a wallet-owned error rather than as the
// waddrmgr.ManagerError that waddrmgr.ValidateAccountName returns.
func TestRenameAccountInvalidName(t *testing.T) {
	t.Parallel()

	names := []struct {
		name    string
		oldName string
		newName string
	}{
		{
			name:    "empty source before occupied target",
			oldName: "",
			newName: "occupied",
		},
		{
			name:    "empty target",
			oldName: testAccountName,
			newName: "",
		},
		{
			name:    "reserved",
			oldName: testAccountName,
			newName: waddrmgr.ImportedAddrAccountName,
		},
	}

	for _, tc := range names {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a started wallet and a target name the
			// account-name rules reject.
			w, deps := createStartedWalletWithMocks(t)

			// Act: rename an account to that target.
			err := w.RenameAccount(
				t.Context(), waddrmgr.KeyScopeBIP0084,
				tc.oldName, tc.newName,
			)

			// Assert: the rejection is a wallet-owned invalid
			// parameter, carries no legacy identity, and never
			// reached the store.
			require.ErrorIs(t, err, ErrInvalidParam)

			var mErr waddrmgr.ManagerError
			require.NotErrorAs(t, err, &mErr)

			deps.store.AssertNotCalled(t, "RenameAccount",
				mock.Anything, mock.Anything)
			deps.store.AssertExpectations(t)
		})
	}
}

// TestRenameAccountSelfRename verifies that renaming an account to the name it
// already holds is settled at the wallet boundary, where both backends agree,
// rather than being handed to a store that answers it differently — and that
// the conflict answer does not mask an account that is not there at all.
func TestRenameAccountSelfRename(t *testing.T) {
	t.Parallel()

	scope := waddrmgr.KeyScopeBIP0084

	t.Run("existing account conflicts", func(t *testing.T) {
		t.Parallel()

		// Arrange: a started wallet holding the account being renamed.
		w, deps := createStartedWalletWithMocks(t)
		name := testAccountName
		deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
			WalletID:    0,
			Scope:       db.KeyScope(scope),
			Name:        &name,
			SkipBalance: true,
		}).Return(&db.AccountInfo{
			AccountName: testAccountName,
			KeyScope:    db.KeyScope(scope),
		}, nil).Once()

		// Act: rename the account to the name it already holds.
		err := w.RenameAccount(
			t.Context(), scope, testAccountName, testAccountName,
		)

		// Assert: the name conflicts with itself and no write is
		// attempted.
		require.ErrorIs(t, err, ErrAccountAlreadyExists)

		deps.store.AssertNotCalled(t, "RenameAccount", mock.Anything,
			mock.Anything)
		deps.store.AssertExpectations(t)
	})

	t.Run("missing account is still missing", func(t *testing.T) {
		t.Parallel()

		// Arrange: a started wallet that holds no such account.
		w, deps := createStartedWalletWithMocks(t)
		deps.store.On("GetAccount", mock.Anything, mock.Anything).
			Return((*db.AccountInfo)(nil), db.ErrAccountNotFound).
			Once()

		// Act: rename an absent account to its own name.
		err := w.RenameAccount(t.Context(), scope, "missing", "missing")

		// Assert: a conflict presumes the account exists, so the
		// missing account is reported instead, and no write is
		// attempted.
		require.ErrorIs(t, err, ErrAccountNotFound)
		require.NotErrorIs(t, err, ErrAccountAlreadyExists)

		deps.store.AssertNotCalled(t, "RenameAccount", mock.Anything,
			mock.Anything)
		deps.store.AssertExpectations(t)
	})
}

// TestImportAccount verifies the normal import path routes through
// Store.CreateImportedAccount.
func TestImportAccount(t *testing.T) {
	t.Parallel()

	// Arrange: a valid account key and an available name in its derived scope.
	w, deps := createStartedWalletWithMocks(t)

	acctPubKey, masterFP := importAccountTestKey(t, 84)

	addrType := waddrmgr.WitnessPubKey
	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}

	expectAccountNameAvailable(deps, scope, testAccountName)
	deps.store.On("CreateImportedAccount", mock.Anything,
		db.CreateImportedAccountParams{
			WalletID:          0,
			Name:              testAccountName,
			Scope:             dbScope,
			MasterFingerprint: masterFP,
			PublicKey:         []byte(acctPubKey.String()),
		}).Return(&db.AccountInfo{
		AccountName: testAccountName,
		IsImported:  true,
		IsWatchOnly: true,
		KeyScope:    dbScope,
		PublicKey:   []byte(acctPubKey.String()),
	}, nil).Once()

	// Act: import the account through the public boundary.
	props, err := w.ImportAccount(
		t.Context(), testAccountName, acctPubKey,
		masterFP, addrType, false,
	)

	// Assert: the imported account is returned and all Store calls occurred.
	require.NoError(t, err)
	require.Equal(t, testAccountName, props.AccountName)
	deps.store.AssertExpectations(t)
}

// TestImportAccountDryRun verifies that dry-run imports still route through
// Store.CreateImportedAccount with the DryRun contract flag set.
func TestImportAccountDryRun(t *testing.T) {
	t.Parallel()

	// Arrange: a valid dry-run import under an available account name.
	w, deps := createStartedWalletWithMocks(t)

	acctPubKey, masterFP := importAccountTestKey(t, 84)

	addrType := waddrmgr.WitnessPubKey
	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}

	expectAccountNameAvailable(deps, scope, testAccountName)
	deps.store.On("CreateImportedAccount", mock.Anything,
		db.CreateImportedAccountParams{
			WalletID:          0,
			Name:              testAccountName,
			Scope:             dbScope,
			MasterFingerprint: masterFP,
			PublicKey:         []byte(acctPubKey.String()),
			DryRun:            true,
		}).Return(&db.AccountInfo{
		AccountName: testAccountName,
		IsImported:  true,
		IsWatchOnly: true,
		KeyScope:    dbScope,
		PublicKey:   []byte(acctPubKey.String()),
	}, nil).Once()

	// Act: validate the import without persisting it.
	props, err := w.ImportAccount(
		t.Context(), testAccountName, acctPubKey,
		masterFP, addrType, true,
	)

	// Assert: the Store receives the dry-run flag and returns the account view.
	require.NoError(t, err)
	require.Equal(t, testAccountName, props.AccountName)
	deps.store.AssertExpectations(t)
}

// TestImportAccountAddrSchema verifies that strict BIP-49 imports pass their
// per-account address-schema override through to the store.
func TestImportAccountAddrSchema(t *testing.T) {
	t.Parallel()

	// Arrange: a BIP49 account key whose derived scope requires a nested
	// witness address-schema override.
	w, deps := createStartedWalletWithMocks(t)

	acctPubKey, masterFP := importAccountTestKey(t, 49)

	addrType := waddrmgr.NestedWitnessPubKey
	scope := waddrmgr.KeyScopeBIP0049Plus
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	addrSchema := db.ScopeAddrSchema{
		ExternalAddrType: db.NestedWitnessPubKey,
		InternalAddrType: db.NestedWitnessPubKey,
	}

	expectAccountNameAvailable(deps, scope, testAccountName)
	deps.store.On("CreateImportedAccount", mock.Anything,
		db.CreateImportedAccountParams{
			WalletID:          0,
			Name:              testAccountName,
			Scope:             dbScope,
			MasterFingerprint: masterFP,
			PublicKey:         []byte(acctPubKey.String()),
			AddrSchema:        &addrSchema,
		}).Return(&db.AccountInfo{
		AccountName: testAccountName,
		IsImported:  true,
		IsWatchOnly: true,
		KeyScope:    dbScope,
		PublicKey:   []byte(acctPubKey.String()),
	}, nil).Once()

	// Act: import the account with the matching public address type.
	props, err := w.ImportAccount(
		t.Context(), testAccountName, acctPubKey,
		masterFP, addrType, false,
	)

	// Assert: the Store receives the converted schema and returns the account.
	require.NoError(t, err)
	require.Equal(t, testAccountName, props.AccountName)
	deps.store.AssertExpectations(t)
}

// TestDBScopeAddrSchemaMapsTypes verifies dbScopeAddrSchema converts a
// per-account schema override through the explicit wallet->store address-type
// mapping rather than a raw enum cast. The two enums do not share ordinals
// (waddrmgr.PubKeyHash=0 vs db.RawPubKey=0, waddrmgr.Script=1 vs
// db.PubKeyHash=1, waddrmgr.TaprootScript=7 vs db.Anchor=7), so a raw cast
// silently stores the wrong script type. P2PKH is the headline case: a
// BIP-0044 imported xpub whose external schema is PubKeyHash must be stored as
// db.PubKeyHash so NewAddress later derives a P2PKH script, not a raw pubkey.
func TestDBScopeAddrSchemaMapsTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		external waddrmgr.AddressType
		internal waddrmgr.AddressType
		want     db.ScopeAddrSchema
	}{
		{
			name:     "pubkeyhash not raw pubkey",
			external: waddrmgr.PubKeyHash,
			internal: waddrmgr.PubKeyHash,
			want: db.ScopeAddrSchema{
				ExternalAddrType: db.PubKeyHash,
				InternalAddrType: db.PubKeyHash,
			},
		},
		{
			name:     "script not pubkeyhash",
			external: waddrmgr.Script,
			internal: waddrmgr.Script,
			want: db.ScopeAddrSchema{
				ExternalAddrType: db.ScriptHash,
				InternalAddrType: db.ScriptHash,
			},
		},
		{
			name:     "raw pubkey not script hash",
			external: waddrmgr.RawPubKey,
			internal: waddrmgr.RawPubKey,
			want: db.ScopeAddrSchema{
				ExternalAddrType: db.RawPubKey,
				InternalAddrType: db.RawPubKey,
			},
		},
		{
			name:     "taproot script not anchor",
			external: waddrmgr.TaprootScript,
			internal: waddrmgr.TaprootScript,
			want: db.ScopeAddrSchema{
				ExternalAddrType: db.TaprootPubKey,
				InternalAddrType: db.TaprootPubKey,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := dbScopeAddrSchema(&waddrmgr.ScopeAddrSchema{
				ExternalAddrType: tc.external,
				InternalAddrType: tc.internal,
			})
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tc.want, *got)
		})
	}

	// A nil override stays nil so the store falls back to the scope default.
	got, err := dbScopeAddrSchema(nil)
	require.NoError(t, err)
	require.Nil(t, got)
}

// importAccountTestKey derives an account-level public key for import routing
// tests using the requested BIP purpose.
func importAccountTestKey(t *testing.T,
	purposeNum uint32) (*hdkeychain.ExtendedKey, uint32) {

	t.Helper()

	root, err := hdkeychain.NewMaster(
		[]byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		},
		&chainParams,
	)
	require.NoError(t, err)

	purpose, err := root.DeriveNonStandard( //nolint:staticcheck
		hardenedKey(purposeNum),
	)
	require.NoError(t, err)
	cointype, err := purpose.DeriveNonStandard( //nolint:staticcheck
		hardenedKey(1),
	)
	require.NoError(t, err)
	acct, err := cointype.DeriveNonStandard( //nolint:staticcheck
		hardenedKey(0),
	)
	require.NoError(t, err)

	acctPubKey, err := acct.Neuter()
	require.NoError(t, err)

	return acctPubKey, root.ParentFingerprint()
}

// TestExtractAddrFromPKScript tests that the extractAddrFromPKScript
// helper function works as expected.
func TestExtractAddrFromPKScript(t *testing.T) {
	t.Parallel()

	w := testWallet(t)

	w.cfg.ChainParams = &chaincfg.MainNetParams

	p2pkhAddr, err := address.DecodeAddress(
		"17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem", w.cfg.ChainParams,
	)
	require.NoError(t, err)

	p2shAddr, err := address.DecodeAddress(
		"347N1Thc213QqfYCz3PZkjoJpNv5b14kBd", w.cfg.ChainParams,
	)
	require.NoError(t, err)

	p2wpkhAddr, err := address.DecodeAddress(
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", w.cfg.ChainParams,
	)
	require.NoError(t, err)

	testCases := []struct {
		name   string
		script func() []byte
		addr   string
	}{
		{
			name: "p2pkh",
			script: func() []byte {
				pkScript, err := txscript.PayToAddrScript(
					p2pkhAddr,
				)
				require.NoError(t, err)

				return pkScript
			},
			addr: p2pkhAddr.String(),
		},
		{
			name: "p2sh",
			script: func() []byte {
				pkScript, err := txscript.PayToAddrScript(
					p2shAddr,
				)
				require.NoError(t, err)

				return pkScript
			},
			addr: p2shAddr.String(),
		},
		{
			name: "p2wpkh",
			script: func() []byte {
				pkScript, err := txscript.PayToAddrScript(
					p2wpkhAddr,
				)
				require.NoError(t, err)

				return pkScript
			},
			addr: p2wpkhAddr.String(),
		},
		{
			name: "op_return",
			script: func() []byte {
				pkScript, err := txscript.NewScriptBuilder().
					AddOp(txscript.OP_RETURN).
					AddData([]byte("test")).
					Script()
				require.NoError(t, err)

				return pkScript
			},
			addr: "",
		},
		{
			name:   "invalid script",
			script: func() []byte { return []byte("invalid") },
			addr:   "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			addr := extractAddrFromPKScript(
				testCase.script(), w.cfg.ChainParams,
			)
			if addr == nil {
				require.Empty(t, testCase.addr)
			} else {
				require.Equal(t, testCase.addr, addr.String())
			}
		})
	}
}
