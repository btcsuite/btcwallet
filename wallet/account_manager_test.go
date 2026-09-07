// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
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
	"github.com/btcsuite/btcwallet/wallet/internal/addresstype"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
	"github.com/jackc/pgx/v5/pgconn"
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

	deps.store.On("GetEncryptedHDSeed", mock.Anything, uint32(0)).
		Return(append([]byte(nil), stub.encryptedSeed...), nil).Once()
	deps.vault.On("Decrypt", waddrmgr.CKTPrivate,
		mock.Anything).Return(
		append([]byte(nil), stub.plaintextMasterKey...), nil,
	).Once()
}

// accountNameQuery is the read-only lookup the account mutations perform to
// learn whether a name is already taken within a key scope.
func accountNameQuery(scope waddrmgr.KeyScope,
	name string) db.GetAccountQuery {

	return db.GetAccountQuery{
		WalletID:    0,
		Scope:       db.KeyScope(scope),
		Name:        &name,
		SkipBalance: true,
	}
}

// expectAccountNameFree answers the name lookup with an absent account, which
// lets the mutation proceed.
func expectAccountNameFree(t *testing.T, deps *mockWalletDeps,
	scope waddrmgr.KeyScope, name string) {

	t.Helper()

	deps.store.On("GetAccount", mock.Anything,
		accountNameQuery(scope, name)).
		Return((*db.AccountInfo)(nil), db.ErrAccountNotFound).Once()
}

// expectAccountNameTaken answers the same lookup with an existing account.
func expectAccountNameTaken(t *testing.T, deps *mockWalletDeps,
	scope waddrmgr.KeyScope, name string) {

	t.Helper()

	deps.store.On("GetAccount", mock.Anything,
		accountNameQuery(scope, name)).
		Return(&db.AccountInfo{
			AccountName: name,
			KeyScope:    db.KeyScope(scope),
		}, nil).Once()
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

// TestListAccountsByScopeUnknownScope verifies an unexpected scope error from
// a read does not become a caller-validation error.
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

	// Assert: only the diagnostic crosses the boundary.
	require.EqualError(t, err, db.ErrUnknownKeyScope.Error())
	require.Empty(t, reportedIdentities(err))
	require.NotErrorIs(t, err, db.ErrUnknownKeyScope)
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

// TestGetAccountErrors verifies that routed lookups apply the public error
// contract to ordinary Store failures and legacy ManagerError values.
func TestGetAccountErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		storeErr error
		want     error
	}{
		{
			name:     "store error",
			storeErr: errDBMock,
		},
		{
			name:     "manager error",
			storeErr: legacyErr(waddrmgr.ErrAccountNotFound),
			want:     ErrAccountNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Start a Wallet and require the exact account query
			// to return the error identity under test once.
			w, deps := createStartedWalletWithMocks(t)
			scope := waddrmgr.KeyScopeBIP0084
			name := testAccountName
			deps.store.On(
				"GetAccount", mock.Anything, db.GetAccountQuery{
					WalletID: 0,
					Scope:    db.KeyScope(scope),
					Name:     &name,
				},
			).Return((*db.AccountInfo)(nil), test.storeErr).Once()

			// Act: Route the lookup through mainLoop and its concurrent
			// account handler.
			_, err := w.GetAccount(t.Context(), scope, name)

			// Assert: Only the wallet-owned identity reaches callers.
			if test.want != nil {
				require.ErrorIs(t, err, test.want)
			} else {
				require.EqualError(t, err, test.storeErr.Error())
				require.Empty(t, reportedIdentities(err))
			}

			require.NotErrorIs(t, err, test.storeErr)
			requireNoInternalIdentity(t, err)
		})
	}
}

// TestGetAccountLifecycle verifies pre-start and terminal calls are rejected
// before the Store can be reached.
func TestGetAccountLifecycle(t *testing.T) {
	t.Parallel()

	// Arrange: Create a fresh Wallet with no GetAccount expectation because
	// neither lifecycle state should admit Store access.
	w, _ := createTestWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0084

	// Act: Attempt a lookup before Start, then make the Wallet terminal and
	// attempt the same lookup through the retained pointer.
	_, initializedErr := w.GetAccount(t.Context(), scope, testAccountName)
	require.NoError(t, w.Stop(t.Context()))
	_, stoppedErr := w.GetAccount(t.Context(), scope, testAccountName)

	// Assert: Initialized retains the broad state error, terminal access
	// gains the specific sentinel, and neither attempt reaches Store.
	require.ErrorIs(t, initializedErr, ErrStateForbidden)
	require.NotErrorIs(t, initializedErr, ErrWalletStopped)
	require.ErrorIs(t, stoppedErr, ErrWalletStopped)
}

// TestGetAccountConcurrentDrain verifies account lookups overlap, accepted
// work delays Stop, and a late lookup is rejected before Store access.
func TestGetAccountConcurrentDrain(t *testing.T) {
	t.Parallel()

	// Arrange: Block two exact Store calls after they enter. Observing both
	// entries before release proves mainLoop launched the handlers in
	// parallel instead of executing either lookup inline.
	w, deps := createStartedWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0084
	name := testAccountName
	accountNumber := uint32(1)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID: 0,
		Scope:    db.KeyScope(scope),
		Name:     &name,
	}).Run(func(mock.Arguments) {
		entered <- struct{}{}
		<-release
	}).Return(&db.AccountInfo{
		AccountNumber: &accountNumber,
		AccountName:   name,
		KeyScope:      db.KeyScope(scope),
	}, nil).Twice()

	results := make(chan accountResp, 2)
	for range 2 {
		go func() {
			info, err := w.GetAccount(t.Context(), scope, name)
			results <- accountResp{info: info, err: err}
		}()
	}

	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("account lookups did not overlap")
		}
	}

	// Act: Begin Stop while both accepted handlers are blocked, then issue
	// a third lookup after lifetime cancellation has closed admission.
	stopResult := make(chan error, 1)
	go func() {
		stopResult <- w.Stop(t.Context())
	}()

	<-w.lifetimeCtx.Done()
	_, lateErr := w.GetAccount(t.Context(), scope, name)

	// Assert: The late call is rejected and Stop remains blocked until both
	// accepted handlers deliver ordinary results.
	require.ErrorIs(t, lateErr, ErrWalletStopped)

	select {
	case err := <-stopResult:
		t.Fatalf("Stop returned before account handlers: %v", err)
	default:
	}

	close(release)

	for range 2 {
		result := <-results
		require.NoError(t, result.err)
		require.NotNil(t, result.info)
	}

	require.NoError(t, <-stopResult)
}

// TestGetAccountCanceledCallerDrains verifies caller cancellation does not
// release an accepted lookup from the Wallet's shutdown responsibility.
func TestGetAccountCanceledCallerDrains(t *testing.T) {
	t.Parallel()

	// Arrange: Accept one lookup whose Store call ignores caller
	// cancellation until the test explicitly releases it.
	w, deps := createStartedWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0084
	name := testAccountName
	entered := make(chan struct{})
	release := make(chan struct{})
	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID: 0,
		Scope:    db.KeyScope(scope),
		Name:     &name,
	}).Run(func(mock.Arguments) {
		close(entered)
		<-release
	}).Return(&db.AccountInfo{
		AccountName: name,
		KeyScope:    db.KeyScope(scope),
	}, nil).Once()

	ctx, cancel := context.WithCancel(t.Context())
	callResult := make(chan error, 1)

	go func() {
		_, err := w.GetAccount(ctx, scope, name)
		callResult <- err
	}()

	<-entered

	// Act: Cancel only the caller, wait for its prompt return, then begin
	// Wallet shutdown while the accepted handler still owns Store work.
	cancel()
	require.ErrorIs(t, <-callResult, context.Canceled)

	stopResult := make(chan error, 1)
	go func() {
		stopResult <- w.Stop(t.Context())
	}()

	<-w.lifetimeCtx.Done()

	// Assert: Stop waits after the caller has gone until Store release lets
	// the buffered handler response complete without a stranded goroutine.
	select {
	case err := <-stopResult:
		t.Fatalf("Stop returned before canceled caller's handler: %v", err)
	default:
	}

	close(release)
	require.NoError(t, <-stopResult)
}

// TestGetAccountTranslatesStoreError verifies an account either backend cannot
// resolve is reported as the wallet-owned absence.
func TestGetAccountTranslatesStoreError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		inject error
		want   error
	}{{
		name:   "account absent",
		inject: db.ErrAccountNotFound,
		want:   ErrAccountNotFound,
	}, {
		name:   "key scope absent",
		inject: db.ErrKeyScopeNotFound,
		want:   ErrAccountNotFound,
	}, {
		name:   "legacy account absent",
		inject: wrapped(legacyErr(waddrmgr.ErrAccountNotFound)),
		want:   ErrAccountNotFound,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a started wallet whose account read fails.
			w, deps := createStartedWalletWithMocks(t)
			deps.store.On("GetAccount", mock.Anything,
				mock.Anything).
				Return((*db.AccountInfo)(nil), tc.inject).Once()

			// Act: read the account by name.
			account, err := w.GetAccount(
				t.Context(), waddrmgr.KeyScopeBIP0084,
				testAccountName,
			)

			// Assert: only the wallet-owned identity is reported.
			require.Nil(t, account)
			require.ErrorContains(t, err, tc.inject.Error())
			require.Equal(
				t, []string{tc.want.Error()}, reportedIdentities(err),
			)
			require.NotErrorIs(t, err, tc.inject)
			requireNoInternalIdentity(t, err)
		})
	}
}

// TestGetAccountKeepsCallerCancellation verifies a cancellation or deadline the
// backend reports keeps the caller-owned identity, while a store identity
// joined to it stops at the boundary.
func TestGetAccountKeepsCallerCancellation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		inject error
		want   error
	}{{
		name:   "cancelled with joined store failure",
		inject: errors.Join(context.Canceled, db.ErrAccountNotFound),
		want:   context.Canceled,
	}, {
		name:   "deadline exceeded",
		inject: context.DeadlineExceeded,
		want:   context.DeadlineExceeded,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a started wallet whose read is abandoned.
			w, deps := createStartedWalletWithMocks(t)
			deps.store.On("GetAccount", mock.Anything,
				mock.Anything).
				Return((*db.AccountInfo)(nil), tc.inject).Once()

			// Act: read the account by name.
			account, err := w.GetAccount(
				t.Context(), waddrmgr.KeyScopeBIP0084,
				testAccountName,
			)

			// Assert: the caller keeps its identity and no account
			// outcome is claimed.
			require.Nil(t, account)
			require.ErrorIs(t, err, tc.want)
			require.Empty(t, reportedIdentities(err))
			requireNoInternalIdentity(t, err)
		})
	}
}

// TestGetAccountDropsUnknownIdentity verifies a failure the contract does not
// name reaches the caller as diagnostic text alone, so no unmapped outcome can
// be matched by accident.
func TestGetAccountDropsUnknownIdentity(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet whose account read fails unexpectedly.
	w, deps := createStartedWalletWithMocks(t)
	injected := wrapped(errors.New("backend exploded"))

	deps.store.On("GetAccount", mock.Anything, mock.Anything).
		Return((*db.AccountInfo)(nil), injected).Once()

	// Act: read the account by name.
	account, err := w.GetAccount(
		t.Context(), waddrmgr.KeyScopeBIP0084, testAccountName,
	)

	// Assert: the text survives, the identity does not.
	require.Nil(t, account)
	require.EqualError(t, err, injected.Error())
	require.NotErrorIs(t, err, injected)
	require.Empty(t, reportedIdentities(err))
	requireNoInternalIdentity(t, err)
}

// TestGetAccountConversionFailure verifies a Store snapshot the wallet cannot
// convert fails the read instead of returning a partial account, and that the
// internal conversion identity does not escape either.
func TestGetAccountConversionFailure(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet whose Store reports an address schema the
	// public result cannot represent.
	w, deps := createStartedWalletWithMocks(t)
	deps.store.On("GetAccount", mock.Anything, mock.Anything).
		Return(&db.AccountInfo{
			AccountName: testAccountName,
			AddrSchema: db.ScopeAddrSchema{
				ExternalAddrType: db.Anchor,
				InternalAddrType: db.WitnessPubKey,
			},
		}, nil).Once()

	// Act: read the account by name.
	account, err := w.GetAccount(
		t.Context(), waddrmgr.KeyScopeBIP0084, testAccountName,
	)

	// Assert: the read fails with the conversion diagnostic only.
	require.Nil(t, account)
	require.ErrorContains(t, err, "external account address schema")
	require.Empty(t, reportedIdentities(err))
	require.NotErrorIs(t, err, addresstype.ErrUnknown)
	requireNoInternalIdentity(t, err)
}

// TestNewAccount verifies NewAccount routes through
// w.store.CreateDerivedAccount.
func TestNewAccount(t *testing.T) {
	t.Parallel()

	// Arrange: an unlocked wallet with an available account name and valid
	// derivation material.
	w, deps := createUnlockedWalletWithMocks(t)
	stub := newStubAccountDeriveFn(t)
	w.masterFingerprint = stub.masterKeyFingerprint

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	accountNumber := uint32(1)

	expectAccountNameFree(t, deps, scope, testAccountName)
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
}

// TestNewAccountMissingHDSeedDefersToStore verifies that neutered-root kvdb
// wallets can let the store fall back to scoped coin-type key derivation.
func TestNewAccountMissingHDSeedDefersToStore(t *testing.T) {
	t.Parallel()

	// Arrange: an unlocked wallet whose root seed is absent, allowing the
	// legacy Store callback to derive from its scoped key instead.
	w, deps := createUnlockedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	accountNumber := uint32(1)

	expectAccountNameFree(t, deps, scope, testAccountName)
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
}

// TestRenameAccount verifies RenameAccount routes through
// w.store.RenameAccount with the correct params and reports a missing
// account through the wallet-owned ErrAccountNotFound.
func TestRenameAccount(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet whose store accepts the rename.
	w, deps := createStartedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}

	expectAccountNameFree(t, deps, scope, "renamed")
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
}

// accountManagerIdentities lists every wallet-owned identity the
// AccountManager boundary may report. Assertions compare against the whole
// set so a translation that reports the wrong outcome fails on the identity it
// leaked, not only on the one it missed.
var accountManagerIdentities = []error{
	ErrAccountNotFound, ErrAccountAlreadyExists,
	ErrAccountOperationUnsupported, ErrAccountDerivationExhausted,
	ErrInvalidParam, ErrInvalidAccountKey, ErrStateForbidden,
}

// internalIdentities lists the Store, vault, and wallet-internal identities
// that must never reach a caller of a public AccountManager method.
var internalIdentities = []error{
	db.ErrAccountNotFound, db.ErrKeyScopeNotFound,
	db.ErrWatchOnlyViolation, db.ErrSpendableWalletNeedsAccountPrivKey,
	db.ErrMaxAccountNumberReached, db.ErrMissingAccountName,
	db.ErrMissingAccountPublicKey, db.ErrMissingField, db.ErrInvalidParam,
	db.ErrReservedAccountName, db.ErrInvalidAccountQuery,
	db.ErrUnknownKeyScope, keyvault.ErrVaultLocked, addresstype.ErrUnknown,
	errWatchOnlyAccountDerivation,
}

// reportedIdentities names the wallet-owned identities err reports, ordered as
// accountManagerIdentities lists them. Naming them lets a case state its whole
// expectation as one equality instead of an assertion per identity.
func reportedIdentities(err error) []string {
	var reported []string
	for _, identity := range accountManagerIdentities {
		if errors.Is(err, identity) {
			reported = append(reported, identity.Error())
		}
	}

	return reported
}

// legacyErr builds the error the legacy waddrmgr backend reports for code.
func legacyErr(code waddrmgr.ErrorCode) error {
	return waddrmgr.ManagerError{
		ErrorCode:   code,
		Description: "address manager operation failed",
	}
}

// wrapped restates err the way the legacy backend and the SQL stores do, which
// is why the boundary has to unwrap rather than type-assert.
func wrapped(err error) error {
	return fmt.Errorf("create account: %w", err)
}

// requireNoInternalIdentity asserts no Store, vault, or legacy manager
// identity survived the boundary. The diagnostic text may still name the
// source failure; only the identity has to be gone.
func requireNoInternalIdentity(t *testing.T, got error) {
	t.Helper()

	for _, internal := range internalIdentities {
		require.NotErrorIs(t, got, internal)
	}

	var mgrErr waddrmgr.ManagerError
	require.NotErrorAs(t, got, &mgrErr)
}

// TestNewAccountAdmission verifies lifecycle and context errors are
// returned before Store access.
func TestNewAccountAdmission(t *testing.T) {
	t.Parallel()

	t.Run("not started", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createTestWalletWithMocks(t)

		// Act.
		account, err := w.NewAccount(
			t.Context(), waddrmgr.KeyScopeBIP0084, testAccountName,
		)

		// Assert.
		require.Nil(t, account)
		require.ErrorIs(t, err, ErrStateForbidden)
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("cancelled", func(t *testing.T) {
		t.Parallel()

		// Arrange: cancellation must precede the watch-only refusal.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		// Act.
		account, err := w.NewAccount(
			ctx, waddrmgr.KeyScopeBIP0084, testAccountName,
		)

		// Assert.
		require.Nil(t, account)
		require.Equal(t, context.Canceled, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("deadline exceeded", func(t *testing.T) {
		t.Parallel()

		// Arrange: the deadline must precede the watch-only refusal.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithDeadline(
			t.Context(), time.Now().Add(-time.Second),
		)
		t.Cleanup(cancel)

		// Act.
		account, err := w.NewAccount(
			ctx, waddrmgr.KeyScopeBIP0084, testAccountName,
		)

		// Assert.
		require.Nil(t, account)
		require.Equal(t, context.DeadlineExceeded, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})
}

// TestListAccountsAdmission verifies lifecycle and context errors are
// returned before Store access.
func TestListAccountsAdmission(t *testing.T) {
	t.Parallel()

	t.Run("not started", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createTestWalletWithMocks(t)

		// Act.
		accounts, err := w.ListAccounts(t.Context())

		// Assert.
		require.Nil(t, accounts)
		require.ErrorIs(t, err, ErrStateForbidden)
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("cancelled", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		// Act.
		accounts, err := w.ListAccounts(ctx)

		// Assert.
		require.Nil(t, accounts)
		require.Equal(t, context.Canceled, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("deadline exceeded", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithDeadline(
			t.Context(), time.Now().Add(-time.Second),
		)
		t.Cleanup(cancel)

		// Act.
		accounts, err := w.ListAccounts(ctx)

		// Assert.
		require.Nil(t, accounts)
		require.Equal(t, context.DeadlineExceeded, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})
}

// TestListAccountsByScopeAdmission verifies lifecycle and context errors are
// returned before Store access.
func TestListAccountsByScopeAdmission(t *testing.T) {
	t.Parallel()

	t.Run("not started", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createTestWalletWithMocks(t)

		// Act.
		accounts, err := w.ListAccountsByScope(
			t.Context(), waddrmgr.KeyScopeBIP0084,
		)

		// Assert.
		require.Nil(t, accounts)
		require.ErrorIs(t, err, ErrStateForbidden)
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("cancelled", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		// Act.
		accounts, err := w.ListAccountsByScope(
			ctx, waddrmgr.KeyScopeBIP0084,
		)

		// Assert.
		require.Nil(t, accounts)
		require.Equal(t, context.Canceled, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("deadline exceeded", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithDeadline(
			t.Context(), time.Now().Add(-time.Second),
		)
		t.Cleanup(cancel)

		// Act.
		accounts, err := w.ListAccountsByScope(
			ctx, waddrmgr.KeyScopeBIP0084,
		)

		// Assert.
		require.Nil(t, accounts)
		require.Equal(t, context.DeadlineExceeded, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})
}

// TestListAccountsByNameAdmission verifies lifecycle and context errors are
// returned before Store access.
func TestListAccountsByNameAdmission(t *testing.T) {
	t.Parallel()

	t.Run("not started", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createTestWalletWithMocks(t)

		// Act.
		accounts, err := w.ListAccountsByName(t.Context(), testAccountName)

		// Assert.
		require.Nil(t, accounts)
		require.ErrorIs(t, err, ErrStateForbidden)
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("cancelled", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		// Act.
		accounts, err := w.ListAccountsByName(ctx, testAccountName)

		// Assert.
		require.Nil(t, accounts)
		require.Equal(t, context.Canceled, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("deadline exceeded", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithDeadline(
			t.Context(), time.Now().Add(-time.Second),
		)
		t.Cleanup(cancel)

		// Act.
		accounts, err := w.ListAccountsByName(ctx, testAccountName)

		// Assert.
		require.Nil(t, accounts)
		require.Equal(t, context.DeadlineExceeded, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})
}

// TestGetAccountAdmission verifies lifecycle and context errors are
// returned before Store access.
func TestGetAccountAdmission(t *testing.T) {
	t.Parallel()

	t.Run("not started", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createTestWalletWithMocks(t)

		// Act.
		account, err := w.GetAccount(
			t.Context(), waddrmgr.KeyScopeBIP0084, testAccountName,
		)

		// Assert.
		require.Nil(t, account)
		require.ErrorIs(t, err, ErrStateForbidden)
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("cancelled", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		// Act.
		account, err := w.GetAccount(
			ctx, waddrmgr.KeyScopeBIP0084, testAccountName,
		)

		// Assert.
		require.Nil(t, account)
		require.Equal(t, context.Canceled, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("deadline exceeded", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithDeadline(
			t.Context(), time.Now().Add(-time.Second),
		)
		t.Cleanup(cancel)

		// Act.
		account, err := w.GetAccount(
			ctx, waddrmgr.KeyScopeBIP0084, testAccountName,
		)

		// Assert.
		require.Nil(t, account)
		require.Equal(t, context.DeadlineExceeded, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})
}

// TestRenameAccountAdmission verifies lifecycle and context errors are
// returned before Store access.
func TestRenameAccountAdmission(t *testing.T) {
	t.Parallel()

	t.Run("not started", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createTestWalletWithMocks(t)

		// Act.
		err := w.RenameAccount(
			t.Context(), waddrmgr.KeyScopeBIP0084, testAccountName, "renamed",
		)

		// Assert.
		require.ErrorIs(t, err, ErrStateForbidden)
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("cancelled", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		// Act.
		err := w.RenameAccount(
			ctx, waddrmgr.KeyScopeBIP0084, testAccountName, "renamed",
		)

		// Assert.
		require.Equal(t, context.Canceled, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("deadline exceeded", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithDeadline(
			t.Context(), time.Now().Add(-time.Second),
		)
		t.Cleanup(cancel)

		// Act.
		err := w.RenameAccount(
			ctx, waddrmgr.KeyScopeBIP0084, testAccountName, "renamed",
		)

		// Assert.
		require.Equal(t, context.DeadlineExceeded, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})
}

// TestImportAccountAdmission verifies lifecycle and context errors are
// returned before Store access.
func TestImportAccountAdmission(t *testing.T) {
	t.Parallel()

	t.Run("not started", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createTestWalletWithMocks(t)

		acctPubKey, masterFP := importAccountTestKey(t, 84)

		// Act.
		account, err := w.ImportAccount(
			t.Context(), testAccountName, acctPubKey, masterFP,
			waddrmgr.WitnessPubKey, false,
		)

		// Assert.
		require.Nil(t, account)
		require.ErrorIs(t, err, ErrStateForbidden)
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("cancelled", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		acctPubKey, masterFP := importAccountTestKey(t, 84)

		// Act.
		account, err := w.ImportAccount(
			ctx, testAccountName, acctPubKey, masterFP,
			waddrmgr.WitnessPubKey, false,
		)

		// Assert.
		require.Nil(t, account)
		require.Equal(t, context.Canceled, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})

	t.Run("deadline exceeded", func(t *testing.T) {
		t.Parallel()

		// Arrange.
		w, deps := createStartedWalletWithMocks(t)
		w.isWatchOnly = true
		ctx, cancel := context.WithDeadline(
			t.Context(), time.Now().Add(-time.Second),
		)
		t.Cleanup(cancel)

		acctPubKey, masterFP := importAccountTestKey(t, 84)

		// Act.
		account, err := w.ImportAccount(
			ctx, testAccountName, acctPubKey, masterFP,
			waddrmgr.WitnessPubKey, false,
		)

		// Assert.
		require.Nil(t, account)
		require.Equal(t, context.DeadlineExceeded, err)
		require.Empty(t, reportedIdentities(err))
		requireNoInternalIdentity(t, err)
		deps.store.AssertNotCalled(
			t, "GetAccount", mock.Anything, mock.Anything,
		)
	})
}

// TestAccountManagerErrTranslatesIdentities verifies the classifications no
// public method exercises directly: each store or legacy waddrmgr failure is
// reported as its wallet-owned identity and as no other, with the source text
// preserved and the source identity dropped.
func TestAccountManagerErrTranslatesIdentities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		inject error
		want   error
	}{{
		name:   "legacy scope not found",
		inject: legacyErr(waddrmgr.ErrScopeNotFound),
		want:   ErrAccountNotFound,
	}, {
		name:   "watch-only import violation",
		inject: db.ErrWatchOnlyViolation,
		want:   ErrAccountOperationUnsupported,
	}, {
		name:   "legacy watching only",
		inject: legacyErr(waddrmgr.ErrWatchingOnly),
		want:   ErrAccountOperationUnsupported,
	}, {
		name:   "legacy locked",
		inject: legacyErr(waddrmgr.ErrLocked),
		want:   ErrStateForbidden,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := accountManagerErr(tc.inject)

			require.ErrorContains(t, err, tc.inject.Error())
			require.Equal(
				t, []string{tc.want.Error()}, reportedIdentities(err),
			)
			require.NotErrorIs(t, err, tc.inject)
			requireNoInternalIdentity(t, err)
		})
	}
}

// TestAccountManagerErrKeepsCallerIdentity verifies a cancellation or deadline
// belongs to the caller, so its identity survives the restatement a backend
// wraps it in. Neither is an account outcome, so they must claim no
// wallet-owned identity.
func TestAccountManagerErrKeepsCallerIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		inject error
		want   error
	}{{
		name:   "wrapped cancelled",
		inject: wrapped(context.Canceled),
		want:   context.Canceled,
	}, {
		name:   "wrapped deadline exceeded",
		inject: wrapped(context.DeadlineExceeded),
		want:   context.DeadlineExceeded,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := accountManagerErr(tc.inject)

			require.ErrorIs(t, err, tc.want)
			require.ErrorContains(t, err, tc.inject.Error())
			require.Empty(t, reportedIdentities(err))
			requireNoInternalIdentity(t, err)
		})
	}
}

// TestRenameAccountTranslatesStoreError verifies RenameAccount reports an
// absent source through the wallet-owned identity.
func TestRenameAccountTranslatesStoreError(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet whose source account does not exist.
	w, deps := createStartedWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0084

	expectAccountNameFree(t, deps, scope, "renamed")
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
	require.ErrorContains(t, err, db.ErrAccountNotFound.Error())
	require.Equal(
		t, []string{ErrAccountNotFound.Error()}, reportedIdentities(err),
	)
	require.NotErrorIs(t, err, db.ErrAccountNotFound)
	requireNoInternalIdentity(t, err)
}

// TestRenameAccountTranslatesPostgresNameConflict verifies a SQL name conflict
// returns only the wallet-owned error through the public rename method.
func TestRenameAccountTranslatesPostgresNameConflict(t *testing.T) {
	t.Parallel()

	// Arrange: the target becomes occupied after the initial name lookup.
	w, deps := createStartedWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0084
	driverErr := &pgconn.PgError{
		Code:           "23505",
		ConstraintName: "uidx_accounts_wallet_scope_account_name",
		Message:        "duplicate key value violates unique constraint",
	}
	sqlErr := dberr.NewSQLError(
		dberr.BackendPostgres, dberr.ReasonConstraint,
		driverErr.Code, driverErr,
	)
	storeErr := fmt.Errorf("rename account: %w", sqlErr)

	expectAccountNameFree(t, deps, scope, "renamed")
	deps.store.On("RenameAccount", mock.Anything, db.RenameAccountParams{
		WalletID: 0,
		Scope:    db.KeyScope(scope),
		OldName:  testAccountName,
		NewName:  "renamed",
	}).Return(storeErr).Once()

	// Act.
	err := w.RenameAccount(t.Context(), scope, testAccountName, "renamed")

	// Assert.
	require.ErrorIs(t, err, ErrAccountAlreadyExists)
	require.ErrorContains(t, err, storeErr.Error())
	require.Equal(
		t, []string{ErrAccountAlreadyExists.Error()}, reportedIdentities(err),
	)
	require.NotErrorIs(t, err, storeErr)
	require.NotErrorIs(t, err, driverErr)
	requireNoInternalIdentity(t, err)

	var leakedSQL *dberr.SQLError
	require.NotErrorAs(t, err, &leakedSQL)

	var leakedDriver *pgconn.PgError
	require.NotErrorAs(t, err, &leakedDriver)
}

// TestListAccountsTranslatesStoreError verifies unexpected Store validation
// errors do not blame the caller of an unfiltered listing.
func TestListAccountsTranslatesStoreError(t *testing.T) {
	t.Parallel()

	for _, storeErr := range []error{
		db.ErrUnknownKeyScope,
		db.ErrMissingAccountName,
		db.ErrMissingAccountPublicKey,
		db.ErrMissingField,
		db.ErrInvalidParam,
		db.ErrReservedAccountName,
		db.ErrInvalidAccountQuery,
		legacyErr(waddrmgr.ErrInvalidAccount),
	} {
		t.Run(storeErr.Error(), func(t *testing.T) {
			t.Parallel()

			// Arrange: an unfiltered query fails inside the Store.
			w, deps := createStartedWalletWithMocks(t)
			injected := fmt.Errorf("list accounts: %w", storeErr)
			deps.store.On(
				"ListAccounts", mock.Anything,
				db.ListAccountsQuery{WalletID: w.id},
			).Return([]db.AccountInfo(nil), injected).Once()

			// Act: list every account without caller-supplied filters.
			accounts, err := w.ListAccounts(t.Context())

			// Assert: preserve diagnostics without a public outcome.
			require.Nil(t, accounts)
			require.EqualError(t, err, injected.Error())
			require.Empty(t, reportedIdentities(err))
			require.NotErrorIs(t, err, storeErr)
			requireNoInternalIdentity(t, err)
		})
	}
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

	// The public name preflight belongs to the public contract only.
	deps.store.AssertNotCalled(t, "GetAccount", mock.Anything, mock.Anything)
}

// TestImportAccountInvalidRequest verifies the request shape is settled before
// any name lookup or Store work, with unusable key material keeping its own
// identity and invalid names or unsupported address types reported as invalid
// parameters.
func TestImportAccountInvalidRequest(t *testing.T) {
	t.Parallel()

	acctPubKey, masterFP := importAccountTestKey(t, 44)

	privKey, err := hdkeychain.NewMaster(fixedTestSeed(), &chainParams)
	require.NoError(t, err)

	tests := []struct {
		name     string
		acctName string
		key      *hdkeychain.ExtendedKey
		addrType waddrmgr.AddressType
		want     error
	}{{
		name:     "missing key material",
		acctName: testAccountName,
		addrType: waddrmgr.WitnessPubKey,
		want:     ErrInvalidAccountKey,
	}, {
		name:     "private key material",
		acctName: testAccountName,
		key:      privKey,
		addrType: waddrmgr.WitnessPubKey,
		want:     ErrInvalidAccountKey,
	}, {
		name:     "address type the key version cannot serve",
		acctName: testAccountName,
		key:      acctPubKey,
		addrType: waddrmgr.PubKeyHash,
		want:     ErrInvalidParam,
	}, {
		name:     "empty account name",
		acctName: "",
		key:      acctPubKey,
		addrType: waddrmgr.WitnessPubKey,
		want:     ErrInvalidParam,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a started wallet awaiting the import.
			w, deps := createStartedWalletWithMocks(t)

			// Act: import the unusable request.
			account, err := w.ImportAccount(
				t.Context(), tc.acctName, tc.key, masterFP,
				tc.addrType, false,
			)

			// Assert: the wallet-owned identity is the only one
			// reported, and neither the name lookup nor the write
			// happened.
			require.Nil(t, account)
			require.Equal(t, []string{tc.want.Error()},
				reportedIdentities(err))
			requireNoInternalIdentity(t, err)
			deps.store.AssertNotCalled(t, "GetAccount",
				mock.Anything, mock.Anything)
			deps.store.AssertNotCalled(t, "CreateImportedAccount",
				mock.Anything, mock.Anything)
		})
	}
}

// TestImportAccountInternalPreservesRequestError verifies the Manager-owned
// initialization path keeps its raw request failure, so an unusable initial
// account is not restated through the public contract.
func TestImportAccountInternalPreservesRequestError(t *testing.T) {
	t.Parallel()

	// Arrange: an internal import whose address type serves no key scope.
	w, deps := createStartedWalletWithMocks(t)
	acctPubKey, masterFP := importAccountTestKey(t, 44)

	// Act: import through the Manager-owned initialization path.
	account, err := w.importAccountInternal(
		t.Context(), testAccountName, acctPubKey, masterFP,
		waddrmgr.PubKeyHash, false,
	)

	// Assert: the raw diagnostic survives with no public identity attached.
	require.Nil(t, account)
	require.ErrorContains(t, err, "unsupported address type")
	require.Empty(t, reportedIdentities(err))
	deps.store.AssertNotCalled(t, "CreateImportedAccount", mock.Anything,
		mock.Anything)
}

// TestNewAccountVaultLockedForbidden verifies a Vault that locks after the
// wallet admitted the request surfaces as ErrStateForbidden without leaking
// the Vault sentinel.
func TestNewAccountVaultLockedForbidden(t *testing.T) {
	t.Parallel()

	// Arrange: an unlocked wallet whose vault locks again between the
	// wallet's own lock check and the master-key read.
	w, deps := createUnlockedWalletWithMocks(t)
	stub := newStubAccountDeriveFn(t)
	scope := waddrmgr.KeyScopeBIP0084

	expectAccountNameFree(t, deps, scope, testAccountName)
	deps.store.On("GetEncryptedHDSeed", mock.Anything, uint32(0)).
		Return(append([]byte(nil), stub.encryptedSeed...), nil).Once()
	deps.vault.On("Decrypt", waddrmgr.CKTPrivate, mock.Anything).
		Return([]byte(nil), keyvault.ErrVaultLocked).Once()

	// Act: create an account while the vault is locked.
	account, err := w.NewAccount(t.Context(), scope, testAccountName)

	// Assert: the lock is reported as a forbidden state, the vault
	// identity does not escape, and no account row was attempted.
	require.Nil(t, account)
	require.ErrorIs(t, err, ErrStateForbidden)
	require.NotErrorIs(t, err, keyvault.ErrVaultLocked)

	deps.store.AssertNotCalled(t, "CreateDerivedAccount", mock.Anything,
		mock.Anything, mock.Anything)
}

// TestNewAccountWatchOnlyUnsupported verifies that a watch-only wallet is
// refused before any write is attempted, as an unsupported operation rather
// than as the locked wallet it also is, since it holds no signing material.
func TestNewAccountWatchOnlyUnsupported(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet holding no master HD private key.
	w, deps := createStartedWalletWithMocks(t)
	w.isWatchOnly = true

	scope := waddrmgr.KeyScopeBIP0084

	expectAccountNameFree(t, deps, scope, testAccountName)

	// Act: create a derived account on the watch-only wallet.
	account, err := w.NewAccount(t.Context(), scope, testAccountName)

	// Assert: the refusal is reported as unsupported, the internal
	// derivation sentinel does not escape, and the only Store call was the
	// read-only name lookup.
	require.Nil(t, account)
	require.ErrorIs(t, err, ErrAccountOperationUnsupported)
	require.NotErrorIs(t, err, ErrStateForbidden)
	require.NotErrorIs(t, err, errWatchOnlyAccountDerivation)

	deps.store.AssertNotCalled(t, "CreateDerivedAccount", mock.Anything,
		mock.Anything, mock.Anything)
}

// TestNewAccountLocked verifies a spendable wallet refuses derivation while it
// is locked, before it reads or writes anything.
func TestNewAccountLocked(t *testing.T) {
	t.Parallel()

	// Arrange: a started but still locked spendable wallet.
	w, deps := createStartedWalletWithMocks(t)

	// Act: create an account while the wallet is locked.
	account, err := w.NewAccount(
		t.Context(), waddrmgr.KeyScopeBIP0084, testAccountName,
	)

	// Assert: the wallet reports its own forbidden state and performs
	// neither the name lookup nor the account write.
	require.Nil(t, account)
	require.ErrorIs(t, err, ErrStateForbidden)
	requireNoInternalIdentity(t, err)

	deps.store.AssertNotCalled(t, "GetAccount", mock.Anything, mock.Anything)
	deps.store.AssertNotCalled(t, "CreateDerivedAccount", mock.Anything,
		mock.Anything, mock.Anything)
}

// TestNewAccountOccupiedName verifies a taken name is settled by the read-only
// preflight in every wallet mode, before any derivation material is touched
// and ahead of the watch-only refusal.
func TestNewAccountOccupiedName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		watchOnly bool
	}{{
		name: "spendable unlocked wallet",
	}, {
		name:      "watch-only locked wallet",
		watchOnly: true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a wallet whose scope already holds the name.
			// A watch-only wallet holds no signing material, so it
			// stays locked and its own refusal would answer first
			// if the occupied name did not outrank it.
			w, deps := createUnlockedWalletWithMocks(t)
			if tc.watchOnly {
				w.isWatchOnly = true
				w.state.toLocked()
			}

			scope := waddrmgr.KeyScopeBIP0084
			expectAccountNameTaken(t, deps, scope, testAccountName)

			// Act: create an account under the occupied name.
			account, err := w.NewAccount(
				t.Context(), scope, testAccountName,
			)

			// Assert: the conflict is the only outcome reported, and
			// nothing was derived or written.
			require.Nil(t, account)
			require.ErrorContains(t, err, testAccountName)
			require.Equal(t,
				[]string{ErrAccountAlreadyExists.Error()},
				reportedIdentities(err))

			deps.store.AssertNotCalled(t, "GetEncryptedHDSeed",
				mock.Anything, mock.Anything)
			deps.store.AssertNotCalled(t, "CreateDerivedAccount",
				mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestNewAccountTranslatesStoreError verifies account write failures use the
// expected public identities without exposing Store errors.
func TestNewAccountTranslatesStoreError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		scope  waddrmgr.KeyScope
		inject error
		want   error
	}{{
		name:   "sql derivation range exhausted",
		scope:  waddrmgr.KeyScopeBIP0084,
		inject: db.ErrMaxAccountNumberReached,
		want:   ErrAccountDerivationExhausted,
	}, {
		name:   "kvdb derivation range exhausted",
		scope:  waddrmgr.KeyScopeBIP0084,
		inject: wrapped(legacyErr(waddrmgr.ErrAccountNumTooHigh)),
		want:   ErrAccountDerivationExhausted,
	}, {
		name:   "kvdb duplicate account",
		scope:  waddrmgr.KeyScopeBIP0084,
		inject: wrapped(legacyErr(waddrmgr.ErrDuplicateAccount)),
		want:   ErrAccountAlreadyExists,
	}, {
		name:   "scope cannot be created",
		scope:  waddrmgr.KeyScope{Purpose: 123, Coin: 456},
		inject: wrapped(db.ErrUnknownKeyScope),
		want:   ErrInvalidParam,
	}, {
		name:  "cancellation before scope validation",
		scope: waddrmgr.KeyScope{Purpose: 123, Coin: 456},
		inject: errors.Join(
			context.Canceled, db.ErrUnknownKeyScope,
		),
		want: context.Canceled,
	}, {
		name:  "deadline before scope validation",
		scope: waddrmgr.KeyScope{Purpose: 123, Coin: 456},
		inject: errors.Join(
			context.DeadlineExceeded, db.ErrUnknownKeyScope,
		),
		want: context.DeadlineExceeded,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: an unlocked wallet whose write fails.
			w, deps := createUnlockedWalletWithMocks(t)
			stub := newStubAccountDeriveFn(t)

			expectAccountNameFree(t, deps, tc.scope, testAccountName)
			expectAccountDeriveSetup(t, deps, stub)
			deps.store.On("CreateDerivedAccount", mock.Anything,
				mock.Anything, mock.Anything).
				Return((*db.AccountInfo)(nil), tc.inject).Once()

			// Act: create the next account in the scope.
			account, err := w.NewAccount(
				t.Context(), tc.scope, testAccountName,
			)

			// Assert: only the expected error identity is reported.
			require.Nil(t, account)
			require.ErrorIs(t, err, tc.want)
			require.ErrorContains(t, err, tc.inject.Error())
			require.NotErrorIs(t, err, tc.inject)
			requireNoInternalIdentity(t, err)

			for _, sentinel := range accountManagerIdentities {
				if !errors.Is(tc.want, sentinel) {
					require.NotErrorIs(t, err, sentinel)
				}
			}
		})
	}
}

// TestNewAccountInvalidName verifies name validation outranks the watch-only
// refusal, which would otherwise short-circuit the store's own name checks.
func TestNewAccountInvalidName(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"", waddrmgr.ImportedAddrAccountName} {
		t.Run("invalid name "+name, func(t *testing.T) {
			t.Parallel()

			// Arrange.
			w, _ := createStartedWalletWithMocks(t)
			w.isWatchOnly = true

			// Act.
			account, err := w.NewAccount(
				t.Context(), waddrmgr.KeyScopeBIP0084, name,
			)

			// Assert: validation outranks the watch-only refusal.
			require.Nil(t, account)
			require.ErrorIs(t, err, ErrInvalidParam)
			require.NotErrorIs(t, err, ErrAccountOperationUnsupported)
		})
	}
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
		})
	}
}

// TestRenameAccountSelfRename verifies that renaming an account to the name it
// already holds is settled at the wallet boundary, rather than being handed to
// a store that answers it differently, and that a self-rename of an account
// that does not exist reports the absence instead of the conflict.
func TestRenameAccountSelfRename(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		exists bool
		want   error
	}{{
		name:   "existing account",
		exists: true,
		want:   ErrAccountAlreadyExists,
	}, {
		name:   "missing account",
		exists: false,
		want:   ErrAccountNotFound,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a started wallet that holds the name, or not.
			w, deps := createStartedWalletWithMocks(t)
			scope := waddrmgr.KeyScopeBIP0084

			if tc.exists {
				expectAccountNameTaken(
					t, deps, scope, testAccountName,
				)
			} else {
				expectAccountNameFree(
					t, deps, scope, testAccountName,
				)
			}

			// Act: rename the account to the name it already holds.
			err := w.RenameAccount(
				t.Context(), scope, testAccountName,
				testAccountName,
			)

			// Assert: the wallet-owned outcome is the only identity
			// reported and no write is attempted.
			require.Equal(t, []string{tc.want.Error()},
				reportedIdentities(err))
			requireNoInternalIdentity(t, err)
			deps.store.AssertNotCalled(t, "RenameAccount",
				mock.Anything, mock.Anything)
		})
	}
}

// TestRenameAccountOccupiedTarget verifies the target name is resolved before
// the write, so a conflict cannot move the source account.
func TestRenameAccountOccupiedTarget(t *testing.T) {
	t.Parallel()

	// Arrange: a started wallet whose scope already holds the target name.
	w, deps := createStartedWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0084

	expectAccountNameTaken(t, deps, scope, "occupied")

	// Act: rename the source account onto the occupied name.
	err := w.RenameAccount(t.Context(), scope, testAccountName, "occupied")

	// Assert: the conflict names the target and no write is attempted.
	require.ErrorIs(t, err, ErrAccountAlreadyExists)
	require.ErrorContains(t, err, "occupied")
	deps.store.AssertNotCalled(t, "RenameAccount", mock.Anything,
		mock.Anything)
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

	expectAccountNameFree(t, deps, scope, testAccountName)
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

	expectAccountNameFree(t, deps, scope, testAccountName)
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

	expectAccountNameFree(t, deps, scope, testAccountName)
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
}

// TestImportAccountCanceledCallerKeepsKeySnapshot verifies an accepted import
// owns its extended key after caller cancellation permits the caller to zero
// the original key.
func TestImportAccountCanceledCallerKeepsKeySnapshot(t *testing.T) {
	t.Parallel()

	// Arrange: Mark a fixture Wallet started without launching mainLoop so the
	// test can receive the submitted request before any handler consumes it.
	w, _ := createTestWalletWithMocks(t)
	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	accountKey, masterFP := importAccountTestKey(t, 84)
	wantKey := accountKey.String()
	ctx, cancel := context.WithCancel(t.Context())

	result := make(chan error, 1)
	go func() {
		_, err := w.ImportAccount(
			ctx, testAccountName, accountKey, masterFP,
			waddrmgr.WitnessPubKey, false,
		)
		result <- err
	}()

	// Act: Accept the request, let the public call return on cancellation,
	// then zero the original key as its caller is now entitled to do.
	rawReq := <-w.requestChan

	cancel()

	callErr := <-result

	accountKey.Zero()

	// Assert: Cancellation reaches the caller while the accepted request owns
	// an independent key that retains the original serialized account data.
	require.ErrorIs(t, callErr, context.Canceled)

	req, ok := rawReq.(importAccountReq)
	require.True(t, ok)
	require.NotSame(t, accountKey, req.accountKey)
	require.Equal(t, wantKey, req.accountKey.String())
}

// TestImportAccountRejectsInvalidKeyBeforeAdmission verifies invalid key
// material is classified before request submission could retain it.
func TestImportAccountRejectsInvalidKeyBeforeAdmission(t *testing.T) {
	t.Parallel()

	// Arrange: Build private and malformed public key inputs that must share
	// the same pre-admission error contract without entering mainLoop.
	privateKey, err := hdkeychain.NewMaster(fixedTestSeed(), &chainParams)
	require.NoError(t, err)

	zeroedKey, err := privateKey.Neuter()
	require.NoError(t, err)
	zeroedKey.Zero()

	tests := []struct {
		name string
		key  *hdkeychain.ExtendedKey
	}{
		{
			name: "private key",
			key:  privateKey,
		},
		{
			name: "zeroed public key",
			key:  zeroedKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Mark a fixture Wallet started without a mainLoop
			// receiver, then cancel its caller context so any submission
			// attempt returns cancellation instead of the key sentinel.
			w, _ := createTestWalletWithMocks(t)
			require.NoError(t, w.state.toStarting())
			require.NoError(t, w.state.toStarted())

			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			// Act: Attempt to import the invalid key through the public API.
			_, err := w.ImportAccount(
				ctx, testAccountName, test.key, 0,
				waddrmgr.WitnessPubKey, false,
			)

			// Assert: The account-key sentinel, rather than caller
			// cancellation, proves rejection preceded request submission.
			require.ErrorIs(t, err, ErrInvalidAccountKey)
			require.NotErrorIs(t, err, context.Canceled)
		})
	}
}

// TestNewAccountRejectsStopped verifies account creation does not cross a
// terminal Wallet's request boundary.
func TestNewAccountRejectsStopped(t *testing.T) {
	t.Parallel()

	// Arrange: Stop a fresh Wallet before startup so no request handler or
	// Store expectation exists for the attempted account creation.
	w, _ := createTestWalletWithMocks(t)
	require.NoError(t, w.Stop(t.Context()))

	// Act: Attempt to create an account through the terminal Wallet.
	_, err := w.NewAccount(
		t.Context(), waddrmgr.KeyScopeBIP0084, testAccountName,
	)

	// Assert: The terminal sentinel proves the request was rejected before
	// account derivation or Store access began.
	require.ErrorIs(t, err, ErrWalletStopped)
}

// TestListAccountsRejectsStopped verifies an unfiltered account listing does
// not cross a terminal Wallet's request boundary.
func TestListAccountsRejectsStopped(t *testing.T) {
	t.Parallel()

	// Arrange: Stop a fresh Wallet with no Store expectations because the
	// list request must be rejected before reaching the cache.
	w, _ := createTestWalletWithMocks(t)
	require.NoError(t, w.Stop(t.Context()))

	// Act: Attempt to list every account through the terminal Wallet.
	_, err := w.ListAccounts(t.Context())

	// Assert: The terminal sentinel confirms no list request was admitted.
	require.ErrorIs(t, err, ErrWalletStopped)
}

// TestListAccountsByScopeRejectsStopped verifies a scope-filtered account
// listing does not cross a terminal Wallet's request boundary.
func TestListAccountsByScopeRejectsStopped(t *testing.T) {
	t.Parallel()

	// Arrange: Stop a fresh Wallet without Store expectations so any admitted
	// scope query would fail the fixture's mock verification.
	w, _ := createTestWalletWithMocks(t)
	require.NoError(t, w.Stop(t.Context()))

	// Act: Attempt the filtered listing through the terminal Wallet.
	_, err := w.ListAccountsByScope(
		t.Context(), waddrmgr.KeyScopeBIP0084,
	)

	// Assert: The terminal sentinel confirms the scope query was not admitted.
	require.ErrorIs(t, err, ErrWalletStopped)
}

// TestListAccountsByNameRejectsStopped verifies a name-filtered account
// listing does not cross a terminal Wallet's request boundary.
func TestListAccountsByNameRejectsStopped(t *testing.T) {
	t.Parallel()

	// Arrange: Stop a fresh Wallet without Store expectations so the name
	// filter cannot reach the account cache after shutdown.
	w, _ := createTestWalletWithMocks(t)
	require.NoError(t, w.Stop(t.Context()))

	// Act: Attempt the name-filtered listing through the terminal Wallet.
	_, err := w.ListAccountsByName(t.Context(), testAccountName)

	// Assert: The terminal sentinel confirms the name query was not admitted.
	require.ErrorIs(t, err, ErrWalletStopped)
}

// TestRenameAccountRejectsStopped verifies an account rename does not cross a
// terminal Wallet's request boundary.
func TestRenameAccountRejectsStopped(t *testing.T) {
	t.Parallel()

	// Arrange: Stop a fresh Wallet without Store expectations so validation
	// and persistence remain behind the terminal request boundary.
	w, _ := createTestWalletWithMocks(t)
	require.NoError(t, w.Stop(t.Context()))

	// Act: Attempt to rename an account through the terminal Wallet.
	err := w.RenameAccount(
		t.Context(), waddrmgr.KeyScopeBIP0084, testAccountName, "renamed",
	)

	// Assert: The terminal sentinel confirms validation and Store mutation
	// were both bypassed.
	require.ErrorIs(t, err, ErrWalletStopped)
}

// TestImportAccountRejectsStopped verifies an account import does not cross a
// terminal Wallet's request boundary.
func TestImportAccountRejectsStopped(t *testing.T) {
	t.Parallel()

	// Arrange: Stop a fresh Wallet and intentionally provide no key or Store
	// expectation so lifecycle rejection must precede argument validation.
	w, _ := createTestWalletWithMocks(t)
	require.NoError(t, w.Stop(t.Context()))

	// Act: Attempt to import the invalid key through the terminal Wallet.
	_, err := w.ImportAccount(
		t.Context(), testAccountName, nil, 0,
		waddrmgr.WitnessPubKey, false,
	)

	// Assert: The terminal sentinel proves shutdown wins before key validation
	// or Store access.
	require.ErrorIs(t, err, ErrWalletStopped)
}

// TestImportAccountOccupiedName verifies the name is resolved in the scope the
// key version selects, before the account is written.
func TestImportAccountOccupiedName(t *testing.T) {
	t.Parallel()

	// Arrange: a valid key whose derived scope already holds the name.
	w, deps := createStartedWalletWithMocks(t)
	acctPubKey, masterFP := importAccountTestKey(t, 84)

	expectAccountNameTaken(
		t, deps, waddrmgr.KeyScopeBIP0084, testAccountName,
	)

	// Act: import the account under the occupied name.
	account, err := w.ImportAccount(
		t.Context(), testAccountName, acctPubKey, masterFP,
		waddrmgr.WitnessPubKey, false,
	)

	// Assert: the conflict is reported and nothing is written.
	require.Nil(t, account)
	require.ErrorIs(t, err, ErrAccountAlreadyExists)
	require.ErrorContains(t, err, testAccountName)
	deps.store.AssertNotCalled(t, "CreateImportedAccount", mock.Anything,
		mock.Anything)
}

// TestImportAccountSpendableWalletUnsupported verifies a store that demands
// account signing material from a spendable wallet, as ADR 0012 requires,
// reports an unsupported operation without leaking its own sentinel.
func TestImportAccountSpendableWalletUnsupported(t *testing.T) {
	t.Parallel()

	// Arrange: a spendable wallet importing XPub-only material.
	w, deps := createStartedWalletWithMocks(t)
	acctPubKey, masterFP := importAccountTestKey(t, 84)

	expectAccountNameFree(
		t, deps, waddrmgr.KeyScopeBIP0084, testAccountName,
	)
	deps.store.On("CreateImportedAccount", mock.Anything, mock.Anything).
		Return((*db.AccountInfo)(nil),
			db.ErrSpendableWalletNeedsAccountPrivKey).Once()

	// Act: import the watch-only account key.
	account, err := w.ImportAccount(
		t.Context(), testAccountName, acctPubKey, masterFP,
		waddrmgr.WitnessPubKey, false,
	)

	// Assert: the refusal is reported as unsupported by this wallet.
	require.Nil(t, account)
	require.ErrorContains(
		t, err, db.ErrSpendableWalletNeedsAccountPrivKey.Error(),
	)
	require.Equal(
		t, []string{ErrAccountOperationUnsupported.Error()},
		reportedIdentities(err),
	)
	require.NotErrorIs(t, err, db.ErrSpendableWalletNeedsAccountPrivKey)
	requireNoInternalIdentity(t, err)
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
