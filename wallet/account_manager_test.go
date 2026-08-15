// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"encoding/binary"
	"errors"
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

// TestListAccountsByScopeUnknownScope verifies backend errors are propagated.
func TestListAccountsByScopeUnknownScope(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	scope := waddrmgr.KeyScope{Purpose: 123, Coin: 456}
	dbScope := db.KeyScope(scope)
	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 0,
		Scope:    &dbScope,
	}).Return(nil, db.ErrUnknownKeyScope).Once()

	_, err := w.ListAccountsByScope(t.Context(), scope)
	require.ErrorIs(t, err, db.ErrUnknownKeyScope)
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

	w, deps := createStartedWalletWithMocks(t)
	stub := newStubAccountDeriveFn(t)
	w.masterFingerprint = stub.masterKeyFingerprint

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	accountNumber := uint32(1)

	// Success path.
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

	account, err := w.NewAccount(t.Context(), scope, testAccountName)
	require.NoError(t, err)
	require.NotNil(t, account.AccountNumber)
	require.Equal(t, AccountNumber(1), *account.AccountNumber)
	require.NotNil(t, account.MasterKeyFingerprint)
	require.Equal(t, MasterFingerprint(stub.masterKeyFingerprint),
		*account.MasterKeyFingerprint)

	// Duplicate-name path.
	expectAccountDeriveSetup(t, deps, stub)
	deps.store.On("CreateDerivedAccount", mock.Anything, mock.Anything,
		mock.Anything).Return((*db.AccountInfo)(nil),
		waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrDuplicateAccount,
		}).Once()

	_, err = w.NewAccount(t.Context(), scope, testAccountName)
	require.Error(t, err)
	require.True(t,
		waddrmgr.IsError(err, waddrmgr.ErrDuplicateAccount),
	)
}

// TestNewAccountMissingHDSeedDefersToStore verifies that neutered-root kvdb
// wallets can let the store fall back to scoped coin-type key derivation.
func TestNewAccountMissingHDSeedDefersToStore(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	accountNumber := uint32(1)

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

	account, err := w.NewAccount(t.Context(), scope, testAccountName)
	require.NoError(t, err)
	require.NotNil(t, account.AccountNumber)
	require.Equal(t, AccountNumber(1), *account.AccountNumber)
}

// TestRenameAccount verifies RenameAccount routes through
// w.store.RenameAccount with the correct params and preserves
// db.ErrAccountNotFound passthrough.
func TestRenameAccount(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}

	deps.store.On("RenameAccount", mock.Anything, db.RenameAccountParams{
		WalletID: 0,
		Scope:    dbScope,
		OldName:  testAccountName,
		NewName:  "renamed",
	}).Return(nil).Once()

	err := w.RenameAccount(t.Context(), scope, testAccountName, "renamed")
	require.NoError(t, err)

	// Invalid new name path (validated locally before the store call).
	err = w.RenameAccount(t.Context(), scope, testAccountName, "")
	require.Error(t, err)

	// Not-found path.
	deps.store.On("RenameAccount", mock.Anything, mock.Anything).Return(
		db.ErrAccountNotFound,
	).Once()

	err = w.RenameAccount(t.Context(), scope, "missing", "x")
	require.ErrorIs(t, err, db.ErrAccountNotFound)
}

// TestImportAccount verifies the normal import path routes through
// Store.CreateImportedAccount.
func TestImportAccount(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	acctPubKey, masterFP := importAccountTestKey(t, 84)

	addrType := waddrmgr.WitnessPubKey
	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}

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

	props, err := w.ImportAccount(
		t.Context(), testAccountName, acctPubKey,
		masterFP, addrType, false,
	)
	require.NoError(t, err)
	require.Equal(t, testAccountName, props.AccountName)
}

// TestImportAccountDryRun verifies that dry-run imports still route through
// Store.CreateImportedAccount with the DryRun contract flag set.
func TestImportAccountDryRun(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	acctPubKey, masterFP := importAccountTestKey(t, 84)

	addrType := waddrmgr.WitnessPubKey
	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}

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

	props, err := w.ImportAccount(
		t.Context(), testAccountName, acctPubKey,
		masterFP, addrType, true,
	)
	require.NoError(t, err)
	require.Equal(t, testAccountName, props.AccountName)
}

// TestImportAccountAddrSchema verifies that strict BIP-49 imports pass their
// per-account address-schema override through to the store.
func TestImportAccountAddrSchema(t *testing.T) {
	t.Parallel()

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

	props, err := w.ImportAccount(
		t.Context(), testAccountName, acctPubKey,
		masterFP, addrType, false,
	)
	require.NoError(t, err)
	require.Equal(t, testAccountName, props.AccountName)
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
