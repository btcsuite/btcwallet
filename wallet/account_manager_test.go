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
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
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

	// Arrange: Cover scalar copying once, then isolate absent optionals and
	// the wallet fingerprint override without repeating scalar permutations.
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

	// The optional-only fixtures leave Store address types at RawPubKey.
	rawSchema := waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.RawPubKey,
		InternalAddrType: waddrmgr.RawPubKey,
	}
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
				KeyScope: db.KeyScope{
					Purpose: 49,
					Coin:    0,
				},
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
				KeyScope: waddrmgr.KeyScope{
					Purpose: 49,
					Coin:    0,
				},
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
				IsImported: true,
			},
			want: AccountInfo{
				IsImported: true,
				AddrSchema: rawSchema,
			},
		},
		{
			name:              "modern kvdb ignores stale fingerprint",
			walletFingerprint: uint32(publicFingerprintSet),
			store: db.AccountInfo{
				AccountNumber:        &storeAccountSeven,
				MasterKeyFingerprint: &storeFingerprintStale,
			},
			want: AccountInfo{
				AddrSchema:           rawSchema,
				AccountNumber:        &publicAccountSeven,
				MasterKeyFingerprint: &publicFingerprintSet,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			w := &Wallet{
				masterFingerprint: test.walletFingerprint,
			}

			// Act: Convert one Store snapshot using the wallet fingerprint.
			got, err := w.accountInfoFromStore(&test.store)

			// Assert: Match only public fields, including nil versus zero.
			require.NoError(t, err)
			require.Equal(t, test.want, *got)
		})
	}
}

// TestAccountInfoFromStoreCopiesMutableFields verifies independently converted
// results do not alias Store-owned optionals or public-key bytes.
func TestAccountInfoFromStoreCopiesMutableFields(t *testing.T) {
	t.Parallel()

	// Arrange: Convert the same mutable Store snapshot into two results.
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

	// Act: Mutate one public result as its caller is entitled to do.
	*first.AccountNumber = AccountNumber(20)
	*first.MasterKeyFingerprint = MasterFingerprint(30)
	first.PublicKey[0] = 40

	// Assert: Neither Store data nor the independent result aliases it.
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

	// Arrange: Return an unsupported Store schema through a started wallet
	// so conversion failure must cross the same boundary as lookup failure.
	w, deps := createStartedWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0084
	name := testAccountName
	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		Scope: db.KeyScope(scope),
		Name:  &name,
	}).Return(&db.AccountInfo{
		AddrSchema: db.ScopeAddrSchema{
			ExternalAddrType: db.Anchor,
			InternalAddrType: db.WitnessPubKey,
		},
	}, nil).Once()

	// Act: Read through the public API, including Store result conversion.
	got, err := w.GetAccount(t.Context(), scope, name)

	// Assert: Retain diagnostics without an internal identity or partial data.
	require.ErrorContains(t, err, "external account address schema")
	require.NotErrorIs(t, err, addresstype.ErrUnknown)
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

// expectAccountNameAvailable makes the account-name preflight report that the
// requested name is unused.
func expectAccountNameAvailable(deps *mockWalletDeps,
	scope waddrmgr.KeyScope, name string) {

	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID:    0,
		Scope:       db.KeyScope(scope),
		Name:        &name,
		SkipBalance: true,
	}).Return((*db.AccountInfo)(nil), db.ErrAccountNotFound).Once()
}

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

	// Arrange: Cancel after the required Store calls have been consumed;
	// the existing Once expectations forbid any additional Store access.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Retry through this method's independent admission boundary.
	_, err = w.ListAccounts(ctx)

	// Assert: Admission preserves cancellation without another Store call.
	require.ErrorIs(t, err, context.Canceled)
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

	// Arrange: Cancel after the required Store calls have been consumed;
	// the existing Once expectations forbid any additional Store access.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Retry through this method's independent admission boundary.
	_, err = w.ListAccountsByScope(ctx, scope)

	// Assert: Admission preserves cancellation without another Store call.
	require.ErrorIs(t, err, context.Canceled)
}

// TestListAccountsByScopeUnknownScope verifies list failures do not expose
// backend error identities.
func TestListAccountsByScopeUnknownScope(t *testing.T) {
	t.Parallel()

	// Arrange: Require a filtered Store read to fail with its internal scope
	// sentinel.
	w, deps := createStartedWalletWithMocks(t)

	scope := waddrmgr.KeyScope{
		Purpose: 123,
		Coin:    456,
	}
	dbScope := db.KeyScope(scope)
	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 0,
		Scope:    &dbScope,
	}).Return(nil, db.ErrUnknownKeyScope).Once()

	// Act: List the unknown scope through the public read boundary.
	_, err := w.ListAccountsByScope(t.Context(), scope)

	// Assert: Keep the diagnostic text without inventing a validation identity.
	require.ErrorContains(t, err, db.ErrUnknownKeyScope.Error())
	require.NotErrorIs(t, err, db.ErrUnknownKeyScope)
	require.NotErrorIs(t, err, ErrInvalidParam)
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

	// Arrange: Cancel after the required Store calls have been consumed;
	// the existing Once expectations forbid any additional Store access.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Retry through this method's independent admission boundary.
	_, err = w.ListAccountsByName(ctx, testAccountName)

	// Assert: Admission preserves cancellation without another Store call.
	require.ErrorIs(t, err, context.Canceled)
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

	// Arrange: return a stored exclusion policy on a spendable account so
	// the public snapshot must use persisted data, not custody or a default.
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
		NoChainSync:        true,
	}, nil).Once()

	// Act: read the account through the public API and its Store snapshot.
	info, err := w.GetAccount(t.Context(), scope, name)

	// Assert: policy, identity, and balances survive the Wallet conversion,
	// and the single expected Store read supplies the complete result.
	require.NoError(t, err)
	require.True(t, info.NoChainSync)
	require.NotNil(t, info.AccountNumber)
	require.Equal(t, AccountNumber(1), *info.AccountNumber)
	require.Equal(t, name, info.AccountName)
	require.Equal(t, btcutil.Amount(100), info.ConfirmedBalance)
	require.Equal(t, btcutil.Amount(23), info.UnconfirmedBalance)
	require.NotNil(t, info.MasterKeyFingerprint)
	require.Equal(t, MasterFingerprint(masterFP),
		*info.MasterKeyFingerprint)

	// Arrange: Cancel after the required Store calls have been consumed;
	// the existing Once expectations forbid any additional Store access.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Retry through this method's independent admission boundary.
	_, err = w.GetAccount(ctx, scope, name)

	// Assert: Admission preserves cancellation without another Store call.
	require.ErrorIs(t, err, context.Canceled)
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

// TestGetAccountErrors verifies lookup failures cross the public boundary
// without exposing Store or legacy manager identities.
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
			name:     "deadline",
			storeErr: fmt.Errorf("lookup: %w", context.DeadlineExceeded),
			want:     context.DeadlineExceeded,
		},
		{
			name:     "cancellation",
			storeErr: fmt.Errorf("lookup: %w", context.Canceled),
			want:     context.Canceled,
		},
		{
			name: "legacy missing account",
			storeErr: fmt.Errorf("lookup: %w", waddrmgr.ManagerError{
				ErrorCode: waddrmgr.ErrAccountNotFound,
			}),
			want: ErrAccountNotFound,
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

			// Assert: Known outcomes use wallet identities while unknown
			// failures retain only their diagnostic text.
			require.ErrorContains(t, err, test.storeErr.Error())

			if test.want != nil {
				require.ErrorIs(t, err, test.want)
			}

			require.NotErrorIs(t, err, test.storeErr)

			var managerErr waddrmgr.ManagerError
			require.NotErrorAs(t, err, &managerErr)
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

// TestNewAccount verifies NewAccount routes through
// w.store.CreateDerivedAccount.
func TestNewAccount(t *testing.T) {
	t.Parallel()

	// Arrange: Admit spendable derivation and require one exact Store write.
	w, deps := createUnlockedWalletWithMocks(t)
	stub := newStubAccountDeriveFn(t)

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
			WalletID:    0,
			Scope:       dbScope,
			Name:        testAccountName,
			NoChainSync: false,
		}, mock.Anything).Return(
		&db.AccountInfo{
			AccountNumber: &accountNumber,
			AccountName:   testAccountName,
			KeyScope:      dbScope,
		}, nil,
	).Once()

	// Act: Create the account through the public request path.
	account, err := w.NewAccount(t.Context(), NewAccountParams{
		Scope: scope,
		Name:  testAccountName,
	})

	// Assert: The public result reports the number and default sync policy.
	require.NoError(t, err)
	require.False(t, account.NoChainSync)
	require.Equal(t, AccountNumber(1), *account.AccountNumber)

	// Arrange: Cancel after the required Store calls have been consumed;
	// the existing Once expectations forbid any additional Store access.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Retry through this method's independent admission boundary.
	_, err = w.NewAccount(ctx, NewAccountParams{
		Scope: scope,
		Name:  testAccountName,
	})

	// Assert: Admission preserves cancellation without another Store call.
	require.ErrorIs(t, err, context.Canceled)
}

// TestNewAccountStoreErrors verifies backend creation outcomes use the public
// account error contract.
func TestNewAccountStoreErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		storeErr error
		want     error
	}{
		{
			name:     "sql duplicate",
			storeErr: db.ErrAccountNameConflict,
			want:     ErrAccountAlreadyExists,
		},
		{
			name:     "occupied number",
			storeErr: db.ErrAccountNumberConflict,
			want:     ErrAccountAlreadyExists,
		},
		{
			name: "indeterminate cancellation",
			storeErr: &dbruntime.AmbiguousTxCommitError{
				Err: context.Canceled,
			},
			want: ErrIndeterminateCommit,
		},
		{
			name:     "sql exhaustion",
			storeErr: db.ErrMaxAccountNumberReached,
			want:     ErrAccountDerivationExhausted,
		},
		{
			name: "legacy exhaustion",
			storeErr: waddrmgr.ManagerError{
				ErrorCode: waddrmgr.ErrAccountNumTooHigh,
			},
			want: ErrAccountDerivationExhausted,
		},
		{
			name:     "unknown scope",
			storeErr: db.ErrUnknownKeyScope,
			want:     ErrInvalidParam,
		},
		{
			name:     "absent legacy scope",
			storeErr: db.ErrAccountNotFound,
			want:     ErrAccountNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: A failed Store write also supplies a candidate account;
			// the public boundary must discard it when exposing the failure.
			w, deps := createUnlockedWalletWithMocks(t)
			stub := newStubAccountDeriveFn(t)
			scope := waddrmgr.KeyScopeBIP0084

			expectAccountNameAvailable(deps, scope, testAccountName)
			expectAccountDeriveSetup(t, deps, stub)
			deps.store.On(
				"CreateDerivedAccount", mock.Anything, mock.Anything,
				mock.Anything,
			).Return(&db.AccountInfo{}, test.storeErr).Once()

			// Act: Create through the public boundary, not the mapper.
			info, err := w.NewAccount(t.Context(), NewAccountParams{
				Scope: scope,
				Name:  testAccountName,
			})

			// Assert: Expose the public outcome and strip the Store cause.
			require.Nil(t, info)
			require.ErrorIs(t, err, test.want)
			require.NotErrorIs(t, err, test.storeErr)
		})
	}
}

// TestNewAccountWatchOnly verifies name conflicts take precedence over the
// watch-only unsupported-operation error.
func TestNewAccountWatchOnly(t *testing.T) {
	t.Parallel()

	// Arrange: A watch-only wallet has one occupied and one free name.
	w, deps := createStartedWalletWithMocks(t)
	w.isWatchOnly = true
	scope := waddrmgr.KeyScopeBIP0084
	occupied := "occupied"
	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID:    0,
		Scope:       db.KeyScope(scope),
		Name:        &occupied,
		SkipBalance: true,
	}).Return(&db.AccountInfo{}, nil).Once()

	expectAccountNameAvailable(deps, scope, testAccountName)

	// Act: Try the occupied name before the free name, without derivation.
	_, err := w.NewAccount(t.Context(), NewAccountParams{
		Scope: scope,
		Name:  occupied,
	})

	// Assert: Name conflict takes precedence over watch-only refusal.
	require.ErrorIs(t, err, ErrAccountAlreadyExists)

	// Act: The free name reaches the wallet-mode check.
	_, err = w.NewAccount(t.Context(), NewAccountParams{
		Scope: scope,
		Name:  testAccountName,
	})

	// Assert: An available name exposes only the public mode refusal.
	require.ErrorIs(t, err, ErrAccountOperationUnsupported)
	require.NotErrorIs(t, err, errWatchOnlyAccountDerivation)
}

// TestNewAccountLocked verifies vault lock errors become wallet state errors.
func TestNewAccountLocked(t *testing.T) {
	t.Parallel()

	// Arrange: Start locked with no Store calls allowed before unlock.
	w, deps := createStartedWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0084

	// Act: Try a valid request and an invalid name while still locked.
	_, lockedErr := w.NewAccount(t.Context(), NewAccountParams{
		Scope: scope,
		Name:  testAccountName,
	})
	_, invalidErr := w.NewAccount(t.Context(), NewAccountParams{
		Scope: scope,
		Name:  "",
	})

	// Assert: Admission refuses signing but still classifies invalid names.
	require.ErrorIs(t, lockedErr, ErrStateForbidden)
	require.ErrorIs(t, invalidErr, ErrInvalidParam)

	// Arrange: Unlock admission but let the Vault report a subsequent lock.
	w.state.toUnlocked()
	expectAccountNameAvailable(deps, scope, testAccountName)
	deps.store.On("GetEncryptedHDSeed", mock.Anything, uint32(0)).
		Return([]byte("encrypted"), nil).Once()
	deps.vault.On("Decrypt", waddrmgr.CKTPrivate, mock.Anything).
		Return(nil, keyvault.ErrVaultLocked).Once()

	// Act: Reach the Vault through account creation after admission.
	_, err := w.NewAccount(t.Context(), NewAccountParams{
		Scope: scope,
		Name:  testAccountName,
	})

	// Assert: A later Vault failure has the same wallet-owned state identity.
	require.ErrorIs(t, err, ErrStateForbidden)
	require.NotErrorIs(t, err, keyvault.ErrVaultLocked)
}

// TestNewAccountNoChainSyncUnsupported verifies the common Wallet boundary
// refuses exclusion before any backend can prepare secrets or mutate accounts.
func TestNewAccountNoChainSyncUnsupported(t *testing.T) {
	t.Parallel()

	// Arrange: allow the existing admission checks on an unlocked wallet
	// with an available name. Strict mocks have no secret or write
	// expectations, so crossing into creation would fail this test.
	w, deps := createUnlockedWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0084

	expectAccountNameAvailable(deps, scope, testAccountName)

	// Act: request exclusion through the public API while its receiving and
	// recovery support is unavailable.
	account, err := w.NewAccount(t.Context(), NewAccountParams{
		Scope:       scope,
		Name:        testAccountName,
		NoChainSync: true,
	})

	// Assert: the stable unsupported error returns no account, and only the
	// required read-only admission calls reach the Store and Vault.
	require.ErrorIs(t, err, ErrAccountOperationUnsupported)
	require.Nil(t, account)
}

// TestNewAccountMissingHDSeedDefersToStore verifies that neutered-root kvdb
// wallets can let the store fall back to scoped coin-type key derivation.
func TestNewAccountMissingHDSeedDefersToStore(t *testing.T) {
	t.Parallel()

	// Arrange: Allow derivation admission but return a missing root seed so the
	// Store can use its scoped fallback.
	w, deps := createUnlockedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	accountNumber := uint32(1)

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

	// Act: Create the account through the fallback-capable Store call.
	account, err := w.NewAccount(t.Context(), NewAccountParams{
		Scope: scope,
		Name:  testAccountName,
	})

	// Assert: The Store result succeeds despite the absent master seed.
	require.NoError(t, err)
	require.Equal(t, AccountNumber(1), *account.AccountNumber)
}

// TestRenameAccount verifies RenameAccount routes through the Store and
// translates account-name validation failures.
func TestRenameAccount(t *testing.T) {
	t.Parallel()

	// Arrange: Require a free target and a rename with exact account names.
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

	// Act: Rename through the public method and its name preflight.
	err := w.RenameAccount(t.Context(), scope, testAccountName, "renamed")

	// Assert: Successful persistence completes the public rename.
	require.NoError(t, err)

	// Act: Submit an invalid target without permitting another Store call.
	err = w.RenameAccount(t.Context(), scope, testAccountName, "")

	// Assert: Name validation refuses the write with a public identity.
	require.ErrorIs(t, err, ErrInvalidParam)

	// Arrange: Cancel after the required Store calls have been consumed;
	// the existing Once expectations forbid any additional Store access.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Retry through this method's independent admission boundary.
	err = w.RenameAccount(ctx, scope, testAccountName, "renamed")

	// Assert: Admission preserves cancellation without another Store call.
	require.ErrorIs(t, err, context.Canceled)
}

// TestRenameAccountConflicts verifies occupied targets and self-renames share
// the same public conflict error.
func TestRenameAccountConflicts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		oldName string
		newName string
	}{
		{
			name:    "occupied target",
			oldName: "old",
			newName: "occupied",
		},
		{
			name:    "self rename",
			oldName: testAccountName,
			newName: testAccountName,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Occupy the target and allow no persistence call.
			w, deps := createStartedWalletWithMocks(t)
			scope := waddrmgr.KeyScopeBIP0084
			deps.store.On("GetAccount", mock.Anything,
				db.GetAccountQuery{
					WalletID:    0,
					Scope:       db.KeyScope(scope),
					Name:        &test.newName,
					SkipBalance: true,
				}).Return(&db.AccountInfo{}, nil).Once()

			// Act: Attempt the requested rename through public preflight.
			err := w.RenameAccount(
				t.Context(), scope, test.oldName, test.newName,
			)

			// Assert: Both conflicts refuse mutation and identify the target
			// name and scope so callers can diagnose the rejected rename.
			require.ErrorIs(t, err, ErrAccountAlreadyExists)
			require.EqualError(t, err, fmt.Sprintf(
				"account already exists: %q in scope %d/%d",
				test.newName, scope.Purpose, scope.Coin,
			))
		})
	}
}

// TestRenameAccountStoreErrors verifies backend rename outcomes use public
// wallet identities.
func TestRenameAccountStoreErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		storeErr error
		want     error
	}{
		{
			name:     "absent self rename",
			storeErr: db.ErrAccountNotFound,
			want:     ErrAccountNotFound,
		},
		{
			name: "legacy name conflict",
			storeErr: fmt.Errorf("rename: %w", waddrmgr.ManagerError{
				ErrorCode:   waddrmgr.ErrDuplicateAccount,
				Description: "duplicate account",
			}),
			want: ErrAccountAlreadyExists,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Leave the target free, then fail the Store write.
			w, deps := createStartedWalletWithMocks(t)
			scope := waddrmgr.KeyScopeBIP0084
			expectAccountNameAvailable(deps, scope, testAccountName)
			deps.store.On(
				"RenameAccount", mock.Anything, mock.Anything,
			).Return(test.storeErr).Once()

			// Act: Rename through preflight and persistence.
			err := w.RenameAccount(
				t.Context(), scope, testAccountName, testAccountName,
			)

			// Assert: Missing sources and racing conflicts remain distinct.
			require.ErrorIs(t, err, test.want)
			require.NotErrorIs(t, err, test.storeErr)

			var managerErr waddrmgr.ManagerError
			require.NotErrorAs(t, err, &managerErr)
		})
	}
}

// TestImportAccount verifies ordinary, dry-run, and BIP-49 imports preserve
// their distinct Store parameters through the same public request path.
func TestImportAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		purpose    uint32
		scope      waddrmgr.KeyScope
		addrType   waddrmgr.AddressType
		addrSchema *db.ScopeAddrSchema
		dryRun     bool
	}{
		{
			name:     "persist account",
			purpose:  84,
			scope:    waddrmgr.KeyScopeBIP0084,
			addrType: waddrmgr.WitnessPubKey,
		},
		{
			name:     "preview account",
			purpose:  84,
			scope:    waddrmgr.KeyScopeBIP0084,
			addrType: waddrmgr.WitnessPubKey,
			dryRun:   true,
		},
		{
			name:     "override address schema",
			purpose:  49,
			scope:    waddrmgr.KeyScopeBIP0049Plus,
			addrType: waddrmgr.NestedWitnessPubKey,
			addrSchema: &db.ScopeAddrSchema{
				ExternalAddrType: db.NestedWitnessPubKey,
				InternalAddrType: db.NestedWitnessPubKey,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Require the derived scope, key, and import options
			// in one exact Store call after name preflight succeeds.
			w, deps := createStartedWalletWithMocks(t)
			key, fingerprint := importAccountTestKey(t, test.purpose)
			expectAccountNameAvailable(deps, test.scope, testAccountName)
			deps.store.On("CreateImportedAccount", mock.Anything,
				db.CreateImportedAccountParams{
					Name:              testAccountName,
					Scope:             db.KeyScope(test.scope),
					MasterFingerprint: fingerprint,
					PublicKey:         []byte(key.String()),
					AddrSchema:        test.addrSchema,
					DryRun:            test.dryRun,
				}).Return(&db.AccountInfo{
				AccountName: testAccountName,
			}, nil).Once()

			// Act: Import through the public API with the selected options.
			info, err := w.ImportAccount(
				t.Context(), testAccountName, key, fingerprint,
				test.addrType, test.dryRun,
			)

			// Assert: Return the Store result after the exact call above;
			// fixture cleanup checks that every expectation was consumed.
			require.NoError(t, err)
			require.False(t, info.NoChainSync)
			require.Equal(t, testAccountName, info.AccountName)
		})
	}
}

// TestImportAccountOccupiedName verifies import checks the derived scope for
// an existing account before mutation.
func TestImportAccountOccupiedName(t *testing.T) {
	t.Parallel()

	// Arrange: Occupy the name in the key-derived scope and allow no write.
	w, deps := createStartedWalletWithMocks(t)
	accountKey, masterFP := importAccountTestKey(t, 84)
	scope := waddrmgr.KeyScopeBIP0084
	name := testAccountName
	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID:    0,
		Scope:       db.KeyScope(scope),
		Name:        &name,
		SkipBalance: true,
	}).Return(&db.AccountInfo{}, nil).Once()

	// Act: Import the public key using the occupied account name.
	_, err := w.ImportAccount(
		t.Context(), name, accountKey, masterFP,
		waddrmgr.WitnessPubKey, false,
	)

	// Assert: The conflict identity proves preflight refused mutation.
	require.ErrorIs(t, err, ErrAccountAlreadyExists)
}

// TestImportAccountStoreErrors verifies backend import outcomes use public
// wallet identities.
func TestImportAccountStoreErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		storeErr error
		want     error
	}{
		{
			name:     "name conflict",
			storeErr: db.ErrAccountNameConflict,
			want:     ErrAccountAlreadyExists,
		},
		{
			name:     "spendable wallet",
			storeErr: db.ErrSpendableWalletNeedsAccountPrivKey,
			want:     ErrAccountOperationUnsupported,
		},
		{
			name:     "absent legacy scope",
			storeErr: db.ErrKeyScopeNotFound,
			want:     ErrAccountNotFound,
		},
		{
			name: "locked legacy scope creation",
			storeErr: fmt.Errorf("scope: %w", waddrmgr.ManagerError{
				ErrorCode: waddrmgr.ErrLocked,
			}),
			want: ErrStateForbidden,
		},
		{
			name: "rootless legacy scope creation",
			storeErr: fmt.Errorf("scope: %w", waddrmgr.ManagerError{
				ErrorCode: waddrmgr.ErrWatchingOnly,
			}),
			want: ErrAccountOperationUnsupported,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Let a valid import reach the backend refusal.
			w, deps := createStartedWalletWithMocks(t)
			accountKey, masterFP := importAccountTestKey(t, 84)
			scope := waddrmgr.KeyScopeBIP0084
			expectAccountNameAvailable(deps, scope, testAccountName)
			deps.store.On(
				"CreateImportedAccount", mock.Anything, mock.Anything,
			).Return((*db.AccountInfo)(nil), test.storeErr).Once()

			// Act: Import through public translation after name preflight.
			_, err := w.ImportAccount(
				t.Context(), testAccountName, accountKey, masterFP,
				waddrmgr.WitnessPubKey, false,
			)

			// Assert: Preserve each public identity without the backend cause.
			require.ErrorIs(t, err, test.want)
			require.NotErrorIs(t, err, test.storeErr)

			var managerErr waddrmgr.ManagerError
			require.NotErrorAs(t, err, &managerErr)
		})
	}
}

// TestImportAccountInvalidRequest verifies invalid names and address types use
// wallet-owned validation errors before Store access.
func TestImportAccountInvalidRequest(t *testing.T) {
	t.Parallel()

	// Arrange: Use a started wallet with no Store expectations so invalid
	// requests must fail before persistence.
	w, _ := createStartedWalletWithMocks(t)
	accountKey, masterFP := importAccountTestKey(t, 44)

	// Act: Try an empty account name with valid public key material.
	_, err := w.ImportAccount(
		t.Context(), "", accountKey, masterFP,
		waddrmgr.WitnessPubKey, false,
	)

	// Assert: Name validation returns the wallet-owned parameter identity.
	require.ErrorIs(t, err, ErrInvalidParam)

	// Act: A valid name allows the unsupported address type to be checked.
	_, err = w.ImportAccount(
		t.Context(), testAccountName, accountKey, masterFP,
		waddrmgr.PubKeyHash, false,
	)

	// Assert: Address validation also hides internal error identities.
	require.ErrorIs(t, err, ErrInvalidParam)

	// Arrange: Cancel before admission while retaining the same invalid name.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Retry with an already-canceled caller and valid key material.
	_, err = w.ImportAccount(ctx, "", accountKey, masterFP,
		waddrmgr.WitnessPubKey, false)

	// Assert: Caller cancellation precedes name validation and Store work.
	require.ErrorIs(t, err, context.Canceled)
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
	// a key snapshot independently of the original key.
	require.ErrorIs(t, callErr, context.Canceled)

	req, ok := rawReq.(importAccountReq)
	require.True(t, ok)
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
	_, err := w.NewAccount(t.Context(), NewAccountParams{
		Scope: waddrmgr.KeyScopeBIP0084,
		Name:  testAccountName,
	})

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

// TestNewAccountInvalidPath verifies Wallet runs shared path validation before
// loading secrets or invoking Store operations.
func TestNewAccountInvalidPath(t *testing.T) {
	t.Parallel()

	// Arrange: use an invalid exact number and strict mocks with no expected
	// calls. The shared validator's tests own the complete path-input matrix.
	w, _ := createStartedWalletWithMocks(t)
	w.addrStore = nil
	number := AccountNumber(db.MaxAccountNumber + 1)

	// Act: enter creation through the public boundary with a malformed path.
	info, err := w.NewAccount(t.Context(), NewAccountParams{
		Scope:         waddrmgr.KeyScopeBIP0084,
		Name:          testAccountName,
		AccountNumber: &number,
	})

	// Assert: validation exposes only the public identity and no account,
	// without making a secret or Store call before refusing the request.
	require.ErrorIs(t, err, ErrInvalidParam)
	require.NotErrorIs(t, err, db.ErrInvalidParam)
	require.Nil(t, info)
}

// TestNewAccountExactUnsupported verifies kvdb rejects exact creation with
// either policy after admission and before root preparation or Store mutation.
func TestNewAccountExactUnsupported(t *testing.T) {
	t.Parallel()

	// Arrange: vary the unsupported mode with identical read-only admission
	// expectations. Any secret or creation call would fail the strict mocks.
	tests := []struct {
		name        string
		noChainSync bool
	}{
		{
			name: "kvdb exact",
		},
		{
			name:        "kvdb no chain sync",
			noChainSync: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			w, deps := createUnlockedWalletWithMocks(t)
			scope := waddrmgr.KeyScopeBIP0084
			number := AccountNumber(7)

			expectAccountNameAvailable(deps, scope, testAccountName)

			// Act: submit a valid path with the unsupported backend/policy.
			info, err := w.NewAccount(t.Context(), NewAccountParams{
				Scope:         scope,
				Name:          testAccountName,
				AccountNumber: &number,
				NoChainSync:   test.noChainSync,
			})

			// Assert: both forms preserve the public unsupported outcome
			// and stop after the required admission reads.
			require.ErrorIs(t, err, ErrAccountOperationUnsupported)
			require.Nil(t, info)
		})
	}
}

// TestNewAccountCancellationPreservesCommitError verifies cancellation cannot
// hide an uncertain commit after the exact-account request has been admitted.
func TestNewAccountCancellationPreservesCommitError(t *testing.T) {
	t.Parallel()

	// Arrange: hold an admitted Store write until explicitly released with
	// an ambiguous result. Cleanup releases it before the fixture drains Stop.
	w, deps := createUnlockedWalletWithMocks(t)
	w.addrStore = nil
	scope := waddrmgr.KeyScopeBIP0084
	number := AccountNumber(7)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	resumeCtx, resume := context.WithCancel(t.Context())
	t.Cleanup(resume)

	entered := make(chan struct{})
	infos := make(chan *AccountInfo, 1)
	result := make(chan error, 1)

	expectAccountNameAvailable(deps, scope, testAccountName)
	expectAccountDeriveSetup(t, deps, newStubAccountDeriveFn(t))
	deps.store.On("CreateDerivedAccount", ctx,
		db.CreateDerivedAccountParams{
			WalletID:      w.id,
			Scope:         db.KeyScope(scope),
			Name:          testAccountName,
			AccountNumber: (*uint32)(&number),
		}, mock.Anything).Run(func(mock.Arguments) {
		close(entered)
		<-resumeCtx.Done()
	}).Return(&db.AccountInfo{}, &dbruntime.AmbiguousTxCommitError{
		Err: context.Canceled,
	}).Once()

	// Act: cancel after admission, while the write's outcome is still held.
	go func() {
		info, err := w.NewAccount(ctx, NewAccountParams{
			Scope:         scope,
			Name:          testAccountName,
			AccountNumber: &number,
		})
		infos <- info

		result <- err
	}()

	<-entered
	cancel()

	// Assert: the bounded observation window detects premature cancellation;
	// only explicit Store release may supply the authoritative public result.
	select {
	case err := <-result:
		t.Fatalf("NewAccount returned before the Store outcome: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	resume()

	err := <-result
	require.ErrorIs(t, err, ErrIndeterminateCommit)
	require.NotErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, dbruntime.ErrAmbiguousTxCommit)
	require.Nil(t, <-infos)
}
