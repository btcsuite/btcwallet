// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"encoding/binary"
	"strings"
	"testing"

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

// hardenedKey returns the hardened child index for the given key index.
func hardenedKey(key uint32) uint32 {
	return key + hdkeychain.HardenedKeyStart
}

// deriveAcctPubKey derives the account extended public key for the scope and
// path from the test root key.
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

	require.Equal(t, uint32(7), info.AccountNumber)
	require.Equal(t, db.DerivedAccount, info.Origin)
	require.False(t, info.IsWatchOnly)
	require.Equal(t, masterFingerprint, info.MasterKeyFingerprint)
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

	require.Equal(t, uint32(0), info.AccountNumber)
	require.Equal(t, db.ImportedAccount, info.Origin)
	require.True(t, info.IsWatchOnly)
	require.Equal(t, importedFingerprint, info.MasterKeyFingerprint)
}

// TestListAccounts tests that ListAccounts returns the cache-backed
// snapshot of all accounts for the wallet.
func TestListAccounts(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	// Seed a non-zero cached master fingerprint so the derived-account
	// override path in listAccountInfos produces an observable value on
	// each entry.
	const masterFP uint32 = 0xDEADBEEF

	w.masterFingerprint = masterFP

	bip84 := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}

	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 0,
	}).Return([]db.AccountInfo{
		{
			AccountNumber:        0,
			AccountName:          "default",
			Origin:               db.DerivedAccount,
			KeyScope:             bip84,
			MasterKeyFingerprint: 0,
		},
	}, nil).Once()

	accounts, err := w.ListAccounts(t.Context())
	require.NoError(t, err)

	require.Len(t, accounts, 1)
	require.Equal(t, "default", accounts[0].AccountName)
	require.Equal(t, masterFP, accounts[0].MasterKeyFingerprint)
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

	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 0,
		Scope:    &dbScope,
	}).Return([]db.AccountInfo{
		{
			AccountNumber: 0,
			AccountName:   "default",
			KeyScope:      dbScope,
		},
	}, nil).Once()
	deps.addrStore.On("FetchScopedKeyManager", scope).Return(
		deps.accountManager, nil,
	).Once()

	accounts, err := w.ListAccountsByScope(t.Context(), scope)
	require.NoError(t, err)
	require.Len(t, accounts, 1)
}

// TestListAccountsByScopeUnknownScope verifies the public wallet API preserves
// the legacy scope-not-found error surface.
func TestListAccountsByScopeUnknownScope(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	scope := waddrmgr.KeyScope{Purpose: 123, Coin: 456}
	deps.addrStore.On("FetchScopedKeyManager", scope).Return(
		nil, waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrScopeNotFound,
		},
	).Once()

	_, err := w.ListAccountsByScope(t.Context(), scope)
	require.Error(t, err)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound))
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

	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 0,
		Name:     &name,
	}).Return([]db.AccountInfo{
		{
			AccountNumber: 1,
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
			Origin:           db.ImportedAccount,
			KeyScope:         dbScope,
			ImportedKeyCount: 2,
		},
	}, nil).Once()

	accounts, err := w.ListAccountsByName(t.Context(), name)
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	require.Equal(t, waddrmgr.ImportedAddrAccountName,
		accounts[0].AccountName)
	require.Equal(t, db.ImportedAccount, accounts[0].Origin)
	require.Equal(t, uint32(0), accounts[0].AccountNumber)
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
	// The mocked store deliberately returns MasterKeyFingerprint: 0
	// (matching what waddrmgr's default-account row carries for
	// legacy derived rows) so the wallet-level override is what
	// surfaces the value to the caller.
	const masterFP uint32 = 0xDEADBEEF

	w.masterFingerprint = masterFP

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	name := testAccountName

	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID: 0,
		Scope:    dbScope,
		Name:     &name,
	}).Return(&db.AccountInfo{
		AccountNumber:        1,
		AccountName:          name,
		Origin:               db.DerivedAccount,
		KeyScope:             dbScope,
		ConfirmedBalance:     100,
		UnconfirmedBalance:   23,
		MasterKeyFingerprint: 0,
	}, nil).Once()

	info, err := w.GetAccount(t.Context(), scope, name)
	require.NoError(t, err)
	require.Equal(t, uint32(1), info.AccountNumber)
	require.Equal(t, name, info.AccountName)
	require.Equal(
		t,
		btcutil.Amount(123),
		info.ConfirmedBalance+info.UnconfirmedBalance,
	)
	require.Equal(t, masterFP, info.MasterKeyFingerprint)
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
		Origin:           db.ImportedAccount,
		KeyScope:         dbScope,
		ImportedKeyCount: 3,
	}, nil).Once()

	account, err := w.GetAccount(
		t.Context(), scope, name,
	)
	require.NoError(t, err)
	require.Equal(t, waddrmgr.ImportedAddrAccountName, account.AccountName)
	require.Equal(t, db.ImportedAccount, account.Origin)
	require.Equal(t, uint32(0), account.AccountNumber)
	require.Equal(t, uint32(3), account.ImportedKeyCount)
}

// TestRenameAccount tests that the RenameAccount method works as expected.
func TestRenameAccount(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// We'll create a new account under the BIP0084 scope.
	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	oldName := "old name"
	newName := "new name"

	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("NewAccount", mock.Anything, oldName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   oldName,
		}, nil).Once()

	_, err := w.NewAccount(t.Context(), scope, oldName)
	require.NoError(t, err)

	// Mock expectations for RenameAccount.
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, oldName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("RenameAccount", mock.Anything, uint32(1), newName).
		Return(nil).Once()

	// We should be able to rename the account.
	err = w.RenameAccount(t.Context(), scope, oldName, newName)
	require.NoError(t, err)

	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID: 0,
		Scope:    dbScope,
		Name:     &newName,
	}).Return(&db.AccountInfo{
		AccountNumber: 1,
		AccountName:   newName,
		Origin:        db.DerivedAccount,
		KeyScope:      dbScope,
	}, nil).Once()

	// We should be able to get the account by its new name.
	account, err := w.GetAccount(t.Context(), scope, newName)
	require.NoError(t, err)
	require.Equal(t, newName, account.AccountName)

	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID: 0,
		Scope:    dbScope,
		Name:     &oldName,
	}).Return((*db.AccountInfo)(nil), waddrmgr.ManagerError{
		ErrorCode: waddrmgr.ErrAccountNotFound,
	}).Once()

	// We should not be able to get the account by its old name.
	_, err = w.GetAccount(t.Context(), scope, oldName)
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound),
		"expected ErrAccountNotFound",
	)

	// Mock expectations for RenameAccount (duplicate name).
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("LookupAccount", mock.Anything, newName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On(
		"RenameAccount", mock.Anything, uint32(1), "default",
	).Return(waddrmgr.ManagerError{
		ErrorCode: waddrmgr.ErrDuplicateAccount,
	}).Once()

	// We should not be able to rename an account to an existing name.
	err = w.RenameAccount(t.Context(), scope, newName, "default")
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrDuplicateAccount),
		"expected ErrDuplicateAccount",
	)

	// Mock expectations for RenameAccount (non-existent account).
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, "non-existent").
		Return(uint32(0), waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrAccountNotFound,
		}).Once()

	// We should not be able to rename a non-existent account.
	err = w.RenameAccount(t.Context(), scope, "non-existent", "new name 2")
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound),
		"expected ErrAccountNotFound",
	)
}

// TestImportAccount tests that the ImportAccount works as expected.
func TestImportAccount(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// We'll start by creating a new account under the BIP0084 scope.
	scope := waddrmgr.KeyScopeBIP0084
	addrType := waddrmgr.WitnessPubKey
	masterPriv := "tprv8ZgxMBicQKsPeWwrFuNjEGTTDSY4mRLwd2KDJAPGa1AY" +
		"quw38bZqNMSuB3V1Va3hqJBo9Pt8Sx7kBQer5cNMrb8SYquoWPt9" +
		"Y3BZdhdtUcw"
	root, err := hdkeychain.NewKeyFromString(masterPriv)
	require.NoError(t, err)
	acctPubKey := deriveAcctPubKey(t, root, scope, hardenedKey(0))

	// Mock expectations for ImportAccount.
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("NewAccountWatchingOnly", mock.Anything,
		testAccountName, acctPubKey, root.ParentFingerprint(),
		mock.Anything).Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   testAccountName,
		}, nil).Once()

	// We should be able to import the account.
	props, err := w.ImportAccount(
		t.Context(), testAccountName, acctPubKey,
		root.ParentFingerprint(), addrType, false,
	)
	require.NoError(t, err)
	require.Equal(t, testAccountName, props.AccountName)

	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	name := testAccountName
	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID: 0,
		Scope:    dbScope,
		Name:     &name,
	}).Return(&db.AccountInfo{
		AccountNumber: 1,
		AccountName:   testAccountName,
		Origin:        db.ImportedAccount,
		IsWatchOnly:   true,
		KeyScope:      dbScope,
	}, nil).Once()

	// We should be able to get the account by its name.
	_, err = w.GetAccount(t.Context(), scope, testAccountName)
	require.NoError(t, err)

	// Mock expectations for duplicate ImportAccount.
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("NewAccountWatchingOnly", mock.Anything,
		testAccountName, acctPubKey, root.ParentFingerprint(),
		mock.Anything).Return(uint32(0), waddrmgr.ManagerError{
		ErrorCode: waddrmgr.ErrDuplicateAccount,
	}).Once()

	// We should not be able to import an account with the same name.
	_, err = w.ImportAccount(
		t.Context(), testAccountName, acctPubKey,
		root.ParentFingerprint(), addrType, false,
	)
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrDuplicateAccount),
		"expected ErrDuplicateAccount",
	)

	// Mock expectations for dry-run.
	dryRunName := "dry run"

	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("NewAccountWatchingOnly", mock.Anything,
		dryRunName, acctPubKey, root.ParentFingerprint(),
		mock.Anything).Return(uint32(2), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(2)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 2,
			AccountName:   dryRunName,
		}, nil).Twice()
	deps.accountManager.On("InvalidateAccountCache", uint32(2)).Return().Once()
	deps.accountManager.On("NextExternalAddresses", mock.Anything, uint32(2),
		uint32(1)).Return([]waddrmgr.ManagedAddress(nil), nil).Once()
	deps.accountManager.On("NextInternalAddresses", mock.Anything, uint32(2),
		uint32(1)).Return([]waddrmgr.ManagedAddress(nil), nil).Once()

	// We should be able to do a dry run of the import.
	_, err = w.ImportAccount(
		t.Context(), dryRunName, acctPubKey,
		root.ParentFingerprint(), addrType, true,
	)
	require.NoError(t, err)

	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID: 0,
		Scope:    dbScope,
		Name:     &dryRunName,
	}).Return((*db.AccountInfo)(nil), waddrmgr.ManagerError{
		ErrorCode: waddrmgr.ErrAccountNotFound,
	}).Once()

	// The account should not have been imported.
	_, err = w.GetAccount(t.Context(), scope, dryRunName)
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound),
		"expected ErrAccountNotFound",
	)
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
