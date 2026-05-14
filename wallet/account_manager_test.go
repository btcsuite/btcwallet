// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func hardenedKey(key uint32) uint32 {
	return key + hdkeychain.HardenedKeyStart
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

	seed := make([]byte, hdkeychain.RecommendedSeedLen)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	masterKey, err := hdkeychain.NewMaster(seed, &chainParams)
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

	deps.addrStore.On("WatchOnly").Return(false).Once()
	deps.store.On("GetEncryptedHDSeed", mock.Anything, uint32(0)).
		Return(append([]byte(nil), stub.encryptedSeed...), nil).Once()
	deps.addrStore.On("Decrypt", waddrmgr.CKTPrivate,
		mock.Anything).Return(
		append([]byte(nil), stub.plaintextMasterKey...), nil,
	).Once()
}

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

// TestNewAccount verifies NewAccount routes through
// w.store.CreateDerivedAccount.
func TestNewAccount(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)
	stub := newStubAccountDeriveFn(t)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}

	// Success path.
	expectAccountDeriveSetup(t, deps, stub)
	deps.store.On("CreateDerivedAccount", mock.Anything,
		db.CreateDerivedAccountParams{
			WalletID: 0,
			Scope:    dbScope,
			Name:     testAccountName,
		}, mock.Anything).Return(
		&db.AccountInfo{
			AccountNumber: 1,
			AccountName:   testAccountName,
			Origin:        db.DerivedAccount,
			KeyScope:      dbScope,
		}, nil,
	).Once()

	account, err := w.NewAccount(t.Context(), scope, testAccountName)
	require.NoError(t, err)
	require.Equal(t, uint32(1), account.AccountNumber)

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

// TestListAccounts verifies ListAccounts pairs cache.ListAccounts with
// cache.AccountBalances.
func TestListAccounts(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	bip84 := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}

	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 0,
	}).Return([]db.AccountInfo{
		{
			AccountNumber: 0,
			AccountName:   "default",
			KeyScope:      bip84,
		},
	}, nil).Once()

	result, err := w.ListAccounts(t.Context())
	require.NoError(t, err)
	require.Len(t, result.Accounts, 1)
	require.Equal(t, "default", result.Accounts[0].AccountName)
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

	result, err := w.ListAccountsByScope(t.Context(), scope)
	require.NoError(t, err)
	require.Len(t, result.Accounts, 1)
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

	result, err := w.ListAccountsByName(t.Context(), testAccountName)
	require.NoError(t, err)
	require.Len(t, result.Accounts, 1)
}

// TestGetAccount verifies GetAccount routes through cache + store.Balance.
func TestGetAccount(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

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
		AccountNumber: 1,
		AccountName:   name,
		Origin:        db.DerivedAccount,
		KeyScope:      dbScope,
	}, nil).Once()

	acctNum := uint32(1)
	minConfs := int32(0)
	deps.store.On("Balance", mock.Anything, db.BalanceParams{
		WalletID: 0,
		Scope:    &dbScope,
		Account:  &acctNum,
		MinConfs: &minConfs,
	}).Return(db.BalanceResult{}, nil).Once()

	info, err := w.GetAccount(t.Context(), scope, name)
	require.NoError(t, err)
	require.Equal(t, uint32(1), info.AccountNumber)
	require.Equal(t, name, info.AccountName)
}

// TestRenameAccount verifies RenameAccount routes through
// w.store.RenameAccount.
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

// TestBalance verifies Balance routes through cache.GetAccount + store.Balance.
func TestBalance(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

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
		AccountNumber: 1,
		AccountName:   name,
		KeyScope:      dbScope,
	}, nil).Once()

	acctNum := uint32(1)
	minConfs := int32(0)
	deps.store.On("Balance", mock.Anything, db.BalanceParams{
		WalletID: 0,
		Scope:    &dbScope,
		Account:  &acctNum,
		MinConfs: &minConfs,
	}).Return(db.BalanceResult{Total: 500}, nil).Once()

	balance, err := w.Balance(t.Context(), 0, scope, name)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(500), balance)
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

	// Mock expectations for GetAccount.
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("LookupAccount", mock.Anything, testAccountName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   testAccountName,
		}, nil).Once()

	deps.txStore.On("UnspentOutputs", mock.Anything).
		Return([]wtxmgr.Credit(nil), nil).Once()

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

	// Mock expectations for GetAccount (fail).
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, dryRunName).
		Return(uint32(0), waddrmgr.ManagerError{
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

	p2pkhAddr, err := btcutil.DecodeAddress(
		"17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem", w.cfg.ChainParams,
	)
	require.NoError(t, err)

	p2shAddr, err := btcutil.DecodeAddress(
		"347N1Thc213QqfYCz3PZkjoJpNv5b14kBd", w.cfg.ChainParams,
	)
	require.NoError(t, err)

	p2wpkhAddr, err := btcutil.DecodeAddress(
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
