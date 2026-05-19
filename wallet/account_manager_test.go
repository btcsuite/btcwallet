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

	deps.store.On("GetEncryptedHDSeed", mock.Anything, uint32(0)).
		Return(append([]byte(nil), stub.encryptedSeed...), nil).Once()
	deps.addrStore.On("Decrypt", waddrmgr.CKTPrivate,
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

// TestListAccounts verifies ListAccounts pairs cache.ListAccounts with
// cache.AccountBalances.
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
	require.Equal(t, btcutil.Amount(100), info.ConfirmedBalance)
	require.Equal(t, btcutil.Amount(23), info.UnconfirmedBalance)
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
		AccountNumber: 1,
		AccountName:   testAccountName,
		Origin:        db.ImportedAccount,
		IsWatchOnly:   true,
		KeyScope:      dbScope,
		PublicKey:     []byte(acctPubKey.String()),
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
		Origin:      db.ImportedAccount,
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
		Origin:      db.ImportedAccount,
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
