// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"iter"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/addresstype"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// addressInfoFromAddr builds a store address record for a test address.
func addressInfoFromAddr(t *testing.T, addr address.Address) *db.AddressInfo {
	t.Helper()

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return &db.AddressInfo{ScriptPubKey: pkScript}
}

// derivedAddressInfoFromAddr builds derived store address metadata for tests.
func derivedAddressInfoFromAddr(t *testing.T, addr address.Address,
	addrType db.AddressType, accountName string, scope waddrmgr.KeyScope,
	change bool, index uint32, fingerprint uint32,
	pubKey *btcec.PublicKey) *db.AddressInfo {

	t.Helper()

	info := addressInfoFromAddr(t, addr)
	info.AddrType = addrType
	info.Origin = db.DerivedAccount
	info.IsImported = false
	info.HasDerivationPath = true
	info.AccountName = accountName
	accountNumber := uint32(0)
	info.AccountNumber = &accountNumber
	info.KeyScope = db.KeyScope(scope)
	info.MasterKeyFingerprint = fingerprint
	info.Index = index

	if change {
		info.Branch = 1
	}

	if pubKey != nil {
		info.PubKey = pubKey.SerializeCompressed()
	}

	return info
}

// importedPubKeyAddressInfoFromAddr builds imported public-key store metadata
// for tests.
func importedPubKeyAddressInfoFromAddr(t *testing.T, addr address.Address,
	scope waddrmgr.KeyScope, pubKey *btcec.PublicKey) *db.AddressInfo {

	t.Helper()

	info := addressInfoFromAddr(t, addr)
	info.AddrType = db.WitnessPubKey
	info.Origin = db.ImportedAccount
	info.IsImported = true
	info.HasDerivationPath = false
	info.AccountName = db.DefaultImportedAccountName
	info.KeyScope = db.KeyScope(scope)
	info.IsWatchOnly = true

	if pubKey != nil {
		info.PubKey = pubKey.SerializeCompressed()
	}

	return info
}

// expectStoreNewAddress configures mock expectations for deriving an address.
func expectStoreNewAddress(t *testing.T, w *Wallet, deps *mockWalletDeps,
	accountName string, scope waddrmgr.KeyScope, change bool,
	addr address.Address) {

	t.Helper()

	deps.store.On(
		"NewDerivedAddress", mock.Anything,
		db.NewDerivedAddressParams{
			WalletID:    w.id,
			AccountName: accountName,
			Scope:       db.KeyScope(scope),
			Change:      change,
		},
	).Return(addressInfoFromAddr(t, addr), nil).Once()
	deps.chain.On("NotifyReceived", []address.Address{addr}).Return(nil).Once()
}

// expectSignerAddressInfo mocks Store.GetAddress to return a minimal
// AddressInfo for tests that exercise the wallet's address-info read
// path. No call-count constraint — the same address may be looked up
// multiple times (input decoration + change output info).
//
//nolint:unparam // Keep branch metadata in the helper signature.
func expectSignerAddressInfo(t *testing.T, w *Wallet, deps *mockWalletDeps,
	addr address.Address, addrType db.AddressType,
	internal, imported bool, pubKey *btcec.PublicKey) {

	t.Helper()
	expectSignerAddressInfoWithKeyScope(
		t, w, deps, addr, addrType, internal, imported, pubKey,
		waddrmgr.KeyScope{},
	)
}

// expectSignerDerivedAddressInfo mocks Store.GetAddress to return address
// metadata with a usable derivation scope for PSBT derivation tests. The
// helper hard-codes internal=false because every PSBT derivation test
// asserts against an external-branch address.
func expectSignerDerivedAddressInfo(t *testing.T, w *Wallet,
	deps *mockWalletDeps, addr address.Address, addrType db.AddressType,
	pubKey *btcec.PublicKey) {

	t.Helper()

	walletAddrType, err := addresstype.ToWallet(addrType, false)
	require.NoError(t, err)

	keyScope, err := walletAddrType.KeyScope()
	require.NoError(t, err)

	expectSignerAddressInfoWithKeyScope(
		t, w, deps, addr, addrType, false, false, pubKey, keyScope,
	)
}

// expectSignerAddressInfoWithKeyScope mocks Store.GetAddress with the provided
// derivation scope. A zero key scope represents missing derivation metadata.
func expectSignerAddressInfoWithKeyScope(t *testing.T, w *Wallet,
	deps *mockWalletDeps, addr address.Address, addrType db.AddressType,
	internal, imported bool, pubKey *btcec.PublicKey,
	keyScope waddrmgr.KeyScope) {

	t.Helper()

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	origin := db.DerivedAccount
	if imported {
		origin = db.ImportedAccount
	}

	var branch uint32
	if internal {
		branch = 1
	}

	var pubKeyBytes []byte
	if pubKey != nil {
		pubKeyBytes = pubKey.SerializeCompressed()
	}

	storeInfo := &db.AddressInfo{
		ScriptPubKey:      pkScript,
		AddrType:          addrType,
		Origin:            origin,
		IsImported:        imported,
		HasDerivationPath: !imported,
		Branch:            branch,
		PubKey:            pubKeyBytes,
	}
	if !imported {
		accountNumber := uint32(0)
		storeInfo.AccountNumber = &accountNumber
	}
	if keyScope != (waddrmgr.KeyScope{}) {
		storeInfo.KeyScope = db.KeyScope(keyScope)
		storeInfo.MasterKeyFingerprint = 1
	}

	deps.store.On(
		"GetAddress", mock.Anything,
		db.GetAddressQuery{
			WalletID:     w.id,
			ScriptPubKey: pkScript,
		},
	).Return(storeInfo, nil)
}

// addressIter returns an address iterator over static test records.
func addressIter(items ...db.AddressInfo) iter.Seq2[db.AddressInfo, error] {
	return func(yield func(db.AddressInfo, error) bool) {
		for i := range items {
			if !yield(items[i], nil) {
				return
			}
		}
	}
}

// TestNewAddress tests the NewAddress method, ensuring it can generate
// various address types for different accounts and correctly handles both
// internal and external address generation.
// expectStoreAddressInfo configures mock expectations for address lookup.
func expectStoreAddressInfo(t *testing.T, w *Wallet, deps *mockWalletDeps,
	addr address.Address, info *db.AddressInfo) {

	t.Helper()

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	deps.store.On(
		"GetAddress", mock.Anything,
		db.GetAddressQuery{
			WalletID:     w.id,
			ScriptPubKey: pkScript,
		},
	).Return(info, nil).Once()
}

func TestNewAddress(t *testing.T) {
	t.Parallel()

	// Define a set of test cases to cover different address types and
	// scenarios.
	testCases := []struct {
		name             string
		accountName      string
		addrType         waddrmgr.AddressType
		change           bool
		expectErr        bool
		expectedAddrType address.Address
	}{
		{
			name:             "default account p2wkh",
			accountName:      "default",
			addrType:         waddrmgr.WitnessPubKey,
			change:           false,
			expectedAddrType: &address.AddressWitnessPubKeyHash{},
		},
		{
			name:             "p2wkh change address",
			accountName:      "default",
			addrType:         waddrmgr.WitnessPubKey,
			change:           true,
			expectedAddrType: &address.AddressWitnessPubKeyHash{},
		},
		{
			name:             "default account np2wkh",
			accountName:      "default",
			addrType:         waddrmgr.NestedWitnessPubKey,
			change:           false,
			expectedAddrType: &address.AddressScriptHash{},
		},
		{
			name:             "default account p2tr",
			accountName:      "default",
			addrType:         waddrmgr.TaprootPubKey,
			change:           false,
			expectedAddrType: &address.AddressTaproot{},
		},
		{
			name:        "unknown address type",
			accountName: "default",
			addrType:    waddrmgr.WitnessScript,
			expectErr:   true,
		},
		{
			name:        "imported account",
			accountName: waddrmgr.ImportedAddrAccountName,
			addrType:    waddrmgr.WitnessPubKey,
			expectErr:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, deps := createStartedWalletWithMocks(t)

			if tc.expectErr {
				_, err := w.NewAddress(
					t.Context(), tc.accountName,
					tc.addrType, tc.change,
				)
				require.Error(t, err)

				return
			}

			var addr address.Address
			switch tc.addrType {
			case waddrmgr.WitnessPubKey:
				addr, _ = address.NewAddressWitnessPubKeyHash(
					make([]byte, 20), w.cfg.ChainParams,
				)
			case waddrmgr.NestedWitnessPubKey:
				addr, _ = address.NewAddressScriptHash(
					make([]byte, 20), w.cfg.ChainParams,
				)
			case waddrmgr.TaprootPubKey:
				addr, _ = address.NewAddressTaproot(
					make([]byte, 32), w.cfg.ChainParams,
				)
			case waddrmgr.PubKeyHash, waddrmgr.Script,
				waddrmgr.RawPubKey, waddrmgr.WitnessScript,
				waddrmgr.TaprootScript:

				require.FailNow(t, "unhandled address type", tc.addrType)

			default:
				require.FailNow(t, "unknown address type", tc.addrType)
			}

			scope, err := tc.addrType.KeyScope()
			require.NoError(t, err)

			storeAddrType, err := addresstype.FromWallet(tc.addrType)
			require.NoError(t, err)

			expectStoreNewAddress(
				t, w, deps, tc.accountName, scope, tc.change, addr,
			)
			expectStoreAddressInfo(t, w, deps, addr,
				derivedAddressInfoFromAddr(
					t, addr, storeAddrType.Type, tc.accountName, scope,
					tc.change, 0, 0, nil,
				),
			)

			addr, err = w.NewAddress(
				t.Context(), tc.accountName,
				tc.addrType, tc.change,
			)
			require.NoError(t, err)
			require.NotNil(t, addr)

			require.IsType(t, tc.expectedAddrType, addr)

			addrInfo, err := w.GetAddressInfo(t.Context(), addr)
			require.NoError(t, err)
			require.Equal(t, tc.change, addrInfo.Internal)
		})
	}
}

// TestGetUnusedAddress tests the GetUnusedAddress method to ensure it
// correctly returns the earliest unused address.
func TestGetUnusedAddress(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	firstAddr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	scope := waddrmgr.KeyScopeBIP0084
	storeScope := db.KeyScope(scope)
	accountName := "default"
	req, err := addressPageRequest()
	require.NoError(t, err)

	deps.store.On(
		"IterAddresses", mock.Anything,
		db.ListAddressesQuery{
			WalletID:    w.id,
			AccountName: &accountName,
			Scope:       &storeScope,
			Page:        req,
		},
	).Return(addressIter(*derivedAddressInfoFromAddr(
		t, firstAddr, db.WitnessPubKey, "default", scope, false, 0, 0, nil,
	))).Once()

	unusedAddr, err := w.GetUnusedAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)
	require.Equal(t, firstAddr.String(), unusedAddr.String())

	usedFirstAddr := derivedAddressInfoFromAddr(
		t, firstAddr, db.WitnessPubKey, "default", scope, false,
		0, 0, nil,
	)
	usedFirstAddr.IsUsed = true

	deps.store.On(
		"IterAddresses", mock.Anything,
		db.ListAddressesQuery{
			WalletID:    w.id,
			AccountName: &accountName,
			Scope:       &storeScope,
			Page:        req,
		},
	).Return(addressIter(*usedFirstAddr)).Once()

	nextAddrVal, _ := address.NewAddressWitnessPubKeyHash(
		[]byte{
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
			11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		}, w.cfg.ChainParams,
	)
	expectStoreNewAddress(t, w, deps, "default", scope, false, nextAddrVal)

	nextAddr, err := w.GetUnusedAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// The next unused address should not be the same as the first one.
	require.NotEqual(t, firstAddr.String(), nextAddr.String())

	changeAddrVal, _ := address.NewAddressWitnessPubKeyHash(
		[]byte{
			21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
			31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		}, w.cfg.ChainParams,
	)

	deps.store.On(
		"IterAddresses", mock.Anything,
		db.ListAddressesQuery{
			WalletID:    w.id,
			AccountName: &accountName,
			Scope:       &storeScope,
			Page:        req,
		},
	).Return(addressIter(*derivedAddressInfoFromAddr(
		t, changeAddrVal, db.WitnessPubKey, "default", scope, true, 0, 0, nil,
	))).Once()

	unusedChangeAddr, err := w.GetUnusedAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, true,
	)
	require.NoError(t, err)
	require.Equal(t, changeAddrVal.String(), unusedChangeAddr.String())
}

// TestGetAddressInfo tests the GetAddressInfo method to ensure it returns
// information for both internal and external addresses.
func TestGetAddressInfo(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	extAddr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	expectStoreAddressInfo(t, w, deps, extAddr, derivedAddressInfoFromAddr(
		t, extAddr, db.WitnessPubKey, "default", waddrmgr.KeyScopeBIP0084,
		false, 0, 0, pubKey,
	))

	extInfo, err := w.GetAddressInfo(t.Context(), extAddr)
	require.NoError(t, err)

	require.Equal(t, extAddr.String(), extInfo.Addr.String())
	require.False(t, extInfo.Internal)
	require.True(t, extInfo.Compressed)
	require.False(t, extInfo.Imported)
	require.Equal(t, waddrmgr.WitnessPubKey, extInfo.AddrType)

	intAddr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	expectStoreAddressInfo(t, w, deps, intAddr, derivedAddressInfoFromAddr(
		t, intAddr, db.WitnessPubKey, "default", waddrmgr.KeyScopeBIP0084,
		true, 0, 0, pubKey,
	))

	intInfo, err := w.GetAddressInfo(t.Context(), intAddr)
	require.NoError(t, err)

	require.Equal(t, intAddr.String(), intInfo.Addr.String())
	require.True(t, intInfo.Internal)
	require.True(t, intInfo.Compressed)
	require.False(t, intInfo.Imported)
	require.Equal(t, waddrmgr.WitnessPubKey, intInfo.AddrType)
}

// TestGetDerivationInfoExternalAddressSuccess tests that we can successfully
// get the derivation info for an external address.
func TestGetDerivationInfoExternalAddressSuccess(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)
	addr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	privKey, _ := btcec.NewPrivateKey()
	pubKey := privKey.PubKey()

	scope := waddrmgr.KeyScopeBIP0084
	path := waddrmgr.DerivationPath{
		Account:              0,
		Branch:               0,
		Index:                0,
		MasterKeyFingerprint: 123,
	}
	expectStoreAddressInfo(t, w, deps, addr, derivedAddressInfoFromAddr(
		t, addr, db.WitnessPubKey, "default", scope, false, path.Index,
		path.MasterKeyFingerprint, pubKey,
	))

	derivationInfo, err := w.GetDerivationInfo(t.Context(), addr)

	require.NoError(t, err)
	require.NotNil(t, derivationInfo)

	expectedPath := []uint32{
		scope.Purpose + hdkeychain.HardenedKeyStart,
		scope.Coin + hdkeychain.HardenedKeyStart,
		path.Account + hdkeychain.HardenedKeyStart,
		path.Branch,
		path.Index,
	}

	require.Equal(t, pubKey.SerializeCompressed(), derivationInfo.PubKey)
	require.Equal(t, path.MasterKeyFingerprint,
		derivationInfo.MasterKeyFingerprint)
	require.Equal(t, expectedPath, derivationInfo.Bip32Path)
}

// TestGetDerivationInfoInternalAddressSuccess tests that we can successfully
// get the derivation info for an internal address.
func TestGetDerivationInfoInternalAddressSuccess(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)
	addr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	privKey, _ := btcec.NewPrivateKey()
	pubKey := privKey.PubKey()

	scope := waddrmgr.KeyScopeBIP0084
	path := waddrmgr.DerivationPath{
		Account:              0,
		Branch:               1,
		Index:                0,
		MasterKeyFingerprint: 123,
	}
	expectStoreAddressInfo(t, w, deps, addr, derivedAddressInfoFromAddr(
		t, addr, db.WitnessPubKey, "default", scope, true, path.Index,
		path.MasterKeyFingerprint, pubKey,
	))

	derivationInfo, err := w.GetDerivationInfo(t.Context(), addr)

	require.NoError(t, err)
	require.NotNil(t, derivationInfo)

	expectedPath := []uint32{
		scope.Purpose + hdkeychain.HardenedKeyStart,
		scope.Coin + hdkeychain.HardenedKeyStart,
		path.Account + hdkeychain.HardenedKeyStart,
		path.Branch,
		path.Index,
	}
	require.Equal(t, expectedPath, derivationInfo.Bip32Path)
	require.Equal(t, uint32(1), path.Branch)
}

// TestGetDerivationInfoNoDerivationInfo tests that we get an error when trying
// to get the derivation info for an address that is not in the wallet or is
// imported.
func TestGetDerivationInfoNoDerivationInfo(t *testing.T) {
	t.Parallel()

	// Arrange: Create a new test wallet and a key and address that is not
	// in the wallet.
	w, deps := createStartedWalletWithMocks(t)
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Act & Assert: Check that we get an error for an address not in the
	// wallet.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	deps.store.On(
		"GetAddress", mock.Anything,
		db.GetAddressQuery{
			WalletID:     w.id,
			ScriptPubKey: pkScript,
		},
	).Return(nil, errDBMock).Once()

	_, err = w.GetDerivationInfo(t.Context(), addr)
	require.Error(t, err)

	// Arrange: Import the key as a watch-only address.
	deps.store.On(
		"NewImportedAddress", mock.Anything,
		db.NewImportedAddressParams{
			WalletID:     w.id,
			Scope:        db.KeyScope(waddrmgr.KeyScopeBIP0084),
			AddressType:  db.WitnessPubKey,
			ScriptPubKey: pkScript,
			PubKey:       pubKey.SerializeCompressed(),
		},
	).Return(importedPubKeyAddressInfoFromAddr(
		t, addr, waddrmgr.KeyScopeBIP0084, pubKey,
	), nil).Once()
	deps.chain.On("NotifyReceived", []address.Address{addr}).
		Return(nil).Once()

	err = w.ImportPublicKey(t.Context(), pubKey, waddrmgr.WitnessPubKey)
	require.NoError(t, err)

	// Act & Assert: Check that we still get an error because it's an
	// imported key.
	expectStoreAddressInfo(t, w, deps, addr, importedPubKeyAddressInfoFromAddr(
		t, addr, waddrmgr.KeyScopeBIP0084, pubKey,
	))

	_, err = w.GetDerivationInfo(t.Context(), addr)
	require.ErrorIs(t, err, ErrDerivationPathNotFound)
}

// TestListAddresses tests the ListAddresses method to ensure it returns the
// correct addresses and balances for a given account.
func TestListAddresses(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	mockAddr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	expectStoreNewAddress(
		t, w, deps, "default", waddrmgr.KeyScopeBIP0084, false, mockAddr,
	)

	addr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	req, err := addressPageRequest()
	require.NoError(t, err)
	accountName := "default"
	storeScope := db.KeyScope(waddrmgr.KeyScopeBIP0084)

	deps.store.On(
		"IterAddresses", mock.Anything,
		db.ListAddressesQuery{
			WalletID:    w.id,
			AccountName: &accountName,
			Scope:       &storeScope,
			Page:        req,
		},
	).Return(addressIter(db.AddressInfo{ScriptPubKey: pkScript})).Once()
	deps.store.On(
		"ListUTXOs", mock.Anything, db.ListUtxosQuery{
			WalletID: w.id,
		},
	).Return([]db.UtxoInfo{{
		Amount:   1000,
		PkScript: pkScript,
	}}, nil).Once()

	addrs, err := w.ListAddresses(
		t.Context(), "default", waddrmgr.WitnessPubKey,
	)
	require.NoError(t, err)

	// We should have one address with a balance of 1000.
	require.Len(t, addrs, 1)
	require.Equal(t, addr.String(), addrs[0].Address.String())
	require.Equal(t, btcutil.Amount(1000), addrs[0].Balance)
}

// TestListAddressesImportedAlias tests that raw imported addresses are listed
// through the public imported alias without a scoped account selector.
func TestListAddressesImportedAlias(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	witnessAddr, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	scriptAddr, err := address.NewAddressWitnessScriptHash(
		make([]byte, 32), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	witnessScript, err := txscript.PayToAddrScript(witnessAddr)
	require.NoError(t, err)

	scriptScript, err := txscript.PayToAddrScript(scriptAddr)
	require.NoError(t, err)

	req, err := addressPageRequest()
	require.NoError(t, err)

	deps.store.On(
		"ListUTXOs", mock.Anything, db.ListUtxosQuery{
			WalletID: w.id,
		},
	).Return([]db.UtxoInfo{{
		Amount:   1000,
		PkScript: witnessScript,
	}, {
		Amount:   2000,
		PkScript: scriptScript,
	}}, nil).Once()

	deps.store.On(
		"IterAddresses", mock.Anything,
		db.ListAddressesQuery{
			WalletID: w.id,
			Page:     req,
		},
	).Return(addressIter(db.AddressInfo{
		ScriptPubKey: witnessScript,
		AddrType:     db.WitnessPubKey,
	}, db.AddressInfo{
		ScriptPubKey: scriptScript,
		AddrType:     db.WitnessScript,
		HasScript:    true,
	})).Once()

	addrs, err := w.ListAddresses(
		t.Context(), db.DefaultImportedAccountName,
		waddrmgr.WitnessPubKey,
	)
	require.NoError(t, err)
	require.Len(t, addrs, 1)
	require.Equal(t, witnessAddr.String(), addrs[0].Address.String())
	require.Equal(t, btcutil.Amount(1000), addrs[0].Balance)
}

// TestImportPublicKey tests the ImportPublicKey method to ensure it can
// import a public key as a watch-only address.
func TestImportPublicKey(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	addr, _ := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	deps.store.On(
		"NewImportedAddress", mock.Anything,
		db.NewImportedAddressParams{
			WalletID:     w.id,
			Scope:        db.KeyScope(waddrmgr.KeyScopeBIP0084),
			AddressType:  db.WitnessPubKey,
			ScriptPubKey: pkScript,
			PubKey:       pubKey.SerializeCompressed(),
		},
	).Return(importedPubKeyAddressInfoFromAddr(
		t, addr, waddrmgr.KeyScopeBIP0084, pubKey,
	), nil).Once()
	deps.chain.On("NotifyReceived", []address.Address{addr}).
		Return(nil).Once()

	err = w.ImportPublicKey(t.Context(), pubKey, waddrmgr.WitnessPubKey)
	require.NoError(t, err)

	expectStoreAddressInfo(t, w, deps, addr, importedPubKeyAddressInfoFromAddr(
		t, addr, waddrmgr.KeyScopeBIP0084, pubKey,
	))

	info, err := w.GetAddressInfo(t.Context(), addr)
	require.NoError(t, err)
	require.NotNil(t, info)
}

// TestImportTaprootScript tests the ImportTaprootScript method to ensure it can
// import a taproot script as a watch-only address.
func TestImportTaprootScript(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	// Create a new tapscript to import.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	script, err := txscript.NewScriptBuilder().
		AddData(pubKey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	leaf := txscript.NewTapLeaf(txscript.BaseLeafVersion, script)
	tree := txscript.AssembleTaprootScriptTree(leaf)
	rootHash := tree.RootNode.TapHash()
	tapscript := waddrmgr.Tapscript{
		Type: waddrmgr.TapscriptTypeFullTree,
		ControlBlock: &txscript.ControlBlock{
			InternalKey: pubKey,
		},
		Leaves: []txscript.TapLeaf{leaf},
	}

	addr, _ := address.NewAddressTaproot(
		schnorr.SerializePubKey(txscript.ComputeTaprootOutputKey(
			pubKey, rootHash[:],
		)), w.cfg.ChainParams,
	)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	encodedScript, err := waddrmgr.EncodeTaprootScript(&tapscript)
	require.NoError(t, err)

	encryptedScript := []byte("encrypted tapscript")
	deps.vault.On(
		"Encrypt", waddrmgr.CKTPublic, encodedScript,
	).Return(encryptedScript, nil).Once()
	deps.store.On("NewImportedAddress", mock.Anything,
		db.NewImportedAddressParams{
			WalletID:        w.id,
			Scope:           db.KeyScope(waddrmgr.KeyScopeBIP0086),
			AddressType:     db.TaprootPubKey,
			ScriptPubKey:    pkScript,
			EncryptedScript: encryptedScript,
		}).Return(&db.AddressInfo{
		AddrType:          db.TaprootPubKey,
		Origin:            db.ImportedAccount,
		IsImported:        true,
		HasDerivationPath: false,
		AccountName:       db.DefaultImportedAccountName,
		KeyScope:          db.KeyScope(waddrmgr.KeyScopeBIP0086),
		ScriptPubKey:      pkScript,
		HasScript:         true,
		IsWatchOnly:       true,
	}, nil).Once()
	deps.chain.On("NotifyReceived", []address.Address{addr}).
		Return(nil).Once()

	info, err := w.ImportTaprootScript(t.Context(), tapscript)
	require.NoError(t, err)
	require.Equal(t, addr, info.Addr)
	require.Equal(t, waddrmgr.TaprootScript, info.AddrType)
	require.True(t, info.Imported)
}

// TestScriptForOutput tests the ScriptForOutput method to ensure it returns the
// correct script for a given output.
func TestScriptForOutput(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	addr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	output := wire.TxOut{
		Value:    1000,
		PkScript: pkScript,
	}

	_, pubKey := deterministicPrivKey(t)
	expectStoreAddressInfo(t, w, deps, addr, derivedAddressInfoFromAddr(
		t, addr, db.WitnessPubKey, "default", waddrmgr.KeyScopeBIP0084,
		false, 0, 0, pubKey,
	))

	script, err := w.ScriptForOutput(t.Context(), output)
	require.NoError(t, err)

	// Check that the script is correct.
	require.Equal(t, addr, script.Addr)
	require.Equal(t, waddrmgr.WitnessPubKey, script.AddrType)
	require.Equal(t, pkScript, script.WitnessProgram)
	require.Nil(t, script.RedeemScript)
}

// TestScriptForOutputNestedWitness tests that ScriptForOutput carries the
// redeem script needed for nested witness outputs.
func TestScriptForOutputNestedWitness(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)
	_, pubKey := deterministicPrivKey(t)
	witnessProgram, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(address.Hash160(pubKey.SerializeCompressed())).
		Script()
	require.NoError(t, err)

	addr, err := address.NewAddressScriptHash(witnessProgram, w.cfg.ChainParams)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	expectedSigScript, err := txscript.NewScriptBuilder().
		AddData(witnessProgram).
		Script()
	require.NoError(t, err)

	expectStoreAddressInfo(t, w, deps, addr, derivedAddressInfoFromAddr(
		t, addr, db.NestedWitnessPubKey, "default",
		waddrmgr.KeyScopeBIP0049Plus, false, 0, 0, pubKey,
	))

	scriptInfo, err := w.ScriptForOutput(t.Context(), wire.TxOut{
		Value:    1000,
		PkScript: pkScript,
	})
	require.NoError(t, err)
	require.Equal(t, addr, scriptInfo.Addr)
	require.Equal(t, waddrmgr.NestedWitnessPubKey,
		scriptInfo.AddrType)
	require.Equal(t, witnessProgram, scriptInfo.WitnessProgram)
	require.Equal(t, witnessProgram, scriptInfo.RedeemScript)
	require.Equal(t, expectedSigScript, scriptInfo.SigScript)
}
