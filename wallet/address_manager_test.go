// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestNewAddress tests the NewAddress method, ensuring it can generate
// various address types for different accounts and correctly handles both
// internal and external address generation.
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
		expectedAddrType btcutil.Address
	}{
		{
			name:             "default account p2wkh",
			accountName:      "default",
			addrType:         waddrmgr.WitnessPubKey,
			change:           false,
			expectedAddrType: &btcutil.AddressWitnessPubKeyHash{},
		},
		{
			name:             "p2wkh change address",
			accountName:      "default",
			addrType:         waddrmgr.WitnessPubKey,
			change:           true,
			expectedAddrType: &btcutil.AddressWitnessPubKeyHash{},
		},
		{
			name:             "default account np2wkh",
			accountName:      "default",
			addrType:         waddrmgr.NestedWitnessPubKey,
			change:           false,
			expectedAddrType: &btcutil.AddressScriptHash{},
		},
		{
			name:             "default account p2tr",
			accountName:      "default",
			addrType:         waddrmgr.TaprootPubKey,
			change:           false,
			expectedAddrType: &btcutil.AddressTaproot{},
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

			// Create a new test wallet for each test case.
			w, deps := createStartedWalletWithMocks(t)

			// Setup mock expectations.
			if tc.expectErr {
				// Attempt to generate a new address with the specified
				// parameters.
				_, err := w.NewAddress(
					t.Context(), tc.accountName,
					tc.addrType, tc.change,
				)
				require.Error(t, err)

				return
			}

			var addr btcutil.Address
			switch tc.addrType {
			case waddrmgr.WitnessPubKey:
				addr, _ = btcutil.NewAddressWitnessPubKeyHash(
					make([]byte, 20), w.cfg.ChainParams,
				)
			case waddrmgr.NestedWitnessPubKey:
				addr, _ = btcutil.NewAddressScriptHash(
					make([]byte, 20), w.cfg.ChainParams,
				)
			case waddrmgr.TaprootPubKey:
				addr, _ = btcutil.NewAddressTaproot(
					make([]byte, 32), w.cfg.ChainParams,
				)
			case waddrmgr.PubKeyHash, waddrmgr.Script,
				waddrmgr.RawPubKey, waddrmgr.WitnessScript,
				waddrmgr.TaprootScript:

				require.FailNow(t, "unhandled address type", tc.addrType)

			default:
				require.FailNow(t, "unknown address type", tc.addrType)
			}

			deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
				Return(deps.accountManager, nil).
				Once()
			deps.addrStore.On("Address", mock.Anything, addr).
				Return(deps.addr, nil).
				Once()

			deps.accountManager.On(
				"NewAddress", mock.Anything, tc.accountName, tc.change,
			).Return(addr, nil).Once()

			deps.chain.On("NotifyReceived", []btcutil.Address{addr}).
				Return(nil).
				Once()

			deps.addr.On("Address").Return(addr).Once()
			deps.addr.On("AddrType").Return(tc.addrType).Once()
			deps.addr.On("Imported").Return(false).Once()
			deps.addr.On("Internal").Return(tc.change).Once()
			deps.addr.On("Compressed").Return(true).Once()

			// Attempt to generate a new address with the specified
			// parameters.
			addr, err := w.NewAddress(
				t.Context(), tc.accountName,
				tc.addrType, tc.change,
			)
			require.NoError(t, err)
			require.NotNil(t, addr)

			// Verify that the address is of the correct type.
			require.IsType(t, tc.expectedAddrType, addr)

			// Verify that the address is correctly marked as
			// internal or external.
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

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// Get a new address to start with.
	mockAddr, _ := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("NewAddress", mock.Anything, "default", false).
		Return(mockAddr, nil).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{mockAddr}).
		Return(nil).Once()

	addr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// The first unused address should be the one we just created.
	// GetUnusedAddress calls:
	// - addrType.KeyScope
	// - w.addrStore.FetchScopedKeyManager
	// - w.findUnusedAddress (calls manager.LookupAccount and
	//   ForEachAccountAddress)
	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("LookupAccount", mock.Anything, "default").
		Return(uint32(0), nil).Once()

	deps.accountManager.On("ForEachAccountAddress", mock.Anything, uint32(0),
		mock.Anything).Run(func(args mock.Arguments) {
		f, ok := args.Get(2).(func(waddrmgr.ManagedAddress) error)
		require.True(t, ok)
		mockAddr1 := &mockManagedAddress{}
		mockAddr1.On("Internal").Return(false).Once()
		mockAddr1.On("Used", mock.Anything).Return(false).Once()
		mockAddr1.On("Address").Return(addr).Once()
		_ = f(mockAddr1)
	}).Return(errStopIteration).Once()

	unusedAddr, err := w.GetUnusedAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)
	require.Equal(t, addr.String(), unusedAddr.String())

	// "Use" the address by creating a fake UTXO for it.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Setup expectations for using the address.
	deps.txStore.On("InsertTx", mock.Anything, mock.Anything,
		mock.Anything).Return(nil).Once()
	deps.txStore.On("AddCredit", mock.Anything, mock.Anything,
		mock.Anything, uint32(0), false).Return(nil).Once()
	deps.addrStore.On("MarkUsed", mock.Anything, addr).Return(nil).Once()

	// We need to create a realistic transaction that has at least one
	// input.
	err = walletdb.Update(w.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		// Create a new transaction and set the output to the address
		// we want to mark as used.
		msgTx := TstTx.MsgTx()
		msgTx.TxOut = []*wire.TxOut{{
			PkScript: pkScript,
			Value:    1000,
		}}

		rec, err := wtxmgr.NewTxRecordFromMsgTx(msgTx, time.Now())
		if err != nil {
			return err
		}

		err = w.txStore.InsertTx(txmgrNs, rec, nil)
		if err != nil {
			return err
		}

		err = w.txStore.AddCredit(txmgrNs, rec, nil, 0, false)
		if err != nil {
			return err
		}

		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		return w.addrStore.MarkUsed(addrmgrNs, addr)
	})
	require.NoError(t, err)

	// Get the next unused address.
	// This time findUnusedAddress will find the first address as used, and
	// then we mock it returning nil for any more existing addresses,
	// triggering a NewAddress call.
	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Twice()

	deps.accountManager.On("LookupAccount", mock.Anything, "default").
		Return(uint32(0), nil).Once()

	deps.accountManager.On("ForEachAccountAddress", mock.Anything, uint32(0),
		mock.Anything).Run(func(args mock.Arguments) {
		f, ok := args.Get(2).(func(waddrmgr.ManagedAddress) error)
		require.True(t, ok)

		// First addr is used.
		mockAddr1 := &mockManagedAddress{}
		mockAddr1.On("Internal").Return(false).Once()
		mockAddr1.On("Used", mock.Anything).Return(true).Once()
		_ = f(mockAddr1)
	}).Return(nil).Once()

	nextAddrVal, _ := btcutil.NewAddressWitnessPubKeyHash(
		[]byte{
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
			11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		}, w.cfg.ChainParams,
	)
	deps.accountManager.On("NewAddress", mock.Anything, "default", false).
		Return(nextAddrVal, nil).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{nextAddrVal}).
		Return(nil).Once()

	nextAddr, err := w.GetUnusedAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// The next unused address should not be the same as the first one.
	require.NotEqual(t, addr.String(), nextAddr.String())

	// Now, let's test the change address.
	changeAddrVal, _ := btcutil.NewAddressWitnessPubKeyHash(
		[]byte{
			21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
			31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		}, w.cfg.ChainParams,
	)

	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("NewAddress", mock.Anything, "default", true).
		Return(changeAddrVal, nil).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{changeAddrVal}).
		Return(nil).Once()

	changeAddr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, true,
	)
	require.NoError(t, err)

	// The first unused change address should be the one we just created.
	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("LookupAccount", mock.Anything, "default").
		Return(uint32(0), nil).Once()

	deps.accountManager.On("ForEachAccountAddress", mock.Anything, uint32(0),
		mock.Anything).Run(func(args mock.Arguments) {
		f, ok := args.Get(2).(func(waddrmgr.ManagedAddress) error)
		require.True(t, ok)

		// First external addr (used).
		deps.addr.On("Internal").Return(false).Once()
		_ = f(deps.addr)

		// First internal addr (unused).
		mockAddr2 := &mockManagedAddress{}
		mockAddr2.On("Internal").Return(true).Once()
		mockAddr2.On("Used", mock.Anything).Return(false).Once()
		mockAddr2.On("Address").Return(changeAddrVal).Once()
		_ = f(mockAddr2)
	}).Return(errStopIteration).Once()

	unusedChangeAddr, err := w.GetUnusedAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, true,
	)
	require.NoError(t, err)
	require.Equal(t, changeAddr.String(), unusedChangeAddr.String())
}

// TestGetAddressInfo tests the GetAddressInfo method to ensure it returns
// information for both internal and external addresses.
func TestGetAddressInfo(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// Get a new external address to test with.
	var addr btcutil.Address

	addr, _ = btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("NewAddress", mock.Anything, "default", false).
		Return(addr, nil).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{addr}).
		Return(nil).Once()

	extAddr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// Get the address info for the external address.
	deps.addrStore.On("Address", mock.Anything, extAddr).
		Return(deps.addr, nil).Once()
	deps.addr.On("Address").Return(extAddr).Once()
	deps.addr.On("Internal").Return(false).Once()
	deps.addr.On("Compressed").Return(true).Once()
	deps.addr.On("Imported").Return(false).Once()
	deps.addr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()

	extInfo, err := w.GetAddressInfo(t.Context(), extAddr)
	require.NoError(t, err)

	// Check the external address info.
	require.Equal(t, extAddr.String(), extInfo.Addr.String())
	require.False(t, extInfo.Internal)
	require.True(t, extInfo.Compressed)
	require.False(t, extInfo.Imported)
	require.Equal(t, waddrmgr.WitnessPubKey, extInfo.AddrType)

	// Get a new internal address to test with.
	addr, _ = btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("NewAddress", mock.Anything, "default", true).
		Return(addr, nil).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{addr}).
		Return(nil).Once()

	intAddr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, true,
	)
	require.NoError(t, err)

	// Get the address info for the internal address.
	deps.addrStore.On("Address", mock.Anything, intAddr).
		Return(deps.addr, nil).Once()
	deps.addr.On("Address").Return(intAddr).Once()
	deps.addr.On("Internal").Return(true).Once()
	deps.addr.On("Compressed").Return(true).Once()
	deps.addr.On("Imported").Return(false).Once()
	deps.addr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()

	intInfo, err := w.GetAddressInfo(t.Context(), intAddr)
	require.NoError(t, err)

	// Check the internal address info.
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

	// Arrange: Create a new test wallet and a new p2wkh address to test
	// with.
	w, deps := createStartedWalletWithMocks(t)
	mockAddr, _ := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("NewAddress", mock.Anything, "default", false).
		Return(mockAddr, nil).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{mockAddr}).
		Return(nil).Once()

	addr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// Act: Get the derivation info for the address.
	deps.addrStore.On("Address", mock.Anything, addr).
		Return(deps.pubKeyAddr, nil).Once()
	deps.pubKeyAddr.On("Address").Return(addr).Once()
	deps.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()
	deps.pubKeyAddr.On("Imported").Return(false).Once()
	deps.pubKeyAddr.On("Internal").Return(false).Once()
	deps.pubKeyAddr.On("Compressed").Return(true).Once()

	privKey, _ := btcec.NewPrivateKey()
	pubKey := privKey.PubKey()
	deps.pubKeyAddr.On("PubKey").Return(pubKey).Once()

	scope := waddrmgr.KeyScopeBIP0084
	path := waddrmgr.DerivationPath{
		Account:              0,
		Branch:               0,
		Index:                0,
		MasterKeyFingerprint: 123,
	}
	deps.pubKeyAddr.On("DerivationInfo").Return(scope, path, true).Once()

	derivationInfo, err := w.GetDerivationInfo(t.Context(), addr)

	// Assert: Check that the correct derivation info is returned.
	require.NoError(t, err)
	require.NotNil(t, derivationInfo)

	expectedPath := []uint32{
		scope.Purpose + hdkeychain.HardenedKeyStart,
		scope.Coin + hdkeychain.HardenedKeyStart,
		path.Account,
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

	// Arrange: Create a new test wallet and a new p2wkh change address to
	// test with.
	w, deps := createStartedWalletWithMocks(t)
	mockAddr, _ := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("NewAddress", mock.Anything, "default", true).
		Return(mockAddr, nil).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{mockAddr}).
		Return(nil).Once()

	addr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, true,
	)
	require.NoError(t, err)

	// Act: Get the derivation info for the address.
	deps.addrStore.On("Address", mock.Anything, addr).
		Return(deps.pubKeyAddr, nil).Once()
	deps.pubKeyAddr.On("Address").Return(addr).Once()
	deps.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()
	deps.pubKeyAddr.On("Imported").Return(false).Once()
	deps.pubKeyAddr.On("Internal").Return(true).Once()
	deps.pubKeyAddr.On("Compressed").Return(true).Once()

	privKey, _ := btcec.NewPrivateKey()
	pubKey := privKey.PubKey()
	deps.pubKeyAddr.On("PubKey").Return(pubKey).Once()

	scope := waddrmgr.KeyScopeBIP0084
	path := waddrmgr.DerivationPath{
		Account:              0,
		Branch:               1,
		Index:                0,
		MasterKeyFingerprint: 123,
	}
	deps.pubKeyAddr.On("DerivationInfo").Return(scope, path, true).Once()

	derivationInfo, err := w.GetDerivationInfo(t.Context(), addr)

	// Assert: Check that the correct derivation info is returned.
	require.NoError(t, err)
	require.NotNil(t, derivationInfo)

	expectedPath := []uint32{
		scope.Purpose + hdkeychain.HardenedKeyStart,
		scope.Coin + hdkeychain.HardenedKeyStart,
		path.Account,
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
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Act & Assert: Check that we get an error for an address not in the
	// wallet.
	deps.addrStore.On("Address", mock.Anything, addr).Return(
		nil, errDBMock).Once()

	_, err = w.GetDerivationInfo(t.Context(), addr)
	require.Error(t, err)

	// Arrange: Import the key as a watch-only address.
	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("ImportPublicKey", mock.Anything, pubKey,
		mock.Anything).Return(deps.pubKeyAddr, nil).Once()
	deps.pubKeyAddr.On("Address").Return(addr).Twice()
	deps.chain.On("NotifyReceived", []btcutil.Address{addr}).
		Return(nil).Once()

	err = w.ImportPublicKey(t.Context(), pubKey, waddrmgr.WitnessPubKey)
	require.NoError(t, err)

	// Act & Assert: Check that we still get an error because it's an
	// imported key.
	deps.addrStore.On("Address", mock.Anything, addr).
		Return(deps.pubKeyAddr, nil).Once()
	deps.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()
	deps.pubKeyAddr.On("Imported").Return(true).Once()
	deps.pubKeyAddr.On("Internal").Return(false).Once()
	deps.pubKeyAddr.On("Compressed").Return(true).Once()
	deps.pubKeyAddr.On("PubKey").Return(pubKey).Once()
	deps.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScope{}, waddrmgr.DerivationPath{}, false,
	).Once()

	_, err = w.GetDerivationInfo(t.Context(), addr)
	require.ErrorIs(t, err, ErrDerivationPathNotFound)
}

// TestListAddresses tests the ListAddresses method to ensure it returns the
// correct addresses and balances for a given account.
func TestListAddresses(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// Get a new address and give it a balance.
	mockAddr, _ := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("NewAddress", mock.Anything, "default", false).
		Return(mockAddr, nil).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{mockAddr}).
		Return(nil).Once()

	addr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// We need to create a realistic transaction that has at least one
	// input.
	deps.txStore.On("InsertTx", mock.Anything, mock.Anything,
		mock.Anything).Return(nil).Once()
	deps.txStore.On("AddCredit", mock.Anything, mock.Anything,
		mock.Anything, uint32(0), false).Return(nil).Once()
	deps.addrStore.On("MarkUsed", mock.Anything, addr).Return(nil).Once()

	err = walletdb.Update(w.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		// Create a new transaction and set the output to the address
		// we want to mark as used.
		msgTx := TstTx.MsgTx()
		msgTx.TxOut = []*wire.TxOut{{
			PkScript: pkScript,
			Value:    1000,
		}}

		rec, err := wtxmgr.NewTxRecordFromMsgTx(msgTx, time.Now())
		if err != nil {
			return err
		}

		err = w.txStore.InsertTx(txmgrNs, rec, nil)
		if err != nil {
			return err
		}

		err = w.txStore.AddCredit(txmgrNs, rec, nil, 0, false)
		if err != nil {
			return err
		}

		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		return w.addrStore.MarkUsed(addrmgrNs, addr)
	})
	require.NoError(t, err)

	// List the addresses for the default account.
	deps.txStore.On("UnspentOutputs", mock.Anything).Return([]wtxmgr.Credit{
		{
			Amount:   1000,
			PkScript: pkScript,
		},
	}, nil).Once()

	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("LookupAccount", mock.Anything, "default").
		Return(uint32(0), nil).Once()

	deps.accountManager.On("ForEachAccountAddress", mock.Anything, uint32(0),
		mock.Anything).Run(func(args mock.Arguments) {
		f, ok := args.Get(2).(func(waddrmgr.ManagedAddress) error)
		require.True(t, ok)
		deps.addr.On("Address").Return(addr).Once()
		_ = f(deps.addr)
	}).Return(nil).Once()

	addrs, err := w.ListAddresses(
		t.Context(), "default", waddrmgr.WitnessPubKey,
	)
	require.NoError(t, err)

	// We should have one address with a balance of 1000.
	require.Len(t, addrs, 1)
	require.Equal(t, addr.String(), addrs[0].Address.String())
	require.Equal(t, btcutil.Amount(1000), addrs[0].Balance)
}

// TestImportPublicKey tests the ImportPublicKey method to ensure it can
// import a public key as a watch-only address.
func TestImportPublicKey(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// Create a new public key to import.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	// Import the public key.
	addr, _ := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)

	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("ImportPublicKey", mock.Anything, pubKey,
		mock.Anything).Return(deps.pubKeyAddr, nil).Once()
	deps.pubKeyAddr.On("Address").Return(addr).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{addr}).
		Return(nil).Once()

	err = w.ImportPublicKey(t.Context(), pubKey, waddrmgr.WitnessPubKey)
	require.NoError(t, err)

	// Check that the address is now managed by the wallet.
	deps.addrStore.On("Address", mock.Anything, addr).
		Return(deps.pubKeyAddr, nil).Once()
	deps.pubKeyAddr.On("Address").Return(addr).Once()
	deps.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()
	deps.pubKeyAddr.On("Imported").Return(true).Once()
	deps.pubKeyAddr.On("Internal").Return(false).Once()
	deps.pubKeyAddr.On("Compressed").Return(true).Once()
	deps.pubKeyAddr.On("PubKey").Return(pubKey).Once()
	deps.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScope{}, waddrmgr.DerivationPath{}, false,
	).Once()

	info, err := w.GetAddressInfo(t.Context(), addr)
	require.NoError(t, err)
	require.NotNil(t, info)
}

// TestImportTaprootScript tests the ImportTaprootScript method to ensure it can
// import a taproot script as a watch-only address.
func TestImportTaprootScript(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
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

	// Import the tapscript.
	addr, _ := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(txscript.ComputeTaprootOutputKey(
			pubKey, rootHash[:],
		)), w.cfg.ChainParams,
	)

	deps.addrStore.On("FetchScopedKeyManager", waddrmgr.KeyScopeBIP0086).
		Return(deps.accountManager, nil).Once()

	// SyncedTo is mocked in createStartedWalletWithMocks (height 1).
	deps.accountManager.On("ImportTaprootScript", mock.Anything,
		mock.Anything, mock.Anything, uint8(1), false).
		Return(deps.taprootAddr, nil).Once()
	deps.taprootAddr.On("Address").Return(addr).Twice()
	deps.taprootAddr.On("AddrType").Return(waddrmgr.TaprootScript).Once()
	deps.taprootAddr.On("Imported").Return(true).Once()
	deps.taprootAddr.On("Internal").Return(false).Once()
	deps.taprootAddr.On("Compressed").Return(false).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{addr}).
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

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// Create a new p2wkh address and output.
	mockAddr, _ := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	deps.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("NewAddress", mock.Anything, "default", false).
		Return(mockAddr, nil).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{mockAddr}).
		Return(nil).Once()

	addr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	output := wire.TxOut{
		Value:    1000,
		PkScript: pkScript,
	}

	// Get the script for the output.
	deps.addrStore.On("Address", mock.Anything, addr).
		Return(deps.pubKeyAddr, nil).Once()
	deps.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()

	script, err := w.ScriptForOutput(t.Context(), output)
	require.NoError(t, err)

	// Check that the script is correct.
	require.Equal(t, pkScript, script.WitnessProgram)
	require.Nil(t, script.RedeemScript)
}
