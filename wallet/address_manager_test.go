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
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// TestKeyScopeFromAddrType tests the keyScopeFromAddrType method to ensure
// it correctly maps address types to their corresponding key scopes.
func TestKeyScopeFromAddrType(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		addrType      waddrmgr.AddressType
		expectedScope waddrmgr.KeyScope
		expectedErr   error
	}{
		{
			name:          "pubkey hash",
			addrType:      waddrmgr.PubKeyHash,
			expectedScope: waddrmgr.KeyScopeBIP0044,
			expectedErr:   nil,
		},
		{
			name:          "witness pubkey",
			addrType:      waddrmgr.WitnessPubKey,
			expectedScope: waddrmgr.KeyScopeBIP0084,
			expectedErr:   nil,
		},
		{
			name:          "nested witness pubkey",
			addrType:      waddrmgr.NestedWitnessPubKey,
			expectedScope: waddrmgr.KeyScopeBIP0049Plus,
			expectedErr:   nil,
		},
		{
			name:          "taproot pubkey",
			addrType:      waddrmgr.TaprootPubKey,
			expectedScope: waddrmgr.KeyScopeBIP0086,
			expectedErr:   nil,
		},
		{
			name:        "unknown address type",
			addrType:    waddrmgr.WitnessScript,
			expectedErr: ErrUnknownAddrType,
		},
	}

	w := &Wallet{}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scope, err := w.keyScopeFromAddrType(tc.addrType)
			require.ErrorIs(t, err, tc.expectedErr)
			require.Equal(t, tc.expectedScope, scope)
		})
	}
}

// TestNewAddress tests the NewAddress method, ensuring it can generate
// various address types for different accounts and correctly handles both
// internal and external address generation.
func TestNewAddress(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	t.Cleanup(cleanup)

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
			// Attempt to generate a new address with the specified
			// parameters.
			addr, err := w.NewAddress(
				t.Context(), tc.accountName,
				tc.addrType, tc.change,
			)

			// If an error is expected, assert that it occurs.
			if tc.expectErr {
				require.Error(t, err)
				return
			}

			// If no error is expected, assert that the address is
			// generated successfully and perform any
			// additional checks.
			require.NoError(t, err)
			require.NotNil(t, addr)

			// Verify that the address is of the correct type.
			require.IsType(t, tc.expectedAddrType, addr)

			// Verify that the address is correctly marked as
			// internal or external.
			addrInfo, err := w.AddressInfo(t.Context(), addr)
			require.NoError(t, err)
			require.Equal(t, tc.change, addrInfo.Internal())
		})
	}
}

// TestGetUnusedAddress tests the GetUnusedAddress method to ensure it
// correctly returns the earliest unused address.
func TestGetUnusedAddress(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	t.Cleanup(cleanup)

	// Get a new address to start with.
	addr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// The first unused address should be the one we just created.
	unusedAddr, err := w.GetUnusedAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)
	require.Equal(t, addr.String(), unusedAddr.String())

	// "Use" the address by creating a fake UTXO for it.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// We need to create a realistic transaction that has at least one
	// input.
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
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
	nextAddr, err := w.GetUnusedAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// The next unused address should not be the same as the first one.
	require.NotEqual(t, addr.String(), nextAddr.String())

	// Now, let's test the change address.
	changeAddr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, true,
	)
	require.NoError(t, err)

	// The first unused change address should be the one we just created.
	unusedChangeAddr, err := w.GetUnusedAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, true,
	)
	require.NoError(t, err)
	require.Equal(t, changeAddr.String(), unusedChangeAddr.String())
}

// TestAddressInfo tests the AddressInfo method to ensure it returns correct
// information for both internal and external addresses.
func TestAddressInfo(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	t.Cleanup(cleanup)

	// Get a new external address to test with.
	extAddr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// Get the address info for the external address.
	extInfo, err := w.AddressInfo(t.Context(), extAddr)
	require.NoError(t, err)

	// Check the external address info.
	require.Equal(t, extAddr.String(), extInfo.Address().String())
	require.False(t, extInfo.Internal())
	require.True(t, extInfo.Compressed())
	require.False(t, extInfo.Imported())
	require.Equal(t, waddrmgr.WitnessPubKey, extInfo.AddrType())

	// Get a new internal address to test with.
	intAddr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, true,
	)
	require.NoError(t, err)

	// Get the address info for the internal address.
	intInfo, err := w.AddressInfo(t.Context(), intAddr)
	require.NoError(t, err)

	// Check the internal address info.
	require.Equal(t, intAddr.String(), intInfo.Address().String())
	require.True(t, intInfo.Internal())
	require.True(t, intInfo.Compressed())
	require.False(t, intInfo.Imported())
	require.Equal(t, waddrmgr.WitnessPubKey, intInfo.AddrType())
}

// TestListAddresses tests the ListAddresses method to ensure it returns the
// correct addresses and balances for a given account.
func TestListAddresses(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	t.Cleanup(cleanup)

	// Get a new address and give it a balance.
	addr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// "Use" the address by creating a fake UTXO for it.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// We need to create a realistic transaction that has at least one
	// input.
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
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
	w, cleanup := testWallet(t)
	t.Cleanup(cleanup)

	// Create a new public key to import.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	// Import the public key.
	err = w.ImportPublicKey(
		t.Context(), pubKey, waddrmgr.WitnessPubKey,
	)
	require.NoError(t, err)

	// Check that the address is now managed by the wallet.
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), w.chainParams,
	)
	require.NoError(t, err)
	managed, err := w.HaveAddress(addr)
	require.NoError(t, err)
	require.True(t, managed)
}

// TestImportTaprootScript tests the ImportTaprootScript method to ensure it can
// import a taproot script as a watch-only address.
func TestImportTaprootScript(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	t.Cleanup(cleanup)

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
	_, err = w.ImportTaprootScript(t.Context(), tapscript)
	require.NoError(t, err)

	// Check that the address is now managed by the wallet.
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(txscript.ComputeTaprootOutputKey(
			pubKey, rootHash[:],
		)), w.chainParams,
	)
	require.NoError(t, err)
	managed, err := w.HaveAddress(addr)
	require.NoError(t, err)
	require.True(t, managed)
}

// TestScriptForOutput tests the ScriptForOutput method to ensure it returns the
// correct script for a given output.
func TestScriptForOutput(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	t.Cleanup(cleanup)

	// Create a new p2wkh address and output.
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
	script, err := w.ScriptForOutput(t.Context(), output)
	require.NoError(t, err)

	// Check that the script is correct.
	require.Equal(t, pkScript, script.WitnessProgram)
	require.Nil(t, script.RedeemScript)
}
