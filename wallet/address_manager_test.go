// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
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
		expectErr     bool
	}{
		{
			name:     "witness pubkey",
			addrType: waddrmgr.WitnessPubKey,
			expectedScope: waddrmgr.KeyScope{
				Purpose: 84,
				Coin:    0,
			},
			expectErr: false,
		},
		{
			name:     "nested witness pubkey",
			addrType: waddrmgr.NestedWitnessPubKey,
			expectedScope: waddrmgr.KeyScope{
				Purpose: 49,
				Coin:    0,
			},
			expectErr: false,
		},
		{
			name:     "taproot pubkey",
			addrType: waddrmgr.TaprootPubKey,
			expectedScope: waddrmgr.KeyScope{
				Purpose: 86,
				Coin:    0,
			},
			expectErr: false,
		},
		{
			name:      "unknown address type",
			addrType:  waddrmgr.PubKeyHash,
			expectErr: true,
		},
	}

	w := &Wallet{}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scope, err := w.keyScopeFromAddrType(tc.addrType)
			if tc.expectErr {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnknownAddrType)
				return
			}

			require.NoError(t, err)
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
	defer cleanup()

	// Define a set of test cases to cover different address types and
	// scenarios.
	testCases := []struct {
		name      string
		account   string
		addrType  waddrmgr.AddressType
		change    bool
		expectErr bool
	}{
		// A test case for generating a p2wkh address.
		{
			name:     "default account p2wkh",
			account:  "default",
			addrType: waddrmgr.WitnessPubKey,
			change:   false,
		},
		// A test case for generating a p2wkh change address.
		{
			name:     "p2wkh change address",
			account:  "default",
			addrType: waddrmgr.WitnessPubKey,
			change:   true,
		},
		// A test case for generating a np2wkh address.
		{
			name:     "default account np2wkh",
			account:  "default",
			addrType: waddrmgr.NestedWitnessPubKey,
			change:   false,
		},
		// A test case for generating a p2tr address.
		{
			name:     "default account p2tr",
			account:  "default",
			addrType: waddrmgr.TaprootPubKey,
			change:   false,
		},
		// A test case for an unknown address type.
		{
			name:      "unknown address type",
			account:   "default",
			addrType:  waddrmgr.PubKeyHash,
			expectErr: true,
		},
		// A test case for the imported account, which does not support
		// address generation.
		{
			name:      "imported account",
			account:   waddrmgr.ImportedAddrAccountName,
			addrType:  waddrmgr.WitnessPubKey,
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Attempt to generate a new address with the specified
			// parameters.
			addr, err := w.NewAddress(
				context.Background(), tc.account, tc.addrType,
				tc.change,
			)

			// If an error is expected, assert that it occurs.
			if tc.expectErr {
				require.Error(t, err)
				return
			}

			// If no error is expected, assert that the address is
			// generated successfully and perform any additional
			// checks.
			require.NoError(t, err)
			require.NotNil(t, addr)

			// Verify that the address is of the correct type.
			switch tc.addrType {
			case waddrmgr.WitnessPubKey:
				require.IsType(
					t, &btcutil.AddressWitnessPubKeyHash{},
					addr,
				)
			case waddrmgr.NestedWitnessPubKey:
				require.IsType(
					t, &btcutil.AddressScriptHash{}, addr,
				)
			case waddrmgr.TaprootPubKey:
				require.IsType(
					t, &btcutil.AddressTaproot{}, addr,
				)
			}

			// Verify that the address is correctly marked as
			// internal or external.
			addrInfo, err := w.AddressInfoDeprecated(addr)
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
	defer cleanup()

	// Get a new address to start with.
	addr, err := w.NewAddress(
		context.Background(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// The first unused address should be the one we just created.
	unusedAddr, err := w.GetUnusedAddress(
		context.Background(), "default", waddrmgr.WitnessPubKey,
	)
	require.NoError(t, err)
	require.Equal(t, addr.String(), unusedAddr.String())

	// "Use" the address by creating a fake UTXO for it.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// We need to create a realistic transaction that has at least one
	// input.
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		dummyHash := chainhash.Hash{1}
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		rec, err := wtxmgr.NewTxRecordFromMsgTx(&wire.MsgTx{
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{
						Hash:  dummyHash,
						Index: 0,
					},
				},
			},
			TxOut: []*wire.TxOut{
				{
					PkScript: pkScript,
					Value:    1000,
				},
			},
		}, time.Now())
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
		context.Background(), "default", waddrmgr.WitnessPubKey,
	)
	require.NoError(t, err)

	// The next unused address should not be the same as the first one.
	require.NotEqual(t, addr.String(), nextAddr.String())
}

// TestAddressInfo tests the AddressInfo method to ensure it returns correct
// information for both internal and external addresses.
func TestAddressInfo(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	defer cleanup()

	// Get a new external address to test with.
	extAddr, err := w.NewAddress(
		context.Background(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// Get the address info for the external address.
	extInfo, err := w.AddressInfo(context.Background(), extAddr)
	require.NoError(t, err)

	// Check the external address info.
	require.Equal(t, extAddr.String(), extInfo.Address().String())
	require.False(t, extInfo.Internal())
	require.True(t, extInfo.Compressed())
	require.False(t, extInfo.Imported())
	require.Equal(t, waddrmgr.WitnessPubKey, extInfo.AddrType())

	// Get a new internal address to test with.
	intAddr, err := w.NewAddress(
		context.Background(), "default", waddrmgr.WitnessPubKey, true,
	)
	require.NoError(t, err)

	// Get the address info for the internal address.
	intInfo, err := w.AddressInfo(context.Background(), intAddr)
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
	defer cleanup()

	// Get a new address and give it a balance.
	addr, err := w.NewAddress(
		context.Background(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// "Use" the address by creating a fake UTXO for it.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// We need to create a realistic transaction that has at least one
	// input.
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		dummyHash := chainhash.Hash{1}
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		rec, err := wtxmgr.NewTxRecordFromMsgTx(&wire.MsgTx{
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{
						Hash:  dummyHash,
						Index: 0,
					},
				},
			},
			TxOut: []*wire.TxOut{
				{
					PkScript: pkScript,
					Value:    1000,
				},
			},
		}, time.Now())
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
		context.Background(), "default", waddrmgr.WitnessPubKey,
	)
	require.NoError(t, err)

	// We should have one address with a balance of 1000.
	require.Len(t, addrs, 1)
	require.Equal(t, addr.String(), addrs[0].Address.String())
	require.Equal(t, btcutil.Amount(1000), addrs[0].Balance)
}