// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
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
	defer cleanup()

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
				context.Background(), tc.accountName,
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
			addrInfo, err := w.AddressInfo(addr)
			require.NoError(t, err)
			require.Equal(t, tc.change, addrInfo.Internal())
		})
	}
}
