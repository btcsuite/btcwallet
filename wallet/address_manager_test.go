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
			addrInfo, err := w.AddressInfo(addr)
			require.NoError(t, err)
			require.Equal(t, tc.change, addrInfo.Internal())
		})
	}
}
