// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestAddressInfoFromManagedAddressPubKey verifies conversion of a managed
// pubkey address into wallet-owned metadata.
func TestAddressInfoFromManagedAddressPubKey(t *testing.T) {
	t.Parallel()

	// Arrange: Create one managed pubkey address mock with derivation data.
	_, mocks := createStartedWalletWithMocks(t)
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(privKey.PubKey().SerializeCompressed()),
		&chainParams,
	)
	require.NoError(t, err)

	mocks.pubKeyAddr.On("Address").Return(addr).Once()
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()
	mocks.pubKeyAddr.On("Imported").Return(false).Once()
	mocks.pubKeyAddr.On("Internal").Return(true).Once()
	mocks.pubKeyAddr.On("Compressed").Return(true).Once()
	mocks.pubKeyAddr.On("PubKey").Return(privKey.PubKey()).Once()
	mocks.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScopeBIP0084,
		waddrmgr.DerivationPath{
			Account:              1,
			Branch:               1,
			Index:                7,
			MasterKeyFingerprint: 99,
		},
		true,
	).Once()

	// Act: Convert the managed address into wallet-owned metadata.
	info, err := addressInfoFromManagedAddress(mocks.pubKeyAddr)
	require.NoError(t, err)

	// Assert: The converted metadata retains the managed address fields and
	// derivation information.
	require.Equal(t, addr, info.Addr)
	require.Equal(t, waddrmgr.WitnessPubKey, info.AddrType)
	require.False(t, info.Imported)
	require.True(t, info.Internal)
	require.True(t, info.Compressed)
	require.Equal(t, privKey.PubKey(), info.PubKey)
	require.NotNil(t, info.Derivation)
	require.Equal(t, waddrmgr.KeyScopeBIP0084, info.Derivation.KeyScope)
	require.Equal(t, uint32(1), info.Derivation.Account)
	require.Equal(t, uint32(1), info.Derivation.Branch)
	require.Equal(t, uint32(7), info.Derivation.Index)
	require.Equal(t, uint32(99), info.Derivation.MasterKeyFingerprint)
}
