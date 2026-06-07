// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
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

	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(privKey.PubKey().SerializeCompressed()),
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

// TestAddressInfoFromStoreAddress verifies that the store-backed mapper
// classifies addresses by their derivation path rather than account
// provenance: imported-xpub watch-only children are genuinely HD and must be
// treated like derived-account children (Internal taken from the branch,
// derivation info populated, never flagged Imported), while only a raw single
// import (no derivation path) is a true non-HD imported address.
func TestAddressInfoFromStoreAddress(t *testing.T) {
	t.Parallel()

	// storeAddr builds a store address record whose pkscript and pubkey
	// belong to a freshly generated key, then applies the test-case
	// overrides.
	storeAddr := func(t *testing.T,
		mutate func(*db.AddressInfo)) *db.AddressInfo {

		t.Helper()

		privKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		pubKey := privKey.PubKey()

		addr, err := btcutil.NewAddressWitnessPubKeyHash(
			btcutil.Hash160(pubKey.SerializeCompressed()),
			&chainParams,
		)
		require.NoError(t, err)

		pkScript, err := txscript.PayToAddrScript(addr)
		require.NoError(t, err)

		info := &db.AddressInfo{
			ScriptPubKey: pkScript,
			AddrType:     db.WitnessPubKey,
			PubKey:       pubKey.SerializeCompressed(),
			KeyScope:     db.KeyScope(waddrmgr.KeyScopeBIP0084),
		}
		mutate(info)

		return info
	}

	tests := []struct {
		name         string
		mutate       func(*db.AddressInfo)
		wantImported bool
		wantInternal bool
		wantDeriv    bool
		wantBranch   uint32
		wantIndex    uint32
	}{
		{
			// An imported-xpub external child carries a real path,
			// so it is HD: derivation populated, not imported, and
			// external (branch 0) so not internal.
			name: "imported-xpub HD external",
			mutate: func(info *db.AddressInfo) {
				info.Origin = db.ImportedAccount
				info.AccountName = "watch-only"
				info.AccountNumber = 3
				info.Branch = waddrmgr.ExternalBranch
				info.Index = 5
				info.HasDerivationPath = true
			},
			wantImported: false,
			wantInternal: false,
			wantDeriv:    true,
			wantBranch:   waddrmgr.ExternalBranch,
			wantIndex:    5,
		},
		{
			// An imported-xpub internal child is HD and change, so
			// it must be flagged internal from its branch even
			// though the account origin is imported.
			name: "imported-xpub HD internal",
			mutate: func(info *db.AddressInfo) {
				info.Origin = db.ImportedAccount
				info.AccountName = "watch-only"
				info.AccountNumber = 3
				info.Branch = waddrmgr.InternalBranch
				info.Index = 8
				info.HasDerivationPath = true
			},
			wantImported: false,
			wantInternal: true,
			wantDeriv:    true,
			wantBranch:   waddrmgr.InternalBranch,
			wantIndex:    8,
		},
		{
			// A raw single import has no chain position, so it is
			// the only address flagged Imported and carries no
			// derivation info.
			name: "raw import",
			mutate: func(info *db.AddressInfo) {
				info.Origin = db.ImportedAccount
				info.AccountName = db.DefaultImportedAccountName
				info.HasDerivationPath = false
			},
			wantImported: true,
			wantInternal: false,
			wantDeriv:    false,
		},
		{
			// A normal derived child is HD and classified by its
			// branch, identical to the imported-xpub HD cases.
			name: "derived internal",
			mutate: func(info *db.AddressInfo) {
				info.Origin = db.DerivedAccount
				info.AccountName = "default"
				info.AccountNumber = 0
				info.Branch = waddrmgr.InternalBranch
				info.Index = 2
				info.HasDerivationPath = true
			},
			wantImported: false,
			wantInternal: true,
			wantDeriv:    true,
			wantBranch:   waddrmgr.InternalBranch,
			wantIndex:    2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Build the store address for this case.
			addr := storeAddr(t, tc.mutate)

			// Act: Convert it into wallet-owned metadata.
			info, err := addressInfoFromStoreAddress(
				addr, &chainParams,
			)
			require.NoError(t, err)

			// Assert: Classification matches HD vs raw-import
			// expectations, and derivation info is populated only
			// for HD addresses.
			require.Equal(t, tc.wantImported, info.Imported)
			require.Equal(t, tc.wantInternal, info.Internal)

			if !tc.wantDeriv {
				require.Nil(t, info.Derivation)

				return
			}

			require.NotNil(t, info.Derivation)
			require.Equal(t, tc.wantBranch, info.Derivation.Branch)
			require.Equal(t, tc.wantIndex, info.Derivation.Index)
		})
	}
}
