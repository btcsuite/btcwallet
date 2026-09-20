// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build itest

package itest

import (
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// createTestAddressInfo independently derives address metadata from the
// fixture account and requested branch; only the chosen child index comes from
// allocation, since BIP32 permits the allocator to skip invalid children.
func createTestAddressInfo(h *bwtest.HarnessTest,
	account *wallet.AccountInfo, branch, index uint32) wallet.AddressInfo {

	h.Helper()

	// Deriving from the account XPub catches a result that returns a coherent
	// key and path belonging to the wrong account or branch.
	accountKey, err := hdkeychain.NewKeyFromString(string(account.PublicKey))
	require.NoError(h, err)
	branchKey, err := accountKey.Derive(branch)
	require.NoError(h, err)
	child, err := branchKey.Derive(index)
	require.NoError(h, err)
	pubKey, err := child.ECPubKey()
	require.NoError(h, err)

	// The persisted branch schema owns address encoding, independent of the
	// allocation result's key or the Store's address conversion.
	addrType := account.AddrSchema.ExternalAddrType
	if branch == 1 {
		addrType = account.AddrSchema.InternalAddrType
	}

	addr, err := addrType.AddrFromPubKeyBytes(
		pubKey.SerializeCompressed(), h.NetParams(),
	)
	require.NoError(h, err)

	return wallet.AddressInfo{
		Addr:       addr,
		AddrType:   addrType,
		Internal:   branch == 1,
		Compressed: true,
		PubKey:     pubKey,
		Derivation: &wallet.AddressDerivation{
			KeyScope:             account.KeyScope,
			Account:              uint32(*account.AccountNumber),
			Branch:               branch,
			Index:                index,
			MasterKeyFingerprint: uint32(*account.MasterKeyFingerprint),
		},
	}
}

// testAddressManagerAllocateKey verifies an excluded account's allocated keys
// match its XPub and retain complete point/list visibility after reopening.
func testAddressManagerAllocateKey(h *bwtest.HarnessTest) {
	// Modern kvdb cannot persist NoChainSync, so it cannot supply this fixture.
	//nolint:staticcheck // This guard excludes the deprecated backend.
	if *dbBackend == string(wallet.DBBackendKVDB) {
		h.Skip("NoChainSync key allocation requires SQL")
	}

	// Arrange: leave both branches unfunded so lookup balances remain zero
	// and no chain observation can stand in for persisted key ownership.
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	number := wallet.AccountNumber(7)
	account, err := w.NewAccount(ctx, wallet.NewAccountParams{
		Scope:         waddrmgr.KeyScopeBIP0084,
		Name:          "allocated keys",
		AccountNumber: &number,
		NoChainSync:   true,
	})
	require.NoError(h, err)

	var manager wallet.AddressManager = w

	selector := wallet.NewAccountSelectorByNumber(account.KeyScope, number)
	wantInfo := make([]wallet.AddressInfo, 0, 2)
	wantList := make([]wallet.AddressProperty, 0, 2)

	for branch := range uint32(2) {
		// Act: use the public key-only operation on each branch, rather
		// than a receiving call that cannot serve excluded accounts.
		key, err := manager.AllocateNextKey(ctx, selector, branch == 1)

		// Assert: the fixture's XPub and requested branch define the key
		// and origin independently of the allocator's returned metadata.
		require.NoError(h, err)
		want := createTestAddressInfo(h, account, branch, key.Index)
		require.Equal(h, &wallet.AllocatedKey{
			PubKey: want.PubKey,
			Branch: branch,
			Index:  want.Derivation.Index,
			Origin: &wallet.KeyOrigin{
				KeyScope:             account.KeyScope,
				Account:              uint32(number),
				MasterKeyFingerprint: want.Derivation.MasterKeyFingerprint,
			},
		}, key)

		info, err := manager.GetAddressInfo(ctx, want.Addr)
		require.NoError(h, err)
		require.Equal(h, want, info)
		wantInfo = append(wantInfo, want)
		wantList = append(wantList, wallet.AddressProperty{
			Address: want.Addr,
		})
	}

	// The account-filtered list proves membership and zero balances without
	// assuming an ordering contract for the two allocated branches.
	listed, err := manager.ListAddresses(
		ctx, account.AccountName, account.AddrSchema.ExternalAddrType,
	)
	require.NoError(h, err)
	require.ElementsMatch(h, wantList, listed)

	// Act: replace the entire wallet/manager through the harness so cached
	// ownership cannot mask a missing persisted child or derivation path.
	w = h.ReloadWallet(w)
	manager = w

	// Assert: the same independently derived address facts and list entries
	// survive reopening, including the unfunded children's zero balances.
	for _, want := range wantInfo {
		info, err := manager.GetAddressInfo(ctx, want.Addr)
		require.NoError(h, err)
		require.Equal(h, want, info)
	}

	listed, err = manager.ListAddresses(
		ctx, account.AccountName, account.AddrSchema.ExternalAddrType,
	)
	require.NoError(h, err)
	require.ElementsMatch(h, wantList, listed)
}
