// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build itest

package itest

import (
	"sync"

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

// testAddressManagerAllocateKeyConcurrent verifies unused custom-scope keys
// have distinct durable locators across concurrent requests and wallet reopen.
func testAddressManagerAllocateKeyConcurrent(h *bwtest.HarnessTest) {
	// Exclusion is a persisted SQL account property that kvdb cannot express.
	//nolint:staticcheck // This guard excludes the deprecated backend.
	if *dbBackend == string(wallet.DBBackendKVDB) {
		h.Skip("NoChainSync key allocation requires SQL")
	}

	// Arrange: a numbered key-family account has no chain history; allocating
	// a later child must depend on persisted progress, not observed usage.
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	number := wallet.AccountNumber(7)
	account, err := w.NewAccount(ctx, wallet.NewAccountParams{
		Scope: waddrmgr.KeyScope{
			Purpose: 1017,
			Coin:    h.NetParams().HDCoinType,
		},
		AddrSchema: &waddrmgr.ScopeAddrSchema{
			ExternalAddrType: waddrmgr.WitnessPubKey,
			InternalAddrType: waddrmgr.WitnessPubKey,
		},
		Name:          "concurrent keys",
		AccountNumber: &number,
		NoChainSync:   true,
	})
	require.NoError(h, err)

	// Each caller owns one result slot, so no shared map or assertion runs
	// in a child goroutine. Joining all callers also makes reload safe.
	type allocation struct {
		key *wallet.AllocatedKey
		err error
	}

	const perBranch = 3

	var manager wallet.AddressManager = w

	selector := wallet.NewAccountSelectorByNumber(account.KeyScope, number)
	results := make([]allocation, 2*perBranch)
	callers := &sync.WaitGroup{}

	// Act: multiple callers request fresh children from both branches, and
	// each public call must finish before its result is inspected.
	for i := range results {
		callers.Add(1)

		go func() {
			defer callers.Done()

			results[i].key, results[i].err = manager.AllocateNextKey(
				ctx, selector, i >= perBranch,
			)
		}()
	}

	callers.Wait()

	// Assert: independent XPub derivation verifies every returned key and
	// origin. Distinct paths need not be contiguous or follow caller order.
	wantOrigin := &wallet.KeyOrigin{
		KeyScope:             account.KeyScope,
		Account:              uint32(number),
		MasterKeyFingerprint: uint32(*account.MasterKeyFingerprint),
	}
	seenPaths := make(map[[2]uint32]bool)
	seenKeys := make(map[string]bool)
	wantInfo := make([]wallet.AddressInfo, 0, len(results))

	var lastIndex [2]uint32

	for i, result := range results {
		require.NoError(h, result.err)
		key := result.key
		branch := uint32(i / perBranch)
		want := createTestAddressInfo(h, account, branch, key.Index)
		require.Equal(h, &wallet.AllocatedKey{
			PubKey: want.PubKey,
			Branch: branch,
			Index:  want.Derivation.Index,
			Origin: wantOrigin,
		}, key)

		path := [2]uint32{branch, key.Index}
		require.NotContains(h, seenPaths, path)
		seenPaths[path] = true
		serialized := string(key.PubKey.SerializeCompressed())
		require.NotContains(h, seenKeys, serialized)
		seenKeys[serialized] = true
		lastIndex[branch] = max(lastIndex[branch], key.Index)

		wantInfo = append(wantInfo, want)
	}

	// Act: replace the wallet and its manager to force subsequent allocation
	// and point lookup to use the persisted children and branch progress.
	w = h.ReloadWallet(w)
	manager = w

	// Assert: custom scopes cannot be selected by ListAddresses' address-type
	// argument; complete point metadata proves account membership here.
	for _, want := range wantInfo {
		info, err := manager.GetAddressInfo(ctx, want.Addr)
		require.NoError(h, err)
		require.Equal(h, want, info)
	}

	for branch := range uint32(2) {
		// Act: request another child while all previous ones remain
		// unfunded, so an oldest-unused implementation would reuse one.
		key, err := manager.AllocateNextKey(ctx, selector, branch == 1)

		// Assert: neither the locator nor public key can repeat, and the
		// new result must still match the original account XPub.
		require.NoError(h, err)
		want := createTestAddressInfo(h, account, branch, key.Index)
		require.Equal(h, &wallet.AllocatedKey{
			PubKey: want.PubKey,
			Branch: branch,
			Index:  want.Derivation.Index,
			Origin: wantOrigin,
		}, key)
		require.Greater(h, key.Index, lastIndex[branch])
		require.NotContains(
			h, seenKeys, string(key.PubKey.SerializeCompressed()),
		)
	}
}
