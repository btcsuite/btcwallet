// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build itest

package itest

import (
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/txscript/v2"
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

// createTestAddressInfos calculates the expected addresses and metadata from a
// fresh account's public key. Tests calculate these values before allocation so
// they can check the API's results independently.
func createTestAddressInfos(h *bwtest.HarnessTest,
	account *wallet.AccountInfo, internal bool,
	count uint32) []wallet.AddressInfo {

	h.Helper()

	// Persisted account identity and schema determine the expected path and
	// encoding; public derivation never needs private-key compatibility rules.
	xpub, err := hdkeychain.NewKeyFromString(string(account.PublicKey))
	require.NoError(h, err)

	branch := waddrmgr.ExternalBranch

	addrType := account.AddrSchema.ExternalAddrType
	if internal {
		branch = waddrmgr.InternalBranch
		addrType = account.AddrSchema.InternalAddrType
	}

	branchKey, err := xpub.Derive(branch)
	require.NoError(h, err)

	// These fixtures create fresh derived accounts, so the known first child
	// is zero and every expected result carries the account's full HD origin.
	want := make([]wallet.AddressInfo, 0, count)
	for index := range count {
		child, err := branchKey.Derive(index)
		require.NoError(h, err)

		pubKey, err := child.ECPubKey()
		require.NoError(h, err)

		addr, err := addrType.AddrFromPubKeyBytes(
			pubKey.SerializeCompressed(), h.NetParams(),
		)
		require.NoError(h, err)

		want = append(want, wallet.AddressInfo{
			Addr:       addr,
			AddrType:   addrType,
			Internal:   internal,
			Compressed: true,
			PubKey:     pubKey,
			Derivation: &wallet.AddressDerivation{
				KeyScope: account.KeyScope,
				Account:  uint32(*account.AccountNumber),
				Branch:   branch,
				Index:    index,
				MasterKeyFingerprint: uint32(
					*account.MasterKeyFingerprint,
				),
			},
		})
	}

	return want
}

// testAddressManagerAllocateBatch proves ordered SQL batches and their complete
// public metadata survive reopening without reusing previously delivered keys.
func testAddressManagerAllocateBatch(h *bwtest.HarnessTest) {
	// Kvdb cannot allocate atomic batches; its refusal is a separate contract.
	//nolint:staticcheck // This guard intentionally selects legacy kvdb.
	if *dbBackend == string(wallet.DBBackendKVDB) {
		h.Skip("address batches require SQL")
	}

	// The count endpoints also exercise each branch without multiplying the
	// same batch contract across unrelated address-type or selector variants.
	tests := []struct {
		name     string
		count    uint32
		internal bool
	}{
		{
			name:  "single external",
			count: 1,
		},
		{
			name:     "maximum internal",
			count:    wallet.MaxBulkAddressCount,
			internal: true,
		},
	}

	// Each row owns its database and wallet name, including reload cleanup.
	for _, tc := range tests {
		h.Run(tc.name, func(t *testing.T) {
			h := h.Subtest(t)

			// Arrange: derive the whole expected batch and its successor
			// from an empty account before any receiving API can allocate.
			const accountName = "batch account"

			ctx := h.Context()
			scope := waddrmgr.KeyScopeBIP0084
			w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
			_, err := w.NewAccount(ctx, wallet.NewAccountParams{
				Scope: scope,
				Name:  accountName,
			})
			require.NoError(h, err)

			account, err := w.GetAccount(ctx, scope, accountName)
			require.NoError(h, err)
			require.Zero(h, account.ExternalKeyCount)
			require.Zero(h, account.InternalKeyCount)

			listed, err := w.ListAddresses(
				ctx, accountName, waddrmgr.WitnessPubKey,
			)
			require.NoError(h, err)
			require.Empty(h, listed)

			want := createTestAddressInfos(
				h, account, tc.internal, tc.count+1,
			)
			selector := wallet.NewAccountSelectorByName(scope, accountName)

			// Act: one public call must deliver the entire usable batch.
			batch, err := w.NewBulkAddresses(
				ctx, selector, tc.internal, tc.count,
			)

			// Assert: independent ordered equality detects wrong keys,
			// partial delivery, and metadata copied from another branch.
			require.NoError(h, err)
			require.Equal(h, want[:tc.count], batch)

			// Only the selected branch may advance; the list has no promised
			// ordering, and these unfunded addresses all have zero balances.
			wantAccount := *account
			if tc.internal {
				wantAccount.InternalKeyCount = tc.count
			} else {
				wantAccount.ExternalKeyCount = tc.count
			}

			wantList := make([]wallet.AddressProperty, 0, tc.count)
			for _, info := range want[:tc.count] {
				wantList = append(wantList, wallet.AddressProperty{
					Address: info.Addr,
				})
			}

			// Check synchronous visibility first, then the identical full
			// public state through a fresh Wallet loaded from durable data.
			for _, reopen := range []bool{false, true} {
				if reopen {
					w = h.ReloadWallet(w)
				}

				for _, expected := range want[:tc.count] {
					info, err := w.GetAddressInfo(ctx, expected.Addr)
					require.NoError(h, err)
					require.Equal(h, expected, info)
				}

				listed, err := w.ListAddresses(
					ctx, accountName, waddrmgr.WitnessPubKey,
				)
				require.NoError(h, err)
				require.ElementsMatch(h, wantList, listed)

				gotAccount, err := w.GetAccount(ctx, scope, accountName)
				require.NoError(h, err)
				require.Equal(h, wantAccount, *gotAccount)
			}

			// A fresh batch after reopen must continue past the delivered
			// children even though none was used, proving durable progress.
			next, err := w.NewBulkAddresses(ctx, selector, tc.internal, 1)
			require.NoError(h, err)
			require.Equal(h, want[tc.count:], next)
		})
	}
}

// testAddressManagerRejectSQLBatch proves invalid counts precede receiving
// policy checks and every rejected request leaves public state unchanged.
func testAddressManagerRejectSQLBatch(h *bwtest.HarnessTest) {
	// Excluded accounts are SQL-only; kvdb refusal has its own fixture.
	//nolint:staticcheck // This guard intentionally selects legacy kvdb.
	if *dbBackend == string(wallet.DBBackendKVDB) {
		h.Skip("excluded account batch checks require SQL")
	}

	// Invalid counts must retain their identity even when the account would
	// refuse a valid receiving request because chain synchronization is off.
	tests := []struct {
		name        string
		count       uint32
		noChainSync bool
		wantErr     error
	}{
		{
			name:    "ordinary zero",
			count:   0,
			wantErr: wallet.ErrInvalidParam,
		},
		{
			name:    "ordinary over maximum",
			count:   wallet.MaxBulkAddressCount + 1,
			wantErr: wallet.ErrInvalidParam,
		},
		{
			name:        "excluded zero",
			count:       0,
			noChainSync: true,
			wantErr:     wallet.ErrInvalidParam,
		},
		{
			name:        "excluded over maximum",
			count:       wallet.MaxBulkAddressCount + 1,
			noChainSync: true,
			wantErr:     wallet.ErrInvalidParam,
		},
		{
			name:        "excluded valid count",
			count:       1,
			noChainSync: true,
			wantErr:     wallet.ErrAccountOperationUnsupported,
		},
	}

	// Row-local harnesses prevent one rejection from masking another's writes.
	for _, tc := range tests {
		h.Run(tc.name, func(t *testing.T) {
			h := h.Subtest(t)

			// Arrange: exact selection activates either policy through the
			// same public request shape, with an independently known child.
			const accountName = "rejected batch account"

			ctx := h.Context()
			scope := waddrmgr.KeyScopeBIP0084
			number := wallet.AccountNumber(7)
			w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
			_, err := w.NewAccount(ctx, wallet.NewAccountParams{
				Scope:         scope,
				Name:          accountName,
				AccountNumber: &number,
				NoChainSync:   tc.noChainSync,
			})
			require.NoError(h, err)

			before, err := w.GetAccount(ctx, scope, accountName)
			require.NoError(h, err)
			require.Equal(h, tc.noChainSync, before.NoChainSync)
			require.Zero(h, before.ExternalKeyCount)
			require.Zero(h, before.InternalKeyCount)

			want := createTestAddressInfos(h, before, false, 1)[0]
			_, err = w.GetAddressInfo(ctx, want.Addr)
			require.ErrorIs(h, err, wallet.ErrAddressNotFound)

			listed, err := w.ListAddresses(
				ctx, accountName, waddrmgr.WitnessPubKey,
			)
			require.NoError(h, err)
			require.Empty(h, listed)

			// Act: submit the count against the persisted receiving policy.
			batch, err := w.NewBulkAddresses(
				ctx, wallet.NewAccountSelectorByName(scope, accountName),
				false, tc.count,
			)

			// Assert: the stable refusal exposes no partial batch, and direct
			// reads must prove the account and address set were not mutated.
			require.ErrorIs(h, err, tc.wantErr)
			require.Nil(h, batch)

			// Reopening excludes an in-memory-only rollback illusion. No
			// allocation API is valid for the excluded account postcondition.
			for _, reopen := range []bool{false, true} {
				if reopen {
					w = h.ReloadWallet(w)
				}

				_, err := w.GetAddressInfo(ctx, want.Addr)
				require.ErrorIs(h, err, wallet.ErrAddressNotFound)

				listed, err := w.ListAddresses(
					ctx, accountName, waddrmgr.WitnessPubKey,
				)
				require.NoError(h, err)
				require.Empty(h, listed)

				after, err := w.GetAccount(ctx, scope, accountName)
				require.NoError(h, err)
				require.Equal(h, before, after)
			}
		})
	}
}

// testAddressManagerRejectKVDBBatch proves unsupported batches preserve the
// legacy branch cursor while invalid counts take precedence over capability.
func testAddressManagerRejectKVDBBatch(h *bwtest.HarnessTest) {
	// Modern kvdb has no batch mutation; SQL success is covered separately.
	//nolint:staticcheck // This guard intentionally selects legacy kvdb.
	if *dbBackend != string(wallet.DBBackendKVDB) {
		h.Skip("batch capability refusal requires kvdb")
	}

	// The valid boundary distinguishes capability refusal from validation.
	tests := []struct {
		name    string
		count   uint32
		wantErr error
	}{
		{
			name:    "zero",
			count:   0,
			wantErr: wallet.ErrInvalidParam,
		},
		{
			name:    "over maximum",
			count:   wallet.MaxBulkAddressCount + 1,
			wantErr: wallet.ErrInvalidParam,
		},
		{
			name:    "valid count",
			count:   1,
			wantErr: wallet.ErrAccountOperationUnsupported,
		},
	}

	// A separate database per row makes each cursor postcondition independent.
	for _, tc := range tests {
		h.Run(tc.name, func(t *testing.T) {
			h := h.Subtest(t)

			// Arrange: snapshot a newly created account through the read API
			// and derive child zero before submitting any receiving request.
			const accountName = "rejected batch account"

			ctx := h.Context()
			scope := waddrmgr.KeyScopeBIP0084
			w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
			_, err := w.NewAccount(ctx, wallet.NewAccountParams{
				Scope: scope,
				Name:  accountName,
			})
			require.NoError(h, err)

			before, err := w.GetAccount(ctx, scope, accountName)
			require.NoError(h, err)
			require.Zero(h, before.ExternalKeyCount)
			require.Zero(h, before.InternalKeyCount)

			want := createTestAddressInfos(h, before, false, 1)[0]
			_, err = w.GetAddressInfo(ctx, want.Addr)
			require.ErrorIs(h, err, wallet.ErrAddressNotFound)

			listed, err := w.ListAddresses(
				ctx, accountName, waddrmgr.WitnessPubKey,
			)
			require.NoError(h, err)
			require.Empty(h, listed)

			// Act: use the public batch API even though this backend cannot
			// satisfy its atomic mutation and delivery contract.
			batch, err := w.NewBulkAddresses(
				ctx, wallet.NewAccountSelectorByName(scope, accountName),
				false, tc.count,
			)

			// Assert: require the error identity and no partial result, then
			// verify both live and reopened views expose no address change.
			require.ErrorIs(h, err, tc.wantErr)
			require.Nil(h, batch)

			for _, reopen := range []bool{false, true} {
				if reopen {
					w = h.ReloadWallet(w)
				}

				_, err := w.GetAddressInfo(ctx, want.Addr)
				require.ErrorIs(h, err, wallet.ErrAddressNotFound)

				listed, err := w.ListAddresses(
					ctx, accountName, waddrmgr.WitnessPubKey,
				)
				require.NoError(h, err)
				require.Empty(h, listed)

				after, err := w.GetAccount(ctx, scope, accountName)
				require.NoError(h, err)
				require.Equal(h, before, after)
			}

			// Kvdb still supports count-one allocation. Child zero after
			// reopen proves rejection did not silently consume its cursor.
			next, err := w.NewAddress(
				ctx, wallet.NewAccountSelectorByName(scope, accountName),
				false,
			)
			require.NoError(h, err)
			require.Equal(h, want.Addr, next.Addr)
		})
	}
}

// testAddressManagerNewAddress proves the first receiving address of a fresh
// account carries the account schema's type and complete HD metadata on both
// branches of every default scope.
func testAddressManagerNewAddress(h *bwtest.HarnessTest) {
	tests := []struct {
		name     string
		scope    waddrmgr.KeyScope
		internal bool
		byNumber bool
	}{
		{
			name:  "bip44 external",
			scope: waddrmgr.KeyScopeBIP0044,
		},
		{
			name:     "bip44 internal",
			scope:    waddrmgr.KeyScopeBIP0044,
			internal: true,
		},
		{
			name:  "bip49 external",
			scope: waddrmgr.KeyScopeBIP0049Plus,
		},
		{
			name:     "bip49 internal",
			scope:    waddrmgr.KeyScopeBIP0049Plus,
			internal: true,
		},
		{
			name:  "bip84 external",
			scope: waddrmgr.KeyScopeBIP0084,
		},
		{
			name:     "bip84 internal",
			scope:    waddrmgr.KeyScopeBIP0084,
			internal: true,
		},
		{
			name:     "bip84 external by number",
			scope:    waddrmgr.KeyScopeBIP0084,
			byNumber: true,
		},
		{
			name:  "bip86 external",
			scope: waddrmgr.KeyScopeBIP0086,
		},
		{
			name:     "bip86 internal",
			scope:    waddrmgr.KeyScopeBIP0086,
			internal: true,
		},
	}

	// Each row owns its wallet, so no row can observe another's allocation.
	for _, tc := range tests {
		h.Run(tc.name, func(t *testing.T) {
			h := h.Subtest(t)

			// Arrange: derive child zero from the fresh account's XPub
			// before any receiving call, so the result is checked against
			// an oracle independent of the allocator.
			const accountName = "receiving account"

			ctx := h.Context()
			w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
			account := h.CreateTestAccount(w, tc.scope, accountName)
			want := createTestAddressInfos(h, account, tc.internal, 1)[0]

			selector := wallet.NewAccountSelectorByName(
				tc.scope, accountName,
			)
			if tc.byNumber {
				selector = wallet.NewAccountSelectorByNumber(
					tc.scope, *account.AccountNumber,
				)
			}

			// Act: request one receiving address from the chosen branch.
			info, err := w.NewAddress(ctx, selector, tc.internal)

			// Assert: complete equality detects a wrong child, branch,
			// type, or origin.
			require.NoError(h, err)
			require.Equal(
				h, withoutFingerprint(want), withoutFingerprint(info),
			)
		})
	}
}

// testAddressManagerRejectNewAddress proves selectors that name no derivable
// account fail with stable error identities and return no address.
func testAddressManagerRejectNewAddress(h *bwtest.HarnessTest) {
	// Only the reserved imported name has a documented identity; how a
	// backend resolves the reserved number is not part of the contract.
	tests := []struct {
		name     string
		selector wallet.AccountSelector
		wantErr  error
	}{
		{
			name: "unknown account name",
			selector: wallet.NewAccountSelectorByName(
				waddrmgr.KeyScopeBIP0084, "missing account",
			),
			wantErr: wallet.ErrAccountNotFound,
		},
		{
			name: "unknown account number",
			selector: wallet.NewAccountSelectorByNumber(
				waddrmgr.KeyScopeBIP0084, 7,
			),
			wantErr: wallet.ErrAccountNotFound,
		},
		{
			name: "unknown scope",
			selector: wallet.NewAccountSelectorByName(
				waddrmgr.KeyScope{Purpose: 1017, Coin: 1},
				waddrmgr.DefaultAccountName,
			),
			wantErr: wallet.ErrAccountNotFound,
		},
		{
			name: "imported account name",
			selector: wallet.NewAccountSelectorByName(
				waddrmgr.KeyScopeBIP0084,
				waddrmgr.ImportedAddrAccountName,
			),
			wantErr: wallet.ErrImportedAccountNoAddrGen,
		},
	}

	for _, tc := range tests {
		h.Run(tc.name, func(t *testing.T) {
			h := h.Subtest(t)

			// Arrange: a started wallet with only its default accounts.
			ctx := h.Context()
			w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})

			// Act: request an external address for the selector.
			info, err := w.NewAddress(ctx, tc.selector, false)

			// Assert: every error returns the zero AddressInfo, so a
			// caller cannot mistake a partial result for an address.
			require.ErrorIs(h, err, tc.wantErr)
			require.Zero(h, info)
		})
	}
}

// testAddressManagerRotateUsedAddress proves a funded address is durably
// recorded as used, so the first receiving call after reopening returns the
// next child rather than the used one.
func testAddressManagerRotateUsedAddress(h *bwtest.HarnessTest) {
	// Arrange: funding pays the default account's first external child and
	// waits for the wallet to sync the confirming block.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: waddrmgr.WitnessPubKey,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})

	account, err := w.GetAccount(ctx, scope, waddrmgr.DefaultAccountName)
	require.NoError(h, err)
	want := createTestAddressInfos(h, account, false, 2)

	// The oracle is only meaningful if funding paid exactly child zero.
	wantScript, err := txscript.PayToAddrScript(want[0].Addr)
	require.NoError(h, err)

	funded := funding.Tx.TxOut[funding.WalletOutpoints[0].Index]
	require.Equal(h, wantScript, funded.PkScript)

	// Reopening drops in-memory state, so only durable used state and branch
	// progress can explain the next result. The reopened wallet is locked,
	// which a receiving call must not require changing.
	w = h.ReloadWallet(w)

	// Act: request the next external receiving address.
	info, err := w.NewAddress(
		ctx, wallet.NewAccountSelectorByName(
			scope, waddrmgr.DefaultAccountName,
		), false,
	)

	// Assert: the used child is skipped and the next one is returned with
	// its full metadata.
	require.NoError(h, err)
	require.Equal(h, withoutFingerprint(want[1]), withoutFingerprint(info))
}

// testAddressManagerListAddresses proves the account listing reports every
// allocated address with its balance, before and after reopening the wallet.
func testAddressManagerListAddresses(h *bwtest.HarnessTest) {
	// Arrange: one funded external child and one unfunded internal child
	// give the listing both branches and both a non-zero and zero balance.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{
		AddrType: waddrmgr.WitnessPubKey,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})

	account, err := w.GetAccount(ctx, scope, waddrmgr.DefaultAccountName)
	require.NoError(h, err)
	external := createTestAddressInfos(h, account, false, 1)[0]
	internal := createTestAddressInfos(h, account, true, 1)[0]

	_, err = w.NewAddress(
		ctx, wallet.NewAccountSelectorByName(
			scope, waddrmgr.DefaultAccountName,
		), true,
	)
	require.NoError(h, err)

	// The expected addresses come from the account XPub, not from the
	// allocation results, so the listing is checked against an oracle.
	wantList := []wallet.AddressProperty{
		{Address: external.Addr, Balance: oneBTC},
		{Address: internal.Addr},
	}

	// Check the live wallet first, then a fresh one loaded from durable
	// data, so cached state cannot stand in for persisted rows.
	for _, reopen := range []bool{false, true} {
		if reopen {
			w = h.ReloadWallet(w)
		}

		// Act: list the account's addresses for its address type.
		listed, err := w.ListAddresses(
			ctx, waddrmgr.DefaultAccountName, waddrmgr.WitnessPubKey,
		)

		// Assert: exactly the allocated addresses and balances, with no
		// ordering contract.
		require.NoError(h, err)
		require.ElementsMatch(h, wantList, listed)
	}
}

// withoutFingerprint returns a copy of info with the root fingerprint cleared.
// Modern kvdb deliberately reports zero for derived address metadata while
// SQL reports the account's fingerprint, so a backend-neutral comparison must
// leave that one field out; every other field remains part of the contract.
func withoutFingerprint(info wallet.AddressInfo) wallet.AddressInfo {
	if info.Derivation == nil {
		return info
	}

	derivation := *info.Derivation
	derivation.MasterKeyFingerprint = 0
	info.Derivation = &derivation

	return info
}
