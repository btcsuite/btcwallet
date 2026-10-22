// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build itest

package itest

import (
	"bytes"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// addressManagerFundingType is the address type funded address cases pay to.
// Each case resolves its key scope from this value, so the funded scope has a
// single authority: the address type owns that mapping.
const addressManagerFundingType = waddrmgr.WitnessPubKey

// testAddressManagerRawImportPublicKey verifies imports and repeats retain
// canonical metadata and observe future payments through the real chain
// client owned by the harness.
func testAddressManagerRawImportPublicKey(h *bwtest.HarnessTest) {
	// SPV supplies confirmed notifications; this case requires observing
	// a future payment while it is still in the full node's mempool.
	if _, ok := h.ChainClient.(*chain.NeutrinoClient); ok {
		h.Skip("unmined raw import payments require a full node")
	}

	// Arrange: use real persistence and chain registration in a signing
	// Wallet. Public-key imports need no unlocked local signing keys.
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{})

	// Unfunded creation supplies no sync boundary. Finish startup watch
	// reconstruction so it cannot register the later import for this test.
	h.AssertWalletSynced(w)

	key, err := btcec.NewPrivateKey()
	require.NoError(h, err)

	addr, err := waddrmgr.WitnessPubKey.AddrFromPubKeyBytes(
		key.PubKey().SerializeCompressed(), h.NetParams(),
	)
	require.NoError(h, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err)

	// Act: import through the public API using real persistence and live
	// registration; public success must establish monitoring.
	err = w.ImportPublicKey(ctx, key.PubKey(), waddrmgr.WitnessPubKey)

	// Assert: the completed import is visible through the public address
	// query before a repeat can reuse its canonical record.
	require.NoError(h, err)

	stored, err := w.GetAddressInfo(ctx, addr)
	require.NoError(h, err)

	// Act: repeat the public import to exercise canonical reuse and live
	// registration without replacing the real harness client.
	err = w.ImportPublicKey(ctx, key.PubKey(), waddrmgr.WitnessPubKey)

	// Assert: the repeat succeeds and public lookup preserves the same
	// canonical metadata supplied by the committed import.
	require.NoError(h, err)

	got, err := w.GetAddressInfo(ctx, addr)
	require.NoError(h, err)
	require.Equal(h, stored, got)

	// Act: pay after the repeated import succeeds, so receipt must come
	// from its live watch rather than startup reconstruction or a scan.
	payment := h.SendOutput(&wire.TxOut{
		Value:    oneBTC,
		PkScript: pkScript,
	}, bwtest.MinerFeeRate)

	// Assert: asynchronous notification reaches the public transaction view
	// before mining. Retain the successful polling result for the unmined
	// assertion, then empty the shared mempool.
	var received *wallet.TxDetail

	err = wait.NoError(func() error {
		var err error

		received, err = w.GetTx(ctx, *payment)

		return err
	}, pollTimeout)
	require.NoError(h, err)

	require.Nil(h, received.Block)

	h.MineBlockWithTx(h.AssertTxInMempool(*payment))
}

// testAddressManagerRawImportTaprootScript proves repeated imports retain the
// original encrypted script across an output-key-only repeat, then receive a
// future unmined payment through the real full-node watch.
func testAddressManagerRawImportTaprootScript(h *bwtest.HarnessTest) {
	// SPV supplies confirmed notifications; this case requires observing
	// a future payment while it is still in the full node's mempool.
	if _, ok := h.ChainClient.(*chain.NeutrinoClient); ok {
		h.Skip("unmined raw import payments require a full node")
	}

	// Arrange: retain a revealed leaf in a signing Wallet so a later
	// key-only repeat must reuse it. SQL needs an unlocked script key;
	// kvdb supplies its public script key while locked.
	ctx := h.Context()

	sqlWallet := *dbBackend == string(wallet.DBBackendSQLite) ||
		*dbBackend == string(wallet.DBBackendPostgres)

	w, _ := h.NewWallet(bwtest.WalletFixture{
		Unlocked: sqlWallet,
	})

	// Unfunded creation supplies no sync boundary. Finish startup watch
	// reconstruction so it cannot register the later import for this test.
	h.AssertWalletSynced(w)

	key, err := btcec.NewPrivateKey()
	require.NoError(h, err)

	leafScript := []byte{txscript.OP_TRUE}
	tapscript := waddrmgr.Tapscript{
		Type: waddrmgr.TapscriptTypePartialReveal,
		ControlBlock: &txscript.ControlBlock{
			InternalKey: key.PubKey(),
			LeafVersion: txscript.BaseLeafVersion,
		},
		RevealedScript: leafScript,
	}

	outputKey, err := tapscript.TaprootKey()
	require.NoError(h, err)

	addr, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), h.NetParams(),
	)
	require.NoError(h, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err)

	repeat := waddrmgr.Tapscript{
		Type:          waddrmgr.TaprootFullKeyOnly,
		FullOutputKey: outputKey,
	}

	// Act: import the script through real persistence and the harness's
	// full-node client; success must include live monitoring.
	_, err = w.ImportTaprootScript(ctx, tapscript)

	// Assert: public lookup observes the committed script metadata that
	// the following output-key-only repeat must preserve.
	require.NoError(h, err)

	stored, err := w.GetAddressInfo(ctx, addr)
	require.NoError(h, err)

	// Act: repeat with an output-key-only representation, which must not
	// replace the original encrypted spending conditions.
	info, err := w.ImportTaprootScript(ctx, repeat)

	// Assert: the repeat returns the canonical stored metadata.
	// Resolving its output below proves the original secret still exists.
	require.NoError(h, err)
	require.Equal(h, stored, info)

	script, err := w.ScriptForOutput(ctx, wire.TxOut{
		PkScript: pkScript,
	})
	require.NoError(h, err)
	require.Equal(h, leafScript, script.Script)

	// Act: broadcast after successful registration so no import-time scan
	// can supply the future payment to the Wallet.
	payment := h.SendOutput(&wire.TxOut{
		Value:    oneBTC,
		PkScript: pkScript,
	}, bwtest.MinerFeeRate)

	// Assert: keep the successful polling result to check the payment is
	// still unmined, then mine to clean the shared harness mempool.
	var received *wallet.TxDetail

	err = wait.NoError(func() error {
		var err error

		received, err = w.GetTx(ctx, *payment)

		return err
	}, pollTimeout)
	require.NoError(h, err)

	require.Nil(h, received.Block)

	h.MineBlockWithTx(h.AssertTxInMempool(*payment))
}

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
			require.NotZero(h, *account.MasterKeyFingerprint)
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
// account fail with stable error identities, return no address, and leave
// every account and branch cursor unchanged across a reopen.
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

			// Arrange: a fresh wallet plus one named account whose child
			// zero witnesses cursor progress. Snapshot every account
			// before the rejected call; SQL materializes defaults lazily,
			// so the snapshot also catches a rejection that creates one.
			const accountName = "rejected address account"

			ctx := h.Context()
			scope := waddrmgr.KeyScopeBIP0084
			w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
			account, err := w.NewAccount(ctx, wallet.NewAccountParams{
				Scope: scope,
				Name:  accountName,
			})
			require.NoError(h, err)
			want := createTestAddressInfos(h, account, false, 1)[0]

			before, err := w.ListAccounts(ctx)
			require.NoError(h, err)

			// Act: request an external address for the selector.
			info, err := w.NewAddress(ctx, tc.selector, false)

			// Assert: every error returns the zero AddressInfo, so a
			// caller cannot mistake a partial result for an address.
			require.ErrorIs(h, err, tc.wantErr)
			require.Zero(h, info)

			// The live and reopened views must expose no account or
			// cursor change, so a rejection cannot persist progress.
			for _, reopen := range []bool{false, true} {
				if reopen {
					w = h.ReloadWallet(w)
				}

				after, err := w.ListAccounts(ctx)
				require.NoError(h, err)
				require.ElementsMatch(h, before, after)
			}

			// Child zero after reopen proves the rejection did not
			// silently consume a derivable account's cursor.
			next, err := w.NewAddress(
				ctx, wallet.NewAccountSelectorByName(scope, accountName),
				false,
			)
			require.NoError(h, err)
			require.Equal(h, want.Addr, next.Addr)
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
	scope, err := addressManagerFundingType.KeyScope()
	require.NoError(h, err)

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: addressManagerFundingType,
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
	scope, err := addressManagerFundingType.KeyScope()
	require.NoError(h, err)

	w, _ := h.NewWallet(bwtest.WalletFixture{
		AddrType: addressManagerFundingType,
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
			ctx, waddrmgr.DefaultAccountName, addressManagerFundingType,
		)

		// Assert: exactly the allocated addresses and balances, with no
		// ordering contract.
		require.NoError(h, err)
		require.ElementsMatch(h, wantList, listed)
	}
}

// testAddressManagerListAddressesAccountMiss proves listing resolves the
// account in the address type's scope: an account absent there fails with
// ErrAccountNotFound on every backend, while an existing account with no
// addresses lists as empty rather than as a miss.
func testAddressManagerListAddressesAccountMiss(h *bwtest.HarnessTest) {
	// A taproot-only account exists in the wallet but not in the BIP84
	// scope that WitnessPubKey selects, so a name match alone is not enough.
	const (
		emptyAccount   = "empty account"
		taprootAccount = "taproot account"
	)

	tests := []struct {
		name        string
		accountName string
		addrType    waddrmgr.AddressType
		wantErr     error
	}{
		{
			name:        "unknown account",
			accountName: "missing account",
			addrType:    waddrmgr.WitnessPubKey,
			wantErr:     wallet.ErrAccountNotFound,
		},
		{
			name:        "account in another scope",
			accountName: taprootAccount,
			addrType:    waddrmgr.WitnessPubKey,
			wantErr:     wallet.ErrAccountNotFound,
		},
		{
			name:        "existing empty account",
			accountName: emptyAccount,
			addrType:    waddrmgr.WitnessPubKey,
		},
	}

	for _, tc := range tests {
		h.Run(tc.name, func(t *testing.T) {
			h := h.Subtest(t)

			// Arrange: both named accounts exist and neither has
			// allocated an address.
			ctx := h.Context()
			w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
			h.CreateTestAccount(w, waddrmgr.KeyScopeBIP0084, emptyAccount)
			h.CreateTestAccount(
				w, waddrmgr.KeyScopeBIP0086, taprootAccount,
			)

			// Act: list the account for the address type.
			listed, err := w.ListAddresses(
				ctx, tc.accountName, tc.addrType,
			)

			// Assert: a miss carries the public identity, and only an
			// existing account may report an empty listing.
			if tc.wantErr != nil {
				require.ErrorIs(h, err, tc.wantErr)
				require.Nil(h, listed)

				return
			}

			require.NoError(h, err)
			require.Empty(h, listed)
		})
	}
}

// testAddressManagerGetAddressInfo proves point lookups return complete
// metadata for allocated addresses on both branches, before and after
// reopening the wallet.
func testAddressManagerGetAddressInfo(h *bwtest.HarnessTest) {
	// Arrange: a funded external child and an unfunded internal child cover
	// both branches and both used and unused state.
	ctx := h.Context()
	scope, err := addressManagerFundingType.KeyScope()
	require.NoError(h, err)

	w, _ := h.NewWallet(bwtest.WalletFixture{
		AddrType: addressManagerFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})

	account, err := w.GetAccount(ctx, scope, waddrmgr.DefaultAccountName)
	require.NoError(h, err)
	wantInfo := []wallet.AddressInfo{
		createTestAddressInfos(h, account, false, 1)[0],
		createTestAddressInfos(h, account, true, 1)[0],
	}

	_, err = w.NewAddress(
		ctx, wallet.NewAccountSelectorByName(
			scope, waddrmgr.DefaultAccountName,
		), true,
	)
	require.NoError(h, err)

	// Check the live wallet first, then a fresh one loaded from durable
	// data, so cached state cannot stand in for persisted rows.
	for _, reopen := range []bool{false, true} {
		if reopen {
			w = h.ReloadWallet(w)
		}

		for _, want := range wantInfo {
			// Act: look up one allocated address.
			info, err := w.GetAddressInfo(ctx, want.Addr)

			// Assert: complete metadata derived from the account XPub.
			require.NoError(h, err)
			require.Equal(
				h, withoutFingerprint(want), withoutFingerprint(info),
			)
		}
	}
}

// testAddressManagerLookupUnknownAddress proves point lookups of addresses the
// wallet never stored fail with ErrAddressNotFound.
func testAddressManagerLookupUnknownAddress(h *bwtest.HarnessTest) {
	// Arrange: an underived child of the wallet's own fresh account must
	// stay unknown until allocated, and a child of an XPub the wallet never
	// imported is never known.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	account := h.CreateTestAccount(w, scope, "lookup account")
	own := createTestAddressInfos(h, account, false, 1)[0]

	foreignBranch, err := deterministicImportedAccountKeys(h).accountKey.
		Derive(waddrmgr.ExternalBranch)
	require.NoError(h, err)
	foreignChild, err := foreignBranch.Derive(0)
	require.NoError(h, err)
	foreignKey, err := foreignChild.ECPubKey()
	require.NoError(h, err)
	foreign, err := waddrmgr.WitnessPubKey.AddrFromPubKeyBytes(
		foreignKey.SerializeCompressed(), h.NetParams(),
	)
	require.NoError(h, err)

	for _, addr := range []address.Address{own.Addr, foreign} {
		// Act: look up the address in the wallet under test.
		info, err := w.GetAddressInfo(ctx, addr)

		// Assert: the stable miss identity and no partial metadata.
		require.ErrorIs(h, err, wallet.ErrAddressNotFound)
		require.Zero(h, info)
	}
}

// testAddressManagerNewAddressFingerprint proves SQL receiving results carry
// the account's root fingerprint, the field the shared cases leave out.
func testAddressManagerNewAddressFingerprint(h *bwtest.HarnessTest) {
	// Modern kvdb deliberately reports a zero fingerprint for derived address
	// metadata, so only SQL can supply the account's value here.
	//nolint:staticcheck // This guard excludes the deprecated backend.
	if *dbBackend == string(wallet.DBBackendKVDB) {
		h.Skip("derived address fingerprints require SQL")
	}

	// Arrange: the oracle takes the fingerprint from the account read, so
	// address metadata must agree with the account it was derived from.
	const accountName = "fingerprint account"

	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	h.CreateTestAccount(w, scope, accountName)
	account, err := w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err)
	require.NotZero(h, *account.MasterKeyFingerprint)
	want := createTestAddressInfos(h, account, false, 1)[0]

	// Act: request the account's first receiving address.
	info, err := w.NewAddress(
		ctx, wallet.NewAccountSelectorByName(scope, accountName), false,
	)

	// Assert: full equality, fingerprint included.
	require.NoError(h, err)
	require.Equal(h, want, info)
}

// withoutFingerprint returns a copy of info with the root fingerprint cleared.
// Modern kvdb deliberately reports zero for derived address metadata while
// SQL reports the account's fingerprint, so a backend-neutral comparison must
// leave that one field out; every other field remains part of the contract.
//
// TODO: remove this helper once the kvdb backend is removed.
func withoutFingerprint(info wallet.AddressInfo) wallet.AddressInfo {
	if info.Derivation == nil {
		return info
	}

	derivation := *info.Derivation
	derivation.MasterKeyFingerprint = 0
	info.Derivation = &derivation

	return info
}

// testAddressManagerRawImportTracking verifies external raw outputs retain
// balances, custody, and future delivery in one signing wallet through reopen.
func testAddressManagerRawImportTracking(h *bwtest.HarnessTest) {
	// Arrange: keep both private keys outside the signing Wallet. The script
	// requires the external leaf key, so retaining it cannot supply a signer.
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	publicKey, err := btcec.NewPrivateKey()
	require.NoError(h, err)
	scriptKey, err := btcec.NewPrivateKey()
	require.NoError(h, err)

	keyAddr, err := waddrmgr.WitnessPubKey.AddrFromPubKeyBytes(
		publicKey.PubKey().SerializeCompressed(), h.NetParams(),
	)
	require.NoError(h, err)
	leafScript, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(scriptKey.PubKey())).
		AddOp(txscript.OP_CHECKSIG).Script()
	require.NoError(h, err)

	tapscript := waddrmgr.Tapscript{
		Type: waddrmgr.TapscriptTypePartialReveal,
		ControlBlock: &txscript.ControlBlock{
			InternalKey: scriptKey.PubKey(),
			LeafVersion: txscript.BaseLeafVersion,
		},
		RevealedScript: leafScript,
	}

	// Act: import public material through the existing Wallet APIs, then fund
	// only after their successful registrations. Mining supplies receipt on
	// full nodes and SPV alike; SPV does not supply external mempool events.
	require.NoError(h, w.ImportPublicKey(
		ctx, publicKey.PubKey(), waddrmgr.WitnessPubKey,
	))
	scriptInfo, err := w.ImportTaprootScript(ctx, tapscript)
	require.NoError(h, err)

	cases := []struct {
		addr     address.Address
		addrType waddrmgr.AddressType
		amount   btcutil.Amount
		script   []byte
		outpoint wire.OutPoint
		info     wallet.AddressInfo
	}{
		{
			addr:     keyAddr,
			addrType: waddrmgr.WitnessPubKey,
			amount:   oneBTC,
		},
		{
			addr:     scriptInfo.Addr,
			addrType: waddrmgr.TaprootScript,
			amount:   2 * oneBTC,
		},
	}

	outputs := make([]*wire.TxOut, len(cases))
	for i := range cases {
		// Public script construction is the funding oracle; ownership is read
		// back through Wallet results rather than inferred from SQL row shape.
		cases[i].script, err = txscript.PayToAddrScript(cases[i].addr)
		require.NoError(h, err)

		outputs[i] = wire.NewTxOut(int64(cases[i].amount), cases[i].script)
	}

	payment := h.SendOutputs(outputs, bwtest.MinerFeeRate)
	funding := h.AssertTxInMempool(*payment)
	h.MineBlockWithTx(funding)

	// Match miner outputs by script because it may sort outputs or add change.
	// The public point lookup below proves each resulting outpoint is owned.
	for i := range cases {
		for index, output := range funding.TxOut {
			if bytes.Equal(output.PkScript, cases[i].script) {
				cases[i].outpoint = wire.OutPoint{
					Hash:  *payment,
					Index: uint32(index),
				}
			}
		}
	}

	// Assert: mining establishes receipt before direct public reads. Capture
	// complete reports so reopen cannot hide a lost credit or changed custody.
	require.False(h, w.IsWatchOnly())
	beforeTx, err := w.GetTx(ctx, *payment)
	require.NoError(h, err)
	require.NotNil(h, beforeTx.Block)

	beforeUtxos, err := w.ListUnspent(ctx, wallet.UtxoQuery{
		Account:  waddrmgr.ImportedAddrAccountName,
		MinConfs: 1,
		MaxConfs: 100,
	})
	require.NoError(h, err)
	require.Len(h, beforeUtxos, len(cases))

	for i := range cases {
		tc := &cases[i]
		info, err := w.GetAddressInfo(ctx, tc.addr)
		require.NoError(h, err)
		require.True(h, info.Imported)
		require.Nil(h, info.Derivation)
		require.Equal(h, tc.addrType, info.AddrType)
		addresses, err := w.ListAddresses(
			ctx, waddrmgr.ImportedAddrAccountName, tc.addrType,
		)
		require.NoError(h, err)
		require.Len(h, addresses, 1)
		require.Equal(h, tc.addr, addresses[0].Address)
		require.Equal(h, tc.amount, addresses[0].Balance)

		utxo, err := w.GetUtxo(ctx, tc.outpoint)
		require.NoError(h, err)
		require.Equal(h, tc.amount, utxo.Amount)
		require.Equal(h, waddrmgr.ImportedAddrAccountName, utxo.Account)
		require.False(h, utxo.Spendable)
		require.Contains(h, beforeUtxos, utxo)

		// Store the full address result as the independent reopen snapshot.
		tc.info = info
	}

	// Act: cross the supported close/reopen boundary visibly. Readiness
	// establishes rebuilt watches; unlocking restores the signing fixture.
	w = h.ReloadWallet(w)
	h.AssertWalletSynced(w)
	h.UnlockWallet(w)

	// Assert: compare complete durable reports after readiness without polling.
	// The root stays signing while its external outputs retain their custody.
	require.False(h, w.IsWatchOnly())
	afterTx, err := w.GetTx(ctx, *payment)
	require.NoError(h, err)
	require.Equal(h, beforeTx, afterTx)

	afterUtxos, err := w.ListUnspent(ctx, wallet.UtxoQuery{
		Account:  waddrmgr.ImportedAddrAccountName,
		MinConfs: 1,
		MaxConfs: 100,
	})
	require.NoError(h, err)
	require.Equal(h, beforeUtxos, afterUtxos)

	for i := range cases {
		tc := &cases[i]
		info, err := w.GetAddressInfo(ctx, tc.addr)
		require.NoError(h, err)
		require.Equal(h, tc.info, info)
		addresses, err := w.ListAddresses(
			ctx, waddrmgr.ImportedAddrAccountName, tc.addrType,
		)
		require.NoError(h, err)
		require.Len(h, addresses, 1)
		require.Equal(h, tc.addr, addresses[0].Address)
		require.Equal(h, tc.amount, addresses[0].Balance)

		// Membership in the unchanged full list also verifies point-read
		// custody and every output field, beyond selected balance values.
		utxo, err := w.GetUtxo(ctx, tc.outpoint)
		require.NoError(h, err)
		require.Contains(h, afterUtxos, utxo)
	}

	// Assert: the reopened Wallet retains script bytes but has no private key
	// for the external public import, even with its own signing vault unlocked.
	script, err := w.ScriptForOutput(ctx, wire.TxOut{
		PkScript: cases[1].script,
	})
	require.NoError(h, err)
	require.Equal(h, leafScript, script.Script)

	_, err = w.GetPrivKeyForAddress(ctx, keyAddr)
	require.ErrorIs(h, err, wallet.ErrNoAssocPrivateKey)

	// Act: pay the reopened import only after watch reconstruction is ready.
	// A new confirmed receipt proves durability includes future delivery.
	future := h.SendOutput(outputs[0], bwtest.MinerFeeRate)
	h.MineBlockWithTx(h.AssertTxInMempool(*future))

	// Assert: block readiness makes the future public transaction read direct,
	// preserving one lifecycle owner and the same chain-neutral contract.
	delivered, err := w.GetTx(ctx, *future)
	require.NoError(h, err)
	require.NotNil(h, delivered.Block)
}
