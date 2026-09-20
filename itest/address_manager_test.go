//go:build itest

package itest

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

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
