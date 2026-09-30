//go:build itest

package itest

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/stretchr/testify/require"
)

// collectWalletPages collects paginated wallet results by iterating through all
// pages from ListWallets until Next is nil.
func collectWalletPages(t *testing.T, store db.WalletStore,
	query db.ListWalletsQuery) []page.Result[db.WalletInfo, uint32] {

	t.Helper()

	pages := make([]page.Result[db.WalletInfo, uint32], 0)
	for {
		pageResult, err := store.ListWallets(t.Context(), query)
		require.NoError(t, err)

		pages = append(pages, pageResult)

		if pageResult.Next == nil {
			return pages
		}

		query.Page.After = pageResult.Next
	}
}

// flattenWalletPages flattens paginated wallet results into a single
// slice containing all wallets from all pages.
func flattenWalletPages(
	pages []page.Result[db.WalletInfo, uint32]) []db.WalletInfo {

	count := 0
	for i := range pages {
		count += len(pages[i].Items)
	}

	wallets := make([]db.WalletInfo, 0, count)
	for i := range pages {
		wallets = append(wallets, pages[i].Items...)
	}

	return wallets
}
