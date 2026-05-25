//go:build itest

package itest

import (
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestListWallets verifies that ListWallets correctly returns wallets and
// handles empty results without error.
func TestListWallets(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	// Initially empty.
	query := db.ListWalletsQuery{
		Page: newTestReq[uint32](t, 10),
	}

	pageResult, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Empty(t, pageResult.Items)
	require.Nil(t, pageResult.Next)

	// Create three wallets.
	names := []string{"wallet-1", "wallet-2", "wallet-3"}
	for _, name := range names {
		params := CreateWalletParamsFixture(name)
		_, err := store.CreateWallet(t.Context(), params)
		require.NoError(t, err)
	}

	pageResult, err = store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, pageResult.Items, 3)

	// Verify all names are present.
	walletsName := make([]string, len(pageResult.Items))
	for i, w := range pageResult.Items {
		walletsName[i] = w.Name
	}

	require.ElementsMatch(t, names, walletsName)
}

// TestListWalletsZeroLimit verifies ListWallets rejects a zero page limit.
func TestListWalletsZeroLimit(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	before := store.StatsSnapshot()

	_, err := store.ListWallets(t.Context(), db.ListWalletsQuery{})
	require.ErrorIs(t, err, db.ErrInvalidPageLimit)

	after := store.StatsSnapshot()
	require.Equal(t, before, after)
}

// TestListWalletsPagination verifies that ListWallets paginates correctly and
// sets Next without requiring an extra round-trip.
func TestListWalletsPagination(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	names := []string{"wallet-1", "wallet-2", "wallet-3", "wallet-4"}
	for _, name := range names {
		params := CreateWalletParamsFixture(name)
		_, err := store.CreateWallet(t.Context(), params)
		require.NoError(t, err)
	}

	query := db.ListWalletsQuery{
		Page: newTestReq[uint32](t, 2),
	}

	page1, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page1.Items, 2)
	require.NotNil(t, page1.Next)
	require.Equal(t, page1.Items[1].ID, *page1.Next)

	query.Page.After = page1.Next
	page2, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page2.Items, 2)
	require.Nil(t, page2.Next)

	query.Page.After = uint32Ptr(page2.Items[len(page2.Items)-1].ID)
	page3, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Empty(t, page3.Items)
	require.Nil(t, page3.Next)

	paged := append([]db.WalletInfo{}, page1.Items...)
	paged = append(paged, page2.Items...)
	require.Len(t, paged, len(names))

	pagedNames := make([]string, len(paged))
	for i, wallet := range paged {
		pagedNames[i] = wallet.Name
	}

	require.Equal(t, names, pagedNames)
}

// TestListWalletsExactBoundary verifies that pagination correctly handles the
// exact boundary case where total results equal page-size multiples.
func TestListWalletsExactBoundary(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	names := []string{"wallet-1", "wallet-2", "wallet-3", "wallet-4"}
	for _, name := range names {
		_, err := store.CreateWallet(
			t.Context(), CreateWalletParamsFixture(name),
		)
		require.NoError(t, err)
	}

	query := db.ListWalletsQuery{
		Page: newTestReq[uint32](t, 2),
	}

	page1, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page1.Items, 2)
	require.Equal(t, names[0], page1.Items[0].Name)
	require.Equal(t, names[1], page1.Items[1].Name)
	require.NotNil(t, page1.Next)
	require.Equal(t, page1.Items[1].ID, *page1.Next)

	query.Page.After = page1.Next
	page2, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page2.Items, 2)
	require.Equal(t, names[2], page2.Items[0].Name)
	require.Equal(t, names[3], page2.Items[1].Name)
	require.Nil(t, page2.Next)
	require.Greater(t, page2.Items[0].ID, *page1.Next)

	query.Page.After = uint32Ptr(page2.Items[len(page2.Items)-1].ID)
	page3, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Empty(t, page3.Items)
	require.Nil(t, page3.Next)
}

// TestIterWallets verifies that IterWallets exhaustively retrieves all wallets
// and yields the same results in the same order as manual cursor-based
// pagination.
func TestIterWallets(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	names := []string{"wallet-1", "wallet-2", "wallet-3", "wallet-4"}
	for _, name := range names {
		params := CreateWalletParamsFixture(name)
		_, err := store.CreateWallet(t.Context(), params)
		require.NoError(t, err)
	}

	query := db.ListWalletsQuery{
		Page: newTestReq[uint32](t, 2),
	}
	expected := flattenWalletPages(collectWalletPages(t, store, query))

	iterWallets := make([]db.WalletInfo, 0, len(expected))
	for wallet, err := range store.IterWallets(t.Context(), query) {
		require.NoError(t, err)

		iterWallets = append(iterWallets, wallet)
	}

	require.Equal(t, expected, iterWallets)
}

// TestIterWalletsPaginated verifies that IterWallets produces the same
// results as manual pagination and correctly signals end-of-list.
func TestIterWalletsPaginated(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	names := []string{"wallet-1", "wallet-2", "wallet-3", "wallet-4"}
	for _, name := range names {
		params := CreateWalletParamsFixture(name)
		_, err := store.CreateWallet(t.Context(), params)
		require.NoError(t, err)
	}

	query := db.ListWalletsQuery{
		Page: newTestReq[uint32](t, 2),
	}

	pages := collectWalletPages(t, store, query)
	require.Len(t, pages, 2)
	require.NotNil(t, pages[0].Next)
	require.Nil(t, pages[1].Next)

	expected := flattenWalletPages(pages)

	iterWallets := make([]db.WalletInfo, 0, len(expected))
	for wallet, err := range store.IterWallets(t.Context(), query) {
		require.NoError(t, err)

		iterWallets = append(iterWallets, wallet)
	}

	require.Equal(t, expected, iterWallets)
}

// TestListWalletsPagedFromCursor verifies that ListWallets can resume
// pagination from a specific cursor position, returning only wallets after
// that cursor.
func TestListWalletsPagedFromCursor(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	names := []string{"wallet-1", "wallet-2", "wallet-3", "wallet-4"}

	created := make([]*db.WalletInfo, 0, len(names))
	for _, name := range names {
		params := CreateWalletParamsFixture(name)
		wallet, err := store.CreateWallet(t.Context(), params)
		require.NoError(t, err)

		created = append(created, wallet)
	}

	pageReq := newTestReq[uint32](t, 2)
	pageReq.After = uint32Ptr(created[1].ID)

	query := db.ListWalletsQuery{
		Page: pageReq,
	}

	pageResult, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, pageResult.Items, 2)
	require.Equal(t, names[2], pageResult.Items[0].Name)
	require.Equal(t, names[3], pageResult.Items[1].Name)
	require.Nil(t, pageResult.Next)

	query.Page.After = uint32Ptr(created[3].ID)
	pageResult, err = store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Empty(t, pageResult.Items)
	require.Nil(t, pageResult.Next)
}

// TestListWalletsPagedWithSyncMetadata verifies that paginated wallet
// listings include sync metadata such as synced-to block and birthday block.
func TestListWalletsPagedWithSyncMetadata(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()

	birthday1 := time.Now().UTC().Add(-48 * time.Hour)
	birthday2 := time.Now().UTC().Add(-24 * time.Hour)

	params1 := CreateWalletParamsFixture("wallet-sync-1")
	params1.Birthday = birthday1
	wallet1, err := store.CreateWallet(t.Context(), params1)
	require.NoError(t, err)

	params2 := CreateWalletParamsFixture("wallet-sync-2")
	params2.Birthday = birthday2
	wallet2, err := store.CreateWallet(t.Context(), params2)
	require.NoError(t, err)

	block1 := CreateBlockFixture(t, queries, 100)
	block2 := CreateBlockFixture(t, queries, 101)

	err = store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID:      wallet1.ID,
		SyncedTo:      &block2,
		BirthdayBlock: &block1,
	})
	require.NoError(t, err)

	err = store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID:      wallet2.ID,
		SyncedTo:      &block2,
		BirthdayBlock: &block1,
	})
	require.NoError(t, err)

	query := db.ListWalletsQuery{
		Page: newTestReq[uint32](t, 1),
	}

	page1, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page1.Items, 1)
	require.NotNil(t, page1.Items[0].SyncedTo)
	require.NotNil(t, page1.Items[0].BirthdayBlock)
	require.False(t, page1.Items[0].Birthday.IsZero())
	require.NotNil(t, page1.Next)

	query.Page.After = page1.Next
	page2, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page2.Items, 1)
	require.NotNil(t, page2.Items[0].SyncedTo)
	require.NotNil(t, page2.Items[0].BirthdayBlock)
	require.False(t, page2.Items[0].Birthday.IsZero())
	require.Nil(t, page2.Next)
}

// TestListWalletsDeterministicPagination verifies stable page ordering and
// next-cursor behavior for multi-page wallet listings.
func TestListWalletsDeterministicPagination(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	names := []string{
		"wallet-page-1",
		"wallet-page-2",
		"wallet-page-3",
		"wallet-page-4",
		"wallet-page-5",
	}

	for _, name := range names {
		_, err := store.CreateWallet(
			t.Context(), CreateWalletParamsFixture(name),
		)
		require.NoError(t, err)
	}

	pages := collectWalletPages(t, store, db.ListWalletsQuery{
		Page: newTestReq[uint32](t, 2),
	})
	require.Len(t, pages, 3)
	require.Len(t, pages[0].Items, 2)
	require.Len(t, pages[1].Items, 2)
	require.Len(t, pages[2].Items, 1)
	require.NotNil(t, pages[0].Next)
	require.NotNil(t, pages[1].Next)
	require.Nil(t, pages[2].Next)

	wallets := flattenWalletPages(pages)
	require.Len(t, wallets, len(names))

	collectedNames := make([]string, len(wallets))
	for i, wallet := range wallets {
		if i > 0 {
			require.Less(t, wallets[i-1].ID, wallet.ID)
		}

		collectedNames[i] = wallet.Name
	}

	require.Equal(t, names, collectedNames)
	require.Equal(t, wallets[1].ID, *pages[0].Next)
	require.Equal(t, wallets[3].ID, *pages[1].Next)

	seenIDs := make(map[uint32]struct{}, len(wallets))
	for i := range pages {
		for j, wallet := range pages[i].Items {
			_, duplicate := seenIDs[wallet.ID]
			require.False(t, duplicate)

			seenIDs[wallet.ID] = struct{}{}

			// Skip the first item on the first page; there's no prior cursor
			// to compare against.
			if i == 0 && j == 0 {
				continue
			}

			// First item on a later page: verify it sorts strictly after the
			// previous page's cursor to ensure no gaps or duplicates at page
			// boundaries.
			if j == 0 {
				require.Greater(t, wallet.ID, *pages[i-1].Next)
				continue
			}

			// Items within the same page: verify strict ordering to ensure
			// the page contents are sorted.
			require.Greater(t, wallet.ID, pages[i].Items[j-1].ID)
		}
	}
}

// TestListWalletsInsertAfterCursor verifies inserts after page N are returned
// on page N+1 when pagination uses increasing ID cursors.
func TestListWalletsInsertAfterCursor(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	for _, name := range []string{"wallet-a", "wallet-b", "wallet-c"} {
		_, err := store.CreateWallet(
			t.Context(), CreateWalletParamsFixture(name),
		)
		require.NoError(t, err)
	}

	query := db.ListWalletsQuery{
		Page: newTestReq[uint32](t, 2),
	}
	page1, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page1.Items, 2)
	require.NotNil(t, page1.Next)

	// Pagination is by increasing wallet ID (id > cursor).
	// A wallet created after page 1 should therefore appear on page 2.
	inserted, err := store.CreateWallet(
		t.Context(), CreateWalletParamsFixture("wallet-d"),
	)
	require.NoError(t, err)

	query.Page.After = page1.Next
	page2, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page2.Items, 2)
	require.Equal(t, "wallet-c", page2.Items[0].Name)
	require.Equal(t, inserted.ID, page2.Items[1].ID)
	require.Equal(t, "wallet-d", page2.Items[1].Name)
	require.Nil(t, page2.Next)
}

// TestListWalletsCursorEdges verifies stale and zero-value cursors produce
// deterministic page results.
func TestListWalletsCursorEdges(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	names := []string{"wallet-1", "wallet-2", "wallet-3"}
	for _, name := range names {
		_, err := store.CreateWallet(
			t.Context(), CreateWalletParamsFixture(name),
		)
		require.NoError(t, err)
	}

	staleReq := newTestReq[uint32](t, 2)
	staleReq.After = uint32Ptr(math.MaxUint32)

	stalePage, err := store.ListWallets(
		t.Context(), db.ListWalletsQuery{
			Page: staleReq,
		},
	)
	require.NoError(t, err)
	require.Empty(t, stalePage.Items)
	require.Nil(t, stalePage.Next)

	zeroReq := newTestReq[uint32](t, 2)
	zeroReq.After = uint32Ptr(0)

	zeroPage, err := store.ListWallets(
		t.Context(), db.ListWalletsQuery{
			Page: zeroReq,
		},
	)
	require.NoError(t, err)
	require.Len(t, zeroPage.Items, 2)
	require.Equal(t, names[0], zeroPage.Items[0].Name)
	require.Equal(t, names[1], zeroPage.Items[1].Name)
	require.NotNil(t, zeroPage.Next)
}
