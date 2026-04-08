//go:build itest

package itest

import (
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/stretchr/testify/require"
)

// uint32Ptr returns a pointer to the given uint32 value.
func uint32Ptr(v uint32) *uint32 {
	return &v
}

// TestCreateWallet verifies that CreateWallet correctly creates a wallet
// and returns its information.
func TestCreateWallet(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	params := CreateWalletParamsFixture("test-wallet")
	info, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)
	require.NotNil(t, info)

	require.Equal(t, info.ID, uint32(1), "first wallet ID should be 1")
	require.Equal(t, params.Name, info.Name)
	require.Equal(t, params.IsImported, info.IsImported)
	require.Equal(t, params.ManagerVersion, info.ManagerVersion)
	require.Equal(t, params.IsWatchOnly, info.IsWatchOnly)

	require.Nil(t, info.SyncedTo)
	require.Nil(t, info.BirthdayBlock)
	require.True(t, info.Birthday.IsZero())
}

// TestCreateWallet_WithBirthday checks that CreateWallet correctly sets the
// wallet's birthday timestamp.
func TestCreateWallet_WithBirthday(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("birthday-wallet")
	birthday := time.Now().UTC().Add(-30 * 24 * time.Hour)
	params.Birthday = birthday

	info, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)
	require.NotNil(t, info)

	require.Equal(t, birthday.Unix(), info.Birthday.Unix())
	require.Nil(t, info.BirthdayBlock)
}

// TestCreateWallet_DuplicateName verifies that creating a wallet with a
// duplicate name fails with an appropriate error.
func TestCreateWallet_DuplicateName(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	params := CreateWalletParamsFixture("duplicate-wallet")

	_, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	// Attempt to create second wallet with same name.
	_, err = store.CreateWallet(t.Context(), params)
	require.Error(t, err, "expected error creating duplicate wallet")

	// We still do not normalize this error across database backends,
	// and each engine returns its own message. Because of that,
	// we only check for the shared parts of the message here.
	require.ErrorContains(t, err, "wallets")
	require.ErrorContains(t, err, "name")
	require.ErrorContains(t, err, "constraint")
}

// TestCreateWallet_Variants tests different wallet types.
func TestCreateWallet_Variants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params func(string) db.CreateWalletParams
	}{
		{
			name:   "imported wallet",
			params: CreateImportedWalletParams,
		},
		{
			name:   "watch-only wallet",
			params: CreateWatchOnlyWalletParams,
		},
		{
			name:   "standard wallet",
			params: CreateWalletParamsFixture,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			params := tc.params(tc.name)
			store := NewTestStore(t)

			info, err := store.CreateWallet(t.Context(), params)
			require.NoError(t, err)
			require.NotNil(t, info)
			require.Equal(t, params.IsImported, info.IsImported)
			require.Equal(t, params.IsWatchOnly, info.IsWatchOnly)
		})
	}
}

// TestGetWallet verifies that GetWallet retrieves a wallet by name.
func TestGetWallet(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("get-test-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), params.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
}

// TestGetWallet_NotFound verifies that GetWallet returns ErrWalletNotFound
// when the wallet doesn't exist.
func TestGetWallet_NotFound(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	_, err := store.GetWallet(t.Context(), "non-existent-wallet")
	require.Error(t, err)
	require.ErrorIs(t, err, db.ErrWalletNotFound)
}

// TestListWallets verifies that ListWallets correctly returns wallets and
// handles empty results without error.
func TestListWallets(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	// Initially empty.
	query := db.ListWalletsQuery{
		Page: page.Request[uint32]{Limit: 10},
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

	_, err := store.ListWallets(t.Context(), db.ListWalletsQuery{})
	require.ErrorIs(t, err, db.ErrInvalidPageLimit)
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
		Page: page.Request[uint32]{Limit: 2},
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
		Page: page.Request[uint32]{Limit: 2},
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
		Page: page.Request[uint32]{Limit: 2},
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
		Page: page.Request[uint32]{Limit: 2},
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

	query := db.ListWalletsQuery{
		Page: page.Request[uint32]{
			Limit: 2,
			After: uint32Ptr(created[1].ID),
		},
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
		Page: page.Request[uint32]{Limit: 1},
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
		Page: page.Request[uint32]{Limit: 2},
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
		Page: page.Request[uint32]{Limit: 2},
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

	stalePage, err := store.ListWallets(t.Context(), db.ListWalletsQuery{
		Page: page.Request[uint32]{
			Limit: 2,
			After: uint32Ptr(math.MaxUint32),
		},
	})
	require.NoError(t, err)
	require.Empty(t, stalePage.Items)
	require.Nil(t, stalePage.Next)

	zeroPage, err := store.ListWallets(t.Context(), db.ListWalletsQuery{
		Page: page.Request[uint32]{
			Limit: 2,
			After: uint32Ptr(0),
		},
	})
	require.NoError(t, err)
	require.Len(t, zeroPage.Items, 2)
	require.Equal(t, names[0], zeroPage.Items[0].Name)
	require.Equal(t, names[1], zeroPage.Items[1].Name)
	require.NotNil(t, zeroPage.Next)
}

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

// TestUpdateWallet_SyncedTo checks that updating the wallet's synced-to block
// works correctly.
func TestUpdateWallet_SyncedTo(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()

	params := CreateWalletParamsFixture("update-sync-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	block := CreateBlockFixture(t, queries, 100)

	updateParams := db.UpdateWalletParams{
		WalletID: created.ID,
		SyncedTo: &block,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved.SyncedTo)
	require.Equal(t, block.Height, retrieved.SyncedTo.Height)

	// Assert fields that were not updated remain unchanged.
	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
	require.Nil(t, retrieved.BirthdayBlock)
}

// TestUpdateWallet_BirthdayBlock checks that updating the wallet's birthday
// block works correctly.
func TestUpdateWallet_BirthdayBlock(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()

	params := CreateWalletParamsFixture("update-birthday-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	// Initially, BirthdayBlock should be nil.
	require.Nil(t, created.BirthdayBlock)

	block := CreateBlockFixture(t, queries, 50)

	updateParams := db.UpdateWalletParams{
		WalletID:      created.ID,
		BirthdayBlock: &block,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved.BirthdayBlock)
	require.Equal(t, block.Height, retrieved.BirthdayBlock.Height)
	require.Equal(t, block.Hash, retrieved.BirthdayBlock.Hash)
	require.Equal(t, block.Timestamp.Unix(),
		retrieved.BirthdayBlock.Timestamp.Unix())

	// Assert fields that were not updated remain unchanged.
	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
	require.Nil(t, retrieved.SyncedTo)
}

// TestUpdateWallet_Birthday checks that updating the wallet's birthday
// timestamp works correctly.
func TestUpdateWallet_Birthday(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("birthday-timestamp-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	// Set birthday timestamp without setting birthday block.
	birthdayTime := time.Now().UTC().Add(-30 * 24 * time.Hour)
	updateParams := db.UpdateWalletParams{
		WalletID: created.ID,
		Birthday: &birthdayTime,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.Equal(t, birthdayTime.Unix(), retrieved.Birthday.Unix())

	// Assert fields that were not updated remain unchanged.
	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
	require.Nil(t, retrieved.BirthdayBlock)
	require.Nil(t, retrieved.SyncedTo)
}

// TestUpdateWallet_NotFound verifies that updating a non-existent wallet fails.
func TestUpdateWallet_NotFound(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	updateParams := db.UpdateWalletParams{
		WalletID: 99999, // Non-existent ID.
	}

	err := store.UpdateWallet(t.Context(), updateParams)
	require.Error(t, err)
	require.ErrorIs(t, err, db.ErrWalletNotFound)
}

// TestGetEncryptedHDSeed verifies retrieving the encrypted HD seed.
func TestGetEncryptedHDSeed(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("seed-wallet")
	expectedSeed := params.EncryptedMasterPrivKey

	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
	require.NoError(t, err)
	require.Equal(t, expectedSeed, seed)
}

// TestGetEncryptedHDSeed_WatchOnly verifies that watch-only wallets
// have no encrypted seed.
func TestGetEncryptedHDSeed_WatchOnly(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWatchOnlyWalletParams("watch-only-seed")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
	require.Nil(t, seed, "watch-only wallets should not have HD seed")
	require.ErrorIs(t, err, db.ErrSecretNotFound)
}

// TestUpdateWalletSecrets checks that updating the wallet secrets works
// correctly.
func TestUpdateWalletSecrets(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("secrets-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	newSecrets := db.UpdateWalletSecretsParams{
		WalletID:                 created.ID,
		MasterPrivParams:         RandomBytes(16),
		EncryptedCryptoPrivKey:   RandomBytes(32),
		EncryptedCryptoScriptKey: RandomBytes(32),
		EncryptedMasterHdPrivKey: RandomBytes(32),
	}

	err = store.UpdateWalletSecrets(t.Context(), newSecrets)
	require.NoError(t, err)

	seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
	require.NoError(t, err)
	require.Equal(t, newSecrets.EncryptedMasterHdPrivKey, seed)
}

// TestUpdateWallet_AutoBlockInsertion verifies that UpdateWallet automatically
// inserts blocks when updating SyncedTo or BirthdayBlock.
func TestUpdateWallet_AutoBlockInsertion(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("auto-block-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	// Create a block WITHOUT pre-inserting it into the blocks table.
	block := db.Block{
		Height:    uint32(100),
		Hash:      RandomHash(),
		Timestamp: time.Now().UTC(),
	}

	// Update wallet with SyncedTo - should automatically insert the block.
	updateParams := db.UpdateWalletParams{
		WalletID: created.ID,
		SyncedTo: &block,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	// Verify the wallet was updated.
	retrieved, err := store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved.SyncedTo)
	require.Equal(t, block.Height, retrieved.SyncedTo.Height)
	require.Equal(t, block.Hash, retrieved.SyncedTo.Hash)

	// Update again with the same block - should be idempotent.
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err, "updating with same block should be idempotent")

	// Create another block for BirthdayBlock.
	birthdayBlock := db.Block{
		Height:    uint32(50),
		Hash:      RandomHash(),
		Timestamp: time.Now().UTC().Add(-time.Hour),
	}

	// Update wallet with BirthdayBlock - should automatically insert it.
	updateParams = db.UpdateWalletParams{
		WalletID:      created.ID,
		BirthdayBlock: &birthdayBlock,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	// Verify both blocks are set.
	retrieved, err = store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved.SyncedTo)
	require.NotNil(t, retrieved.BirthdayBlock)
	require.Equal(t, block.Height, retrieved.SyncedTo.Height)
	require.Equal(t, birthdayBlock.Height, retrieved.BirthdayBlock.Height)
}
