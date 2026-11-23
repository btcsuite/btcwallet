//go:build itest

package itest

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestListSyncedBlocksRejectsMissingRanges verifies missing block heights are
// reported for both an interior gap and a missing range tail.
func TestListSyncedBlocksRejectsMissingRanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		query db.ListSyncedBlocksQuery
	}{
		{
			name: "gap",
			query: db.ListSyncedBlocksQuery{
				StartHeight: 144,
				EndHeight:   146,
			},
		},
		{
			name: "short tail",
			query: db.ListSyncedBlocksQuery{
				StartHeight: 146,
				EndHeight:   147,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: persist blocks on either side of the missing range.
			store := NewTestStore(t)
			walletID := newWallet(t, store, "range-owner")
			queries := store.Queries()
			CreateBlockFixture(t, queries, walletID, 144)
			CreateBlockFixture(t, queries, walletID, 146)

			// Act: request a range containing a missing height.
			query := test.query
			query.WalletID = walletID
			_, err := store.ListSyncedBlocks(t.Context(), query)

			// Assert: missing ranges return the shared not-found error.
			require.ErrorIs(t, err, db.ErrBlockNotFound)
		})
	}
}

// TestInsertWalletBlockConstraints checks which block inserts can be ignored.
func TestInsertWalletBlockConstraints(t *testing.T) {
	// Seed a Wallet and block so each replay can conflict on only one key.
	store := NewTestStore(t)
	queries := store.Queries()
	hash, otherHash := [32]byte{1}, [32]byte{2}
	block := insertWalletBlockParams{
		WalletID:       int64(newWatchOnlyWallet(t, store, "owned-blocks")),
		BlockHeight:    1,
		HeaderHash:     hash[:],
		BlockTimestamp: 1,
	}
	require.NoError(t, queries.InsertWalletBlock(t.Context(), block))

	// Each valid replay shares one key. The invalid row shares neither.
	cases := []struct {
		name   string
		params insertWalletBlockParams
	}{
		{
			name: "height conflict",
			params: insertWalletBlockParams{
				BlockHeight: 1,
				HeaderHash:  otherHash[:],
			},
		},
		{
			name: "hash conflict",
			params: insertWalletBlockParams{
				BlockHeight: 2,
				HeaderHash:  hash[:],
			},
		},
		{
			name: "negative timestamp",
			params: insertWalletBlockParams{
				BlockHeight:    3,
				HeaderHash:     otherHash[:],
				BlockTimestamp: -1,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use the seed's Wallet and vary only the case's block data.
			attempt := tc.params
			attempt.WalletID = block.WalletID

			// Call the binding directly to observe the driver's error.
			err := queries.InsertWalletBlock(t.Context(), attempt)

			// Only duplicates may succeed without producing a row.
			if attempt.BlockTimestamp < 0 {
				requireDriverConstraintError(t, err, driverConstraintCheck)
			} else {
				require.NoError(t, err)
			}
		})
	}

	// Both no-ops and the rejected insert leave only the seeded block.
	found, err := queries.GetWalletBlocksInRange(
		t.Context(), getWalletBlocksInRangeParams{
			WalletID: block.WalletID, StartHeight: 1, EndHeight: 3,
		},
	)
	require.NoError(t, err)
	require.Len(t, found, 1)
	require.Equal(t, block.BlockHeight, found[0].BlockHeight)
	require.Equal(t, block.BlockTimestamp, found[0].BlockTimestamp)
	require.Equal(t, block.HeaderHash, found[0].HeaderHash)
}
