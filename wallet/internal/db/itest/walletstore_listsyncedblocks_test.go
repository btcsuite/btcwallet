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
			queries := store.Queries()
			CreateBlockFixture(t, queries, 144)
			CreateBlockFixture(t, queries, 146)

			// Act: request a range containing a missing height.
			_, err := store.ListSyncedBlocks(t.Context(), test.query)

			// Assert: missing ranges return the shared not-found error.
			require.ErrorIs(t, err, db.ErrBlockNotFound)
		})
	}
}
