//go:build itest && test_db_postgres

package itest

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
	"github.com/stretchr/testify/require"
)

// CreateBlockFixture inserts a test block into the database and returns it.
func CreateBlockFixture(t *testing.T, queries *sqlcpg.Queries,
	height uint32) db.Block {
	t.Helper()

	block := NewBlockFixture(height)
	err := queries.InsertBlock(
		t.Context(), sqlcpg.InsertBlockParams{
			BlockHeight:    int32(block.Height),
			HeaderHash:     block.Hash[:],
			BlockTimestamp: block.Timestamp.Unix(),
		},
	)
	require.NoError(t, err, "failed to insert block")

	return block
}
