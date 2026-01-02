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

// SetLastAccountNumber sets the last_account_number for a key scope.
// Used to test account number overflow without creating billions of accounts.
func SetLastAccountNumber(t *testing.T, queries *sqlcpg.Queries,
	scopeID int64, lastAccountNumber int64) {
	t.Helper()

	err := queries.SetLastAccountNumber(
		t.Context(), sqlcpg.SetLastAccountNumberParams{
			LastAccountNumber: lastAccountNumber,
			ID:                scopeID,
		},
	)
	require.NoError(t, err)
}

// GetKeyScopeID retrieves the scope ID for a given wallet and key scope.
func GetKeyScopeID(t *testing.T, queries *sqlcpg.Queries,
	walletID uint32, scope db.KeyScope) int64 {
	t.Helper()

	row, err := queries.GetKeyScopeByWalletAndScope(
		t.Context(), sqlcpg.GetKeyScopeByWalletAndScopeParams{
			WalletID: int64(walletID),
			Purpose:  int64(scope.Purpose),
			CoinType: int64(scope.Coin),
		},
	)
	require.NoError(t, err)

	return row.ID
}
