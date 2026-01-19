//go:build itest && !test_db_postgres

package itest

import (
	"database/sql"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
	"github.com/stretchr/testify/require"
)

// CreateBlockFixture inserts a test block into the database and returns it.
func CreateBlockFixture(t *testing.T, queries *sqlcsqlite.Queries,
	height uint32) db.Block {
	t.Helper()

	block := NewBlockFixture(height)
	err := queries.InsertBlock(
		t.Context(), sqlcsqlite.InsertBlockParams{
			BlockHeight:    int64(block.Height),
			HeaderHash:     block.Hash[:],
			BlockTimestamp: block.Timestamp.Unix(),
		},
	)
	require.NoError(t, err, "failed to insert block")

	return block
}

// CreateAccountWithNumber creates an account with a specific account number.
// Used to test account number overflow without creating billions of accounts.
func CreateAccountWithNumber(t *testing.T, queries *sqlcsqlite.Queries,
	scopeID int64, accountNumber uint32, name string) {
	t.Helper()

	_, err := queries.CreateDerivedAccountWithNumber(
		t.Context(), sqlcsqlite.CreateDerivedAccountWithNumberParams{
			ScopeID:       scopeID,
			AccountNumber: sql.NullInt64{Int64: int64(accountNumber), Valid: true},
			AccountName:   name,
			OriginID:      int64(db.DerivedAccount),
			IsWatchOnly:   false,
		},
	)
	require.NoError(t, err)
}

// GetKeyScopeID retrieves the scope ID for a given wallet and key scope.
func GetKeyScopeID(t *testing.T, queries *sqlcsqlite.Queries,
	walletID uint32, scope db.KeyScope) int64 {
	t.Helper()

	row, err := queries.GetKeyScopeByWalletAndScope(
		t.Context(), sqlcsqlite.GetKeyScopeByWalletAndScopeParams{
			WalletID: int64(walletID),
			Purpose:  int64(scope.Purpose),
			CoinType: int64(scope.Coin),
		},
	)
	require.NoError(t, err)

	return row.ID
}
