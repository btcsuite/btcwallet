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

// CreateAddressWithIndex creates a derived address with a specific address
// index. Used to test address index overflow without creating billions of
// addresses.
func CreateAddressWithIndex(t *testing.T, queries *sqlcsqlite.Queries,
	accountID int64, branch uint32, index uint32) {
	t.Helper()

	_, err := queries.CreateDerivedAddress(
		t.Context(), sqlcsqlite.CreateDerivedAddressParams{
			AccountID:     accountID,
			ScriptPubKey:  RandomBytes(20),
			TypeID:        int64(db.WitnessPubKey),
			AddressBranch: sql.NullInt64{Int64: int64(branch), Valid: true},
			AddressIndex:  sql.NullInt64{Int64: int64(index), Valid: true},
			PubKey:        nil,
		},
	)
	require.NoError(t, err)
}

// UpdateAccountNextExternalIndex updates the account's external index counter.
func UpdateAccountNextExternalIndex(t *testing.T, dbConn *sql.DB,
	accountID int64, nextIndex uint32) {
	t.Helper()

	_, err := dbConn.ExecContext(
		t.Context(),
		"UPDATE accounts SET next_external_index = ? WHERE id = ?",
		int64(nextIndex), accountID,
	)
	require.NoError(t, err)
}

// UpdateAccountNextInternalIndex updates the account's internal index counter.
func UpdateAccountNextInternalIndex(t *testing.T, dbConn *sql.DB,
	accountID int64, nextIndex uint32) {

	t.Helper()

	_, err := dbConn.ExecContext(
		t.Context(),
		"UPDATE accounts SET next_internal_index = ? WHERE id = ?",
		int64(nextIndex), accountID,
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

// GetAccountID retrieves the account ID for a given scope and account name.
func GetAccountID(t *testing.T, queries *sqlcsqlite.Queries,
	scopeID int64, accountName string) int64 {
	t.Helper()

	row, err := queries.GetAccountByScopeAndName(
		t.Context(),
		sqlcsqlite.GetAccountByScopeAndNameParams{
			ScopeID:     scopeID,
			AccountName: accountName,
		},
	)
	require.NoError(t, err)

	return row.ID
}

func getAddressID(t *testing.T, queries *sqlcsqlite.Queries,
	scriptPubKey []byte, walletID uint32) int64 {
	t.Helper()

	addr, err := queries.GetAddressByScriptPubKey(
		t.Context(), sqlcsqlite.GetAddressByScriptPubKeyParams{
			ScriptPubKey: scriptPubKey,
			WalletID:     int64(walletID),
		},
	)
	require.NoError(t, err)

	return addr.ID
}

func getAddressSecret(t *testing.T, queries *sqlcsqlite.Queries,
	addressID int64) (sqlcsqlite.GetAddressSecretRow, error) {
	t.Helper()

	return queries.GetAddressSecret(t.Context(), addressID)
}
