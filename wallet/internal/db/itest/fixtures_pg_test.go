//go:build itest && test_db_postgres

package itest

import (
	"context"
	"database/sql"
	"fmt"
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

// CreateAccountWithNumber creates an account with a specific account number.
// Used to test account number overflow without creating billions of accounts.
func CreateAccountWithNumber(t *testing.T, queries *sqlcpg.Queries,
	scopeID int64, accountNumber uint32, name string) {
	t.Helper()

	_, err := queries.CreateDerivedAccountWithNumber(
		t.Context(), sqlcpg.CreateDerivedAccountWithNumberParams{
			ScopeID:       scopeID,
			AccountNumber: sql.NullInt64{Int64: int64(accountNumber), Valid: true},
			AccountName:   name,
			OriginID:      int16(db.DerivedAccount),
			IsWatchOnly:   false,
		},
	)
	require.NoError(t, err)
}

// CreateAddressWithIndex creates a derived address with a specific address
// index. Used to test address index overflow without creating billions of
// addresses.
func CreateAddressWithIndex(t *testing.T, queries *sqlcpg.Queries,
	accountID int64, branch int16, index uint32) {
	t.Helper()

	_, err := queries.CreateDerivedAddress(
		t.Context(), sqlcpg.CreateDerivedAddressParams{
			AccountID:     accountID,
			ScriptPubKey:  RandomBytes(20),
			TypeID:        int16(db.WitnessPubKey),
			AddressBranch: sql.NullInt16{Int16: branch, Valid: true},
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
		"UPDATE accounts SET next_external_index = $1 WHERE id = $2",
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
		"UPDATE accounts SET next_internal_index = $1 WHERE id = $2",
		int64(nextIndex), accountID,
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

// GetAccountID retrieves the account ID for a given scope and account name.
func GetAccountID(t *testing.T, queries *sqlcpg.Queries,
	scopeID int64, accountName string) int64 {
	t.Helper()

	row, err := queries.GetAccountByScopeAndName(
		t.Context(),
		sqlcpg.GetAccountByScopeAndNameParams{
			ScopeID:     scopeID,
			AccountName: accountName,
		},
	)
	require.NoError(t, err)

	return row.ID
}

func getAddressID(t *testing.T, queries *sqlcpg.Queries, scriptPubKey []byte,
	walletID uint32) int64 {
	t.Helper()

	addr, err := queries.GetAddressByScriptPubKey(
		t.Context(), sqlcpg.GetAddressByScriptPubKeyParams{
			ScriptPubKey: scriptPubKey,
			WalletID:     int64(walletID),
		},
	)
	require.NoError(t, err)

	return addr.ID
}

func getAddressSecret(t *testing.T, queries *sqlcpg.Queries,
	addressID int64) (sqlcpg.GetAddressSecretRow, error) {
	t.Helper()

	return queries.GetAddressSecret(t.Context(), addressID)
}

// MustDeleteAddress deletes an address by ID for test scenarios.
func MustDeleteAddress(t *testing.T, dbConn *sql.DB, addressID uint32) {
	t.Helper()

	err := deleteAddress(t.Context(), dbConn, addressID)
	require.NoError(t, err)
}

// deleteAddress removes a single address row by ID and validates row count.
func deleteAddress(ctx context.Context, dbConn *sql.DB,
	addressID uint32) error {

	result, err := dbConn.ExecContext(
		ctx, "DELETE FROM addresses WHERE id = $1", int64(addressID),
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("expected 1 deleted row, got %d", rows)
	}

	return nil
}
