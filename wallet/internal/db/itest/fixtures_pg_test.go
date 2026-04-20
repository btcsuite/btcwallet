//go:build itest && test_db_postgres

package itest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	sqlc "github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/stretchr/testify/require"
)

// testBackend returns the SQL backend expected by PostgreSQL itests.
func testBackend() dberr.Backend {
	return dberr.BackendPostgres
}

// requireConstraintSQLError verifies that a real PostgreSQL constraint failure
// reaches callers as the shared SQL error wrapper.
func requireConstraintSQLError(t *testing.T, err error) {
	t.Helper()

	var sqlErr *dberr.SQLError
	require.ErrorAs(t, err, &sqlErr)
	require.Equal(t, testBackend(), sqlErr.Backend)
	require.Equal(t, dberr.ReasonConstraint, sqlErr.Reason)
	require.Equal(t, dberr.ClassPermanent, sqlErr.Class())
	require.True(t, errors.Is(err, sqlErr))
}

// CreateBlockFixture inserts a test block into the database and returns it.
func CreateBlockFixture(t *testing.T, queries *sqlc.Queries,
	height uint32) db.Block {
	t.Helper()

	block := NewBlockFixture(height)
	err := queries.InsertBlock(
		t.Context(), sqlc.InsertBlockParams{
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
func CreateAccountWithNumber(t *testing.T, queries *sqlc.Queries,
	scopeID int64, accountNumber uint32, name string) {
	t.Helper()

	_, err := queries.CreateDerivedAccountWithNumber(
		t.Context(), sqlc.CreateDerivedAccountWithNumberParams{
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
func CreateAddressWithIndex(t *testing.T, queries *sqlc.Queries,
	accountID int64, branch int16, index uint32) {
	t.Helper()

	_, err := queries.CreateDerivedAddress(
		t.Context(), sqlc.CreateDerivedAddressParams{
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
func GetKeyScopeID(t *testing.T, queries *sqlc.Queries,
	walletID uint32, scope db.KeyScope) int64 {
	t.Helper()

	row, err := queries.GetKeyScopeByWalletAndScope(
		t.Context(), sqlc.GetKeyScopeByWalletAndScopeParams{
			WalletID: int64(walletID),
			Purpose:  int64(scope.Purpose),
			CoinType: int64(scope.Coin),
		},
	)
	require.NoError(t, err)

	return row.ID
}

// GetAccountID retrieves the account ID for a given scope and account name.
func GetAccountID(t *testing.T, queries *sqlc.Queries,
	scopeID int64, accountName string) int64 {
	t.Helper()

	row, err := queries.GetAccountByScopeAndName(
		t.Context(),
		sqlc.GetAccountByScopeAndNameParams{
			ScopeID:     scopeID,
			AccountName: accountName,
		},
	)
	require.NoError(t, err)

	return row.ID
}

func getAddressID(t *testing.T, queries *sqlc.Queries, scriptPubKey []byte,
	walletID uint32) int64 {
	t.Helper()

	addr, err := queries.GetAddressByScriptPubKey(
		t.Context(), sqlc.GetAddressByScriptPubKeyParams{
			ScriptPubKey: scriptPubKey,
			WalletID:     int64(walletID),
		},
	)
	require.NoError(t, err)

	return addr.ID
}

func GetAddressSecret(t *testing.T, queries *sqlc.Queries,
	addressID int64) (sqlc.GetAddressSecretRow, error) {
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

func setupMaxAccountNumberTest(t *testing.T, store db.AccountStore,
	walletID uint32) {

	t.Helper()

	require.IsType(t, &pg.Store{}, store)

	pgStore := store.(*pg.Store)
	queries := pgStore.Queries()
	scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)
	CreateAccountWithNumber(t, queries, scopeID, math.MaxUint32-1,
		"account-near-max")
}
