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
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

var errUnexpectedDeletedRows = errors.New("unexpected deleted row count")

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
	require.ErrorIs(t, err, sqlErr)
}

// requireDriverConstraintError verifies that a direct PostgreSQL driver error is
// a constraint violation before store-level error wrapping occurs.
func requireDriverConstraintError(t *testing.T, err error) {
	t.Helper()

	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23514", pgErr.Code)
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
			ScopeID: scopeID,
			AccountNumber: sql.NullInt64{
				Int64: int64(accountNumber),
				Valid: true,
			},
			AccountName: name,
			OriginID:    int16(db.DerivedAccount),
		},
	)
	require.NoError(t, err)
}

// createDerivedAccountRaw inserts a derived account directly through the
// database so tests can validate wallet/scope ownership invariants.
func createDerivedAccountRaw(t *testing.T, dbConn *sql.DB, walletID uint32,
	scopeID int64, accountNumber uint32, name string) error {

	t.Helper()

	const stmt = `
		INSERT INTO accounts (
			wallet_id,
			scope_id,
			account_number,
			account_name,
			origin_id
		) VALUES ($1, $2, $3, $4, $5)`

	_, err := dbConn.ExecContext(
		t.Context(), stmt, int64(walletID), scopeID, int64(accountNumber),
		name, int16(db.DerivedAccount),
	)

	return err
}

// createImportedAccountRaw inserts an imported account directly through the
// database so tests can validate wallet/scope ownership invariants.
func createImportedAccountRaw(t *testing.T, dbConn *sql.DB, walletID uint32,
	scopeID int64, name string) error {

	t.Helper()

	const stmt = `
		INSERT INTO accounts (
			wallet_id,
			scope_id,
			account_number,
			account_name,
			origin_id,
			encrypted_public_key
		) VALUES ($1, $2, NULL, $3, $4, $5)`

	_, err := dbConn.ExecContext(
		t.Context(), stmt, int64(walletID), scopeID, name,
		int16(db.ImportedAccount), RandomBytes(32),
	)

	return err
}

// insertAccountSecretRaw inserts an account secret directly through the
// database so tests can validate watch-only triggers on account_secrets.
func insertAccountSecretRaw(t *testing.T, dbConn *sql.DB, accountID int64,
	encryptedPrivateKey []byte) error {

	t.Helper()

	const stmt = `
		INSERT INTO account_secrets (
			account_id,
			encrypted_private_key
		) VALUES ($1, $2)`

	_, err := dbConn.ExecContext(
		t.Context(), stmt, accountID, encryptedPrivateKey,
	)

	return err
}

// updateAccountSecretRaw updates an account secret directly through the
// database so tests can validate watch-only triggers on account_secrets.
func updateAccountSecretRaw(t *testing.T, dbConn *sql.DB, accountID int64,
	encryptedPrivateKey []byte) error {

	t.Helper()

	const stmt = `
		UPDATE account_secrets
		SET encrypted_private_key = $1
		WHERE account_id = $2`

	result, err := dbConn.ExecContext(
		t.Context(), stmt, encryptedPrivateKey, accountID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("expected 1 updated row, got %d", rows)
	}

	return nil
}

// deleteWalletSecretRaw deletes a wallet secret row directly through the
// database so tests can re-exercise wallet_secrets insert triggers.
func deleteWalletSecretRaw(t *testing.T, dbConn *sql.DB, walletID uint32) error {
	t.Helper()

	const stmt = `
		DELETE FROM wallet_secrets
		WHERE wallet_id = $1`

	result, err := dbConn.ExecContext(t.Context(), stmt, int64(walletID))
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

// insertWalletSecretRaw inserts a wallet secret directly through the database
// so tests can validate watch-only triggers on wallet_secrets.
func insertWalletSecretRaw(t *testing.T, dbConn *sql.DB, walletID uint32,
	masterPrivParams []byte, encryptedCryptoPrivKey []byte,
	encryptedCryptoScriptKey []byte, encryptedMasterHDPrivKey []byte) error {

	t.Helper()

	const stmt = `
		INSERT INTO wallet_secrets (
			wallet_id,
			master_priv_params,
			encrypted_crypto_priv_key,
			encrypted_crypto_script_key,
			encrypted_master_hd_priv_key
		) VALUES ($1, $2, $3, $4, $5)`

	_, err := dbConn.ExecContext(
		t.Context(), stmt, int64(walletID), masterPrivParams,
		encryptedCryptoPrivKey, encryptedCryptoScriptKey,
		encryptedMasterHDPrivKey,
	)

	return err
}

// updateWalletSecretRaw updates a wallet secret directly through the database
// so tests can validate watch-only triggers on wallet_secrets.
func updateWalletSecretRaw(t *testing.T, dbConn *sql.DB, walletID uint32,
	masterPrivParams []byte, encryptedCryptoPrivKey []byte,
	encryptedCryptoScriptKey []byte, encryptedMasterHDPrivKey []byte) error {

	t.Helper()

	const stmt = `
		UPDATE wallet_secrets
		SET master_priv_params = $1,
			encrypted_crypto_priv_key = $2,
			encrypted_crypto_script_key = $3,
			encrypted_master_hd_priv_key = $4
		WHERE wallet_id = $5`

	result, err := dbConn.ExecContext(
		t.Context(), stmt, masterPrivParams, encryptedCryptoPrivKey,
		encryptedCryptoScriptKey, encryptedMasterHDPrivKey, int64(walletID),
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("expected 1 updated row, got %d", rows)
	}

	return nil
}

// updateWalletWatchOnlyRaw updates the watch-only flag directly through the
// database so tests can validate its immutability trigger.
func updateWalletWatchOnlyRaw(t *testing.T, dbConn *sql.DB, walletID uint32,
	isWatchOnly bool) error {

	t.Helper()

	const stmt = `
		UPDATE wallets
		SET is_watch_only = $1
		WHERE id = $2`

	result, err := dbConn.ExecContext(
		t.Context(), stmt, isWatchOnly, int64(walletID),
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("expected 1 updated row, got %d", rows)
	}

	return nil
}

// CreateAddressWithIndex creates a derived address with a specific address
// index. Used to test address index overflow without creating billions of
// addresses.
func CreateAddressWithIndex(t *testing.T, queries *sqlc.Queries,
	walletID uint32, accountID int64, branch int16, index uint32) {

	t.Helper()

	_, err := queries.CreateDerivedAddress(
		t.Context(), sqlc.CreateDerivedAddressParams{
			WalletID:      int64(walletID),
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

// getAddressID retrieves an address ID by script and wallet.
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
		return fmt.Errorf("%w: got %d", errUnexpectedDeletedRows, rows)
	}

	return nil
}

// setupMaxAccountNumberTest seeds state near the account-number limit.
func setupMaxAccountNumberTest(t *testing.T, store db.AccountStore,
	walletID uint32) {

	t.Helper()

	pgStore, ok := store.(*pg.Store)
	require.True(t, ok)

	queries := pgStore.Queries()
	scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)
	CreateAccountWithNumber(t, queries, scopeID, math.MaxUint32-1,
		"account-near-max")
}

// createImportedAddressRaw inserts an imported address directly through the
// database so tests can validate wallet/account ownership invariants.
func createImportedAddressRaw(ctx context.Context, queries *sqlc.Queries,
	walletID uint32, accountID int64, scriptPubKey []byte) error {

	_, err := queries.CreateImportedAddress(
		ctx, sqlc.CreateImportedAddressParams{
			WalletID:     int64(walletID),
			AccountID:    accountID,
			ScriptPubKey: scriptPubKey,
			TypeID:       int16(db.WitnessPubKey),
			PubKey:       RandomBytes(33),
		},
	)

	return err
}

// insertAddressSecretRaw inserts an address secret directly through the
// database so tests can validate watch-only triggers on address_secrets.
func insertAddressSecretRaw(t *testing.T, dbConn *sql.DB, addressID int64,
	encryptedPrivKey []byte, encryptedScript []byte) error {

	t.Helper()

	const stmt = `
		INSERT INTO address_secrets (
			address_id,
			encrypted_priv_key,
			encrypted_script
		) VALUES ($1, $2, $3)`

	_, err := dbConn.ExecContext(
		t.Context(), stmt, addressID, encryptedPrivKey, encryptedScript,
	)

	return err
}

// updateAddressSecretRaw updates an address secret directly through the
// database so tests can validate watch-only triggers on address_secrets.
func updateAddressSecretRaw(t *testing.T, dbConn *sql.DB, addressID int64,
	encryptedPrivKey []byte, encryptedScript []byte) error {

	t.Helper()

	const stmt = `
		UPDATE address_secrets
		SET encrypted_priv_key = $1,
			encrypted_script = $2
		WHERE address_id = $3`

	result, err := dbConn.ExecContext(
		t.Context(), stmt, encryptedPrivKey, encryptedScript, addressID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("expected 1 updated row, got %d", rows)
	}

	return nil
}

// createDerivedAddressRaw inserts a derived address directly through
// PostgreSQL sqlc queries for testing database-level invariants.
func createDerivedAddressRaw(t *testing.T, queries *sqlc.Queries,
	walletID uint32, accountID int64, branch uint32, index uint32,
	scriptPubKey []byte) error {

	t.Helper()

	branchNum, err := db.Uint32ToInt16(branch)
	require.NoError(t, err)

	_, err = queries.CreateDerivedAddress(
		t.Context(), sqlc.CreateDerivedAddressParams{
			WalletID:     int64(walletID),
			AccountID:    accountID,
			ScriptPubKey: scriptPubKey,
			TypeID:       int16(db.WitnessPubKey),
			AddressBranch: sql.NullInt16{
				Int16: branchNum,
				Valid: true,
			},
			AddressIndex: sql.NullInt64{
				Int64: int64(index),
				Valid: true,
			},
			PubKey: nil,
		},
	)

	return err
}
