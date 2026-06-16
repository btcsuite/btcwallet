//go:build itest && test_db_postgres

package itest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

var (
	errUnexpectedDeletedRows = errors.New("unexpected deleted row count")
	errUnexpectedUpdatedRows = errors.New("unexpected updated row count")
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
	require.ErrorIs(t, err, sqlErr)
}

// requireDriverConstraintError verifies that a direct PostgreSQL driver error
// indicates a constraint violation before store-level error wrapping occurs.
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

// ReplacementTxHashesByReplaced returns the replacement transaction hashes
// recorded for one replaced transaction hash. It exists so shared itests can
// assert replacement edges without naming the backend-specific generated query
// types.
func ReplacementTxHashesByReplaced(t *testing.T, queries *sqlc.Queries,
	walletID uint32, replacedHash []byte) [][]byte {

	t.Helper()

	rows, err := queries.ListReplacementTxHashesByReplacedTxHash(
		t.Context(), sqlc.ListReplacementTxHashesByReplacedTxHashParams{
			WalletID: int64(walletID),
			TxHash:   replacedHash,
		},
	)
	require.NoError(t, err)

	hashes := make([][]byte, 0, len(rows))
	for _, row := range rows {
		hashes = append(hashes, row.ReplacementTxHash)
	}

	return hashes
}

// CreateAccountWithNumber creates an account with a specific account number.
// Used to test account number overflow without creating billions of accounts.
func CreateAccountWithNumber(t *testing.T, queries *sqlc.Queries,
	scopeID int64, accountNumber uint32, name string) {

	t.Helper()

	account, err := queries.CreateDerivedAccount(
		t.Context(), sqlc.CreateDerivedAccountParams{
			ScopeID:           scopeID,
			AccountName:       name,
			PublicKey:         RandomBytes(32),
			MasterFingerprint: sql.NullInt64{},
		},
	)
	require.NoError(t, err)

	_, err = queries.CreateDerivedAccountNumber(
		t.Context(), sqlc.CreateDerivedAccountNumberParams{
			AccountID:     account.ID,
			AccountNumber: int64(accountNumber),
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
			account_name,
			is_derived,
			public_key
		) VALUES ($1, $2, $3, TRUE, $4)
		RETURNING id`

	var accountID int64

	err := dbConn.QueryRowContext(
		t.Context(), stmt, int64(walletID), scopeID, name, RandomBytes(32),
	).Scan(&accountID)
	if err != nil {
		return err
	}

	const numberStmt = `
		INSERT INTO derived_accounts (
			account_id,
			scope_id,
			account_number
		) VALUES ($1, $2, $3)`

	_, err = dbConn.ExecContext(
		t.Context(), numberStmt, accountID, scopeID, int64(accountNumber),
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
			account_name,
			is_derived,
			public_key
		) VALUES ($1, $2, $3, FALSE, $4)`

	_, err := dbConn.ExecContext(
		t.Context(), stmt, int64(walletID), scopeID, name, RandomBytes(32),
	)

	return err
}

// insertDerivedAccountNumberRaw inserts a derived_accounts child directly so
// tests can model corrupt account shape metadata.
func insertDerivedAccountNumberRaw(t *testing.T, dbConn *sql.DB,
	accountID int64, scopeID int64, accountNumber uint32) error {

	t.Helper()

	const stmt = `
		INSERT INTO derived_accounts (
			account_id,
			scope_id,
			account_number
		) VALUES ($1, $2, $3)`

	_, err := dbConn.ExecContext(
		t.Context(), stmt, accountID, scopeID, int64(accountNumber),
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
		return fmt.Errorf("%w: got %d", errUnexpectedUpdatedRows, rows)
	}

	return nil
}

// deleteKeyScopeSecretRaw deletes a key-scope secret row directly through the
// database so tests can verify or reset absent-row state.
func deleteKeyScopeSecretRaw(t *testing.T, dbConn *sql.DB,
	scopeID int64) error {

	t.Helper()

	const stmt = `
		DELETE FROM key_scope_secrets
		WHERE scope_id = $1`

	result, err := dbConn.ExecContext(t.Context(), stmt, scopeID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows > 1 {
		return fmt.Errorf("%w: got %d", errUnexpectedDeletedRows, rows)
	}

	return nil
}

// insertKeyScopeSecretRaw inserts a key-scope secret directly through the
// database so tests can validate watch-only triggers on key_scope_secrets.
func insertKeyScopeSecretRaw(t *testing.T, dbConn *sql.DB, scopeID int64,
	encryptedCoinPrivKey []byte) error {

	t.Helper()

	const stmt = `
		INSERT INTO key_scope_secrets (
			scope_id,
			encrypted_coin_priv_key
		) VALUES ($1, $2)`

	_, err := dbConn.ExecContext(
		t.Context(), stmt, scopeID, encryptedCoinPrivKey,
	)

	return err
}

// updateKeyScopeSecretRaw updates a key-scope secret directly through the
// database so tests can validate watch-only triggers on key_scope_secrets.
func updateKeyScopeSecretRaw(t *testing.T, dbConn *sql.DB, scopeID int64,
	encryptedCoinPrivKey []byte) error {

	t.Helper()

	const stmt = `
		UPDATE key_scope_secrets
		SET encrypted_coin_priv_key = $1
		WHERE scope_id = $2`

	result, err := dbConn.ExecContext(
		t.Context(), stmt, encryptedCoinPrivKey, scopeID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("%w: got %d", errUnexpectedUpdatedRows, rows)
	}

	return nil
}

// deleteWalletSecretRaw deletes a wallet secret row directly through the
// database so tests can re-exercise wallet_secrets insert triggers.
func deleteWalletSecretRaw(t *testing.T, dbConn *sql.DB,
	walletID uint32) error {

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
		return fmt.Errorf("%w: got %d", errUnexpectedDeletedRows, rows)
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
		return fmt.Errorf("%w: got %d", errUnexpectedUpdatedRows, rows)
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
		return fmt.Errorf("%w: got %d", errUnexpectedUpdatedRows, rows)
	}

	return nil
}

// updateKeyScopeWalletIDRaw updates a key scope wallet_id directly through the
// database so tests can validate its immutability trigger.
func updateKeyScopeWalletIDRaw(t *testing.T, dbConn *sql.DB, scopeID int64,
	walletID uint32) error {

	t.Helper()

	const stmt = `
		UPDATE key_scopes
		SET wallet_id = $1
		WHERE id = $2`

	result, err := dbConn.ExecContext(
		t.Context(), stmt, int64(walletID), scopeID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("%w: got %d", errUnexpectedUpdatedRows, rows)
	}

	return nil
}

// reparentAccountRaw updates an account wallet/scope pair directly through the
// database so tests can validate wallet ownership immutability after insert.
func reparentAccountRaw(t *testing.T, dbConn *sql.DB, accountID int64,
	walletID uint32, scopeID int64) error {

	t.Helper()

	const stmt = `
		UPDATE accounts
		SET wallet_id = $1,
			scope_id = $2
		WHERE id = $3`

	result, err := dbConn.ExecContext(
		t.Context(), stmt, int64(walletID), scopeID, accountID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("%w: got %d", errUnexpectedUpdatedRows, rows)
	}

	return nil
}

// updateAccountIDRaw updates an account primary key directly through the
// database so tests can validate account identity immutability after insert.
func updateAccountIDRaw(t *testing.T, dbConn *sql.DB, accountID int64,
	nextAccountID int64) error {

	t.Helper()

	const stmt = `
		UPDATE accounts
		SET id = $1
		WHERE id = $2`

	result, err := dbConn.ExecContext(
		t.Context(), stmt, nextAccountID, accountID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("%w: got %d", errUnexpectedUpdatedRows, rows)
	}

	return nil
}

// updateDerivedAccountNumberRaw updates a derived account child row directly
// through the database so tests can validate child identity immutability.
func updateDerivedAccountNumberRaw(t *testing.T, dbConn *sql.DB,
	accountID int64, accountNumber uint32) error {

	t.Helper()

	const stmt = `
		UPDATE derived_accounts
		SET account_number = $1
		WHERE account_id = $2`

	result, err := dbConn.ExecContext(
		t.Context(), stmt, int64(accountNumber), accountID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("%w: got %d", errUnexpectedUpdatedRows, rows)
	}

	return nil
}

// reparentAddressRaw updates an address wallet/scope pair directly through
// the database so tests can validate wallet ownership immutability after
// insert.
func reparentAddressRaw(t *testing.T, dbConn *sql.DB, addressID int64,
	walletID uint32, scopeID int64) error {

	t.Helper()

	const stmt = `
		UPDATE addresses
		SET wallet_id = $1,
			scope_id = $2
		WHERE id = $3`

	result, err := dbConn.ExecContext(
		t.Context(), stmt, int64(walletID), scopeID, addressID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("%w: got %d", errUnexpectedUpdatedRows, rows)
	}

	return nil
}

// updateAddressIDRaw updates an address primary key directly through the
// database so tests can validate address identity immutability after insert.
func updateAddressIDRaw(t *testing.T, dbConn *sql.DB, addressID int64,
	nextAddressID int64) error {

	t.Helper()

	const stmt = `
		UPDATE addresses
		SET id = $1
		WHERE id = $2`

	result, err := dbConn.ExecContext(
		t.Context(), stmt, nextAddressID, addressID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("%w: got %d", errUnexpectedUpdatedRows, rows)
	}

	return nil
}

// updateDerivedAddressIndexRaw updates a derived address child row directly
// through the database so tests can validate child identity immutability.
func updateDerivedAddressIndexRaw(t *testing.T, dbConn *sql.DB,
	addressID int64, index uint32) error {

	t.Helper()

	const stmt = `
		UPDATE derived_addresses
		SET address_index = $1
		WHERE address_id = $2`

	result, err := dbConn.ExecContext(
		t.Context(), stmt, int64(index), addressID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("%w: got %d", errUnexpectedUpdatedRows, rows)
	}

	return nil
}

// CreateAddressWithIndex creates a derived address with a specific address
// index. Used to test address index overflow without creating billions of
// addresses.
func CreateAddressWithIndex(t *testing.T, queries *sqlc.Queries,
	walletID uint32, accountID int64, branch int16, index uint32) {

	t.Helper()

	addr, err := queries.CreateDerivedAddress(
		t.Context(), sqlc.CreateDerivedAddressParams{
			WalletID:     int64(walletID),
			AccountID:    accountID,
			ScriptPubKey: RandomBytes(20),
			ScriptTypeID: int16(db.WitnessPubKey),
			PubKey:       nil,
		},
	)
	require.NoError(t, err)

	err = queries.CreateDerivedAddressPath(
		t.Context(), sqlc.CreateDerivedAddressPathParams{
			AccountID:     accountID,
			AddressBranch: branch,
			AddressIndex:  int64(index),
			AddressID:     addr.ID,
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

// UpdateKeyScopeNextAccountNumber updates the key scope's next account number
// counter.
func UpdateKeyScopeNextAccountNumber(t *testing.T, dbConn *sql.DB,
	scopeID int64, nextAccountNumber uint32) {

	t.Helper()

	_, err := dbConn.ExecContext(
		t.Context(),
		"UPDATE key_scopes SET next_account_number = $1 WHERE id = $2",
		int64(nextAccountNumber), scopeID,
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

// createImportedAddressRaw inserts an imported address directly through the
// database so tests can validate wallet/scope ownership invariants.
func createImportedAddressRaw(ctx context.Context, queries *sqlc.Queries,
	walletID uint32, scopeID int64, scriptPubKey []byte) error {

	_, err := queries.CreateImportedAddress(
		ctx, sqlc.CreateImportedAddressParams{
			WalletID:     int64(walletID),
			ScopeID:      scopeID,
			ScriptPubKey: scriptPubKey,
			ScriptTypeID: int16(db.WitnessPubKey),
			PubKey:       RandomBytes(33),
		},
	)

	return err
}

// createDerivedAddressParentRaw inserts only the addresses parent row for a
// derived address so tests can model a missing derived_addresses child row.
func createDerivedAddressParentRaw(t *testing.T, queries *sqlc.Queries,
	walletID uint32, accountID int64, scriptPubKey []byte) (int64, error) {

	t.Helper()

	addr, err := queries.CreateDerivedAddress(
		t.Context(), sqlc.CreateDerivedAddressParams{
			WalletID:     int64(walletID),
			AccountID:    accountID,
			ScriptPubKey: scriptPubKey,
			ScriptTypeID: int16(db.WitnessPubKey),
			PubKey:       nil,
		},
	)
	if err != nil {
		return 0, err
	}

	return addr.ID, nil
}

// insertCorruptDerivedAddressChildRaw inserts a derived_addresses child under
// an arbitrary address parent so tests can model manually corrupted address
// shape metadata.
func insertCorruptDerivedAddressChildRaw(t *testing.T, dbConn *sql.DB,
	walletID uint32, scopeID int64, accountID int64, addressID int64,
	branch uint32, index uint32) error {

	t.Helper()

	branchNum, err := db.Uint32ToInt16(branch)
	require.NoError(t, err)

	const disableStmt = `
		ALTER TABLE derived_addresses
		DISABLE TRIGGER trg_assert_derived_address_parent_insert`

	_, err = dbConn.ExecContext(t.Context(), disableStmt)
	if err != nil {
		return err
	}

	defer func() {
		const enableStmt = `
			ALTER TABLE derived_addresses
			ENABLE TRIGGER trg_assert_derived_address_parent_insert`

		_, enableErr := dbConn.ExecContext(t.Context(), enableStmt)
		require.NoError(t, enableErr)
	}()

	const stmt = `
		INSERT INTO derived_addresses (
			address_id,
			wallet_id,
			scope_id,
			account_id,
			address_branch,
			address_index
		) VALUES ($1, $2, $3, $4, $5, $6)`

	_, err = dbConn.ExecContext(
		t.Context(), stmt, addressID, int64(walletID), scopeID,
		accountID, branchNum, int64(index),
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
		return fmt.Errorf("%w: got %d", errUnexpectedUpdatedRows, rows)
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

	addr, err := queries.CreateDerivedAddress(
		t.Context(), sqlc.CreateDerivedAddressParams{
			WalletID:     int64(walletID),
			AccountID:    accountID,
			ScriptPubKey: scriptPubKey,
			ScriptTypeID: int16(db.WitnessPubKey),
			PubKey:       nil,
		},
	)
	if err != nil {
		return err
	}

	return queries.CreateDerivedAddressPath(
		t.Context(), sqlc.CreateDerivedAddressPathParams{
			AccountID:     accountID,
			AddressBranch: branchNum,
			AddressIndex:  int64(index),
			AddressID:     addr.ID,
		},
	)
}
