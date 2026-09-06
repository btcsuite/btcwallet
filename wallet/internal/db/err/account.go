package dberr

import (
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// IsAccountNameConflict identifies an existing account-name constraint failure
// without changing the error returned by Store. Other uniqueness violations
// must not acquire the public duplicate-account identity.
func IsAccountNameConflict(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505" && pgErr.ConstraintName ==
			"uidx_accounts_wallet_scope_account_name"
	}

	var sqliteErr *sqlite.Error

	return errors.As(err, &sqliteErr) &&
		sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE &&
		strings.Contains(
			sqliteErr.Error(),
			"UNIQUE constraint failed: accounts.wallet_id, "+
				"accounts.scope_id, accounts.account_name",
		)
}

// IsAccountNumberConflict identifies the derived-account number constraint
// without treating unrelated uniqueness failures as occupied account numbers.
func IsAccountNumberConflict(err error) bool {
	// PostgreSQL supplies the index identity; SQLite exposes the constrained
	// column tuple. Require the uniqueness code before inspecting either.
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505" && pgErr.ConstraintName ==
			"uidx_accounts_scope_account_number"
	}

	var sqliteErr *sqlite.Error

	return errors.As(err, &sqliteErr) &&
		sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE &&
		strings.Contains(
			sqliteErr.Error(),
			"UNIQUE constraint failed: accounts.scope_id, "+
				"accounts.account_number",
		)
}
