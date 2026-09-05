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
