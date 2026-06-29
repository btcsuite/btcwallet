//go:build itest && !test_db_postgres

package itest

import (
	"database/sql"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestSQLiteAccountRowIDAliasesImmutable verifies that SQLite rowid aliases
// cannot bypass account identity immutability.
func TestSQLiteAccountRowIDAliasesImmutable(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWatchOnlyWallet(t, store, "sqlite-account-rowid")
	accountName := "rowid-account"

	CreateImportedAccount(
		t, store, walletID, db.KeyScopeBIP0084, accountName, true,
	)

	scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)
	accountID := GetAccountID(t, queries, scopeID, accountName)

	for _, alias := range sqliteRowIDAliases() {
		err := updateSQLiteAccountRowIDAliasRaw(
			t, store.DB(), alias, accountID, accountID+1000,
		)
		require.Error(t, err, alias)
		requireDriverConstraintError(t, err)
	}
}

// TestSQLiteAddressRowIDAliasesImmutable verifies that SQLite rowid aliases
// cannot bypass address identity immutability.
func TestSQLiteAddressRowIDAliasesImmutable(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWatchOnlyWallet(t, store, "sqlite-address-rowid")
	scriptPubKey := RandomBytes(22)

	created, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:     walletID,
			AddressType:  db.WitnessPubKey,
			PubKey:       RandomBytes(33),
			ScriptPubKey: scriptPubKey,
		},
	)
	require.NoError(t, err)

	addressID := int64(created.ID)
	for _, alias := range sqliteRowIDAliases() {
		err = updateSQLiteAddressRowIDAliasRaw(
			t, store.DB(), alias, addressID, addressID+1000,
		)
		require.Error(t, err, alias)
		requireDriverConstraintError(t, err)
	}
}

// sqliteRowIDAliases returns the SQLite aliases that update INTEGER PRIMARY KEY
// row identity without naming the declared column.
func sqliteRowIDAliases() []string {
	return []string{"rowid", "_rowid_", "oid"}
}

// updateSQLiteAccountRowIDAliasRaw updates an account row through one SQLite
// rowid alias.
func updateSQLiteAccountRowIDAliasRaw(t *testing.T, dbConn *sql.DB,
	alias string, accountID int64, nextAccountID int64) error {

	t.Helper()

	var stmt string
	switch alias {
	case "rowid":
		stmt = "UPDATE accounts SET rowid = ? WHERE id = ?"
	case "_rowid_":
		stmt = "UPDATE accounts SET _rowid_ = ? WHERE id = ?"
	case "oid":
		stmt = "UPDATE accounts SET oid = ? WHERE id = ?"
	default:
		require.Failf(t, "unknown rowid alias", "alias=%s", alias)
	}

	_, err := dbConn.ExecContext(t.Context(), stmt, nextAccountID, accountID)

	return err
}

// updateSQLiteAddressRowIDAliasRaw updates an address row through one SQLite
// rowid alias.
func updateSQLiteAddressRowIDAliasRaw(t *testing.T, dbConn *sql.DB,
	alias string, addressID int64, nextAddressID int64) error {

	t.Helper()

	var stmt string
	switch alias {
	case "rowid":
		stmt = "UPDATE addresses SET rowid = ? WHERE id = ?"
	case "_rowid_":
		stmt = "UPDATE addresses SET _rowid_ = ? WHERE id = ?"
	case "oid":
		stmt = "UPDATE addresses SET oid = ? WHERE id = ?"
	default:
		require.Failf(t, "unknown rowid alias", "alias=%s", alias)
	}

	_, err := dbConn.ExecContext(t.Context(), stmt, nextAddressID, addressID)

	return err
}
