//go:build itest && !test_db_postgres

package itest

import (
	"database/sql"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
	"github.com/stretchr/testify/require"
	sqlite3 "modernc.org/sqlite/lib"
)

// TestSQLiteInsertWalletBlockConstraints checks which inserts can be ignored.
func TestSQLiteInsertWalletBlockConstraints(t *testing.T) {
	const checkCode = sqlite3.SQLITE_CONSTRAINT_CHECK

	// Seed a Wallet and block so each replay can conflict on only one key.
	store := NewTestStore(t)
	queries := store.Queries()
	hash, otherHash := [32]byte{1}, [32]byte{2}
	block := sqlc.InsertWalletBlockParams{
		WalletID:       int64(newWatchOnlyWallet(t, store, "owned-blocks")),
		BlockHeight:    1,
		HeaderHash:     hash[:],
		BlockTimestamp: 1,
	}
	require.NoError(t, queries.InsertWalletBlock(t.Context(), block))

	// Each valid replay shares one key. The invalid row shares neither.
	cases := []struct {
		name      string
		height    int64
		hash      []byte
		timestamp int64
	}{
		{
			name:   "height conflict",
			height: 1,
			hash:   otherHash[:],
		},
		{
			name:   "hash conflict",
			height: 2,
			hash:   hash[:],
		},
		{
			name:      "negative timestamp",
			height:    3,
			hash:      otherHash[:],
			timestamp: -1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Keep the Wallet fixed and replace the seeded block data.
			attempt := block
			attempt.BlockHeight = tc.height
			attempt.HeaderHash = tc.hash
			attempt.BlockTimestamp = tc.timestamp

			// Call the binding directly to observe the driver's error.
			err := queries.InsertWalletBlock(t.Context(), attempt)

			// Only duplicates may succeed without producing a row.
			if tc.timestamp < 0 {
				requireDriverConstraintError(t, err, checkCode)
			} else {
				require.NoError(t, err)
			}
		})
	}

	// Both no-ops and the rejected insert leave only the seeded block.
	found, err := queries.GetWalletBlocksInRange(
		t.Context(), sqlc.GetWalletBlocksInRangeParams{
			WalletID: block.WalletID, StartHeight: 1, EndHeight: 3,
		},
	)
	require.NoError(t, err)
	require.Len(t, found, 1)
	require.Equal(t, block.BlockHeight, found[0].BlockHeight)
	require.Equal(t, block.BlockTimestamp, found[0].BlockTimestamp)
	require.Equal(t, block.HeaderHash, found[0].HeaderHash)
}

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
