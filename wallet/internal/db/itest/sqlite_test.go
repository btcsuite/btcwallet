//go:build itest && !test_db_postgres

package itest

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
	"github.com/stretchr/testify/require"
)

// NewTestStore creates a new SQLite database for testing with migrations
// applied. Each test gets its own temporary database file.
func NewTestStore(t *testing.T) *sqlite.Store {
	t.Helper()

	return NewTestStoreWithDerive(t, mockDeriveFunc())
}

// NewTestStoreWithDerive creates a regression-identity SQLite database with
// the provided derivation function so established tests traverse the gate.
func NewTestStoreWithDerive(t *testing.T,
	deriveAddress db.AddressDerivationFunc) *sqlite.Store {

	t.Helper()

	store, _ := newReopenableTestStore(t, deriveAddress)

	return store
}

// newReopenableTestStore retains the same database configuration across opens
// so batch tests can prove progress survives a closed connection pool.
func newReopenableTestStore(t *testing.T,
	deriveAddress db.AddressDerivationFunc) (
	*sqlite.Store, func() *sqlite.Store) {

	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	identity, err := db.NewDatabaseIdentity(&chaincfg.RegressionNetParams, nil)
	require.NoError(t, err)

	cfg := sqlite.Config{
		DBPath:         dbPath,
		MaxConnections: 0,
		DeriveAddress:  deriveAddress,
		Identity:       identity,
	}

	open := func() *sqlite.Store {
		store, err := sqlite.NewStore(t.Context(), cfg)
		require.NoError(t, err, "failed to create sqlite store")

		t.Cleanup(func() {
			_ = store.Close()
		})

		return store
	}

	return open(), open
}

// sqliteDatabaseIdentityFixture exposes SQLite setup behind the shared test
// contract while keeping the concrete NewStore call visible in this file.
func sqliteDatabaseIdentityFixture(t *testing.T,
	dbPath string) databaseIdentityFixture {

	t.Helper()

	return databaseIdentityFixture{
		driver: "sqlite",
		source: dbPath,
		open: func(identity db.DatabaseIdentity) (
			io.Closer, error) {

			store, err := sqlite.NewStore(
				t.Context(), sqlite.Config{
					DBPath: dbPath, Identity: identity,
				},
			)
			if store == nil {
				return nil, err
			}

			return store, err
		},
		malformations: map[string][]string{
			// Preserve the marker table while removing its required row.
			"missing singleton": {
				"DELETE FROM btcwallet_database_identity",
			},
			// Replace the marker with one missing every identity column.
			"unreadable table": {
				"DROP TABLE btcwallet_database_identity",
				"CREATE TABLE btcwallet_database_identity (id INTEGER)",
			},
			// Remove constraints so SQLite can persist nonnumeric magic.
			"invalid stored value": {
				"DROP TABLE btcwallet_database_identity",
				`CREATE TABLE btcwallet_database_identity (
					id INTEGER PRIMARY KEY,
					genesis_hash BLOB NOT NULL,
					network_magic INTEGER NOT NULL,
					signet_challenge_digest BLOB
				)`,
				`INSERT INTO btcwallet_database_identity VALUES (
					1, zeroblob(32), 'not-a-number', NULL
				)`,
			},
		},
	}
}

// newDatabaseIdentityFixture gives the shared contract one isolated file.
func newDatabaseIdentityFixture(t *testing.T) databaseIdentityFixture {
	t.Helper()

	return sqliteDatabaseIdentityFixture(
		t, filepath.Join(t.TempDir(), "identity.db"),
	)
}

// TestSQLiteDatabaseIdentityRejectsPopulatedFile proves an unmarked file is
// rejected without adding identity state or enabling WAL.
func TestSQLiteDatabaseIdentityRejectsPopulatedFile(t *testing.T) {
	// Arrange: Raw DDL creates non-API sqliteX state that exposes LIKE `_`.
	dbPath := filepath.Join(t.TempDir(), "identity.db")
	fixtureDB, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = fixtureDB.ExecContext(t.Context(), "CREATE TABLE sqliteX(x)")
	require.NoError(t, err)
	require.NoError(t, fixtureDB.Close())
	fixture := sqliteDatabaseIdentityFixture(t, dbPath)
	identity, err := db.NewDatabaseIdentity(&chaincfg.RegressionNetParams, nil)
	require.NoError(t, err)

	// Act: Attempt startup, then inspect durable state through raw SQL.
	store, openErr := openAndCloseIdentityStore(t, fixture, identity)
	inspectDB, inspectErr := sql.Open("sqlite", dbPath)

	var (
		objectCount int
		journalMode string
	)

	if inspectErr == nil {
		inspectErr = inspectDB.QueryRowContext(t.Context(), `
			SELECT COUNT(*) FROM sqlite_schema
			WHERE name NOT GLOB 'sqlite_*'
		`).Scan(&objectCount)
	}

	if inspectErr == nil {
		inspectErr = inspectDB.QueryRowContext(
			t.Context(), "PRAGMA journal_mode",
		).Scan(&journalMode)
	}

	if inspectDB != nil {
		inspectErr = errors.Join(inspectErr, inspectDB.Close())
	}

	// Assert: Rejection leaves only the fixture and never enables WAL.
	require.ErrorIs(t, openErr, db.ErrDatabaseIdentityMismatch)
	require.Nil(t, store)
	require.NoError(t, inspectErr)
	require.Equal(t, 1, objectCount)
	require.Equal(t, "delete", journalMode)
}

// childSpendingTxIDs reads active direct children from retained input facts.
// Include confirmed children because lifecycle tests assert both states.
func childSpendingTxIDs(t *testing.T, store *sqlite.Store, walletID uint32,
	txHash chainhash.Hash) []int64 {

	t.Helper()

	// Read the normalized relation directly rather than keep a production
	// raw-history query or decode inputs solely for fixture assertions.
	rows, err := store.DB().QueryContext(
		t.Context(), `
		SELECT DISTINCT i.tx_id FROM tx_inputs AS i
		JOIN transactions AS t ON t.wallet_id = i.wallet_id AND t.id = i.tx_id
		WHERE i.wallet_id = ? AND i.prev_tx_hash = ?
		AND t.tx_status IN (0, 1) ORDER BY i.tx_id
	`, walletID, txHash[:],
	)
	require.NoError(t, err)

	defer func() { require.NoError(t, rows.Close()) }()

	var ids []int64
	for rows.Next() {
		var id int64

		require.NoError(t, rows.Scan(&id))

		ids = append(ids, id)
	}

	require.NoError(t, rows.Err())

	return ids
}

// txIDByHash returns the database row ID for the given wallet-scoped
// transaction hash and reports whether the row exists.
func txIDByHash(t *testing.T, store *sqlite.Store, walletID uint32,
	txHash chainhash.Hash) (int64, bool) {

	t.Helper()

	meta, err := store.Queries().GetTransactionMetaByHash(
		t.Context(), sqlc.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false
		}

		require.NoError(t, err)
	}

	return meta.ID, true
}

// setTxStatus rewrites one wallet-scoped transaction row to the provided
// status using the internal status-update query.
func setTxStatus(t *testing.T, store *sqlite.Store, walletID uint32,
	txHash chainhash.Hash, status db.TxStatus) {

	t.Helper()

	txID, ok := txIDByHash(t, store, walletID, txHash)
	require.True(t, ok)

	rows, err := store.Queries().UpdateTransactionStatusByIDs(
		t.Context(), sqlc.UpdateTransactionStatusByIDsParams{
			WalletID: int64(walletID),
			Status:   int64(status),
			TxIds:    []int64{txID},
		},
	)
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

// walletUtxoExists reports whether one wallet-scoped outpoint is currently
// present in the UTXO set.
func walletUtxoExists(t *testing.T, store *sqlite.Store,
	walletID uint32,
	outPoint wire.OutPoint) bool {

	t.Helper()

	_, err := store.Queries().GetUtxoIDByOutpoint(
		t.Context(), sqlc.GetUtxoIDByOutpointParams{
			WalletID:    int64(walletID),
			TxHash:      outPoint.Hash[:],
			OutputIndex: int64(outPoint.Index),
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false
		}

		require.NoError(t, err)
	}

	return true
}

// walletUtxoSpent distinguishes an eligible claim from a missing credit.
// Ownership must survive before unavailable funding can count as spent.
func walletUtxoSpent(t *testing.T, store *sqlite.Store, walletID uint32,
	outPoint wire.OutPoint) bool {

	t.Helper()

	_, err := store.Queries().GetWalletCreditByOutpoint(
		t.Context(), sqlc.GetWalletCreditByOutpointParams{
			WalletID: int64(walletID), TxHash: outPoint.Hash[:],
			OutputIndex: int64(outPoint.Index),
		},
	)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}

	require.NoError(t, err)

	return !walletUtxoExists(t, store, walletID, outPoint)
}

// insertReplacementEdge records one replacement edge between two wallet-scoped
// transaction rows.
func insertReplacementEdge(t *testing.T, store *sqlite.Store, walletID uint32,
	replacedID, replacementID int64) {

	t.Helper()

	_, err := store.DB().ExecContext(
		t.Context(),
		"INSERT INTO tx_replacements (wallet_id, replaced_tx_id, "+
			"replacement_tx_id) VALUES (?, ?, ?)",
		int64(walletID), replacedID, replacementID,
	)
	require.NoError(t, err)
}

// leaseRows returns the number of lease rows the wallet holds.
func leaseRows(t *testing.T, store *sqlite.Store, walletID uint32) int {
	t.Helper()

	var count int

	err := store.DB().QueryRowContext(
		t.Context(),
		"SELECT COUNT(*) FROM utxo_leases WHERE wallet_id = ?",
		int64(walletID),
	).Scan(&count)
	require.NoError(t, err)

	return count
}

// replacementRows returns the number of replacement edges the wallet holds.
func replacementRows(t *testing.T, store *sqlite.Store, walletID uint32) int {
	t.Helper()

	var count int

	err := store.DB().QueryRowContext(
		t.Context(),
		"SELECT COUNT(*) FROM tx_replacements WHERE wallet_id = ?",
		int64(walletID),
	).Scan(&count)
	require.NoError(t, err)

	return count
}

// rejectBranchRowDelete installs a trigger that aborts the removal of one
// transaction row, so a test can prove the whole write rolls back.
func rejectBranchRowDelete(t *testing.T, store *sqlite.Store,
	txHash chainhash.Hash) {

	t.Helper()

	_, err := store.DB().ExecContext(
		t.Context(),
		fmt.Sprintf(
			"CREATE TRIGGER reject_branch_row_delete BEFORE DELETE ON "+
				"transactions WHEN old.tx_hash = x'%x' BEGIN "+
				"SELECT RAISE(ABORT, 'injected delete failure'); END",
			txHash[:],
		),
	)
	require.NoError(t, err)
}

// txInputOutPoints reads the documented input facts through the existing DB
// fixture, preserving stored positions so mapping errors cannot hide in order.
func txInputOutPoints(t *testing.T, store *sqlite.Store, walletID uint32,
	txHash chainhash.Hash) map[int64]wire.OutPoint {

	t.Helper()

	txID, ok := txIDByHash(t, store, walletID, txHash)
	require.True(t, ok)

	rows, err := store.DB().QueryContext(t.Context(), `
		SELECT input_index, prev_tx_hash, prev_output_index FROM tx_inputs
		WHERE wallet_id = ? AND tx_id = ? ORDER BY input_index
	`, walletID, txID)
	require.NoError(t, err)

	defer func() { require.NoError(t, rows.Close()) }()

	inputs := make(map[int64]wire.OutPoint)
	for rows.Next() {
		var (
			index       int64
			prevHash    []byte
			outputIndex int64
		)

		require.NoError(t, rows.Scan(&index, &prevHash, &outputIndex))

		hash, err := chainhash.NewHash(prevHash)
		require.NoError(t, err)

		output, err := db.Int64ToUint32(outputIndex)
		require.NoError(t, err)

		inputs[index] = wire.OutPoint{
			Hash:  *hash,
			Index: output,
		}
	}

	require.NoError(t, rows.Err())

	return inputs
}

// prepareLegacyInputHistory restores the actual version10 schema around the
// fixture history so public reopening runs the migration and input backfill.
func prepareLegacyInputHistory(t *testing.T, sqlDB *sql.DB) {
	t.Helper()

	rollbackInputHistoryMigrations(t, sqlDB, "../../sql/sqlite/migrations")
}
