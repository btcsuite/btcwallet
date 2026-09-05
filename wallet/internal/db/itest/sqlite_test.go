//go:build itest && !test_db_postgres

package itest

import (
	"database/sql"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	sqliteschema "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
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

	store, err := sqlite.NewStore(t.Context(), cfg)
	require.NoError(t, err, "failed to create sqlite store")

	t.Cleanup(func() {
		_ = store.Close()
	})

	return store
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

// TestSQLiteAccountNoChainSyncMigration verifies the latest migration
// backfills pre-existing account rows and retains a required false default.
func TestSQLiteAccountNoChainSyncMigration(t *testing.T) {
	t.Parallel()

	// Arrange: create current true and false rows, close the Store, roll back
	// one version, and insert a third row using the prior schema shape.
	dbPath := filepath.Join(t.TempDir(), "account-policy.db")
	identity, err := db.NewDatabaseIdentity(
		&chaincfg.RegressionNetParams, nil,
	)
	require.NoError(t, err)

	cfg := sqlite.Config{
		DBPath:         dbPath,
		MaxConnections: 1,
		Identity:       identity,
	}
	initial, err := sqlite.NewStore(t.Context(), cfg)
	require.NoError(t, err)
	walletID := newWallet(t, initial, "sqlite-policy-migration")
	scope := db.KeyScopeBIP0084
	_, err = initial.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID:    walletID,
			Scope:       scope,
			Name:        "preexisting-true",
			NoChainSync: true,
		}, SpendableDeriveFn(),
	)
	require.NoError(t, err)
	scopeID := GetKeyScopeID(t, initial.Queries(), walletID, scope)
	require.NoError(t, initial.Close())

	raw, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys=on")
	require.NoError(t, err)
	require.NoError(t, sqliteschema.RollbackMigration(raw))

	var oldColumnCount int

	err = raw.QueryRowContext(t.Context(), `
		SELECT count(*) FROM pragma_table_info('accounts')
		WHERE name = 'no_chain_sync'`).Scan(&oldColumnCount)
	require.NoError(t, err)
	_, oldInsertErr := raw.ExecContext(t.Context(), `
		INSERT INTO accounts (
			wallet_id, scope_id, account_name, is_derived,
			account_number, public_key
		) VALUES (?, ?, ?, TRUE, ?, ?)`, walletID, scopeID,
		"old-shape", 99, RandomBytes(33))
	require.NoError(t, raw.Close())

	// Act: reopen through production startup, which reapplies the migration,
	// and attempt an explicit NULL insert against the migrated schema.
	reopened, reopenErr := sqlite.NewStore(t.Context(), cfg)

	var nullErr error

	if reopened != nil {
		t.Cleanup(func() { _ = reopened.Close() })
		_, nullErr = reopened.DB().ExecContext(t.Context(), `
			INSERT INTO accounts (
				wallet_id, scope_id, account_name, is_derived,
				no_chain_sync, public_key
			) VALUES (?, ?, ?, FALSE, NULL, ?)`, walletID, scopeID,
			"migrated-null", RandomBytes(33))
	}

	// Assert: rollback exposed the old shape, forward migration preserved all
	// rows as synchronized accounts, and the migrated column rejects NULL.
	require.Zero(t, oldColumnCount)
	require.NoError(t, oldInsertErr)
	require.NoError(t, reopenErr)
	require.NotNil(t, reopened)

	for _, name := range []string{"preexisting-true", "old-shape"} {
		info, readErr := reopened.GetAccount(
			t.Context(), getAccountQueryByName(walletID, scope, name),
		)
		require.NoError(t, readErr)
		require.False(t, info.NoChainSync)
	}

	require.Error(t, nullErr)
	requireDriverConstraintError(t, nullErr)
}

// TestSQLiteAccountNoChainSyncReopen verifies current false and true values
// survive a complete Store close and production reopen.
func TestSQLiteAccountNoChainSyncReopen(t *testing.T) {
	t.Parallel()

	// Arrange: create both values in one file, then close the only Store so the
	// later reads cannot observe in-memory account state.
	dbPath := filepath.Join(t.TempDir(), "account-policy.db")
	identity, err := db.NewDatabaseIdentity(
		&chaincfg.RegressionNetParams, nil,
	)
	require.NoError(t, err)

	cfg := sqlite.Config{
		DBPath:         dbPath,
		MaxConnections: 1,
		Identity:       identity,
	}
	initial, err := sqlite.NewStore(t.Context(), cfg)
	require.NoError(t, err)
	walletID := newWallet(t, initial, "sqlite-policy-reopen")
	scope := db.KeyScopeBIP0084

	expected := map[string]bool{
		"reopen-false": false,
		"reopen-true":  true,
	}
	for name, noChainSync := range expected {
		_, err = initial.CreateDerivedAccount(
			t.Context(), db.CreateDerivedAccountParams{
				WalletID:    walletID,
				Scope:       scope,
				Name:        name,
				NoChainSync: noChainSync,
			}, SpendableDeriveFn(),
		)
		require.NoError(t, err)
	}

	require.NoError(t, initial.Close())

	// Act: reopen the same physical file and load both accounts by durable
	// wallet, scope, and name identity.
	reopened, reopenErr := sqlite.NewStore(t.Context(), cfg)
	if reopened != nil {
		t.Cleanup(func() { _ = reopened.Close() })
	}

	// Assert: startup succeeds and every account retains its exact stored bit
	// rather than collapsing true to the database default.
	require.NoError(t, reopenErr)

	for name, noChainSync := range expected {
		info, readErr := reopened.GetAccount(
			t.Context(), getAccountQueryByName(walletID, scope, name),
		)
		require.NoError(t, readErr)
		require.Equal(t, noChainSync, info.NoChainSync)
	}
}

// TestSQLiteAccountNoChainSyncRejectsMalformedStorage verifies a corrupted
// flexible-typed value fails at the Store read boundary instead of becoming
// true through boolean coercion.
func TestSQLiteAccountNoChainSyncRejectsMalformedStorage(t *testing.T) {
	t.Parallel()

	// Arrange: create a valid wallet and scope, then temporarily bypass SQLite
	// checks to model external corruption with the integer value two.
	store := NewTestStore(t)
	store.DB().SetMaxOpenConns(1)
	walletID := newWallet(t, store, "sqlite-malformed-policy")
	scope := db.KeyScopeBIP0084
	createDerivedAccount(t, store, walletID, scope, "scope-seed")
	scopeID := GetKeyScopeID(t, store.Queries(), walletID, scope)
	_, err := store.DB().ExecContext(
		t.Context(), "PRAGMA ignore_check_constraints = ON",
	)
	require.NoError(t, err)
	_, err = store.DB().ExecContext(t.Context(), `
		INSERT INTO accounts (
			wallet_id, scope_id, account_name, is_derived,
			no_chain_sync, public_key
		) VALUES (?, ?, ?, FALSE, 2, ?)`, walletID, scopeID,
		"malformed-policy", RandomBytes(33))
	require.NoError(t, err)
	_, err = store.DB().ExecContext(
		t.Context(), "PRAGMA ignore_check_constraints = OFF",
	)
	require.NoError(t, err)

	// Act: read the corrupted row through the normal Store conversion.
	info, readErr := store.GetAccount(
		t.Context(), getAccountQueryByName(
			walletID, scope, "malformed-policy",
		),
	)

	// Assert: sql scanning rejects the non-boolean representation and returns
	// no AccountInfo that could misstate the stored policy.
	require.Error(t, readErr)
	require.ErrorContains(t, readErr, "couldn't convert 2 into type bool")
	require.Nil(t, info)
}

// childSpendingTxIDs returns the direct child transaction IDs recorded for the
// provided parent transaction hash.
func childSpendingTxIDs(t *testing.T, store *sqlite.Store,
	walletID uint32,
	txHash chainhash.Hash) []int64 {

	t.Helper()

	meta, err := store.Queries().GetTransactionMetaByHash(
		t.Context(), sqlc.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	require.NoError(t, err)

	childIDs, err := store.Queries().ListSpendingTxIDsByParentTxID(
		t.Context(), sqlc.ListSpendingTxIDsByParentTxIDParams{
			WalletID: int64(walletID),
			TxID:     meta.ID,
		},
	)
	require.NoError(t, err)

	ids := make([]int64, 0, len(childIDs))
	for _, childID := range childIDs {
		require.True(t, childID.Valid)
		ids = append(ids, childID.Int64)
	}

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

// walletUtxoSpent reports whether one wallet-scoped outpoint exists and is
// recorded as spent, i.e. its spend edge points at a spending transaction.
func walletUtxoSpent(t *testing.T, store *sqlite.Store,
	walletID uint32,
	outPoint wire.OutPoint) bool {

	t.Helper()

	spentBy, err := store.Queries().GetUtxoSpendByOutpoint(
		t.Context(), sqlc.GetUtxoSpendByOutpointParams{
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

	return spentBy.SpentByTxID.Valid
}

// clearUtxosSpentByTxID clears all UTXO spend edges claimed by one transaction.
func clearUtxosSpentByTxID(t *testing.T, store *sqlite.Store,
	walletID uint32, txHash chainhash.Hash) {

	t.Helper()

	txID, ok := txIDByHash(t, store, walletID, txHash)
	require.True(t, ok)

	rows, err := store.Queries().ClearUtxosSpentByTxID(
		t.Context(), sqlc.ClearUtxosSpentByTxIDParams{
			WalletID: int64(walletID),
			SpentByTxID: sql.NullInt64{
				Int64: txID,
				Valid: true,
			},
		},
	)
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}
