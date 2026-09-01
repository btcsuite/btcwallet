//go:build itest && !test_db_postgres

package itest

import (
	"database/sql"
	"errors"
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

// openIdentityStore joins open/close errors so rejection leaks no SQLite Store.
func openIdentityStore(t *testing.T, dbPath string,
	identity db.DatabaseIdentity) (*sqlite.Store, error) {

	t.Helper()

	cfg := sqlite.Config{DBPath: dbPath, Identity: identity}

	store, err := sqlite.NewStore(t.Context(), cfg)
	if store == nil {
		return nil, errors.Join(err, errors.New("nil Store"))
	}

	return store, errors.Join(err, store.Close())
}

// TestSQLiteDatabaseIdentity proves startup gating against real database files.
func TestSQLiteDatabaseIdentity(t *testing.T) {
	// Arrange: Build the ordinary and same-prefix signet tuples reused below.
	c := chaincfg.DefaultSignetChallenge
	digest := chainhash.DoubleHashB(append([]byte{byte(len(c))}, c...))
	otherDigest := append([]byte(nil), digest...)
	otherDigest[len(otherDigest)-1] ^= 1
	signetParams := &chaincfg.SigNetParams
	regtest, regErr := db.NewDatabaseIdentity(
		&chaincfg.RegressionNetParams, nil,
	)
	testnet, testErr := db.NewDatabaseIdentity(&chaincfg.TestNet3Params, nil)
	signet, sigErr := db.NewDatabaseIdentity(signetParams, digest)
	otherSignet, otherErr := db.NewDatabaseIdentity(signetParams, otherDigest)
	require.NoError(t, errors.Join(regErr, testErr, sigErr, otherErr))

	t.Run("initializes and reopens", func(t *testing.T) {
		// Arrange: Select one empty file for both startup attempts.
		dbPath := filepath.Join(t.TempDir(), "identity.db")

		// Act: Open the file twice with the same regression-test tuple.
		_, firstErr := openIdentityStore(t, dbPath, regtest)
		_, secondErr := openIdentityStore(t, dbPath, regtest)

		// Assert: Initial creation and matching reopen both return a Store.
		require.NoError(t, errors.Join(firstErr, secondErr))
	})

	t.Run("rejects wrong network", func(t *testing.T) {
		// Arrange: Persist regression testnet in one isolated file.
		dbPath := filepath.Join(t.TempDir(), "identity.db")
		_, err := openIdentityStore(t, dbPath, regtest)
		require.NoError(t, err)

		// Act: Try testnet, then retry the stored regression-test tuple.
		rejected, rejectErr := openIdentityStore(t, dbPath, testnet)
		_, reopenErr := openIdentityStore(t, dbPath, regtest)

		// Assert: Only the mismatch stops and returns no Store.
		require.ErrorIs(t, rejectErr, db.ErrDatabaseIdentityMismatch)
		require.Nil(t, rejected)
		require.NoError(t, reopenErr)
	})

	t.Run("rejects different signet", func(t *testing.T) {
		// Arrange: Persist one full signet challenge digest.
		dbPath := filepath.Join(t.TempDir(), "identity.db")
		_, err := openIdentityStore(t, dbPath, signet)
		require.NoError(t, err)

		// Act: Try the other digest, then retry the stored digest.
		rejected, rejectErr := openIdentityStore(t, dbPath, otherSignet)
		_, reopenErr := openIdentityStore(t, dbPath, signet)

		// Assert: The full digest mismatch leaves the original usable.
		require.ErrorIs(t, rejectErr, db.ErrDatabaseIdentityMismatch)
		require.Nil(t, rejected)
		require.NoError(t, reopenErr)
	})

	t.Run("rejects populated file", func(t *testing.T) {
		// Arrange: Raw DDL creates non-API sqliteX state that exposes LIKE `_`.
		dbPath := filepath.Join(t.TempDir(), "identity.db")
		fixtureDB, err := sql.Open("sqlite", dbPath)
		require.NoError(t, err)
		_, err = fixtureDB.ExecContext(t.Context(), "CREATE TABLE sqliteX(x)")
		require.NoError(t, err)
		require.NoError(t, fixtureDB.Close())

		// Act: Attempt startup, then inspect durable state through raw SQL.
		store, openErr := openIdentityStore(t, dbPath, regtest)
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
	})
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
