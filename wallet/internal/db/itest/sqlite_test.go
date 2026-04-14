//go:build itest && !test_db_postgres

package itest

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
	"github.com/stretchr/testify/require"
)

// NewTestStore creates a new SQLite database for testing with migrations
// applied. Each test gets its own temporary database file.
func NewTestStore(t *testing.T) *sqlite.Store {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := sqlite.Config{
		DBPath:         dbPath,
		MaxConnections: 0,
	}

	store, err := sqlite.NewStore(t.Context(), cfg)
	require.NoError(t, err, "failed to create sqlite store")

	t.Cleanup(func() {
		_ = store.Close()
	})

	return store
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

// rawTxByHash returns the serialized transaction bytes for the given
// wallet-scoped transaction hash.
func rawTxByHash(t *testing.T, store *sqlite.Store, walletID uint32,
	txHash chainhash.Hash) []byte {

	t.Helper()

	row, err := store.Queries().GetTransactionByHash(
		t.Context(), sqlc.GetTransactionByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	require.NoError(t, err)

	return row.RawTx
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
