//go:build itest && test_db_postgres

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	"github.com/stretchr/testify/require"
)

// These postgres-only helpers intentionally drop backend CHECK constraints in
// the isolated test database so corruption itests can persist rows that normal
// store writes would reject. The follow-up read paths must treat those rows as
// corruption instead of silently accepting them.

// corruptTransactionStatus writes an invalid tx status after dropping the
// validating constraints that normally reject it. The corruption itests use
// this to verify that reads reject impossible tx states.
func corruptTransactionStatus(t *testing.T, store *pg.Store,
	walletID uint32, txHash chainhash.Hash, status int64) {
	t.Helper()

	for _, stmt := range []string{
		"ALTER TABLE transactions DROP CONSTRAINT IF EXISTS valid_status",
		"ALTER TABLE transactions DROP CONSTRAINT IF EXISTS check_orphaned_coinbase_only",
		"ALTER TABLE transactions DROP CONSTRAINT IF EXISTS check_confirmed_published",
		"ALTER TABLE transactions DROP CONSTRAINT IF EXISTS check_coinbase_not_pending",
		"ALTER TABLE transactions DROP CONSTRAINT IF EXISTS check_coinbase_confirmation_state",
	} {
		_, err := store.DB().ExecContext(t.Context(), stmt)
		require.NoError(t, err)
	}

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE transactions SET tx_status = $1 WHERE wallet_id = $2 AND tx_hash = $3",
		status, int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

// corruptTransactionHash writes malformed tx-hash bytes after dropping the
// fixed-length hash check. The corruption itests then verify that hash
// decoding fails with the expected error path.
func corruptTransactionHash(t *testing.T, store *pg.Store,
	walletID uint32, txHash chainhash.Hash, hash []byte) {
	t.Helper()

	_, err := store.DB().ExecContext(
		t.Context(),
		"ALTER TABLE transactions DROP CONSTRAINT IF EXISTS transactions_tx_hash_check",
	)
	require.NoError(t, err)

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE transactions SET tx_hash = $1 WHERE wallet_id = $2 AND tx_hash = $3",
		hash, int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

// corruptTransactionBlockHeight writes an invalid block height after dropping
// the non-negative height check and creating a matching block row. The
// corruption itests use this to verify that reads reject impossible
// confirmation metadata.
func corruptTransactionBlockHeight(t *testing.T, store *pg.Store,
	walletID uint32, txHash chainhash.Hash, height int64) {
	t.Helper()

	_, err := store.DB().ExecContext(
		t.Context(),
		"ALTER TABLE blocks DROP CONSTRAINT IF EXISTS blocks_block_height_check",
	)
	require.NoError(t, err)

	blockHash := RandomHash()
	_, err = store.DB().ExecContext(
		t.Context(),
		"INSERT INTO blocks (block_height, header_hash, block_timestamp) VALUES ($1, $2, $3) "+
			"ON CONFLICT (block_height) DO UPDATE SET header_hash = EXCLUDED.header_hash, "+
			"block_timestamp = EXCLUDED.block_timestamp",
		height, blockHash[:], time.Now().Unix(),
	)
	require.NoError(t, err)

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE transactions SET block_height = $1 WHERE wallet_id = $2 AND tx_hash = $3",
		height, int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

// corruptUtxoOutputIndex writes an invalid output index after dropping the
// non-negative output-index check. The corruption itests then verify that UTXO
// decoding rejects the malformed persisted value.
func corruptUtxoOutputIndex(t *testing.T, store *pg.Store,
	walletID uint32, txHash chainhash.Hash, oldIndex uint32, newIndex int64) {
	t.Helper()

	_, err := store.DB().ExecContext(
		t.Context(),
		"ALTER TABLE utxos DROP CONSTRAINT IF EXISTS utxos_output_index_check",
	)
	require.NoError(t, err)

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE utxos SET output_index = $1 WHERE output_index = $2 "+
			"AND tx_id = (SELECT id FROM transactions WHERE wallet_id = $3 AND tx_hash = $4)",
		newIndex, int64(oldIndex), int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

// corruptActiveLeaseLockID writes an invalid lease lock ID after dropping the
// fixed-length lock-id check. The corruption itests use this to verify that
// lease reads reject malformed lock identifiers.
func corruptActiveLeaseLockID(t *testing.T, store *pg.Store,
	walletID uint32, txHash chainhash.Hash, outputIndex uint32, lockID []byte) {
	t.Helper()

	_, err := store.DB().ExecContext(
		t.Context(),
		"ALTER TABLE utxo_leases DROP CONSTRAINT IF EXISTS utxo_leases_lock_id_check",
	)
	require.NoError(t, err)

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE utxo_leases SET lock_id = $1 WHERE wallet_id = $2 AND utxo_id = ("+
			"SELECT u.id FROM utxos u JOIN transactions t ON t.id = u.tx_id "+
			"WHERE t.wallet_id = $3 AND t.tx_hash = $4 AND u.output_index = $5)",
		lockID, int64(walletID), int64(walletID), txHash[:], int64(outputIndex),
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}
