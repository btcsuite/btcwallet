package sqlite

import (
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/stretchr/testify/require"
)

// TestUtxoInfoFromSqliteRowInvalidOutputIndex verifies sqlite row decoding.
func TestUtxoInfoFromSqliteRowInvalidOutputIndex(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{13}
	_, err := utxoInfoFromSqliteRow(
		hash[:], -1, 1000, []byte{0x57}, time.Unix(888, 0), false,
		sql.NullInt64{},
	)
	require.ErrorContains(t, err, "utxo output index")
}

// TestUtxoInfoFromSqliteRowInvalidBlockHeight verifies sqlite row decoding.
func TestUtxoInfoFromSqliteRowInvalidBlockHeight(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{14}
	_, err := utxoInfoFromSqliteRow(
		hash[:], 0, 1000, []byte{0x58}, time.Unix(999, 0), false,
		sql.NullInt64{Int64: -1, Valid: true},
	)
	require.ErrorContains(t, err, "utxo block height")
}
