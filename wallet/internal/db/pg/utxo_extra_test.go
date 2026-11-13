package pg

import (
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/stretchr/testify/require"
)

// TestUtxoInfoFromPgRowInvalidOutputIndex verifies postgres row decoding.
func TestUtxoInfoFromPgRowInvalidOutputIndex(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{15}
	_, err := utxoInfoFromRow(
		hash[:], -1, 1000, []byte{0x59}, time.Unix(1000, 0), false,
		sql.NullInt32{},
	)
	require.ErrorContains(t, err, "utxo output index")
}

// TestUtxoInfoFromPgRowInvalidBlockHeight verifies postgres row decoding.
func TestUtxoInfoFromPgRowInvalidBlockHeight(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{16}
	_, err := utxoInfoFromRow(
		hash[:], 0, 1000, []byte{0x5a}, time.Unix(1001, 0), false,
		sql.NullInt32{Int32: -1, Valid: true},
	)
	require.ErrorContains(t, err, "utxo block height")
}
