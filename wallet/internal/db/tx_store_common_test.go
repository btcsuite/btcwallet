package db

import (
	"bytes"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// TestSerializeDeserializeMsgTx verifies that the common serialization helpers
// preserve transaction bytes across a round trip.
func TestSerializeDeserializeMsgTx(t *testing.T) {
	t.Parallel()

	tx := testRegularMsgTx()

	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	decoded, err := deserializeMsgTx(rawTx)
	require.NoError(t, err)

	var got bytes.Buffer

	err = decoded.Serialize(&got)
	require.NoError(t, err)

	require.Equal(t, rawTx, got.Bytes())
}

// TestSerializeMsgTxNil verifies that serializeMsgTx rejects a missing
// transaction pointer with the public invalid-param error.
func TestSerializeMsgTxNil(t *testing.T) {
	t.Parallel()

	_, err := serializeMsgTx(nil)
	require.ErrorIs(t, err, ErrInvalidParam)
}

// TestParseTxStatus verifies that stored numeric values map back to the public
// TxStatus enum and that unknown values fail loudly.
func TestParseTxStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  int64
		want    TxStatus
		wantErr error
	}{
		{name: "pending", status: 0, want: TxStatusPending},
		{name: "published", status: 1, want: TxStatusPublished},
		{name: "replaced", status: 2, want: TxStatusReplaced},
		{name: "failed", status: 3, want: TxStatusFailed},
		{name: "orphaned", status: 4, want: TxStatusOrphaned},
		{name: "invalid", status: 9, wantErr: ErrInvalidStatus},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseTxStatus(tc.status)
			require.ErrorIs(t, err, tc.wantErr)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestBuildTxInfo verifies the shared row-to-domain conversion used by both
// SQL backends when returning a valid TxInfo value.
func TestBuildTxInfo(t *testing.T) {
	t.Parallel()

	tx := testRegularMsgTx()
	hash := tx.TxHash()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	blockHash := chainhash.Hash{1, 2, 3}
	block := &Block{
		Hash:      blockHash,
		Height:    77,
		Timestamp: time.Unix(500, 0),
	}

	info, err := buildTxInfo(
		hash[:], rawTx, time.Unix(600, 0).In(time.FixedZone("X", 3600)),
		block, int64(TxStatusPublished), "note",
	)
	require.NoError(t, err)
	require.Equal(t, hash, info.Hash)
	require.Equal(t, rawTx, info.SerializedTx)
	require.Equal(t, TxStatusPublished, info.Status)
	require.Equal(t, "note", info.Label)
	require.Equal(t, time.UTC, info.Received.Location())
	require.Equal(t, block, info.Block)
}

// TestBuildTxInfoInvalidHash verifies that buildTxInfo rejects malformed hash
// bytes.
func TestBuildTxInfoInvalidHash(t *testing.T) {
	t.Parallel()

	tx := testRegularMsgTx()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	_, err = buildTxInfo([]byte{1, 2, 3}, rawTx, time.Now(), nil,
		int64(TxStatusPending), "")
	require.Error(t, err)
}

// TestBuildTxInfoInvalidStatus verifies that buildTxInfo rejects unknown status
// codes.
func TestBuildTxInfoInvalidStatus(t *testing.T) {
	t.Parallel()

	tx := testRegularMsgTx()
	hash := tx.TxHash()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	_, err = buildTxInfo(hash[:], rawTx, time.Now(), nil, 9, "")
	require.ErrorIs(t, err, ErrInvalidStatus)
}

// testRegularMsgTx builds a minimal non-coinbase transaction fixture for the
// shared TxStore helper tests.
func testRegularMsgTx() *wire.MsgTx {
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}}})
	tx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})

	return tx
}
