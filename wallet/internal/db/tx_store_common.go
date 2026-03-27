package db

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

var (
	// ErrInvalidParam is returned when a TxStore method receives invalid input.
	ErrInvalidParam = errors.New("invalid param")

	// ErrInvalidStatus is returned when a transaction status is unknown or not
	// allowed for the requested operation.
	ErrInvalidStatus = errors.New("invalid transaction status")
)

// serializeMsgTx serializes a wire.MsgTx so it can be stored in the
// transactions table.
func serializeMsgTx(tx *wire.MsgTx) ([]byte, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: tx is required", ErrInvalidParam)
	}

	var buf bytes.Buffer

	err := tx.Serialize(&buf)
	if err != nil {
		return nil, fmt.Errorf("serialize tx: %w", err)
	}

	return buf.Bytes(), nil
}

// deserializeMsgTx deserializes a stored transaction payload back into a
// wire.MsgTx.
func deserializeMsgTx(rawTx []byte) (*wire.MsgTx, error) {
	var tx wire.MsgTx

	err := tx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		return nil, fmt.Errorf("deserialize tx: %w", err)
	}

	return &tx, nil
}

// parseTxStatus converts a stored numeric status code into the strongly typed
// TxStatus enum used by the public db API.
func parseTxStatus(status int64) (TxStatus, error) {
	txStatus, err := int64ToUint8(status)
	if err != nil {
		return TxStatus(0), fmt.Errorf("status %d: %w", status,
			ErrInvalidStatus)
	}

	switch TxStatus(txStatus) {
	case TxStatusPending,
		TxStatusPublished,
		TxStatusReplaced,
		TxStatusFailed,
		TxStatusOrphaned:

		return TxStatus(txStatus), nil

	default:
		return TxStatus(0), fmt.Errorf("status %d: %w", status,
			ErrInvalidStatus)
	}
}

// buildTxInfo converts normalized transaction fields into the public TxInfo
// shape returned by the db interfaces.
func buildTxInfo(hash []byte, rawTx []byte, received time.Time, block *Block,
	status int64, label string) (*TxInfo, error) {

	txHash, err := chainhash.NewHash(hash)
	if err != nil {
		return nil, fmt.Errorf("tx hash: %w", err)
	}

	txStatus, err := parseTxStatus(status)
	if err != nil {
		return nil, err
	}

	return &TxInfo{
		Hash:         *txHash,
		SerializedTx: rawTx,
		Received:     received.UTC(),
		Block:        block,
		Status:       txStatus,
		Label:        label,
	}, nil
}
