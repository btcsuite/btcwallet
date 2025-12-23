package db

import (
	"bytes"
	"database/sql"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// buildTxInfo constructs a TxInfo from the provided components that are common
// across different database backends.
func buildTxInfo(txHash []byte, serializedTx []byte, receivedTimestamp int64,
	label string, blockHeight sql.NullInt32, blockHash []byte,
	blockTimestamp sql.NullInt64) (*TxInfo, error) {

	hash, err := chainhash.NewHash(txHash)
	if err != nil {
		return nil, fmt.Errorf("parse tx hash: %w", err)
	}

	info := &TxInfo{
		Hash:         *hash,
		SerializedTx: serializedTx,
		Received:     time.Unix(receivedTimestamp, 0),
		Label:        label,
	}

	// Build block metadata if the transaction is confirmed.
	if blockHeight.Valid {
		height, err := nullInt32ToUint32(blockHeight)
		if err != nil {
			return nil, fmt.Errorf("convert block height: %w", err)
		}

		block, err := buildBlock(
			blockHash, height, blockTimestamp.Int64,
		)
		if err != nil {
			return nil, fmt.Errorf("build block: %w", err)
		}

		info.Block = block
	}

	return info, nil
}

// serializeTx serializes a wire.MsgTx to a byte slice.
func serializeTx(tx *wire.MsgTx) ([]byte, error) {
	if tx == nil {
		return nil, ErrTxNil
	}

	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())

	err := tx.Serialize(&buf)
	if err != nil {
		return nil, fmt.Errorf("serialize transaction: %w", err)
	}

	return buf.Bytes(), nil
}

// isCoinbaseTx returns true if the transaction is a coinbase transaction.
func isCoinbaseTx(tx *wire.MsgTx) bool {
	if tx == nil || len(tx.TxIn) == 0 {
		return false
	}

	return tx.TxIn[0].PreviousOutPoint.Index == wire.MaxPrevOutIndex &&
		tx.TxIn[0].PreviousOutPoint.Hash == chainhash.Hash{}
}
