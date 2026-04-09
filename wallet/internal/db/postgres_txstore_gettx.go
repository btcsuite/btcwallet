package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// GetTx retrieves one wallet-scoped transaction snapshot by hash.
//
// The returned TxInfo is rebuilt from normalized SQL columns; missing rows map
// to ErrTxNotFound for the requested wallet/hash pair.
func (s *PostgresStore) GetTx(ctx context.Context,
	query GetTxQuery) (*TxInfo, error) {

	row, err := s.queries.GetTransactionByHash(
		ctx, sqlcpg.GetTransactionByHashParams{
			WalletID: int64(query.WalletID),
			TxHash:   query.Txid[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("tx %s: %w", query.Txid, ErrTxNotFound)
		}

		return nil, fmt.Errorf("get tx: %w", err)
	}

	return txInfoFromPgRow(
		row.TxHash, row.RawTx, row.ReceivedTime, row.BlockHeight,
		row.BlockHash, row.BlockTimestamp, int64(row.TxStatus), row.TxLabel,
	)
}

// txInfoFromPgRow converts one normalized postgres query row into the public
// TxInfo shape.
func txInfoFromPgRow(hash []byte, rawTx []byte, received time.Time,
	blockHeight sql.NullInt32, blockHash []byte, blockTimestamp sql.NullInt64,
	status int64, label string) (*TxInfo, error) {

	var (
		block *Block
		err   error
	)

	// Unmined rows legitimately have no block metadata, so only build the Block
	// shape when the row still carries a valid height.
	if blockHeight.Valid {
		block, err = buildPgBlock(blockHeight, blockHash, blockTimestamp)
		if err != nil {
			return nil, err
		}
	}

	return BuildTxInfo(hash, rawTx, received, block, status, label)
}
