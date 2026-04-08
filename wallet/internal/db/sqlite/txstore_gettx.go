package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"time"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// GetTx retrieves one wallet-scoped transaction snapshot by hash.
//
// The returned TxInfo is rebuilt from normalized SQL columns; missing rows map
// to ErrTxNotFound for the requested wallet/hash pair.
func (s *SqliteStore) GetTx(ctx context.Context,
	query db.GetTxQuery) (*db.TxInfo, error) {

	row, err := s.queries.GetTransactionByHash(
		ctx, sqlcsqlite.GetTransactionByHashParams{
			WalletID: int64(query.WalletID),
			TxHash:   query.Txid[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("tx %s: %w", query.Txid, db.ErrTxNotFound)
		}

		return nil, fmt.Errorf("get tx: %w", err)
	}

	return txInfoFromSqliteRow(
		row.TxHash, row.RawTx, row.ReceivedTime, row.BlockHeight,
		row.BlockHash, row.BlockTimestamp, row.TxStatus, row.TxLabel,
	)
}

// txInfoFromSqliteRow converts one normalized sqlite query row into the public
// TxInfo shape.
func txInfoFromSqliteRow(hash []byte, rawTx []byte, received time.Time,
	blockHeight sql.NullInt64, blockHash []byte, blockTimestamp sql.NullInt64,
	status int64, label string) (*db.TxInfo, error) {

	var (
		block *db.Block
		err   error
	)

	// Unmined rows legitimately have no block metadata, so only build the Block
	// shape when the row still carries a valid height.
	if blockHeight.Valid {
		block, err = buildSqliteBlock(blockHeight, blockHash, blockTimestamp)
		if err != nil {
			return nil, err
		}
	}

	return db.BuildTxInfo(hash, rawTx, received, block, status, label)
}
