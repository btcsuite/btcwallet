package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// GetTx retrieves one wallet-scoped transaction snapshot by hash.
//
// The returned TxInfo is rebuilt from normalized SQL columns; missing rows map
// to ErrTxNotFound for the requested wallet/hash pair.
func (s *Store) GetTx(ctx context.Context,
	query db.GetTxQuery) (*db.TxInfo, error) {

	var info *db.TxInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetTransactionByHash(
			ctx, sqlc.GetTransactionByHashParams{
				WalletID: int64(query.WalletID),
				TxHash:   query.Txid[:],
			},
		)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("tx %s: %w",
					query.Txid, db.ErrTxNotFound)
			}

			return fmt.Errorf("get tx: %w", err)
		}

		info, err = txInfoFromRow(
			row.TxHash, row.RawTx, row.ReceivedTime.Time, row.BlockHeight,
			row.BlockHash, row.BlockTimestamp, int64(row.TxStatus), row.TxLabel,
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// txInfoFromRow converts one normalized postgres query row into the public
// TxInfo shape.
func txInfoFromRow(hash []byte, rawTx []byte, received time.Time,
	blockHeight pgtype.Int4, blockHash []byte, blockTimestamp pgtype.Int8,
	status int64, label string) (*db.TxInfo, error) {

	var (
		block *db.Block
		err   error
	)

	// Unmined rows legitimately have no block metadata, so only build the Block
	// shape when the row still carries a valid height.
	if blockHeight.Valid {
		block, err = buildBlock(blockHeight, blockHash, blockTimestamp)
		if err != nil {
			return nil, err
		}
	}

	return db.BuildTxInfo(hash, rawTx, received, block, status, label)
}
