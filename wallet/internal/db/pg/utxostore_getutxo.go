package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// GetUtxo retrieves one current wallet-owned UTXO by outpoint.
//
// The output must still be unspent and its creating transaction must still be
// in `pending` or `published` status.
func (s *Store) GetUtxo(ctx context.Context,
	query db.GetUtxoQuery) (*db.UtxoInfo, error) {

	outputIndex, err := db.Uint32ToInt32(query.OutPoint.Index)
	if err != nil {
		return nil, fmt.Errorf("convert output index: %w", err)
	}

	var utxo *db.UtxoInfo

	err = s.execRead(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetUtxoByOutpoint(
			ctx, sqlc.GetUtxoByOutpointParams{
				WalletID:    int64(query.WalletID),
				TxHash:      query.OutPoint.Hash[:],
				OutputIndex: outputIndex,
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("utxo %s: %w", query.OutPoint,
					db.ErrUtxoNotFound)
			}

			return fmt.Errorf("get utxo: %w", err)
		}

		utxo, err = utxoInfoFromRow(
			row.TxHash, row.OutputIndex, row.Amount, row.ScriptPubKey,
			row.ReceivedTime, row.IsCoinbase, row.BlockHeight,
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return utxo, nil
}

// utxoInfoFromRow converts one normalized postgres query row into the public
// UtxoInfo shape.
func utxoInfoFromRow(hash []byte, outputIndex int32, amount int64,
	pkScript []byte, received time.Time, isCoinbase bool,
	blockHeight sql.NullInt32) (*db.UtxoInfo, error) {

	index, err := db.Int64ToUint32(int64(outputIndex))
	if err != nil {
		return nil, fmt.Errorf("utxo output index: %w", err)
	}

	var height *uint32
	if blockHeight.Valid {
		heightValue, err := db.NullInt32ToUint32(blockHeight)
		if err != nil {
			return nil, fmt.Errorf("utxo block height: %w", err)
		}

		height = &heightValue
	}

	return db.BuildUtxoInfo(
		hash, index, amount, pkScript, received, isCoinbase, height,
	)
}
