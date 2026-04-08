package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	sqlc "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// GetUtxo retrieves one current wallet-owned UTXO by outpoint.
//
// The output must still be unspent and its creating transaction must still be
// in `pending` or `published` status.
func (s *Store) GetUtxo(ctx context.Context,
	query db.GetUtxoQuery) (*db.UtxoInfo, error) {

	row, err := s.queries.GetUtxoByOutpoint(
		ctx, sqlc.GetUtxoByOutpointParams{
			WalletID:    int64(query.WalletID),
			TxHash:      query.OutPoint.Hash[:],
			OutputIndex: int64(query.OutPoint.Index),
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("utxo %s: %w", query.OutPoint,
				db.ErrUtxoNotFound)
		}

		return nil, fmt.Errorf("get utxo: %w", err)
	}

	return utxoInfoFromRow(
		row.TxHash, row.OutputIndex, row.Amount, row.ScriptPubKey,
		row.ReceivedTime, row.IsCoinbase, row.BlockHeight,
	)
}

// utxoInfoFromRow converts one normalized sqlite query row into the
// public UtxoInfo shape.
func utxoInfoFromRow(hash []byte, outputIndex int64, amount int64,
	pkScript []byte, received time.Time, isCoinbase bool,
	blockHeight sql.NullInt64) (*db.UtxoInfo, error) {

	index, err := db.Int64ToUint32(outputIndex)
	if err != nil {
		return nil, fmt.Errorf("utxo output index: %w", err)
	}

	var height *uint32
	if blockHeight.Valid {
		heightValue, err := db.Int64ToUint32(blockHeight.Int64)
		if err != nil {
			return nil, fmt.Errorf("utxo block height: %w", err)
		}

		height = &heightValue
	}

	return db.BuildUtxoInfo(
		hash, index, amount, pkScript, received, isCoinbase, height,
	)
}
