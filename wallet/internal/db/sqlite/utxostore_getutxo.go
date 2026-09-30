package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// GetUtxo retrieves one current wallet-owned UTXO by outpoint.
//
// The output must still be unspent and its creating transaction must still be
// in `pending` or `published` status.
func (s *Store) GetUtxo(ctx context.Context,
	query db.GetUtxoQuery) (*db.UtxoInfo, error) {

	var utxo *db.UtxoInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetUtxoByOutpoint(
			ctx, sqlc.GetUtxoByOutpointParams{
				NowUtc:      time.Now().UTC(),
				WalletID:    int64(query.WalletID),
				TxHash:      query.OutPoint.Hash[:],
				OutputIndex: int64(query.OutPoint.Index),
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("utxo %s: %w", query.OutPoint,
					db.ErrUtxoNotFound)
			}

			return fmt.Errorf("get utxo: %w", err)
		}

		utxo, err = utxoInfoFromGetRow(row)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return utxo, nil
}

// utxoInfoFromGetRow converts and enriches one GetUtxo query row.
func utxoInfoFromGetRow(row sqlc.GetUtxoByOutpointRow) (*db.UtxoInfo,
	error) {

	addrType, err := db.IDToAddressType(row.TypeID)
	if err != nil {
		return nil, fmt.Errorf("addr type: %w", err)
	}

	keyScope, hasScope, err := db.KeyScopeFromNullIDs(
		row.Purpose, row.CoinType,
	)
	if err != nil {
		return nil, fmt.Errorf("key scope: %w", err)
	}

	err = db.ValidateUtxoAddressShape(db.UtxoAddressShape{
		IsDerived:        row.AddressIsDerived,
		DerivedAddressID: row.DerivedAddressID,
		AccountID:        row.AccountID,
		AccountIsDerived: row.AccountIsDerived,
		AccountNumber:    row.AccountNumber,
	})
	if err != nil {
		return nil, err
	}

	utxo, err := utxoInfoFromRow(
		row.TxHash, row.OutputIndex, row.Amount, row.ScriptPubKey,
		row.ReceivedTime, row.IsCoinbase, row.BlockHeight,
	)
	if err != nil {
		return nil, err
	}

	if row.AddressIsDerived && !hasScope {
		return nil, fmt.Errorf("key scope: %w",
			db.ErrInvalidListAddressesQuery)
	}

	if row.AccountName.Valid {
		utxo.AccountName = row.AccountName.String
	}

	utxo.AddrType = addrType
	utxo.HasScript = row.HasScript
	utxo.IsLocked = row.IsLocked != 0

	if hasScope {
		utxo.KeyScope = keyScope
	}

	return utxo, nil
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
