package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// txDetailEdgesOps adapts sqlite owned-edge queries to the shared tx-detail
// read workflows.
type txDetailEdgesOps struct {
	q *sqlc.Queries
}

// getTxDetailOps adapts sqlite sqlc queries to the shared GetTxDetail flow.
type getTxDetailOps struct {
	txDetailEdgesOps
}

var _ db.GetTxDetailOps = (*getTxDetailOps)(nil)

// ownedInputOutpointKey keys wallet-owned previous output amounts by outpoint.
type ownedInputOutpointKey struct {
	hash  chainhash.Hash
	index uint32
}

// GetTxDetail retrieves one detailed wallet-scoped transaction view by hash.
func (s *Store) GetTxDetail(ctx context.Context, query db.GetTxDetailQuery) (
	*db.TxDetailInfo, error) {

	var detail *db.TxDetailInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		var err error

		detail, err = db.GetTxDetailWithOps(ctx, query, &getTxDetailOps{
			txDetailEdgesOps: txDetailEdgesOps{q: q},
		})

		return err
	})
	if err != nil {
		return nil, err
	}

	return detail, nil
}

// LoadBase loads the normalized base transaction row for one wallet-scoped
// hash lookup.
func (o *getTxDetailOps) LoadBase(ctx context.Context,
	query db.GetTxDetailQuery) (db.TxDetailBase, error) {

	row, err := o.q.GetTransactionByHash(
		ctx, sqlc.GetTransactionByHashParams{
			WalletID: int64(query.WalletID),
			TxHash:   query.Txid[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return db.TxDetailBase{}, fmt.Errorf("tx %s: %w",
				query.Txid, db.ErrTxNotFound)
		}

		return db.TxDetailBase{}, fmt.Errorf("get tx detail: %w", err)
	}

	return txDetailBaseFromHashRow(row)
}

// txDetailBaseFromHashRow converts one sqlite GetTransactionByHash row into the
// normalized tx-detail base shape.
func txDetailBaseFromHashRow(row sqlc.GetTransactionByHashRow) (
	db.TxDetailBase, error) {

	var (
		block *db.Block
		err   error
	)

	if row.BlockHeight.Valid {
		block, err = buildBlock(
			row.BlockHeight, row.BlockHash, row.BlockTimestamp,
		)
		if err != nil {
			return db.TxDetailBase{}, err
		}
	}

	return db.TxDetailBase{
		ID:       row.ID,
		Hash:     row.TxHash,
		RawTx:    row.RawTx,
		Received: row.ReceivedTime,
		Block:    block,
		Status:   row.TxStatus,
		Label:    row.TxLabel,
	}, nil
}

// LoadOwnedOutputs loads all wallet-owned outputs created by the
// selected transaction rows and groups them by tx id.
func (o *txDetailEdgesOps) LoadOwnedOutputs(ctx context.Context,
	walletID uint32, txIDs []int64) (
	map[int64][]db.TxOwnedOutput, error) {

	rows, err := o.q.ListOwnedOutputsByTxIDs(
		ctx, sqlc.ListOwnedOutputsByTxIDsParams{
			WalletID: int64(walletID),
			TxIds:    txIDs,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list owned outputs by tx ids: %w", err)
	}

	result := make(map[int64][]db.TxOwnedOutput)
	for _, row := range rows {
		index, err := db.Int64ToUint32(row.OutputIndex)
		if err != nil {
			return nil, fmt.Errorf("owned output index: %w", err)
		}

		result[row.TxID] = append(result[row.TxID], db.TxOwnedOutput{
			Index:  index,
			Amount: btcutil.Amount(row.Amount),
		})
	}

	return result, nil
}

// LoadOwnedInputs loads all wallet-owned inputs referenced by the selected
// transaction input outpoints and groups them by spender tx id.
func (o *txDetailEdgesOps) LoadOwnedInputs(ctx context.Context,
	walletID uint32, inputOutpoints []db.TxInputOutpoint) (
	map[int64][]db.TxOwnedInput, error) {

	result := make(map[int64][]db.TxOwnedInput)
	if len(inputOutpoints) == 0 {
		return result, nil
	}

	prevHashes := make(map[chainhash.Hash]struct{})

	prevHashBytes := make([][]byte, 0, len(inputOutpoints))
	for _, inputOutpoint := range inputOutpoints {
		if _, ok := prevHashes[inputOutpoint.PrevTxHash]; ok {
			continue
		}

		prevHashes[inputOutpoint.PrevTxHash] = struct{}{}
		prevHash := inputOutpoint.PrevTxHash
		prevHashBytes = append(prevHashBytes, prevHash[:])
	}

	rows, err := o.q.ListOwnedInputPrevOutputsByTxHashes(
		ctx, sqlc.ListOwnedInputPrevOutputsByTxHashesParams{
			WalletID: int64(walletID),
			TxHashes: prevHashBytes,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list owned input prev outputs by tx hashes: %w", err,
		)
	}

	prevAmounts := make(map[ownedInputOutpointKey]btcutil.Amount)
	for _, row := range rows {
		prevHash, err := chainhash.NewHash(row.TxHash)
		if err != nil {
			return nil, fmt.Errorf("owned input prev tx hash: %w", err)
		}

		index, err := db.Int64ToUint32(row.OutputIndex)
		if err != nil {
			return nil, fmt.Errorf("owned input prev output index: %w",
				err)
		}

		prevAmounts[ownedInputOutpointKey{
			hash:  *prevHash,
			index: index,
		}] = btcutil.Amount(row.Amount)
	}

	for _, inputOutpoint := range inputOutpoints {
		amount, ok := prevAmounts[ownedInputOutpointKey{
			hash:  inputOutpoint.PrevTxHash,
			index: inputOutpoint.PrevOutputIndex,
		}]
		if !ok {
			continue
		}

		result[inputOutpoint.TxID] = append(
			result[inputOutpoint.TxID], db.TxOwnedInput{
				Index:  inputOutpoint.InputIndex,
				Amount: amount,
			},
		)
	}

	return result, nil
}
