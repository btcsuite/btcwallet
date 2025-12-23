package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// Ensure SQLiteWalletDB satisfies the TxStore interface.
var _ TxStore = (*SQLiteWalletDB)(nil)

// CreateTx atomically records a transaction and its credits.
func (w *SQLiteWalletDB) CreateTx(ctx context.Context,
	params CreateTxParams) error {

	return w.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		txBuf, err := serializeTx(params.Tx)
		if err != nil {
			return err
		}

		var blockHeight sql.NullInt64

		txHash := params.Tx.TxHash()
		insertParams := sqlcsqlite.InsertTransactionParams{
			TxHash:            txHash[:],
			BlockHeight:       blockHeight,
			IsCoinbase:        isCoinbaseTx(params.Tx),
			ReceivedTimestamp: time.Now().Unix(),
			SerializedTx:      txBuf,
			TxLabel:           params.Label,
		}

		_, err = qtx.InsertTransaction(ctx, insertParams)
		if err != nil {
			return fmt.Errorf("insert transaction: %w", err)
		}

		return nil
	})
}

// UpdateTx updates an existing transaction record in the database.
func (w *SQLiteWalletDB) UpdateTx(ctx context.Context,
	params UpdateTxParams) error {

	return w.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		// Update block height if provided.
		if params.Block != nil {
			// Ensure the block exists in the database.
			err := ensureBlockExistsSqlite(ctx, qtx, params.Block)
			if err != nil {
				return fmt.Errorf("ensure block exists: %w",
					err)
			}

			updateParams := sqlcsqlite.UpdateTransactionBlockParams{
				BlockHeight: sql.NullInt64{
					Int64: int64(params.Block.Height),
					Valid: true,
				},
				TxHash: params.Txid[:],
			}

			err = qtx.UpdateTransactionBlock(ctx, updateParams)
			if err != nil {
				return fmt.Errorf("update transaction "+
					"block: %w", err)
			}
		}

		// Update label if provided.
		if params.Label != nil {
			updateParams := sqlcsqlite.UpdateTransactionLabelParams{
				TxLabel: *params.Label,
				TxHash:  params.Txid[:],
			}

			err := qtx.UpdateTransactionLabel(ctx, updateParams)
			if err != nil {
				return fmt.Errorf("update transaction "+
					"label: %w", err)
			}
		}

		return nil
	})
}

// GetTx retrieves a transaction record by its hash. Credits and debits are
// derived from the UTXO store, not stored directly in the transaction record.
func (w *SQLiteWalletDB) GetTx(ctx context.Context,
	query GetTxQuery) (*TxInfo, error) {

	row, err := w.queries.GetTransactionByHash(ctx, query.Txid[:])
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrTxNotFound,
				query.Txid)
		}

		return nil, fmt.Errorf("get transaction: %w", err)
	}

	return buildSqliteTxInfoFromGetRow(row)
}

// ListTxns returns a slice of transaction information based on the provided
// query parameters.
func (w *SQLiteWalletDB) ListTxns(ctx context.Context,
	query ListTxnsQuery) ([]TxInfo, error) {

	if query.UnminedOnly {
		rows, err := w.queries.GetAllUnconfirmedTransactions(ctx)
		if err != nil {
			return nil, fmt.Errorf("list unmined txs: %w", err)
		}

		txInfos := make([]TxInfo, 0, len(rows))
		for _, row := range rows {
			txInfo, err := buildTxInfoFromUnconfirmedSqlite(row)
			if err != nil {
				return nil, err
			}

			txInfos = append(txInfos, *txInfo)
		}

		return txInfos, nil
	}

	// Get transactions by height range.
	params := sqlcsqlite.ListTransactionsByHeightRangeParams{
		BlockHeight: sql.NullInt64{
			Int64: int64(query.StartHeight),
			Valid: true,
		},
		BlockHeight_2: sql.NullInt64{
			Int64: int64(query.EndHeight),
			Valid: true,
		},
	}

	rows, err := w.queries.ListTransactionsByHeightRange(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list txs by height range: %w", err)
	}

	txInfos := make([]TxInfo, 0, len(rows))
	for _, row := range rows {
		txInfo, err := buildSqliteTxInfoFromListRow(row)
		if err != nil {
			return nil, err
		}

		txInfos = append(txInfos, *txInfo)
	}

	return txInfos, nil
}

// DeleteTx removes an unmined transaction from the store.
func (w *SQLiteWalletDB) DeleteTx(ctx context.Context,
	params DeleteTxParams) error {

	err := w.queries.DeleteUnconfirmedTransaction(ctx, params.Txid[:])
	if err != nil {
		return fmt.Errorf("delete unmined transaction: %w", err)
	}

	return nil
}

// RollbackToBlock removes all blocks at and after a given height, moving
// transactions back to the unconfirmed pool.
func (w *SQLiteWalletDB) RollbackToBlock(ctx context.Context,
	height uint32) error {

	return w.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		// Move all transactions at or after this height back to
		// unconfirmed.
		blockHeight := sql.NullInt64{
			Int64: int64(height),
			Valid: true,
		}

		err := qtx.UnconfirmTransactionsFromHeight(ctx, blockHeight)
		if err != nil {
			return fmt.Errorf("unconfirm transactions: %w", err)
		}

		// Delete all blocks at or after this height.
		err = qtx.DeleteBlocksFromHeightOnwards(ctx, int64(height))
		if err != nil {
			return fmt.Errorf("delete blocks: %w", err)
		}

		return nil
	})
}

// buildSqliteTxInfoFromGetRow constructs a TxInfo from GetTransactionByHashRow.
func buildSqliteTxInfoFromGetRow(
	row sqlcsqlite.GetTransactionByHashRow) (*TxInfo, error) {

	return buildSqliteTxInfoFromFields(
		row.TxHash,
		row.SerializedTx,
		row.ReceivedTimestamp,
		row.TxLabel,
		row.BlockHeight,
		row.HeaderHash,
		row.BlockTimestamp,
	)
}

// buildSqliteTxInfoFromListRow constructs a TxInfo from
// ListTransactionsByHeightRangeRow.
func buildSqliteTxInfoFromListRow(
	row sqlcsqlite.ListTransactionsByHeightRangeRow) (*TxInfo, error) {

	return buildSqliteTxInfoFromFields(
		row.TxHash,
		row.SerializedTx,
		row.ReceivedTimestamp,
		row.TxLabel,
		row.BlockHeight,
		row.HeaderHash,
		row.BlockTimestamp,
	)
}

// buildSqliteTxInfoFromFields constructs a TxInfo from SQLite transaction
// fields.
func buildSqliteTxInfoFromFields(txHash, serializedTx []byte,
	receivedTimestamp int64, txLabel string, blockHeightInt64 sql.NullInt64,
	headerHash []byte, blockTimestamp sql.NullInt64) (*TxInfo, error) {

	var blockHeight sql.NullInt32
	if blockHeightInt64.Valid {
		height, err := int64ToInt32(blockHeightInt64.Int64)
		if err != nil {
			return nil, fmt.Errorf("convert block height: %w", err)
		}

		blockHeight = sql.NullInt32{Int32: height, Valid: true}
	}

	return buildTxInfo(
		txHash,
		serializedTx,
		receivedTimestamp,
		txLabel,
		blockHeight,
		headerHash,
		blockTimestamp,
	)
}

// buildTxInfoFromUnconfirmedSqlite constructs a TxInfo from an unconfirmed
// transaction row (without block metadata).
func buildTxInfoFromUnconfirmedSqlite(
	row sqlcsqlite.Transaction) (*TxInfo, error) {

	var blockHeight sql.NullInt32
	if row.BlockHeight.Valid {
		height, err := int64ToInt32(row.BlockHeight.Int64)
		if err != nil {
			return nil, fmt.Errorf("convert block height: %w", err)
		}

		blockHeight = sql.NullInt32{Int32: height, Valid: true}
	}

	return buildTxInfo(
		row.TxHash,
		row.SerializedTx,
		row.ReceivedTimestamp,
		row.TxLabel,
		blockHeight,
		nil,
		sql.NullInt64{},
	)
}
