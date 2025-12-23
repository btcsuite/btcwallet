package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// Ensure PostgresWalletDB satisfies the TxStore interface.
var _ TxStore = (*PostgresWalletDB)(nil)

// CreateTx atomically records a transaction and its credits.
func (w *PostgresWalletDB) CreateTx(ctx context.Context,
	params CreateTxParams) error {

	return w.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		txBuf, err := serializeTx(params.Tx)
		if err != nil {
			return err
		}

		var blockHeight sql.NullInt32

		// Insert the transaction record.
		txHash := params.Tx.TxHash()
		insertParams := sqlcpg.InsertTransactionParams{
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
func (w *PostgresWalletDB) UpdateTx(ctx context.Context,
	params UpdateTxParams) error {

	return w.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		// Update block height if provided.
		if params.Block != nil {
			// Ensure the block exists in the database.
			err := ensureBlockExistsPg(ctx, qtx, params.Block)
			if err != nil {
				return fmt.Errorf("ensure block exists: %w",
					err)
			}

			height, err := uint32ToInt32(params.Block.Height)
			if err != nil {
				return fmt.Errorf("convert block height: %w",
					err)
			}

			updateParams := sqlcpg.UpdateTransactionBlockParams{
				TxHash: params.Txid[:],
				BlockHeight: sql.NullInt32{
					Int32: height,
					Valid: true,
				},
			}

			err = qtx.UpdateTransactionBlock(ctx, updateParams)
			if err != nil {
				return fmt.Errorf("update transaction "+
					"block: %w", err)
			}
		}

		// Update label if provided.
		if params.Label != nil {
			updateParams := sqlcpg.UpdateTransactionLabelParams{
				TxHash:  params.Txid[:],
				TxLabel: *params.Label,
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
func (w *PostgresWalletDB) GetTx(ctx context.Context,
	query GetTxQuery) (*TxInfo, error) {

	row, err := w.queries.GetTransactionByHash(ctx, query.Txid[:])
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrTxNotFound,
				query.Txid)
		}

		return nil, fmt.Errorf("get transaction: %w", err)
	}

	return buildPgTxInfoFromGetRow(row)
}

// ListTxns returns a slice of transaction information based on the provided
// query parameters.
func (w *PostgresWalletDB) ListTxns(ctx context.Context,
	query ListTxnsQuery) ([]TxInfo, error) {

	if query.UnminedOnly {
		// Get only unconfirmed transactions.
		rows, err := w.queries.GetAllUnconfirmedTransactions(ctx)
		if err != nil {
			return nil, fmt.Errorf("list unmined txs: %w", err)
		}

		txInfos := make([]TxInfo, 0, len(rows))
		for _, row := range rows {
			txInfo, err := buildTxInfoFromUnconfirmedPg(row)
			if err != nil {
				return nil, err
			}

			txInfos = append(txInfos, *txInfo)
		}

		return txInfos, nil
	}

	// Get transactions by height range.
	startHeight, err := uint32ToInt32(query.StartHeight)
	if err != nil {
		return nil, fmt.Errorf("convert start height: %w", err)
	}

	endHeight, err := uint32ToInt32(query.EndHeight)
	if err != nil {
		return nil, fmt.Errorf("convert end height: %w", err)
	}

	params := sqlcpg.ListTransactionsByHeightRangeParams{
		BlockHeight: sql.NullInt32{
			Int32: startHeight,
			Valid: true,
		},
		BlockHeight_2: sql.NullInt32{
			Int32: endHeight,
			Valid: true,
		},
	}

	rows, err := w.queries.ListTransactionsByHeightRange(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list txs by height range: %w", err)
	}

	txInfos := make([]TxInfo, 0, len(rows))
	for _, row := range rows {
		txInfo, err := buildPgTxInfoFromListRow(row)
		if err != nil {
			return nil, err
		}

		txInfos = append(txInfos, *txInfo)
	}

	return txInfos, nil
}

// DeleteTx removes an unmined transaction from the store.
func (w *PostgresWalletDB) DeleteTx(ctx context.Context,
	params DeleteTxParams) error {

	err := w.queries.DeleteUnconfirmedTransaction(ctx, params.Txid[:])
	if err != nil {
		return fmt.Errorf("delete unmined transaction: %w", err)
	}

	return nil
}

// RollbackToBlock removes all blocks at and after a given height, moving
// transactions back to the unconfirmed pool.
func (w *PostgresWalletDB) RollbackToBlock(ctx context.Context,
	height uint32) error {

	return w.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		// Move all transactions at or after this height back to
		// unconfirmed.
		heightInt32, err := uint32ToInt32(height)
		if err != nil {
			return fmt.Errorf("convert height: %w", err)
		}

		blockHeight := sql.NullInt32{
			Int32: heightInt32,
			Valid: true,
		}

		err = qtx.UnconfirmTransactionsFromHeight(ctx, blockHeight)
		if err != nil {
			return fmt.Errorf("unconfirm transactions: %w", err)
		}

		// Delete all blocks at or after this height.
		err = qtx.DeleteBlocksFromHeightOnwards(ctx, heightInt32)
		if err != nil {
			return fmt.Errorf("delete blocks: %w", err)
		}

		return nil
	})
}

// buildPgTxInfoFromGetRow constructs a TxInfo from GetTransactionByHashRow.
func buildPgTxInfoFromGetRow(
	row sqlcpg.GetTransactionByHashRow) (*TxInfo, error) {

	return buildTxInfo(
		row.TxHash,
		row.SerializedTx,
		row.ReceivedTimestamp,
		row.TxLabel,
		row.BlockHeight,
		row.HeaderHash,
		row.BlockTimestamp,
	)
}

// buildPgTxInfoFromListRow constructs a TxInfo from
// ListTransactionsByHeightRangeRow.
func buildPgTxInfoFromListRow(
	row sqlcpg.ListTransactionsByHeightRangeRow) (*TxInfo, error) {

	return buildTxInfo(
		row.TxHash,
		row.SerializedTx,
		row.ReceivedTimestamp,
		row.TxLabel,
		row.BlockHeight,
		row.HeaderHash,
		row.BlockTimestamp,
	)
}

// buildTxInfoFromUnconfirmedPg constructs a TxInfo from an unconfirmed
// transaction row (without block metadata).
func buildTxInfoFromUnconfirmedPg(row sqlcpg.Transaction) (*TxInfo, error) {
	return buildTxInfo(
		row.TxHash,
		row.SerializedTx,
		row.ReceivedTimestamp,
		row.TxLabel,
		row.BlockHeight,
		nil,
		sql.NullInt64{},
	)
}
