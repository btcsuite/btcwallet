package pg

import (
	"context"
	"database/sql"

	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlstore"
	pgdb "github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// pgNullInt64 converts a PostgreSQL nullable int64 into the backend-neutral
// form.
func pgNullInt64(value sql.NullInt32) sql.NullInt64 {
	return sql.NullInt64{
		Int64: int64(value.Int32),
		Valid: value.Valid,
	}
}

// pgNullInt32 converts a PostgreSQL nullable int32 into the backend-neutral
// form.
func pgNullInt32(value sql.NullInt64) sql.NullInt32 {
	return sql.NullInt32{
		Int32: int32(value.Int64),
		Valid: value.Valid,
	}
}

// pgDetailsRow converts PostgreSQL transaction columns into a backend-neutral
// details row.
func pgDetailsRow(id int64, rawTx []byte, received int64,
	blockHeight sql.NullInt32, order sql.NullInt64, blockHash []byte,
	blockTime sql.NullInt64, label []byte) sqlstore.TransactionDetailsRow {

	return sqlstore.TransactionDetailsRow{
		ID:             id,
		RawTx:          rawTx,
		Received:       received,
		BlockHeight:    pgNullInt64(blockHeight),
		ConfirmedOrder: order,
		BlockHash:      blockHash,
		BlockTimestamp: blockTime,
		Label:          label,
	}
}

// GetTransactionDetailsByHash reads transaction details by hash from the
// transaction-bound backend.
func (q *queryAdapter) GetTransactionDetailsByHash(ctx context.Context,
	walletID int64, hash []byte) (sqlstore.TransactionDetailsRow, error) {

	row, err := q.queries.GetTransactionDetailsByHash(
		ctx, pgdb.GetTransactionDetailsByHashParams{
			WalletID: walletID,
			TxHash:   hash,
		},
	)

	return pgDetailsRow(
		row.ID, row.RawTx, row.ReceivedUnix, row.BlockHeight,
		row.ConfirmedOrder, row.HeaderHash, row.BlockTimestamp, row.Label,
	), err
}

// GetUnminedTransactionDetails reads unmined transaction details from the
// transaction-bound backend.
func (q *queryAdapter) GetUnminedTransactionDetails(ctx context.Context,
	walletID int64, hash []byte) (sqlstore.TransactionDetailsRow, error) {

	row, err := q.queries.GetUnminedTransactionDetails(
		ctx, pgdb.GetUnminedTransactionDetailsParams{
			WalletID: walletID,
			TxHash:   hash,
		},
	)

	return pgDetailsRow(
		row.ID, row.RawTx, row.ReceivedUnix, row.BlockHeight,
		row.ConfirmedOrder, row.HeaderHash, row.BlockTimestamp, row.Label,
	), err
}

// GetMinedTransactionDetails reads mined transaction details from the
// transaction-bound backend.
func (q *queryAdapter) GetMinedTransactionDetails(ctx context.Context,
	walletID int64, hash []byte, height int32,
	blockHash []byte) (sqlstore.TransactionDetailsRow, error) {

	row, err := q.queries.GetMinedTransactionDetails(
		ctx, pgdb.GetMinedTransactionDetailsParams{
			WalletID:    walletID,
			TxHash:      hash,
			BlockHeight: height,
			BlockHash:   blockHash,
		},
	)

	return pgDetailsRow(
		row.ID, row.RawTx, row.ReceivedUnix, sql.NullInt32{
			Int32: row.BlockHeight,
			Valid: true,
		}, row.ConfirmedOrder, row.HeaderHash, sql.NullInt64{
			Int64: row.BlockTimestamp,
			Valid: true,
		}, row.Label,
	), err
}

// GetTransactionDetailsByID reads transaction details by id from the
// transaction-bound backend.
func (q *queryAdapter) GetTransactionDetailsByID(ctx context.Context,
	walletID, transactionID int64) (sqlstore.TransactionDetailsRow, error) {

	row, err := q.queries.GetTransactionDetailsByID(
		ctx, pgdb.GetTransactionDetailsByIDParams{
			WalletID: walletID,
			ID:       transactionID,
		},
	)

	return pgDetailsRow(
		row.ID, row.RawTx, row.ReceivedUnix, row.BlockHeight,
		row.ConfirmedOrder, row.HeaderHash, row.BlockTimestamp, row.Label,
	), err
}

// ListTransactionDetailCredits reads transaction detail credits from the
// transaction-bound backend in stable order.
func (q *queryAdapter) ListTransactionDetailCredits(ctx context.Context,
	walletID, transactionID int64) ([]sqlstore.TransactionCreditRow, error) {

	rows, err := q.queries.ListTransactionCredits(
		ctx, pgdb.ListTransactionCreditsParams{
			WalletID:      walletID,
			TransactionID: transactionID,
		},
	)
	if err != nil {
		return nil, err
	}

	result := make([]sqlstore.TransactionCreditRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, sqlstore.TransactionCreditRow{
			OutputIndex: row.OutputIndex,
			Amount:      row.Amount,
			IsChange:    row.IsChange,
			IsSpent:     row.IsSpent.Bool,
		})
	}

	return result, nil
}

// ListTransactionDebits reads transaction debits from the transaction-bound
// backend in stable order.
func (q *queryAdapter) ListTransactionDebits(ctx context.Context,
	walletID, transactionID int64) ([]sqlstore.TransactionDebitRow, error) {

	rows, err := q.queries.ListTransactionDebits(
		ctx, pgdb.ListTransactionDebitsParams{
			WalletID:     walletID,
			SpendingTxID: transactionID,
		},
	)
	if err != nil {
		return nil, err
	}

	result := make([]sqlstore.TransactionDebitRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, sqlstore.TransactionDebitRow{
			InputIndex: row.InputIndex,
			Amount:     row.Amount,
		})
	}

	return result, nil
}

// GetTransactionLabel reads transaction label from the transaction-bound
// backend.
func (q *queryAdapter) GetTransactionLabel(ctx context.Context,
	walletID int64, hash []byte) ([]byte, error) {

	return q.queries.GetTransactionLabel(
		ctx, pgdb.GetTransactionLabelParams{
			WalletID: walletID,
			TxHash:   hash,
		},
	)
}

// ListUnminedTransactions reads unmined transactions from the transaction-bound
// backend in stable order.
func (q *queryAdapter) ListUnminedTransactions(ctx context.Context,
	walletID int64) ([]sqlstore.TransactionRow, error) {

	rows, err := q.queries.ListUnminedTransactions(ctx, walletID)
	if err != nil {
		return nil, err
	}

	result := make([]sqlstore.TransactionRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, sqlstore.TransactionRow{
			ID:    row.ID,
			Hash:  row.TxHash,
			RawTx: row.RawTx,
		})
	}

	return result, nil
}

// ListMinedTransactionsForward reads mined transactions forward from the
// transaction-bound backend in stable order.
func (q *queryAdapter) ListMinedTransactionsForward(ctx context.Context,
	walletID int64, startHeight,
	endHeight int32) ([]sqlstore.TransactionIncidenceRow, error) {

	rows, err := q.queries.ListMinedTransactionsForward(
		ctx, pgdb.ListMinedTransactionsForwardParams{
			WalletID:    walletID,
			StartHeight: startHeight,
			EndHeight:   endHeight,
		},
	)
	if err != nil {
		return nil, err
	}

	result := make([]sqlstore.TransactionIncidenceRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, sqlstore.TransactionIncidenceRow{
			ID:     row.ID,
			Height: row.BlockHeight,
		})
	}

	return result, nil
}

// ListMinedTransactionsReverse reads mined transactions reverse from the
// transaction-bound backend in stable order.
func (q *queryAdapter) ListMinedTransactionsReverse(ctx context.Context,
	walletID int64, startHeight,
	endHeight int32) ([]sqlstore.TransactionIncidenceRow, error) {

	rows, err := q.queries.ListMinedTransactionsReverse(
		ctx, pgdb.ListMinedTransactionsReverseParams{
			WalletID:    walletID,
			StartHeight: startHeight,
			EndHeight:   endHeight,
		},
	)
	if err != nil {
		return nil, err
	}

	result := make([]sqlstore.TransactionIncidenceRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, sqlstore.TransactionIncidenceRow{
			ID:     row.ID,
			Height: row.BlockHeight,
		})
	}

	return result, nil
}

// ListUnspentCredits reads unspent credits from the transaction-bound backend
// in stable order.
func (q *queryAdapter) ListUnspentCredits(ctx context.Context, walletID,
	nowUnix int64) ([]sqlstore.CreditRow, error) {

	rows, err := q.queries.ListUnspentCredits(
		ctx, pgdb.ListUnspentCreditsParams{
			WalletID: walletID,
			NowUnix:  nowUnix,
		},
	)
	if err != nil {
		return nil, err
	}

	result := make([]sqlstore.CreditRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, sqlstore.CreditRow{
			Hash:           row.TxHash,
			OutputIndex:    row.OutputIndex,
			Amount:         row.Amount,
			PkScript:       row.PkScript,
			Received:       row.ReceivedUnix,
			BlockHeight:    pgNullInt64(row.BlockHeight),
			IsCoinbase:     row.IsCoinbase,
			BlockHash:      row.HeaderHash,
			BlockTimestamp: row.BlockTimestamp,
		})
	}

	return result, nil
}

// ListOutputsToWatch reads outputs to watch from the transaction-bound backend
// in stable order.
func (q *queryAdapter) ListOutputsToWatch(ctx context.Context,
	walletID int64) ([]sqlstore.CreditRow, error) {

	rows, err := q.queries.ListOutputsToWatch(ctx, walletID)
	if err != nil {
		return nil, err
	}

	result := make([]sqlstore.CreditRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, sqlstore.CreditRow{
			Hash:        row.TxHash,
			OutputIndex: row.OutputIndex,
			PkScript:    row.PkScript,
		})
	}

	return result, nil
}

// GetMinedTransactionID reads mined transaction id from the transaction-bound
// backend.
func (q *queryAdapter) GetMinedTransactionID(ctx context.Context,
	walletID int64, hash []byte, height int32, blockHash []byte) (int64,
	error) {

	return q.queries.GetMinedTransactionID(
		ctx, pgdb.GetMinedTransactionIDParams{
			WalletID:    walletID,
			TxHash:      hash,
			BlockHeight: height,
			BlockHash:   blockHash,
		},
	)
}

// GetUnminedPreviousPkScript reads unmined previous pk script from the
// transaction-bound backend.
func (q *queryAdapter) GetUnminedPreviousPkScript(ctx context.Context,
	walletID int64, hash []byte, index uint32) ([]byte, error) {

	return q.queries.GetUnminedPreviousPkScript(
		ctx, pgdb.GetUnminedPreviousPkScriptParams{
			WalletID:    walletID,
			TxHash:      hash,
			OutputIndex: int64(index),
		},
	)
}

// GetMinedPreviousPkScript reads mined previous pk script from the
// transaction-bound backend.
func (q *queryAdapter) GetMinedPreviousPkScript(ctx context.Context,
	walletID, transactionID int64, inputIndex uint32) ([]byte, error) {

	return q.queries.GetMinedPreviousPkScript(
		ctx, pgdb.GetMinedPreviousPkScriptParams{
			WalletID:     walletID,
			SpendingTxID: transactionID,
			InputIndex:   int64(inputIndex),
		},
	)
}

// NextBlockTransactionOrder returns next block transaction order from the
// transaction-bound backend.
func (q *queryAdapter) NextBlockTransactionOrder(ctx context.Context,
	walletID int64, blockHash []byte) (int64, error) {

	return q.queries.NextBlockTransactionOrder(
		ctx, pgdb.NextBlockTransactionOrderParams{
			WalletID:  walletID,
			BlockHash: blockHash,
		},
	)
}

// InsertTransaction records transaction through the transaction-bound backend.
func (q *queryAdapter) InsertTransaction(ctx context.Context,
	params sqlstore.InsertTransactionParams) (int64, error) {

	return q.queries.InsertTransaction(ctx, pgdb.InsertTransactionParams{
		WalletID:       params.WalletID,
		TxHash:         params.Hash,
		RawTx:          params.RawTx,
		ReceivedUnix:   params.Received,
		BlockHash:      params.BlockHash,
		ConfirmedOrder: params.ConfirmedOrder,
		IsCoinbase:     params.IsCoinbase,
	})
}

// PromoteUnminedTransaction promotes unmined transaction in the
// transaction-bound backend.
func (q *queryAdapter) PromoteUnminedTransaction(ctx context.Context,
	walletID int64, hash, blockHash []byte, order int64) (int64, error) {

	return q.queries.PromoteUnminedTransaction(
		ctx, pgdb.PromoteUnminedTransactionParams{
			BlockHash: blockHash,
			ConfirmedOrder: sql.NullInt64{
				Int64: order,
				Valid: true,
			},
			WalletID: walletID,
			TxHash:   hash,
		},
	)
}

// InsertTransactionInput records transaction input through the
// transaction-bound backend.
func (q *queryAdapter) InsertTransactionInput(ctx context.Context,
	transactionID int64, inputIndex uint32, prevHash []byte,
	prevIndex uint32) error {

	return q.queries.InsertTransactionInput(
		ctx, pgdb.InsertTransactionInputParams{
			SpendingTxID:    transactionID,
			InputIndex:      int64(inputIndex),
			PrevTxHash:      prevHash,
			PrevOutputIndex: int64(prevIndex),
		},
	)
}

// ListUnminedSpenders reads unmined spenders from the transaction-bound backend
// in stable order.
func (q *queryAdapter) ListUnminedSpenders(ctx context.Context,
	walletID int64, prevHash []byte, prevIndex uint32,
	excludeTransactionID int64) ([]sqlstore.UnminedSpenderRow, error) {

	rows, err := q.queries.ListUnminedSpenders(
		ctx, pgdb.ListUnminedSpendersParams{
			WalletID:             walletID,
			PrevTxHash:           prevHash,
			PrevOutputIndex:      int64(prevIndex),
			ExcludeTransactionID: excludeTransactionID,
		},
	)
	if err != nil {
		return nil, err
	}

	result := make([]sqlstore.UnminedSpenderRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, sqlstore.UnminedSpenderRow{
			ID:   row.ID,
			Hash: row.TxHash,
		})
	}

	return result, nil
}

// GetActiveCreditID reads active credit id from the transaction-bound backend.
func (q *queryAdapter) GetActiveCreditID(ctx context.Context, walletID int64,
	hash []byte, index uint32) (int64, error) {

	return q.queries.GetActiveCreditID(
		ctx, pgdb.GetActiveCreditIDParams{
			WalletID:    walletID,
			TxHash:      hash,
			OutputIndex: int64(index),
		},
	)
}

// RecordCreditSpend records credit spend in the transaction-bound backend.
func (q *queryAdapter) RecordCreditSpend(ctx context.Context, walletID,
	creditID, transactionID int64, inputIndex uint32) (int64, error) {

	return q.queries.RecordCreditSpend(
		ctx, pgdb.RecordCreditSpendParams{
			WalletID:     walletID,
			ID:           creditID,
			SpendingTxID: transactionID,
			InputIndex:   int64(inputIndex),
		},
	)
}

// DeleteOutputLeaseAnyOwner removes output lease any owner through the
// transaction-bound backend.
func (q *queryAdapter) DeleteOutputLeaseAnyOwner(ctx context.Context,
	walletID int64, hash []byte, index uint32) (int64, error) {

	return q.queries.DeleteOutputLeaseAnyOwner(
		ctx, pgdb.DeleteOutputLeaseAnyOwnerParams{
			WalletID:    walletID,
			TxHash:      hash,
			OutputIndex: int64(index),
		},
	)
}

// GetCreditID reads credit id from the transaction-bound backend.
func (q *queryAdapter) GetCreditID(ctx context.Context, transactionID int64,
	index uint32) (int64, error) {

	row, err := q.queries.GetCredit(ctx, pgdb.GetCreditParams{
		TransactionID: transactionID,
		OutputIndex:   int64(index),
	})

	return row.ID, err
}

// InsertCredit records credit through the transaction-bound backend.
func (q *queryAdapter) InsertCredit(ctx context.Context, walletID,
	transactionID int64, index uint32, amount int64, pkScript []byte,
	change bool) (int64, error) {

	return q.queries.InsertCredit(ctx, pgdb.InsertCreditParams{
		WalletID:      walletID,
		TransactionID: transactionID,
		OutputIndex:   int64(index),
		Amount:        amount,
		PkScript:      pkScript,
		IsChange:      change,
	})
}

// PutTransactionLabel stores transaction label through the transaction-bound
// backend.
func (q *queryAdapter) PutTransactionLabel(ctx context.Context,
	walletID int64, hash, label []byte) error {

	return q.queries.PutTransactionLabel(
		ctx, pgdb.PutTransactionLabelParams{
			WalletID: walletID,
			TxHash:   hash,
			Label:    label,
		},
	)
}

// IsKnownOutput reports whether known output is present in the
// transaction-bound backend.
func (q *queryAdapter) IsKnownOutput(ctx context.Context, walletID int64,
	hash []byte, index uint32) (bool, error) {

	return q.queries.IsKnownOutput(ctx, pgdb.IsKnownOutputParams{
		WalletID:    walletID,
		TxHash:      hash,
		OutputIndex: int64(index),
	})
}

// AcquireOutputLease acquires output lease in the transaction-bound backend.
func (q *queryAdapter) AcquireOutputLease(ctx context.Context, walletID int64,
	hash []byte, index uint32, lockID []byte, expiresUnix,
	nowUnix int64) (int64, error) {

	return q.queries.AcquireOutputLease(
		ctx, pgdb.AcquireOutputLeaseParams{
			WalletID:    walletID,
			TxHash:      hash,
			OutputIndex: int64(index),
			LockID:      lockID,
			ExpiresUnix: expiresUnix,
			NowUnix:     nowUnix,
		},
	)
}

// GetOutputLease reads output lease from the transaction-bound backend.
func (q *queryAdapter) GetOutputLease(ctx context.Context, walletID int64,
	hash []byte, index uint32) (sqlstore.OutputLeaseRow, error) {

	row, err := q.queries.GetOutputLease(
		ctx, pgdb.GetOutputLeaseParams{
			WalletID:    walletID,
			TxHash:      hash,
			OutputIndex: int64(index),
		},
	)

	return sqlstore.OutputLeaseRow{
		Hash:       row.TxHash,
		Index:      row.OutputIndex,
		LockID:     row.LockID,
		Expiration: row.ExpiresUnix,
	}, err
}

// DeleteOutputLease removes output lease through the transaction-bound backend.
func (q *queryAdapter) DeleteOutputLease(ctx context.Context, walletID int64,
	hash []byte, index uint32, lockID []byte) (int64, error) {

	return q.queries.DeleteOutputLease(
		ctx, pgdb.DeleteOutputLeaseParams{
			WalletID:    walletID,
			TxHash:      hash,
			OutputIndex: int64(index),
			LockID:      lockID,
		},
	)
}

// DeleteExpiredOutputLeases removes expired output leases through the
// transaction-bound backend.
func (q *queryAdapter) DeleteExpiredOutputLeases(ctx context.Context,
	walletID, nowUnix int64) (int64, error) {

	return q.queries.DeleteExpiredOutputLeases(
		ctx, pgdb.DeleteExpiredOutputLeasesParams{
			WalletID:    walletID,
			ExpiresUnix: nowUnix,
		},
	)
}

// ListActiveOutputLeases reads active output leases from the transaction-bound
// backend in stable order.
func (q *queryAdapter) ListActiveOutputLeases(ctx context.Context, walletID,
	nowUnix int64) ([]sqlstore.OutputLeaseRow, error) {

	rows, err := q.queries.ListActiveOutputLeases(
		ctx, pgdb.ListActiveOutputLeasesParams{
			WalletID:    walletID,
			ExpiresUnix: nowUnix,
		},
	)
	if err != nil {
		return nil, err
	}

	result := make([]sqlstore.OutputLeaseRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, sqlstore.OutputLeaseRow{
			Hash:       row.TxHash,
			Index:      row.OutputIndex,
			LockID:     row.LockID,
			Expiration: row.ExpiresUnix,
		})
	}

	return result, nil
}
