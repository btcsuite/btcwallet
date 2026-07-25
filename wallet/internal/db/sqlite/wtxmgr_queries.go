package sqlite

import (
	"context"
	"database/sql"

	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlstore"
	sqlitedb "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// sqliteDetailsRow converts SQLite transaction columns into a backend-neutral
// details row.
func sqliteDetailsRow(id int64, rawTx []byte, received int64,
	blockHeight, order sql.NullInt64, blockHash []byte,
	blockTime sql.NullInt64, label []byte) sqlstore.TransactionDetailsRow {

	return sqlstore.TransactionDetailsRow{
		ID:             id,
		RawTx:          rawTx,
		Received:       received,
		BlockHeight:    blockHeight,
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
		ctx, sqlitedb.GetTransactionDetailsByHashParams{
			WalletID: walletID,
			TxHash:   hash,
		},
	)

	return sqliteDetailsRow(
		row.ID, row.RawTx, row.ReceivedUnix, row.BlockHeight,
		row.ConfirmedOrder, row.HeaderHash, row.BlockTimestamp, row.Label,
	), err
}

// GetUnminedTransactionDetails reads unmined transaction details from the
// transaction-bound backend.
func (q *queryAdapter) GetUnminedTransactionDetails(ctx context.Context,
	walletID int64, hash []byte) (sqlstore.TransactionDetailsRow, error) {

	row, err := q.queries.GetUnminedTransactionDetails(
		ctx, sqlitedb.GetUnminedTransactionDetailsParams{
			WalletID: walletID,
			TxHash:   hash,
		},
	)

	return sqliteDetailsRow(
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
		ctx, sqlitedb.GetMinedTransactionDetailsParams{
			WalletID:    walletID,
			TxHash:      hash,
			BlockHeight: int64(height),
			BlockHash:   blockHash,
		},
	)

	return sqliteDetailsRow(
		row.ID, row.RawTx, row.ReceivedUnix, row.BlockHeight,
		row.ConfirmedOrder, row.HeaderHash, sql.NullInt64{
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
		ctx, sqlitedb.GetTransactionDetailsByIDParams{
			WalletID: walletID,
			ID:       transactionID,
		},
	)

	return sqliteDetailsRow(
		row.ID, row.RawTx, row.ReceivedUnix, row.BlockHeight,
		row.ConfirmedOrder, row.HeaderHash, row.BlockTimestamp, row.Label,
	), err
}

// ListTransactionDetailCredits reads transaction detail credits from the
// transaction-bound backend in stable order.
func (q *queryAdapter) ListTransactionDetailCredits(ctx context.Context,
	walletID, transactionID int64) ([]sqlstore.TransactionCreditRow, error) {

	rows, err := q.queries.ListTransactionCredits(
		ctx, sqlitedb.ListTransactionCreditsParams{
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
		ctx, sqlitedb.ListTransactionDebitsParams{
			WalletID:      walletID,
			TransactionID: transactionID,
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
		ctx, sqlitedb.GetTransactionLabelParams{
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
			ID:          row.ID,
			Hash:        row.TxHash,
			RawTx:       row.RawTx,
			BlockHeight: row.BlockHeight,
		})
	}

	return result, nil
}

// sqliteIncidences converts SQLite mined rows into backend-neutral transaction
// incidences.
func sqliteIncidences(rows []sqlitedb.ListMinedTransactionsForwardRow) (
	[]sqlstore.TransactionIncidenceRow, error) {

	result := make([]sqlstore.TransactionIncidenceRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, sqlstore.TransactionIncidenceRow{
			ID:     row.ID,
			Height: int32(row.BlockHeight.Int64),
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
		ctx, sqlitedb.ListMinedTransactionsForwardParams{
			WalletID:    walletID,
			StartHeight: int64(startHeight),
			EndHeight:   int64(endHeight),
		},
	)
	if err != nil {
		return nil, err
	}

	return sqliteIncidences(rows)
}

// ListMinedTransactionsReverse reads mined transactions reverse from the
// transaction-bound backend in stable order.
func (q *queryAdapter) ListMinedTransactionsReverse(ctx context.Context,
	walletID int64, startHeight,
	endHeight int32) ([]sqlstore.TransactionIncidenceRow, error) {

	rows, err := q.queries.ListMinedTransactionsReverse(
		ctx, sqlitedb.ListMinedTransactionsReverseParams{
			WalletID:    walletID,
			StartHeight: int64(startHeight),
			EndHeight:   int64(endHeight),
		},
	)
	if err != nil {
		return nil, err
	}

	result := make([]sqlstore.TransactionIncidenceRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, sqlstore.TransactionIncidenceRow{
			ID:     row.ID,
			Height: int32(row.BlockHeight.Int64),
		})
	}

	return result, nil
}

// ListUnspentCredits reads unspent credits from the transaction-bound backend
// in stable order.
func (q *queryAdapter) ListUnspentCredits(ctx context.Context, walletID,
	nowUnix int64) ([]sqlstore.CreditRow, error) {

	rows, err := q.queries.ListUnspentCredits(
		ctx, sqlitedb.ListUnspentCreditsParams{
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
			BlockHeight:    row.BlockHeight,
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
		ctx, sqlitedb.GetMinedTransactionIDParams{
			WalletID:    walletID,
			TxHash:      hash,
			BlockHeight: int64(height),
			BlockHash:   blockHash,
		},
	)
}

// GetUnminedPreviousPkScript reads unmined previous pk script from the
// transaction-bound backend.
func (q *queryAdapter) GetUnminedPreviousPkScript(ctx context.Context,
	walletID int64, hash []byte, index uint32) ([]byte, error) {

	return q.queries.GetUnminedPreviousPkScript(
		ctx, sqlitedb.GetUnminedPreviousPkScriptParams{
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
		ctx, sqlitedb.GetMinedPreviousPkScriptParams{
			WalletID:     walletID,
			SpendingTxID: transactionID,
			InputIndex:   int64(inputIndex),
		},
	)
}

// NextBlockTransactionOrder returns next block transaction order from the
// transaction-bound backend.
func (q *queryAdapter) NextBlockTransactionOrder(ctx context.Context,
	walletID int64, height int32) (int64, error) {

	return q.queries.NextBlockTransactionOrder(
		ctx, sqlitedb.NextBlockTransactionOrderParams{
			WalletID:    walletID,
			BlockHeight: sql.NullInt64{Int64: int64(height), Valid: true},
		},
	)
}

// InsertTransaction records transaction through the transaction-bound backend.
func (q *queryAdapter) InsertTransaction(ctx context.Context,
	params sqlstore.InsertTransactionParams) (int64, error) {

	return q.queries.InsertTransaction(ctx, sqlitedb.InsertTransactionParams{
		WalletID:       params.WalletID,
		TxHash:         params.Hash,
		RawTx:          params.RawTx,
		ReceivedUnix:   params.Received,
		BlockHeight:    params.BlockHeight,
		ConfirmedOrder: params.ConfirmedOrder,
		IsCoinbase:     params.IsCoinbase,
	})
}

// PromoteUnminedTransaction promotes unmined transaction in the
// transaction-bound backend.
func (q *queryAdapter) PromoteUnminedTransaction(ctx context.Context,
	walletID int64, hash []byte, height int32, order int64) (int64, error) {

	return q.queries.PromoteUnminedTransaction(
		ctx, sqlitedb.PromoteUnminedTransactionParams{
			BlockHeight: sql.NullInt64{Int64: int64(height), Valid: true},
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
		ctx, sqlitedb.InsertTransactionInputParams{
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
		ctx, sqlitedb.ListUnminedSpendersParams{
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
		ctx, sqlitedb.GetActiveCreditIDParams{
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
		ctx, sqlitedb.RecordCreditSpendParams{
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
		ctx, sqlitedb.DeleteOutputLeaseAnyOwnerParams{
			WalletID:    walletID,
			TxHash:      hash,
			OutputIndex: int64(index),
		},
	)
}

// GetCreditID reads credit id from the transaction-bound backend.
func (q *queryAdapter) GetCreditID(ctx context.Context, walletID,
	transactionID int64, index uint32) (int64, error) {

	row, err := q.queries.GetCredit(ctx, sqlitedb.GetCreditParams{
		WalletID:      walletID,
		TransactionID: transactionID,
		OutputIndex:   int64(index),
	})

	return row.ID, err
}

// InsertCredit records credit through the transaction-bound backend.
func (q *queryAdapter) InsertCredit(ctx context.Context, walletID,
	transactionID int64, index uint32, amount int64, pkScript []byte,
	change bool) (int64, error) {

	return q.queries.InsertCredit(ctx, sqlitedb.InsertCreditParams{
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
		ctx, sqlitedb.PutTransactionLabelParams{
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

	known, err := q.queries.IsKnownOutput(ctx, sqlitedb.IsKnownOutputParams{
		WalletID:    walletID,
		TxHash:      hash,
		OutputIndex: int64(index),
	})

	return known != 0, err
}

// AcquireOutputLease acquires output lease in the transaction-bound backend.
func (q *queryAdapter) AcquireOutputLease(ctx context.Context, walletID int64,
	hash []byte, index uint32, lockID []byte, expiresUnix,
	nowUnix int64) (int64, error) {

	return q.queries.AcquireOutputLease(
		ctx, sqlitedb.AcquireOutputLeaseParams{
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
		ctx, sqlitedb.GetOutputLeaseParams{
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
		ctx, sqlitedb.DeleteOutputLeaseParams{
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
		ctx, sqlitedb.DeleteExpiredOutputLeasesParams{
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
		ctx, sqlitedb.ListActiveOutputLeasesParams{
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
