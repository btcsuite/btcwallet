// Package pg implements the manager transaction store with PostgreSQL.
package pg

import (
	"context"
	"database/sql"

	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlstore"
	pgdb "github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// Store is the PostgreSQL manager transaction store.
type Store struct {
	*sqlstore.Store
}

// NewStore creates a PostgreSQL manager store for one wallet.
func NewStore(conn *sql.DB, walletID int64) *Store {
	return &Store{
		Store: sqlstore.New(
			conn, walletID, func(tx *sql.Tx) sqlstore.Queries {
				return &queryAdapter{queries: pgdb.New(tx)}
			},
		),
	}
}

type queryAdapter struct {
	queries *pgdb.Queries
}

func (q *queryAdapter) PutBlock(ctx context.Context,
	row sqlstore.BlockRow) error {

	return q.queries.PutBlock(ctx, pgdb.PutBlockParams{
		BlockHeight:    row.Height,
		HeaderHash:     row.Hash,
		BlockTimestamp: row.Timestamp,
	})
}

func (q *queryAdapter) GetBlockByHeight(ctx context.Context,
	height int32) (sqlstore.BlockRow, error) {

	row, err := q.queries.GetBlockByHeight(ctx, height)
	if err != nil {
		return sqlstore.BlockRow{}, err
	}

	return sqlstore.BlockRow{
		Height:    row.BlockHeight,
		Hash:      row.HeaderHash,
		Timestamp: row.BlockTimestamp,
	}, nil
}

func (q *queryAdapter) GetWalletStartBlock(ctx context.Context,
	walletID int64) (sqlstore.BlockRow, error) {

	row, err := q.queries.GetWalletStartBlock(ctx, walletID)
	if err != nil {
		return sqlstore.BlockRow{}, err
	}

	return sqlstore.BlockRow{
		Height:    row.BlockHeight,
		Hash:      row.HeaderHash,
		Timestamp: row.BlockTimestamp,
	}, nil
}

func (q *queryAdapter) SetWalletSyncedTo(ctx context.Context, walletID int64,
	height int32) (int64, error) {

	return q.queries.SetWalletSyncedTo(
		ctx, pgdb.SetWalletSyncedToParams{
			SyncedBlockHeight: height,
			WalletID:          walletID,
		},
	)
}

func (q *queryAdapter) ListMinedTransactionsFromHeight(
	ctx context.Context, walletID int64,
	height int32) ([]sqlstore.MinedTransactionRow, error) {

	rows, err := q.queries.ListMinedTransactionsFromHeight(
		ctx, pgdb.ListMinedTransactionsFromHeightParams{
			WalletID: walletID,
			Height:   height,
		},
	)
	if err != nil {
		return nil, err
	}

	transactions := make([]sqlstore.MinedTransactionRow, 0, len(rows))
	for _, row := range rows {
		transactions = append(transactions, sqlstore.MinedTransactionRow{
			ID:         row.ID,
			Hash:       row.TxHash,
			IsCoinbase: row.IsCoinbase,
		})
	}

	return transactions, nil
}

func (q *queryAdapter) GetUnminedTransactionID(ctx context.Context,
	walletID int64, hash []byte) (int64, error) {

	row, err := q.queries.GetUnminedTransactionByHash(
		ctx, pgdb.GetUnminedTransactionByHashParams{
			WalletID: walletID,
			TxHash:   hash,
		},
	)

	return row.ID, err
}

func (q *queryAdapter) DeleteCreditSpendsBySpendingTx(
	ctx context.Context, walletID, transactionID int64) (int64, error) {

	return q.queries.DeleteCreditSpendsBySpendingTx(
		ctx, pgdb.DeleteCreditSpendsBySpendingTxParams{
			WalletID:     walletID,
			SpendingTxID: transactionID,
		},
	)
}

func (q *queryAdapter) DetachMinedTransaction(ctx context.Context, walletID,
	transactionID int64) (int64, error) {

	return q.queries.DetachMinedTransaction(
		ctx, pgdb.DetachMinedTransactionParams{
			WalletID: walletID,
			ID:       transactionID,
		},
	)
}

func (q *queryAdapter) ListTransactionCreditIDs(ctx context.Context, walletID,
	transactionID int64) ([]int64, error) {

	rows, err := q.queries.ListTransactionCredits(
		ctx, pgdb.ListTransactionCreditsParams{
			WalletID:      walletID,
			TransactionID: transactionID,
		},
	)
	if err != nil {
		return nil, err
	}

	creditIDs := make([]int64, 0, len(rows))
	for _, row := range rows {
		creditIDs = append(creditIDs, row.ID)
	}

	return creditIDs, nil
}

func (q *queryAdapter) SetActiveCreditIncidence(ctx context.Context, walletID,
	creditID int64) error {

	return q.queries.SetActiveCreditIncidence(
		ctx, pgdb.SetActiveCreditIncidenceParams{
			WalletID: walletID,
			ID:       creditID,
		},
	)
}

func (q *queryAdapter) ListUnminedSpendersByPrevHash(
	ctx context.Context, walletID int64,
	hash []byte) ([]sqlstore.UnminedSpenderRow, error) {

	rows, err := q.queries.ListUnminedSpendersByPrevHash(
		ctx, pgdb.ListUnminedSpendersByPrevHashParams{
			WalletID:   walletID,
			PrevTxHash: hash,
		},
	)
	if err != nil {
		return nil, err
	}

	spenders := make([]sqlstore.UnminedSpenderRow, 0, len(rows))
	for _, row := range rows {
		spenders = append(spenders, sqlstore.UnminedSpenderRow{
			ID:   row.ID,
			Hash: row.TxHash,
		})
	}

	return spenders, nil
}

func (q *queryAdapter) DeleteTransaction(ctx context.Context, walletID,
	transactionID int64) (int64, error) {

	return q.queries.DeleteTransactionByID(
		ctx, pgdb.DeleteTransactionByIDParams{
			WalletID: walletID,
			ID:       transactionID,
		},
	)
}

var _ sqlstore.Queries = (*queryAdapter)(nil)
