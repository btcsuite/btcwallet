package sqlite

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlstore"
	sqlitedb "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// EnsureRuntimeState creates the wallet's zeroed runtime-state row through the
// transaction-bound backend when it does not exist yet.
func (q *queryAdapter) EnsureRuntimeState(ctx context.Context,
	walletID int64) error {

	return q.queries.EnsureRuntimeState(ctx, walletID)
}

// GetRuntimeState reads the wallet's runtime-state versions from the
// transaction-bound backend.
func (q *queryAdapter) GetRuntimeState(ctx context.Context,
	walletID int64) (sqlstore.RuntimeStateRow, error) {

	row, err := q.queries.GetRuntimeState(ctx, walletID)
	if err != nil {
		return sqlstore.RuntimeStateRow{}, err
	}

	return sqlstore.RuntimeStateRow{
		StateVersion:  row.StateVersion,
		HistoryEpoch:  row.HistoryEpoch,
		SecretVersion: row.SecretVersion,
	}, nil
}

// BumpStateVersion increments the wallet state version in the transaction-bound
// backend only when it still equals expected.
func (q *queryAdapter) BumpStateVersion(ctx context.Context, walletID,
	expected int64) (int64, error) {

	return q.queries.BumpStateVersion(ctx, sqlitedb.BumpStateVersionParams{
		WalletID:        walletID,
		ExpectedVersion: expected,
	})
}

// BumpHistoryEpoch increments the wallet history epoch in the transaction-bound
// backend only when it still equals expected.
func (q *queryAdapter) BumpHistoryEpoch(ctx context.Context, walletID,
	expected int64) (int64, error) {

	return q.queries.BumpHistoryEpoch(ctx, sqlitedb.BumpHistoryEpochParams{
		WalletID:        walletID,
		ExpectedVersion: expected,
	})
}

// BumpSecretVersion increments the wallet secret version in the
// transaction-bound backend only when it still equals expected.
func (q *queryAdapter) BumpSecretVersion(ctx context.Context, walletID,
	expected int64) (int64, error) {

	return q.queries.BumpSecretVersion(ctx, sqlitedb.BumpSecretVersionParams{
		WalletID:        walletID,
		ExpectedVersion: expected,
	})
}

// GetOperation reads one operation-journal row by its key from the
// transaction-bound backend.
func (q *queryAdapter) GetOperation(ctx context.Context, walletID int64,
	domain string, operationID []byte) (sqlstore.OperationRow, error) {

	row, err := q.queries.GetOperation(ctx, sqlitedb.GetOperationParams{
		WalletID:    walletID,
		Domain:      domain,
		OperationID: operationID,
	})
	if err != nil {
		return sqlstore.OperationRow{}, err
	}

	return sqlstore.OperationRow{
		RequestHash:  row.RequestHash,
		HistoryEpoch: row.HistoryEpoch,
		Status:       row.Status,
		ResultRef:    row.ResultRef,
		ResultHash:   row.ResultHash,
		CreatedAt:    row.CreatedAt,
		ExpiresAt:    row.ExpiresAt,
	}, nil
}

// InsertCommittedOperation records a committed journal row through the
// transaction-bound backend.
func (q *queryAdapter) InsertCommittedOperation(ctx context.Context,
	params sqlstore.InsertCommittedOperationParams) error {

	return q.queries.InsertCommittedOperation(
		ctx, sqlitedb.InsertCommittedOperationParams{
			WalletID:     params.WalletID,
			Domain:       params.Domain,
			OperationID:  params.OperationID,
			RequestHash:  params.RequestHash,
			HistoryEpoch: params.HistoryEpoch,
			ResultRef:    params.ResultRef,
			ResultHash:   params.ResultHash,
			CreatedAt:    params.CreatedAt,
			ExpiresAt:    params.ExpiresAt,
		},
	)
}

// InsertOperationResultFact records one ordered result fact through the
// transaction-bound backend.
func (q *queryAdapter) InsertOperationResultFact(ctx context.Context,
	params sqlstore.InsertOperationResultFactParams) error {

	return q.queries.InsertOperationResultFact(
		ctx, sqlitedb.InsertOperationResultFactParams{
			WalletID:    params.WalletID,
			Domain:      params.Domain,
			OperationID: params.OperationID,
			Ordinal:     params.Ordinal,
			FactType:    params.FactType,
			FactKey:     params.FactKey,
			FactPayload: params.FactPayload,
		},
	)
}

// ListOperationResultFacts reads one operation's result facts from the
// transaction-bound backend in ordinal order.
func (q *queryAdapter) ListOperationResultFacts(ctx context.Context,
	walletID int64, domain string,
	operationID []byte) ([]sqlstore.OperationResultFactRow, error) {

	rows, err := q.queries.ListOperationResultFacts(
		ctx, sqlitedb.ListOperationResultFactsParams{
			WalletID:    walletID,
			Domain:      domain,
			OperationID: operationID,
		},
	)
	if err != nil {
		return nil, err
	}

	facts := make([]sqlstore.OperationResultFactRow, 0, len(rows))
	for _, row := range rows {
		facts = append(facts, sqlstore.OperationResultFactRow{
			Ordinal:     row.Ordinal,
			FactType:    row.FactType,
			FactKey:     row.FactKey,
			FactPayload: row.FactPayload,
		})
	}

	return facts, nil
}

// CollectExpiredOperations deletes terminal journal rows past their retention
// deadline through the transaction-bound backend, cascading their result facts.
func (q *queryAdapter) CollectExpiredOperations(ctx context.Context, walletID,
	nowUnix int64) (int64, error) {

	return q.queries.CollectExpiredOperations(
		ctx, sqlitedb.CollectExpiredOperationsParams{
			WalletID: walletID,
			NowUnix:  nowUnix,
		},
	)
}
