package pg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlstore"
	pgdb "github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// InsertFundingPlan reserves a funding plan through the transaction-bound
// backend and returns its surrogate id.
func (q *queryAdapter) InsertFundingPlan(ctx context.Context,
	params sqlstore.InsertFundingPlanParams) (int64, error) {

	return q.queries.InsertFundingPlan(ctx, pgdb.InsertFundingPlanParams{
		WalletID:      params.WalletID,
		ReservationID: params.ReservationID,
		Purpose:       params.Purpose,
		CreatedAt:     params.CreatedAt,
		ExpiresAt:     params.ExpiresAt,
	})
}

// GetFundingPlan reads one funding plan by its reservation id from the
// transaction-bound backend.
func (q *queryAdapter) GetFundingPlan(ctx context.Context, walletID int64,
	reservationID []byte) (sqlstore.FundingPlanRow, error) {

	row, err := q.queries.GetFundingPlan(ctx, pgdb.GetFundingPlanParams{
		WalletID:      walletID,
		ReservationID: reservationID,
	})
	if err != nil {
		return sqlstore.FundingPlanRow{}, err
	}

	return sqlstore.FundingPlanRow{
		ID:            row.ID,
		ReservationID: row.ReservationID,
		Purpose:       row.Purpose,
		Status:        row.Status,
		CreatedAt:     row.CreatedAt,
		ExpiresAt:     row.ExpiresAt,
		CommittedTxID: row.CommittedTxID,
	}, nil
}

// ConsumeFundingPlan transitions a reserved plan to consumed through the
// transaction-bound backend.
func (q *queryAdapter) ConsumeFundingPlan(ctx context.Context, walletID int64,
	reservationID []byte, committedTxID sql.NullInt64) (int64, error) {

	return q.queries.ConsumeFundingPlan(
		ctx, pgdb.ConsumeFundingPlanParams{
			CommittedTxID: committedTxID,
			WalletID:      walletID,
			ReservationID: reservationID,
		},
	)
}

// ReleaseFundingPlan transitions a reserved plan to released through the
// transaction-bound backend.
func (q *queryAdapter) ReleaseFundingPlan(ctx context.Context, walletID int64,
	reservationID []byte) (int64, error) {

	return q.queries.ReleaseFundingPlan(
		ctx, pgdb.ReleaseFundingPlanParams{
			WalletID:      walletID,
			ReservationID: reservationID,
		},
	)
}

// ExpireFundingPlan transitions a reserved plan to expired through the
// transaction-bound backend.
func (q *queryAdapter) ExpireFundingPlan(ctx context.Context, walletID int64,
	reservationID []byte) (int64, error) {

	return q.queries.ExpireFundingPlan(
		ctx, pgdb.ExpireFundingPlanParams{
			WalletID:      walletID,
			ReservationID: reservationID,
		},
	)
}

// AcquireFundingPlanLease adds one plan-owned lease under a reserved plan
// through the transaction-bound backend.
func (q *queryAdapter) AcquireFundingPlanLease(ctx context.Context,
	params sqlstore.AcquireFundingPlanLeaseParams) (int64, error) {

	return q.queries.AcquireFundingPlanLease(
		ctx, pgdb.AcquireFundingPlanLeaseParams{
			TxHash:        params.TxHash,
			OutputIndex:   int64(params.OutputIndex),
			ExpiresUnix:   params.ExpiresUnix,
			WalletID:      params.WalletID,
			ReservationID: params.ReservationID,
		},
	)
}

// DeleteFundingPlanLeases removes only the leases owned by one plan through the
// transaction-bound backend.
func (q *queryAdapter) DeleteFundingPlanLeases(ctx context.Context,
	walletID int64, reservationID []byte) (int64, error) {

	return q.queries.DeleteFundingPlanLeases(
		ctx, pgdb.DeleteFundingPlanLeasesParams{
			WalletID:      walletID,
			ReservationID: reservationID,
		},
	)
}

// CollectExpiredFundingPlans deletes terminal plans past their retention
// deadline that own no leases through the transaction-bound backend.
func (q *queryAdapter) CollectExpiredFundingPlans(ctx context.Context, walletID,
	nowUnix int64) (int64, error) {

	return q.queries.CollectExpiredFundingPlans(
		ctx, pgdb.CollectExpiredFundingPlansParams{
			WalletID: walletID,
			NowUnix:  nowUnix,
		},
	)
}

// AdvanceBranchIndex advances the account's next index for one branch through
// the transaction-bound backend, dispatching to the external or internal branch
// column. It returns sql.ErrNoRows when the account is missing or the expected
// index no longer matches.
func (q *queryAdapter) AdvanceBranchIndex(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope, account, branch, expected,
	next uint32) (int64, error) {

	scopeID, err := q.pgScopeID(ctx, walletID, scope)
	if err != nil {
		return 0, err
	}

	switch branch {
	case waddrmgr.ExternalBranch:
		return q.queries.AdvanceExternalBranchIndex(
			ctx, pgdb.AdvanceExternalBranchIndexParams{
				NewIndex:      int64(next),
				ScopeID:       scopeID,
				AccountNumber: int64(account),
				ExpectedIndex: int64(expected),
			},
		)

	case waddrmgr.InternalBranch:
		return q.queries.AdvanceInternalBranchIndex(
			ctx, pgdb.AdvanceInternalBranchIndexParams{
				NewIndex:      int64(next),
				ScopeID:       scopeID,
				AccountNumber: int64(account),
				ExpectedIndex: int64(expected),
			},
		)

	default:
		return 0, fmt.Errorf(
			"unsupported branch %d for index allocation", branch,
		)
	}
}
