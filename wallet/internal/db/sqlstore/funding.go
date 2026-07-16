package sqlstore

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
)

// Funding-plan status values. A plan starts reserved and moves exactly once to
// one of the terminal states. They match the status set the funding_plans CHECK
// constraint and the transition queries enforce.
const (
	// FundingPlanReserved is the initial state: the plan owns its leases and
	// may still be consumed, released, or expired.
	FundingPlanReserved = "reserved"

	// FundingPlanConsumed is a terminal state: the plan funded a committed
	// transaction and its leases have been removed.
	FundingPlanConsumed = "consumed"

	// FundingPlanReleased is a terminal state: the reservation was abandoned
	// and its leases have been removed.
	FundingPlanReleased = "released"

	// FundingPlanExpired is a terminal state: the reservation timed out and
	// its leases have been reclaimed.
	FundingPlanExpired = "expired"
)

// FundingPlanRow is the backend-neutral funding-plan row returned by a lookup.
// A null committed transaction is left invalid until the plan is consumed.
type FundingPlanRow struct {
	ID            int64
	ReservationID []byte
	Purpose       string
	Status        string
	CreatedAt     int64
	ExpiresAt     int64
	CommittedTxID sql.NullInt64
}

// InsertFundingPlanParams contains one reserved funding plan to persist.
type InsertFundingPlanParams struct {
	WalletID      int64
	ReservationID []byte
	Purpose       string
	CreatedAt     int64
	ExpiresAt     int64
}

// AcquireFundingPlanLeaseParams contains one plan-owned lease to persist under a
// reserved plan.
type AcquireFundingPlanLeaseParams struct {
	WalletID      int64
	ReservationID []byte
	TxHash        []byte
	OutputIndex   uint32
	ExpiresUnix   int64
}

// FundingPlan describes a reservation to persist. It groups the internally
// owned leases added under the same reservation id so they can be consumed,
// released, or expired together, while utxo_leases remains the only durable
// outpoint-exclusion relation.
type FundingPlan struct {
	// ReservationID is the 32-byte owner token shared by the plan and its
	// leases; a plan's leases reuse it as their durable lock id.
	ReservationID []byte

	// Purpose records why the reservation exists, for example ordinary
	// construction or a persistent PSBT intent.
	Purpose string

	// CreatedAt is when the plan was reserved.
	CreatedAt time.Time

	// ExpiresAt is the deadline after which the plan may be expired and its
	// leases reclaimed.
	ExpiresAt time.Time
}

// FundingPlanState is the durable state of one funding plan.
type FundingPlanState struct {
	// ID is the plan's surrogate identity.
	ID int64

	// ReservationID is the plan's 32-byte owner token.
	ReservationID []byte

	// Purpose records why the reservation exists.
	Purpose string

	// Status is the plan's lifecycle state, one of the FundingPlan status
	// constants.
	Status string

	// CreatedAt is when the plan was reserved.
	CreatedAt time.Time

	// ExpiresAt is the plan's retention and expiry deadline.
	ExpiresAt time.Time

	// CommittedTxID is the transaction a consumed plan funded, or zero when
	// the plan names no committed transaction.
	CommittedTxID int64
}

// ReserveFundingPlan reserves a new funding plan and returns its surrogate id.
// The plan starts in the reserved state and groups the leases later added under
// its reservation id.
func (r *RuntimeStore) ReserveFundingPlan(plan FundingPlan) (int64, error) {
	id, err := r.queries.InsertFundingPlan(r.ctx, InsertFundingPlanParams{
		WalletID:      r.walletID,
		ReservationID: plan.ReservationID,
		Purpose:       plan.Purpose,
		CreatedAt:     plan.CreatedAt.Unix(),
		ExpiresAt:     plan.ExpiresAt.Unix(),
	})
	if err != nil {
		return 0, fmt.Errorf("reserve funding plan: %w", err)
	}

	return id, nil
}

// AddFundingPlanLease adds one plan-owned lease under a reserved plan. The lease
// reuses the plan's reservation id as its durable lock id. It returns
// ErrReservationConflict when the plan is missing or no longer reserved.
func (r *RuntimeStore) AddFundingPlanLease(reservationID, txHash []byte,
	outputIndex uint32, expires time.Time) error {

	rows, err := r.queries.AcquireFundingPlanLease(
		r.ctx, AcquireFundingPlanLeaseParams{
			WalletID:      r.walletID,
			ReservationID: reservationID,
			TxHash:        txHash,
			OutputIndex:   outputIndex,
			ExpiresUnix:   expires.Unix(),
		},
	)
	if err != nil {
		return fmt.Errorf("acquire funding plan lease: %w", err)
	}

	if rows != 1 {
		return fmt.Errorf("reservation %x: %w", reservationID,
			walletstore.ErrReservationConflict)
	}

	return nil
}

// FundingPlan reads a plan by its reservation id. The boolean is false when no
// plan exists for the reservation.
func (r *RuntimeStore) FundingPlan(reservationID []byte) (FundingPlanState,
	bool, error) {

	row, err := r.queries.GetFundingPlan(r.ctx, r.walletID, reservationID)
	if errors.Is(err, sql.ErrNoRows) {
		return FundingPlanState{}, false, nil
	}

	if err != nil {
		return FundingPlanState{}, false, fmt.Errorf(
			"get funding plan: %w", err,
		)
	}

	state := FundingPlanState{
		ID:            row.ID,
		ReservationID: row.ReservationID,
		Purpose:       row.Purpose,
		Status:        row.Status,
		CreatedAt:     time.Unix(row.CreatedAt, 0),
		ExpiresAt:     time.Unix(row.ExpiresAt, 0),
	}
	if row.CommittedTxID.Valid {
		state.CommittedTxID = row.CommittedTxID.Int64
	}

	return state, true, nil
}

// ConsumeFundingPlan transitions a reserved plan to consumed, records the
// transaction it funded, and deletes the plan's own leases; external leases are
// untouched. A committedTxID of zero records no committed transaction. It
// returns ErrReservationConflict when the plan is missing or no longer
// reserved.
func (r *RuntimeStore) ConsumeFundingPlan(reservationID []byte,
	committedTxID int64) error {

	committed := sql.NullInt64{}
	if committedTxID > 0 {
		committed = sql.NullInt64{Int64: committedTxID, Valid: true}
	}

	rows, err := r.queries.ConsumeFundingPlan(
		r.ctx, r.walletID, reservationID, committed,
	)
	if err != nil {
		return fmt.Errorf("consume funding plan: %w", err)
	}

	return r.finishTransition("consume", reservationID, rows)
}

// ReleaseFundingPlan transitions a reserved plan to released and deletes the
// plan's own leases; external leases are untouched. It returns
// ErrReservationConflict when the plan is missing or no longer reserved.
func (r *RuntimeStore) ReleaseFundingPlan(reservationID []byte) error {
	rows, err := r.queries.ReleaseFundingPlan(r.ctx, r.walletID, reservationID)
	if err != nil {
		return fmt.Errorf("release funding plan: %w", err)
	}

	return r.finishTransition("release", reservationID, rows)
}

// ExpireFundingPlan transitions a reserved plan to expired and deletes the
// plan's own leases; external leases are untouched. It returns
// ErrReservationConflict when the plan is missing or no longer reserved.
func (r *RuntimeStore) ExpireFundingPlan(reservationID []byte) error {
	rows, err := r.queries.ExpireFundingPlan(r.ctx, r.walletID, reservationID)
	if err != nil {
		return fmt.Errorf("expire funding plan: %w", err)
	}

	return r.finishTransition("expire", reservationID, rows)
}

// finishTransition converts a guarded transition's affected-row count into a
// reservation conflict and, on success, deletes the plan's own leases so a
// terminal plan owns no leases before it is later collected.
func (r *RuntimeStore) finishTransition(action string, reservationID []byte,
	rows int64) error {

	if rows != 1 {
		return fmt.Errorf("%s reservation %x: %w", action, reservationID,
			walletstore.ErrReservationConflict)
	}

	_, err := r.queries.DeleteFundingPlanLeases(
		r.ctx, r.walletID, reservationID,
	)
	if err != nil {
		return fmt.Errorf("delete %s plan leases: %w", action, err)
	}

	return nil
}

// CollectExpiredFundingPlans deletes terminal plans whose retention deadline is
// at or before now and that own no leases, returning the number of plans
// removed. A reserved plan and a terminal plan that still owns leases are never
// collected.
func (r *RuntimeStore) CollectExpiredFundingPlans(now time.Time) (int64,
	error) {

	deleted, err := r.queries.CollectExpiredFundingPlans(
		r.ctx, r.walletID, now.Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("collect expired funding plans: %w", err)
	}

	return deleted, nil
}

// AdvanceBranchIndex advances the account's next index for one branch through an
// optimistic compare-and-swap: it succeeds only while the stored next index
// still equals expected, and returns the advanced index. It returns
// ErrStaleAccountIndex when the account is missing or the index moved, so the
// caller rereads the account before preparing the allocation again.
func (r *RuntimeStore) AdvanceBranchIndex(scope waddrmgr.KeyScope, account,
	branch, expected, next uint32) (uint32, error) {

	advanced, err := r.queries.AdvanceBranchIndex(
		r.ctx, r.walletID, scope, account, branch, expected, next,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("account %d branch %d expected index %d: %w",
			account, branch, expected, walletstore.ErrStaleAccountIndex)
	}

	if err != nil {
		return 0, fmt.Errorf("advance branch index: %w", err)
	}

	return CheckedUint32(advanced, "next branch index")
}
