package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5"
)

// LeaseOutput atomically acquires or renews a lease for one current UTXO.
//
// The lease lookup and acquisition run in one transaction so competing calls
// cannot observe a partially-written lease. Expiration timestamps are
// normalized to UTC before Insert.
func (s *Store) LeaseOutput(ctx context.Context,
	params db.LeaseOutputParams) (*db.LeasedOutput, error) {

	var lease *db.LeasedOutput

	err := s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		acquiredLease, err := db.LeaseOutputWithOps(
			ctx, params, &leaseOutputOps{qtx: qtx},
		)
		if err != nil {
			return err
		}

		lease = acquiredLease

		return nil
	})
	if err != nil {
		return nil, err
	}

	return lease, nil
}

// leaseOutputOps adapts postgres sqlc queries to the shared LeaseOutput
// workflow.
type leaseOutputOps struct {
	qtx *sqlc.Queries
}

var _ db.LeaseOutputOps = (*leaseOutputOps)(nil)

// Acquire attempts to write or renew one postgres lease row for the requested
// outpoint.
func (o *leaseOutputOps) Acquire(ctx context.Context,
	params db.LeaseOutputParams, nowUTC time.Time,
	expiresAt time.Time) (time.Time, error) {

	outputIndex, err := db.Uint32ToInt32(params.OutPoint.Index)
	if err != nil {
		return time.Time{}, fmt.Errorf("convert output index: %w", err)
	}

	expiration, err := o.qtx.AcquireUtxoLease(
		ctx, sqlc.AcquireUtxoLeaseParams{
			WalletID:    int64(params.WalletID),
			LockID:      params.ID[:],
			ExpiresAt:   timestamp(expiresAt),
			TxHash:      params.OutPoint.Hash[:],
			OutputIndex: outputIndex,
			NowUtc:      timestamp(nowUTC),
		},
	)
	if err == nil {
		return expiration.Time, nil
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, db.ErrLeaseOutputNoRow
	}

	return time.Time{}, fmt.Errorf("acquire lease row: %w", err)
}

// HasUtxo reports whether the requested outpoint still exists as a current
// wallet-owned UTXO.
func (o *leaseOutputOps) HasUtxo(ctx context.Context,
	params db.LeaseOutputParams) (bool, error) {

	outputIndex, err := db.Uint32ToInt32(params.OutPoint.Index)
	if err != nil {
		return false, fmt.Errorf("convert output index: %w", err)
	}

	_, err = o.qtx.GetUtxoIDByOutpoint(
		ctx, sqlc.GetUtxoIDByOutpointParams{
			WalletID:    int64(params.WalletID),
			TxHash:      params.OutPoint.Hash[:],
			OutputIndex: outputIndex,
		},
	)
	if err == nil {
		return true, nil
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}

	return false, fmt.Errorf("lookup utxo row: %w", err)
}
