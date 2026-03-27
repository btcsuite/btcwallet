package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// LeaseOutput atomically acquires or renews a lease for one current UTXO.
//
// The lease lookup and acquisition run in one transaction so competing calls
// cannot observe a partially-written lease. Expiration timestamps are
// normalized to UTC before insert.
func (s *PostgresStore) LeaseOutput(ctx context.Context,
	params LeaseOutputParams) (*LeasedOutput, error) {

	var lease *LeasedOutput

	err := s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		acquiredLease, err := leaseOutputWithOps(
			ctx, params, &pgLeaseOutputOps{qtx: qtx},
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

// pgLeaseOutputOps adapts postgres sqlc queries to the shared LeaseOutput
// workflow.
type pgLeaseOutputOps struct {
	qtx *sqlcpg.Queries
}

var _ leaseOutputOps = (*pgLeaseOutputOps)(nil)

// acquire attempts to write or renew one postgres lease row for the requested
// outpoint.
func (o *pgLeaseOutputOps) acquire(ctx context.Context,
	params LeaseOutputParams, nowUTC time.Time,
	expiresAt time.Time) (time.Time, error) {

	outputIndex, err := uint32ToInt32(params.OutPoint.Index)
	if err != nil {
		return time.Time{}, fmt.Errorf("convert output index: %w", err)
	}

	expiration, err := o.qtx.AcquireUtxoLease(
		ctx, sqlcpg.AcquireUtxoLeaseParams{
			WalletID:    int64(params.WalletID),
			LockID:      params.ID[:],
			ExpiresAt:   expiresAt,
			TxHash:      params.OutPoint.Hash[:],
			OutputIndex: outputIndex,
			NowUtc:      nowUTC,
		},
	)
	if err == nil {
		return expiration, nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, errLeaseOutputNoRow
	}

	return time.Time{}, fmt.Errorf("acquire lease row: %w", err)
}

// hasUtxo reports whether the requested outpoint still exists as a current
// wallet-owned UTXO.
func (o *pgLeaseOutputOps) hasUtxo(ctx context.Context,
	params LeaseOutputParams) (bool, error) {

	outputIndex, err := uint32ToInt32(params.OutPoint.Index)
	if err != nil {
		return false, fmt.Errorf("convert output index: %w", err)
	}

	_, err = o.qtx.GetUtxoIDByOutpoint(
		ctx, sqlcpg.GetUtxoIDByOutpointParams{
			WalletID:    int64(params.WalletID),
			TxHash:      params.OutPoint.Hash[:],
			OutputIndex: outputIndex,
		},
	)
	if err == nil {
		return true, nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	return false, fmt.Errorf("lookup utxo row: %w", err)
}
