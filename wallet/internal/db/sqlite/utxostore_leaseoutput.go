package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"time"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// LeaseOutput atomically acquires or renews a lease for one current UTXO.
//
// The lease lookup and acquisition run in one transaction so competing calls
// cannot observe a partially-written lease. Expiration timestamps are
// normalized to UTC before Insert.
func (s *SqliteStore) LeaseOutput(ctx context.Context,
	params db.LeaseOutputParams) (*db.LeasedOutput, error) {

	var lease *db.LeasedOutput

	err := s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		acquiredLease, err := db.LeaseOutputWithOps(
			ctx, params, &sqliteLeaseOutputOps{qtx: qtx},
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

// sqliteLeaseOutputOps adapts sqlite sqlc queries to the shared LeaseOutput
// workflow.
type sqliteLeaseOutputOps struct {
	qtx *sqlcsqlite.Queries
}

var _ db.LeaseOutputOps = (*sqliteLeaseOutputOps)(nil)

// Acquire attempts to write or renew one sqlite lease row for the requested
// outpoint.
func (o *sqliteLeaseOutputOps) Acquire(ctx context.Context,
	params db.LeaseOutputParams, nowUTC time.Time,
	expiresAt time.Time) (time.Time, error) {

	expiration, err := o.qtx.AcquireUtxoLease(
		ctx, sqlcsqlite.AcquireUtxoLeaseParams{
			WalletID:    int64(params.WalletID),
			LockID:      params.ID[:],
			ExpiresAt:   expiresAt,
			TxHash:      params.OutPoint.Hash[:],
			OutputIndex: int64(params.OutPoint.Index),
			NowUtc:      nowUTC,
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, db.ErrLeaseOutputNoRow
		}

		return time.Time{}, fmt.Errorf("acquire lease row: %w", err)
	}

	return expiration, nil
}

// HasUtxo reports whether the requested outpoint still exists as a current
// wallet-owned UTXO.
func (o *sqliteLeaseOutputOps) HasUtxo(ctx context.Context,
	params db.LeaseOutputParams) (bool, error) {

	_, err := o.qtx.GetUtxoIDByOutpoint(
		ctx, sqlcsqlite.GetUtxoIDByOutpointParams{
			WalletID:    int64(params.WalletID),
			TxHash:      params.OutPoint.Hash[:],
			OutputIndex: int64(params.OutPoint.Index),
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}

		return false, fmt.Errorf("lookup utxo row: %w", err)
	}

	return true, nil
}
