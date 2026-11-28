package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
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

// leaseOutputOps adapts sqlite sqlc queries to the shared LeaseOutput
// workflow.
type leaseOutputOps struct {
	qtx *sqlc.Queries
}

var _ db.LeaseOutputOps = (*leaseOutputOps)(nil)

// Acquire attempts to write or renew one sqlite lease row for the requested
// outpoint.
func (o *leaseOutputOps) Acquire(ctx context.Context,
	params db.LeaseOutputParams, nowUTC time.Time,
	expiresAt time.Time) (time.Time, error) {

	expiration, err := o.qtx.AcquireUtxoLease(
		ctx, sqlc.AcquireUtxoLeaseParams{
			WalletID: int64(params.WalletID),
			LockID:   params.ID[:],
			ExpiresAt: sql.NullTime{
				Time:  expiresAt,
				Valid: !expiresAt.IsZero(),
			},
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

	// A NULL expiration scans as the zero time.
	return expiration.Time, nil
}

// deleteSpentLeases deletes the leases on outputs spent by txHash if that
// transaction is confirmed.
func deleteSpentLeases(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, txHash chainhash.Hash) error {

	_, err := qtx.DeleteUtxoLeasesSpentByConfirmedTx(
		ctx, sqlc.DeleteUtxoLeasesSpentByConfirmedTxParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		return fmt.Errorf("delete spent utxo leases: %w", err)
	}

	return nil
}

// HasUtxo reports whether the requested outpoint still exists as a current
// wallet-owned UTXO.
func (o *leaseOutputOps) HasUtxo(ctx context.Context,
	params db.LeaseOutputParams) (bool, error) {

	_, err := o.qtx.GetUtxoIDByOutpoint(
		ctx, sqlc.GetUtxoIDByOutpointParams{
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

// leaseNow wraps the lease-expiry reference time. sqlc types it as nullable
// because queries compare it with the nullable utxo_leases.expires_at column.
func leaseNow(nowUTC time.Time) sql.NullTime {
	return sql.NullTime{Time: nowUTC, Valid: true}
}
