package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	sqlc "github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// ReleaseOutput atomically releases a lease when the caller provides the
// active lock ID.
//
// The ownership check and lease deletion run in one transaction so callers
// cannot unlock a UTXO using stale state from a separate read.
func (s *Store) ReleaseOutput(ctx context.Context,
	params db.ReleaseOutputParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlc.Queries) error {
		return db.ReleaseOutputWithOps(
			ctx, params, &releaseOutputOps{qtx: qtx},
		)
	})
}

// releaseOutputOps adapts postgres sqlc queries to the shared ReleaseOutput
// workflow.
type releaseOutputOps struct {
	qtx *sqlc.Queries
}

var _ db.ReleaseOutputOps = (*releaseOutputOps)(nil)

// LookupUtxoID resolves the wallet-owned outpoint to its stable postgres UTXO
// row ID.
func (o *releaseOutputOps) LookupUtxoID(ctx context.Context,
	params db.ReleaseOutputParams) (int64, error) {

	outputIndex, err := db.Uint32ToInt32(params.OutPoint.Index)
	if err != nil {
		return 0, err
	}

	utxoID, err := o.qtx.GetUtxoIDByOutpoint(
		ctx, sqlc.GetUtxoIDByOutpointParams{
			WalletID:    int64(params.WalletID),
			TxHash:      params.OutPoint.Hash[:],
			OutputIndex: outputIndex,
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, db.ErrReleaseOutputUtxoNotFound
		}

		return 0, fmt.Errorf("lookup utxo row: %w", err)
	}

	return utxoID, nil
}

// Release attempts to delete the postgres lease row for the provided UTXO ID
// and lock ID.
func (o *releaseOutputOps) Release(ctx context.Context, walletID uint32,
	utxoID int64, lockID [32]byte) (int64, error) {

	rows, err := o.qtx.ReleaseUtxoLease(
		ctx, sqlc.ReleaseUtxoLeaseParams{
			WalletID: int64(walletID),
			UtxoID:   utxoID,
			LockID:   lockID[:],
		},
	)
	if err != nil {
		return 0, fmt.Errorf("release lease row: %w", err)
	}

	return rows, nil
}

// ActiveLockID returns the currently active postgres lease lock ID for the
// provided UTXO ID.
func (o *releaseOutputOps) ActiveLockID(ctx context.Context, walletID uint32,
	utxoID int64, nowUTC time.Time) ([]byte, error) {

	activeLockID, err := o.qtx.GetActiveUtxoLeaseLockID(
		ctx, sqlc.GetActiveUtxoLeaseLockIDParams{
			WalletID: int64(walletID),
			UtxoID:   utxoID,
			NowUtc:   nowUTC,
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, db.ErrReleaseOutputNoActiveLease
		}

		return nil, fmt.Errorf("lookup active lease row: %w", err)
	}

	return activeLockID, nil
}
