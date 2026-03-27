package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// ReleaseOutput atomically releases a lease when the caller provides the
// active lock ID.
//
// The ownership check and lease deletion run in one transaction so callers
// cannot unlock a UTXO using stale state from a separate read.
func (s *PostgresStore) ReleaseOutput(ctx context.Context,
	params ReleaseOutputParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		return releaseOutputWithOps(
			ctx, params, &pgReleaseOutputOps{qtx: qtx},
		)
	})
}

// pgReleaseOutputOps adapts postgres sqlc queries to the shared ReleaseOutput
// workflow.
type pgReleaseOutputOps struct {
	qtx *sqlcpg.Queries
}

var _ releaseOutputOps = (*pgReleaseOutputOps)(nil)

// lookupUtxoID resolves the wallet-owned outpoint to its stable postgres UTXO
// row ID.
func (o *pgReleaseOutputOps) lookupUtxoID(ctx context.Context,
	params ReleaseOutputParams) (int64, error) {

	outputIndex, err := uint32ToInt32(params.OutPoint.Index)
	if err != nil {
		return 0, err
	}

	utxoID, err := o.qtx.GetUtxoIDByOutpoint(
		ctx, sqlcpg.GetUtxoIDByOutpointParams{
			WalletID:    int64(params.WalletID),
			TxHash:      params.OutPoint.Hash[:],
			OutputIndex: outputIndex,
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, errReleaseOutputUtxoNotFound
		}

		return 0, fmt.Errorf("lookup utxo row: %w", err)
	}

	return utxoID, nil
}

// release attempts to delete the postgres lease row for the provided UTXO ID
// and lock ID.
func (o *pgReleaseOutputOps) release(ctx context.Context, walletID uint32,
	utxoID int64, lockID [32]byte) (int64, error) {

	rows, err := o.qtx.ReleaseUtxoLease(
		ctx, sqlcpg.ReleaseUtxoLeaseParams{
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

// activeLockID returns the currently active postgres lease lock ID for the
// provided UTXO ID.
func (o *pgReleaseOutputOps) activeLockID(ctx context.Context, walletID uint32,
	utxoID int64, nowUTC time.Time) ([]byte, error) {

	activeLockID, err := o.qtx.GetActiveUtxoLeaseLockID(
		ctx, sqlcpg.GetActiveUtxoLeaseLockIDParams{
			WalletID: int64(walletID),
			UtxoID:   utxoID,
			NowUtc:   nowUTC,
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errReleaseOutputNoActiveLease
		}

		return nil, fmt.Errorf("lookup active lease row: %w", err)
	}

	return activeLockID, nil
}
