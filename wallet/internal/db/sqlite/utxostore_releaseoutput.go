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

// ReleaseOutput atomically releases a lease when the caller provides the
// active lock ID.
//
// The ownership check and lease deletion run in one transaction so callers
// cannot unlock a UTXO using stale state from a separate read.
func (s *SqliteStore) ReleaseOutput(ctx context.Context,
	params db.ReleaseOutputParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		return db.ReleaseOutputWithOps(
			ctx, params, &sqliteReleaseOutputOps{qtx: qtx},
		)
	})
}

// sqliteReleaseOutputOps adapts sqlite sqlc queries to the shared
// ReleaseOutput workflow.
type sqliteReleaseOutputOps struct {
	qtx *sqlcsqlite.Queries
}

var _ db.ReleaseOutputOps = (*sqliteReleaseOutputOps)(nil)

// LookupUtxoID resolves the wallet-owned outpoint to its stable sqlite UTXO row
// ID.
func (o *sqliteReleaseOutputOps) LookupUtxoID(ctx context.Context,
	params db.ReleaseOutputParams) (int64, error) {

	utxoID, err := o.qtx.GetUtxoIDByOutpoint(
		ctx, sqlcsqlite.GetUtxoIDByOutpointParams{
			WalletID:    int64(params.WalletID),
			TxHash:      params.OutPoint.Hash[:],
			OutputIndex: int64(params.OutPoint.Index),
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

// Release attempts to delete the sqlite lease row for the provided UTXO ID and
// lock ID.
func (o *sqliteReleaseOutputOps) Release(ctx context.Context, walletID uint32,
	utxoID int64, lockID [32]byte) (int64, error) {

	rows, err := o.qtx.ReleaseUtxoLease(
		ctx, sqlcsqlite.ReleaseUtxoLeaseParams{
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

// ActiveLockID returns the currently active sqlite lease lock ID for the
// provided UTXO ID.
func (o *sqliteReleaseOutputOps) ActiveLockID(ctx context.Context,
	walletID uint32, utxoID int64, nowUTC time.Time) ([]byte, error) {

	activeLockID, err := o.qtx.GetActiveUtxoLeaseLockID(
		ctx, sqlcsqlite.GetActiveUtxoLeaseLockIDParams{
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
