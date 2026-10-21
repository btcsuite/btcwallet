package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// UpdateWallet updates various properties of a wallet, such as its
// birthday, birthday block, or sync state. The specific fields to
// update are provided in the UpdateWalletParams struct. It returns an
// error if the update fails.
func (s *Store) UpdateWallet(ctx context.Context,
	params db.UpdateWalletParams) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		return db.UpdateWalletWithOps(
			ctx, params, updateWalletOps{q: qtx},
		)
	})
}

// updateWalletOps adapts SQLite sqlc queries to the shared UpdateWallet
// workflow.
type updateWalletOps struct {
	q *sqlc.Queries
}

// Ensure updateWalletOps implements db.UpdateWalletOps at compile time.
var _ db.UpdateWalletOps = (*updateWalletOps)(nil)

// EnsureBlock implements db.UpdateWalletOps.
func (o updateWalletOps) EnsureBlock(ctx context.Context,
	block *db.Block) error {

	return ensureBlockExists(ctx, o.q, block)
}

// UpdateWalletSyncState implements db.UpdateWalletOps.
func (o updateWalletOps) UpdateWalletSyncState(ctx context.Context,
	params db.UpdateWalletParams) error {

	rowsAffected, err := o.q.UpdateWalletSyncState(
		ctx, buildUpdateSyncParams(params),
	)
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("wallet sync state for wallet %d: %w",
			params.WalletID, db.ErrWalletNotFound)
	}

	return releaseMaturedLeases(ctx, o.q, params.WalletID)
}

// releaseMaturedLeases deletes the wallet's confirmation-controlled leases
// whose spend reached its release depth at the stored sync tip. Writers call it
// after recording their transactions, so a spend confirmed in the same write
// counts, as does one recorded below an unchanged tip.
func releaseMaturedLeases(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32) error {

	_, err := qtx.DeleteMaturedUtxoLeases(ctx, int64(walletID))
	if err != nil {
		return fmt.Errorf("delete matured utxo leases: %w", err)
	}

	return nil
}

// buildUpdateSyncParams constructs the UpdateWalletSyncStateParams from
// the given UpdateWalletParams.
func buildUpdateSyncParams(
	params db.UpdateWalletParams) sqlc.UpdateWalletSyncStateParams {

	syncParams := sqlc.UpdateWalletSyncStateParams{
		WalletID: int64(params.WalletID),
	}

	if params.SyncedTo != nil {
		syncParams.SyncedHeight = sql.NullInt64{
			Int64: int64(params.SyncedTo.Height),
			Valid: true,
		}
	}

	if params.Birthday != nil {
		syncParams.BirthdayTimestamp = sql.NullTime{
			Time:  *params.Birthday,
			Valid: true,
		}
	}

	if params.BirthdayBlock != nil {
		syncParams.BirthdayHeight = sql.NullInt64{
			Int64: int64(params.BirthdayBlock.Height),
			Valid: true,
		}
	}

	return syncParams
}
