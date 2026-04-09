package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// UpdateTx patches the mutable metadata for one wallet-scoped transaction.
//
// UpdateTx may edit the user-visible label, the block/status view, or both in
// one SQL transaction. Immutable transaction facts such as raw_tx, credits, and
// spent-input edges stay owned by CreateTx and the internal rollback/delete
// flows.
func (s *SqliteStore) UpdateTx(ctx context.Context,
	params UpdateTxParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		return UpdateTxWithOps(ctx, params, &sqliteUpdateTxOps{qtx: qtx})
	})
}

// sqliteUpdateTxOps adapts sqlite sqlc queries to the shared UpdateTx flow.
type sqliteUpdateTxOps struct {
	// qtx is the transaction-scoped sqlite query set used by UpdateTx.
	qtx *sqlcsqlite.Queries

	// blockHeight caches the validated sqlite block-height wrapper prepared for
	// the later state update query.
	blockHeight sql.NullInt64

	// status caches the sqlite status code prepared for the later state update
	// query.
	status int64
}

var _ UpdateTxOps = (*sqliteUpdateTxOps)(nil)

// LoadIsCoinbase loads the existing row metadata UpdateTx needs before it can
// validate one patch.
func (o *sqliteUpdateTxOps) LoadIsCoinbase(ctx context.Context,
	walletID uint32, txHash chainhash.Hash) (bool, error) {

	meta, err := o.qtx.GetTransactionMetaByHash(
		ctx,
		sqlcsqlite.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("tx %s: %w", txHash, ErrTxNotFound)
		}

		return false, fmt.Errorf("get tx metadata: %w", err)
	}

	return meta.IsCoinbase, nil
}

// PrepareState validates any referenced confirming block and captures the
// sqlite-specific state params for the later row update.
func (o *sqliteUpdateTxOps) PrepareState(ctx context.Context,
	state UpdateTxState) error {

	blockHeight := sql.NullInt64{}

	if state.Block != nil {
		height, err := requireBlockMatchesSqlite(ctx, o.qtx, state.Block)
		if err != nil {
			return fmt.Errorf("require confirming block: %w", err)
		}

		blockHeight = sql.NullInt64{Int64: height, Valid: true}
	}

	o.blockHeight = blockHeight
	o.status = int64(state.Status)

	return nil
}

// UpdateLabel writes one user-visible label change.
func (o *sqliteUpdateTxOps) UpdateLabel(ctx context.Context, walletID uint32,
	txHash chainhash.Hash, label string) error {

	rows, err := o.qtx.UpdateTransactionLabelByHash(
		ctx,
		sqlcsqlite.UpdateTransactionLabelByHashParams{
			Label:    label,
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		return fmt.Errorf("update tx label query: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("tx %s: %w", txHash, ErrTxNotFound)
	}

	return nil
}

// UpdateState writes one block/status patch after PrepareState has validated
// any referenced block metadata.
func (o *sqliteUpdateTxOps) UpdateState(ctx context.Context, walletID uint32,
	txHash chainhash.Hash, _ UpdateTxState) error {

	rows, err := o.qtx.UpdateTransactionStateByHash(
		ctx,
		sqlcsqlite.UpdateTransactionStateByHashParams{
			BlockHeight: o.blockHeight,
			Status:      o.status,
			WalletID:    int64(walletID),
			TxHash:      txHash[:],
		},
	)
	if err != nil {
		return fmt.Errorf("update tx state query: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("tx %s: %w", txHash, ErrTxNotFound)
	}

	return nil
}
