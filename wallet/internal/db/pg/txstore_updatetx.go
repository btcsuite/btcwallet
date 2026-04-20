package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// UpdateTx patches the mutable metadata for one wallet-scoped transaction.
//
// UpdateTx may edit the user-visible label, the block/status view, or both in
// one SQL transaction. Immutable transaction facts such as raw_tx, credits, and
// spent-input edges stay owned by CreateTx and the internal rollback/delete
// flows.
func (s *Store) UpdateTx(ctx context.Context,
	params db.UpdateTxParams) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		return db.UpdateTxWithOps(ctx, params, &updateTxOps{qtx: qtx})
	})
}

// updateTxOps adapts postgres sqlc queries to the shared UpdateTx flow.
type updateTxOps struct {
	// qtx is the transaction-scoped postgres query set used by UpdateTx.
	qtx *sqlc.Queries

	// blockHeight caches the validated postgres block-height wrapper prepared
	// for the later state update query.
	blockHeight sql.NullInt32

	// status caches the postgres status code prepared for the later state
	// update query.
	status int16
}

var _ db.UpdateTxOps = (*updateTxOps)(nil)

// LoadIsCoinbase loads the existing row metadata UpdateTx needs before it can
// validate one patch.
func (o *updateTxOps) LoadIsCoinbase(ctx context.Context, walletID uint32,
	txHash chainhash.Hash) (bool, error) {

	meta, err := o.qtx.GetTransactionMetaByHash(
		ctx,
		sqlc.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("tx %s: %w", txHash, db.ErrTxNotFound)
		}

		return false, fmt.Errorf("get tx metadata: %w", err)
	}

	return meta.IsCoinbase, nil
}

// PrepareState validates any referenced confirming block and captures the
// postgres-specific state params for the later row update.
func (o *updateTxOps) PrepareState(ctx context.Context,
	state db.UpdateTxState) error {

	blockHeight := sql.NullInt32{}

	if state.Block != nil {
		height, err := requireBlockMatches(ctx, o.qtx, state.Block)
		if err != nil {
			return fmt.Errorf("require confirming block: %w", err)
		}

		blockHeight = sql.NullInt32{Int32: height, Valid: true}
	}

	o.blockHeight = blockHeight
	o.status = int16(state.Status)

	return nil
}

// UpdateState writes one block/status patch after PrepareState has validated
// any referenced block metadata.
func (o *updateTxOps) UpdateState(ctx context.Context, walletID uint32,
	txHash chainhash.Hash, _ db.UpdateTxState) error {

	rows, err := o.qtx.UpdateTransactionStateByHash(
		ctx,
		sqlc.UpdateTransactionStateByHashParams{
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
		return fmt.Errorf("tx %s: %w", txHash, db.ErrTxNotFound)
	}

	return nil
}

// UpdateLabel writes one user-visible label change.
func (o *updateTxOps) UpdateLabel(ctx context.Context, walletID uint32,
	txHash chainhash.Hash, label string) error {

	rows, err := o.qtx.UpdateTransactionLabelByHash(
		ctx,
		sqlc.UpdateTransactionLabelByHashParams{
			Label:    label,
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		return fmt.Errorf("update tx label query: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("tx %s: %w", txHash, db.ErrTxNotFound)
	}

	return nil
}
