package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// UpdateTx patches the mutable metadata for one wallet-scoped transaction.
//
// UpdateTx may edit the user-visible label, the block/status view, or both in
// one SQL transaction. Immutable transaction facts such as raw_tx, credits, and
// spent-input edges stay owned by CreateTx and the internal rollback/delete
// flows.
func (s *Store) UpdateTx(ctx context.Context,
	params db.UpdateTxParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlc.Queries) error {
		return db.UpdateTxWithOps(ctx, params, &updateTxOps{qtx: qtx})
	})
}

// updateTxOps adapts sqlite sqlc queries to the shared UpdateTx flow.
type updateTxOps struct {
	// qtx is the transaction-scoped sqlite query set used by UpdateTx.
	qtx *sqlc.Queries

	// blockHeight caches the validated sqlite block-height wrapper prepared for
	// the later state update query.
	blockHeight sql.NullInt64

	// status caches the sqlite status code prepared for the later state update
	// query.
	status int64
}

var _ db.UpdateTxOps = (*updateTxOps)(nil)

// LoadIsCoinbase loads the existing row metadata UpdateTx needs before it can
// validate one patch.
func (o *updateTxOps) LoadIsCoinbase(ctx context.Context,
	walletID uint32, txHash chainhash.Hash) (bool, error) {

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
// sqlite-specific state params for the later row update.
func (o *updateTxOps) PrepareState(ctx context.Context,
	state db.UpdateTxState) error {

	blockHeight := sql.NullInt64{}

	if state.Block != nil {
		height, err := requireBlockMatches(ctx, o.qtx, state.Block)
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
