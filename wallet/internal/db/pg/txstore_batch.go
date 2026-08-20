package pg

import (
	"context"
	"errors"
	"fmt"

	address "github.com/btcsuite/btcd/address/v2"
	txscript "github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5"
)

// ApplyTxBatch atomically records transactions and an optional sync-tip update.
func (s *Store) ApplyTxBatch(ctx context.Context,
	params db.TxBatchParams) error {

	// Reject a batch that mixes wallets before opening the write transaction:
	// the sync tip is updated for params.WalletID, so a transaction owned by a
	// different wallet must not ride along in the same atomic batch.
	err := db.ValidateBatchTransactionsWalletID(
		params.WalletID, params.Transactions,
	)
	if err != nil {
		return err
	}

	// Reject a nil-Tx member before SortTxBatchParentsFirst dereferences each
	// transaction below; the per-tx NewCreateTxRequest check in
	// applyBatchTransaction runs only after the sort.
	err = db.ValidateBatchTransactionsTx(params.Transactions)
	if err != nil {
		return err
	}

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		err := applyBatchSyncTip(ctx, qtx, params)
		if err != nil {
			return err
		}

		// Record any in-batch parent before its children. Each tx claims
		// its spent parent inputs by updating the parent credit's UTXO row,
		// so a child applied before its in-batch parent would update no row
		// and silently drop the spend edge. Sorting parents first makes the
		// batch order-independent; an already parents-first or
		// dependency-free batch is returned unchanged.
		txs := db.SortTxBatchParentsFirst(params.Transactions)

		for i := range txs {
			err = applyBatchTransaction(ctx, qtx, txs[i])
			if err != nil {
				return fmt.Errorf("create tx %d: %w", i, err)
			}
		}

		return nil
	})
}

// applyBatchTransaction records one transaction from a runtime batch.
func applyBatchTransaction(ctx context.Context, qtx *sqlc.Queries,
	params db.CreateTxParams) error {

	params, err := resolveCreditCandidates(ctx, qtx, params)
	if err != nil {
		return fmt.Errorf("resolve credit candidates: %w", err)
	}

	req, err := db.NewCreateTxRequest(params)
	if err != nil {
		return fmt.Errorf("validate tx: %w", err)
	}

	ops := &createTxOps{
		invalidateUnminedTxOps: invalidateUnminedTxOps{
			qtx: qtx,
		},
	}

	// A confirmed tx may reference a block the batch never advanced the
	// sync tip to: SyncedTo is nil for standalone relevant-tx
	// notifications. Ensure that confirming block row exists before
	// CreateTxWithOps validates it during PrepareBlock, otherwise the
	// confirmed insert fails with ErrBlockNotFound. This only inserts the
	// block row; advancing the wallet sync tip stays the sole
	// responsibility of applyBatchSyncTip.
	if params.Block != nil {
		err = ensureBlockExists(ctx, qtx, params.Block)
		if err != nil {
			return fmt.Errorf("ensure tx block: %w", err)
		}
	}

	err = db.CreateTxWithOps(ctx, req, ops)

	return promoteBatchDuplicate(ctx, qtx, req, ops, err)
}

// resolveCreditCandidates resolves notification credit candidates inside the
// batch write transaction and promotes owned outputs into Credits.
func resolveCreditCandidates(ctx context.Context, qtx *sqlc.Queries,
	params db.CreateTxParams) (db.CreateTxParams, error) {

	if len(params.CreditCandidates) == 0 {
		return params, nil
	}

	credits := make(
		map[uint32]address.Address,
		len(params.Credits)+len(params.CreditCandidates),
	)
	for index, addr := range params.Credits {
		credits[index] = addr
	}

	for index, candidates := range params.CreditCandidates {
		if _, ok := credits[index]; ok {
			continue
		}

		if uint64(index) >= uint64(len(params.Tx.TxOut)) {
			return params, fmt.Errorf("%w: credit candidate index %d: %w",
				db.ErrInvalidParam, index, db.ErrIndexOutOfRange)
		}

		outputScript := params.Tx.TxOut[index].PkScript

		owned, err := creditScriptOwned(
			ctx, qtx, params.WalletID, outputScript,
		)
		if err != nil {
			return params, fmt.Errorf("lookup output script %d: %w", index,
				err)
		}

		if owned {
			credits[index] = nil
			continue
		}

		ownedAddr, err := ownedCreditCandidate(
			ctx, qtx, params.WalletID, outputScript, candidates,
		)
		if err != nil {
			return params, fmt.Errorf("lookup candidate %d: %w", index, err)
		}

		if ownedAddr != nil {
			credits[index] = ownedAddr
		}
	}

	params.Credits = credits
	params.CreditCandidates = nil

	return params, nil
}

// ownedCreditCandidate returns the first candidate address owned by the wallet.
func ownedCreditCandidate(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, outputScript []byte,
	candidates []address.Address) (address.Address, error) {

	for _, candidate := range candidates {
		if candidate == nil {
			return nil, fmt.Errorf("%w: nil credit candidate",
				db.ErrInvalidParam)
		}

		err := db.ValidateCreditAddrMembership(candidate, outputScript)
		if err != nil {
			return nil, err
		}

		candidateScript, err := txscript.PayToAddrScript(candidate)
		if err != nil {
			return nil, fmt.Errorf("candidate script: %w", err)
		}

		owned, err := creditScriptOwned(
			ctx, qtx, walletID, candidateScript,
		)
		if err != nil {
			return nil, err
		}

		if owned {
			return candidate, nil
		}
	}

	return nil, nil //nolint:nilnil // A nil address means no candidate matched.
}

// creditScriptOwned reports whether walletID has an address row for script.
func creditScriptOwned(ctx context.Context, qtx *sqlc.Queries, walletID uint32,
	script []byte) (bool, error) {

	_, err := qtx.GetAddressByScriptPubKey(
		ctx, sqlc.GetAddressByScriptPubKeyParams{
			ScriptPubKey: script,
			WalletID:     int64(walletID),
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	return true, nil
}

// promoteBatchDuplicate promotes a pending unmined duplicate to published when
// the shared create flow rejected that non-idempotent state transition.
func promoteBatchDuplicate(ctx context.Context, qtx *sqlc.Queries,
	req db.CreateTxRequest, ops db.CreateTxOps, createErr error) error {

	txID, ok, err := promotableBatchDuplicate(ctx, qtx, req, createErr)
	if err != nil {
		return err
	}

	if !ok {
		return createErr
	}

	rows, err := qtx.UpdateTransactionStatusByIDs(
		ctx, sqlc.UpdateTransactionStatusByIDsParams{
			WalletID: int64(req.Params.WalletID),
			Status:   int16(db.TxStatusPublished),
			TxIds:    []int64{txID},
		},
	)
	if err != nil {
		return fmt.Errorf("promote duplicate tx status: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("promote duplicate tx %s: %w", req.TxHash,
			db.ErrTxNotFound)
	}

	err = ops.InsertCredits(ctx, req, txID)
	if err != nil {
		return fmt.Errorf("record promoted duplicate tx credits: %w", err)
	}

	err = ops.MarkInputsSpent(ctx, req, txID)
	if err != nil {
		return fmt.Errorf("record promoted duplicate tx spends: %w", err)
	}

	return nil
}

// promotableBatchDuplicate returns the existing tx id when createErr is a
// pending-unmined duplicate that this batch may promote to published state.
func promotableBatchDuplicate(ctx context.Context, qtx *sqlc.Queries,
	req db.CreateTxRequest, createErr error) (int64, bool, error) {

	if createErr == nil || !errors.Is(createErr, db.ErrTxAlreadyExists) {
		return 0, false, nil
	}

	row, err := qtx.GetTransactionByHash(
		ctx, sqlc.GetTransactionByHashParams{
			WalletID: int64(req.Params.WalletID),
			TxHash:   req.TxHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, nil
		}

		return 0, false, fmt.Errorf("get duplicate tx: %w", err)
	}

	status, err := db.ParseTxStatus(int64(row.TxStatus))
	if err != nil {
		return 0, false, fmt.Errorf("parse duplicate tx status: %w", err)
	}

	var block *db.Block
	if row.BlockHeight.Valid {
		block, err = buildBlock(
			row.BlockHeight, row.BlockHash, row.BlockTimestamp,
		)
		if err != nil {
			return 0, false, fmt.Errorf("build duplicate tx block: %w",
				err)
		}
	}

	if !db.CanPromoteUnminedCreateTxDuplicate(
		req, status, row.IsCoinbase, block,
	) {

		return 0, false, nil
	}

	return row.ID, true, nil
}

// applyBatchSyncTip applies the optional sync-tip update within a batch.
func applyBatchSyncTip(ctx context.Context, qtx *sqlc.Queries,
	params db.TxBatchParams) error {

	if params.SyncedTo == nil {
		return nil
	}

	err := ensureBlockExists(ctx, qtx, params.SyncedTo)
	if err != nil {
		return fmt.Errorf("ensure synced block: %w", err)
	}

	syncParams, err := buildUpdateSyncParams(db.UpdateWalletParams{
		WalletID: params.WalletID,
		SyncedTo: params.SyncedTo,
	})
	if err != nil {
		return err
	}

	rowsAffected, err := qtx.UpdateWalletSyncState(ctx, syncParams)
	if err != nil {
		return fmt.Errorf("update wallet sync state: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("wallet sync state for wallet %d: %w",
			params.WalletID, db.ErrWalletNotFound)
	}

	return nil
}
