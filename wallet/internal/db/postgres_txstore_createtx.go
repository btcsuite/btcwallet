package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chainhash/v2"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// CreateTx atomically records a wallet-scoped transaction row, its
// wallet-owned credits, and any spend edges created by its inputs.
//
// The full write runs inside ExecuteTx so the transaction row, created UTXOs,
// spent-parent markers, and any required invalidation are either committed
// together or not at all. Received timestamps are normalized to UTC before
// Insert. When the wallet already stores the same unmined transaction hash,
// CreateTx may promote that existing row to confirmed state instead of
// inserting a duplicate.
func (s *PostgresStore) CreateTx(ctx context.Context,
	params CreateTxParams) error {

	req, err := NewCreateTxRequest(params)
	if err != nil {
		return err
	}

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		return CreateTxWithOps(ctx, req, &pgCreateTxOps{
			pgInvalidateUnminedTxOps: pgInvalidateUnminedTxOps{
				qtx: qtx,
			},
		})
	})
}

// pgCreateTxOps adapts postgres sqlc queries to the shared CreateTx flow.
type pgCreateTxOps struct {
	pgInvalidateUnminedTxOps

	blockHeight sql.NullInt32
}

var _ CreateTxOps = (*pgCreateTxOps)(nil)

// LoadExisting loads any existing wallet-scoped row for the requested tx hash.
func (o *pgCreateTxOps) LoadExisting(ctx context.Context,
	req CreateTxRequest) (*CreateTxExistingTarget, error) {

	meta, err := o.qtx.GetTransactionMetaByHash(
		ctx,
		sqlcpg.GetTransactionMetaByHashParams{
			WalletID: int64(req.Params.WalletID),
			TxHash:   req.TxHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCreateTxExistingNotFound
		}

		return nil, fmt.Errorf("get tx metadata: %w", err)
	}

	status, err := ParseTxStatus(int64(meta.TxStatus))
	if err != nil {
		return nil, err
	}

	return &CreateTxExistingTarget{
		ID:         meta.ID,
		Status:     status,
		HasBlock:   meta.BlockHeight.Valid,
		IsCoinbase: meta.IsCoinbase,
	}, nil
}

// ConfirmExisting promotes one existing unmined row to its confirmed state.
func (o *pgCreateTxOps) ConfirmExisting(ctx context.Context,
	req CreateTxRequest,
	_ CreateTxExistingTarget) error {

	blockHeight, err := requireBlockMatchesPg(ctx, o.qtx, req.Params.Block)
	if err != nil {
		return fmt.Errorf("require confirming block: %w", err)
	}

	rows, err := o.qtx.UpdateTransactionStateByHash(
		ctx, sqlcpg.UpdateTransactionStateByHashParams{
			BlockHeight: sql.NullInt32{Int32: blockHeight, Valid: true},
			Status:      int16(TxStatusPublished),
			WalletID:    int64(req.Params.WalletID),
			TxHash:      req.TxHash[:],
		},
	)
	if err != nil {
		return fmt.Errorf("update tx state query: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("tx %s: %w", req.TxHash, ErrTxNotFound)
	}

	return nil
}

// PrepareBlock validates the optional confirming block and caches the postgres
// block-height value that the later Insert query will store.
func (o *pgCreateTxOps) PrepareBlock(ctx context.Context,
	req CreateTxRequest) error {

	o.blockHeight = sql.NullInt32{}

	if req.Params.Block == nil {
		return nil
	}

	height, err := requireBlockMatchesPg(ctx, o.qtx, req.Params.Block)
	if err != nil {
		return err
	}

	o.blockHeight = sql.NullInt32{Int32: height, Valid: true}

	return nil
}

// ListConflictTxns returns the direct conflict root IDs plus the matching tx
// hashes used for descendant discovery.
func (o *pgCreateTxOps) ListConflictTxns(ctx context.Context,
	req CreateTxRequest) ([]int64, []chainhash.Hash, error) {

	rootIDs, err := collectPgConflictRootIDs(ctx, o.qtx, req)
	if err != nil {
		return nil, nil, err
	}

	if len(rootIDs) == 0 {
		return nil, nil, nil
	}

	rows, err := o.qtx.ListUnminedTransactions(ctx, int64(req.Params.WalletID))
	if err != nil {
		return nil, nil, fmt.Errorf("list unmined txns: %w", err)
	}

	return buildPgConflictRoots(rows, rootIDs)
}

// collectPgConflictRootIDs returns the active unmined spender row IDs
// that currently own any wallet-controlled input spent by the incoming tx.
func collectPgConflictRootIDs(ctx context.Context, qtx *sqlcpg.Queries,
	req CreateTxRequest) (map[int64]struct{}, error) {

	if blockchain.IsCoinBaseTx(req.Params.Tx) {
		return map[int64]struct{}{}, nil
	}

	rootIDs := make(map[int64]struct{}, len(req.Params.Tx.TxIn))
	for inputIndex, txIn := range req.Params.Tx.TxIn {
		outputIndex, err := Uint32ToInt32(txIn.PreviousOutPoint.Index)
		if err != nil {
			return nil, fmt.Errorf("convert input outpoint index %d: %w",
				inputIndex, err)
		}

		spentByTxID, err := qtx.GetUtxoSpendByOutpoint(
			ctx, sqlcpg.GetUtxoSpendByOutpointParams{
				WalletID:    int64(req.Params.WalletID),
				TxHash:      txIn.PreviousOutPoint.Hash[:],
				OutputIndex: outputIndex,
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}

			return nil, fmt.Errorf("lookup input conflict %d: %w", inputIndex,
				err)
		}

		if !spentByTxID.Valid {
			continue
		}

		rootIDs[spentByTxID.Int64] = struct{}{}
	}

	return rootIDs, nil
}

// buildPgConflictRoots maps the selected unmined rows into ordered root IDs and
// the matching root hashes used for descendant discovery.
func buildPgConflictRoots(rows []sqlcpg.ListUnminedTransactionsRow,
	rootIDSet map[int64]struct{}) (
	[]int64, []chainhash.Hash, error) {

	rootIDs := make([]int64, 0, len(rootIDSet))

	rootHashes := make([]chainhash.Hash, 0, len(rootIDSet))
	for _, row := range rows {
		if _, ok := rootIDSet[row.ID]; !ok {
			continue
		}

		txHash, err := chainhash.NewHash(row.TxHash)
		if err != nil {
			return nil, nil, fmt.Errorf("tx hash: %w", err)
		}

		rootIDs = append(rootIDs, row.ID)
		rootHashes = append(rootHashes, *txHash)
	}

	return rootIDs, rootHashes, nil
}

// Insert stores one new postgres transaction row for CreateTx.
func (o *pgCreateTxOps) Insert(ctx context.Context,
	req CreateTxRequest) (int64, error) {

	txID, err := o.qtx.InsertTransaction(ctx, sqlcpg.InsertTransactionParams{
		WalletID:     int64(req.Params.WalletID),
		TxHash:       req.TxHash[:],
		RawTx:        req.RawTx,
		BlockHeight:  o.blockHeight,
		TxStatus:     int16(req.Params.Status),
		ReceivedTime: req.Received,
		IsCoinbase:   req.IsCoinbase,
		TxLabel:      req.Params.Label,
	})
	if err != nil {
		return 0, fmt.Errorf("Insert tx row: %w", err)
	}

	return txID, nil
}

// InsertCredits stores any wallet-owned outputs created by the transaction.
func (o *pgCreateTxOps) InsertCredits(ctx context.Context,
	req CreateTxRequest, txID int64) error {

	return insertCreditsPg(ctx, o.qtx, req.Params, txID)
}

// MarkInputsSpent records wallet-owned inputs spent by the transaction.
func (o *pgCreateTxOps) MarkInputsSpent(ctx context.Context,
	req CreateTxRequest, txID int64) error {

	return markInputsSpentPg(ctx, o.qtx, req.Params, txID)
}

// MarkTxnsReplaced marks the provided direct conflict roots replaced in one
// batch update.
func (o *pgCreateTxOps) MarkTxnsReplaced(
	ctx context.Context, walletID int64, txIDs []int64) error {

	_, err := o.qtx.UpdateTransactionStatusByIDs(
		ctx, sqlcpg.UpdateTransactionStatusByIDsParams{
			WalletID: walletID,
			Status:   int16(TxStatusReplaced),
			TxIds:    txIDs,
		},
	)
	if err != nil {
		return fmt.Errorf("mark txns replaced: %w", err)
	}

	return nil
}

// InsertReplacementEdges records replacement-history edges from each direct
// conflict root to the newly inserted confirmed transaction row.
func (o *pgCreateTxOps) InsertReplacementEdges(
	ctx context.Context, walletID int64, replacedTxIDs []int64,
	replacementTxID int64) error {

	for _, replacedTxID := range replacedTxIDs {
		_, err := o.qtx.InsertTxReplacementEdge(
			ctx, sqlcpg.InsertTxReplacementEdgeParams{
				WalletID:        walletID,
				ReplacedTxID:    replacedTxID,
				ReplacementTxID: replacementTxID,
			},
		)
		if err != nil {
			return fmt.Errorf("Insert replacement edge for %d: %w",
				replacedTxID, err)
		}
	}

	return nil
}

// insertCreditsPg inserts one wallet-owned UTXO row for each credited output of
// the transaction being stored.
func insertCreditsPg(ctx context.Context, qtx *sqlcpg.Queries,
	params CreateTxParams, txID int64) error {

	for index := range params.Credits {
		creditExists, err := creditExistsPg(
			ctx, qtx, params.WalletID, params.Tx.TxHash(), index,
		)
		if err != nil {
			return err
		}

		if creditExists {
			continue
		}

		pkScript := params.Tx.TxOut[index].PkScript

		addrRow, err := qtx.GetAddressByScriptPubKey(
			ctx, sqlcpg.GetAddressByScriptPubKeyParams{
				ScriptPubKey: pkScript,
				WalletID:     int64(params.WalletID),
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("credit output %d: %w", index,
					ErrAddressNotFound)
			}

			return fmt.Errorf("resolve credit address %d: %w", index, err)
		}

		outputIndex, err := Uint32ToInt32(index)
		if err != nil {
			return fmt.Errorf("convert credit index %d: %w", index, err)
		}

		_, err = qtx.InsertUtxo(ctx, sqlcpg.InsertUtxoParams{
			WalletID:    int64(params.WalletID),
			TxID:        txID,
			OutputIndex: outputIndex,
			Amount:      params.Tx.TxOut[index].Value,
			AddressID:   addrRow.ID,
		})
		if err != nil {
			return fmt.Errorf("Insert credit output %d: %w", index, err)
		}
	}

	return nil
}

// creditExistsPg reports whether the wallet already has a UTXO row for the
// given credited output, even if that output is now spent by a child tx.
func creditExistsPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txHash chainhash.Hash, outputIndex uint32) (bool, error) {

	convertedIndex, err := Uint32ToInt32(outputIndex)
	if err != nil {
		return false, fmt.Errorf("convert credit index %d: %w", outputIndex,
			err)
	}

	_, err = qtx.GetUtxoSpendByOutpoint(
		ctx, sqlcpg.GetUtxoSpendByOutpointParams{
			WalletID:    int64(walletID),
			TxHash:      txHash[:],
			OutputIndex: convertedIndex,
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}

		return false, fmt.Errorf("lookup credit output %d: %w", outputIndex,
			err)
	}

	return true, nil
}

// markInputsSpentPg attaches wallet-owned outpoints spent by the stored
// transaction to its row ID and input indexes.
//
// If another wallet transaction already owns the spend edge for a
// wallet-controlled input, the create path fails with ErrTxInputConflict
// instead of silently storing a second spender. Inputs that reference a
// wallet-owned output whose parent transaction is already invalid fail with
// ErrTxInputInvalidParent.
func markInputsSpentPg(ctx context.Context, qtx *sqlcpg.Queries,
	params CreateTxParams, txID int64) error {

	if blockchain.IsCoinBaseTx(params.Tx) {
		return nil
	}

	for inputIndex, txIn := range params.Tx.TxIn {
		outputIndex, err := Uint32ToInt32(txIn.PreviousOutPoint.Index)
		if err != nil {
			return fmt.Errorf("convert input outpoint index %d: %w", inputIndex,
				err)
		}

		spentInputIndex, err := Int64ToInt32(int64(inputIndex))
		if err != nil {
			return fmt.Errorf("convert input index %d: %w", inputIndex, err)
		}

		rowsAffected, err := qtx.MarkUtxoSpent(ctx, sqlcpg.MarkUtxoSpentParams{
			WalletID:        int64(params.WalletID),
			TxHash:          txIn.PreviousOutPoint.Hash[:],
			OutputIndex:     outputIndex,
			SpentByTxID:     sql.NullInt64{Int64: txID, Valid: true},
			SpentInputIndex: sql.NullInt32{Int32: spentInputIndex, Valid: true},
		})
		if err != nil {
			return fmt.Errorf("mark spent input %d: %w", inputIndex, err)
		}

		if rowsAffected == 0 {
			err = ensureSpendConflictPg(
				ctx, qtx, params.WalletID, txIn.PreviousOutPoint.Hash,
				outputIndex, txID,
			)
			if err != nil {
				return fmt.Errorf("mark spent input %d: %w", inputIndex, err)
			}
		}
	}

	return nil
}

// ensureSpendConflictPg reports ErrTxInputConflict when the referenced outpoint
// is wallet-owned, still eligible for spending, and already attached to another
// transaction. If the wallet owns the parent output but that parent is already
// invalid, the helper returns ErrTxInputInvalidParent instead.
func ensureSpendConflictPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txHash chainhash.Hash, outputIndex int32,
	txID int64) error {

	spendByTxID, err := qtx.GetUtxoSpendByOutpoint(
		ctx, sqlcpg.GetUtxoSpendByOutpointParams{
			WalletID:    int64(walletID),
			TxHash:      txHash[:],
			OutputIndex: outputIndex,
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ensureWalletParentValidPg(
				ctx, qtx, walletID, txHash, outputIndex,
			)
		}

		return fmt.Errorf("check spend conflict: %w", err)
	}

	if spendByTxID.Valid && spendByTxID.Int64 != txID {
		return ErrTxInputConflict
	}

	return nil
}

// ensureWalletParentValidPg reports ErrTxInputInvalidParent when the wallet
// owns the referenced outpoint but its parent transaction is already invalid.
func ensureWalletParentValidPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txHash chainhash.Hash, outputIndex int32) error {

	hasInvalid, err := qtx.HasInvalidWalletUtxoByOutpoint(
		ctx, sqlcpg.HasInvalidWalletUtxoByOutpointParams{
			WalletID:    int64(walletID),
			TxHash:      txHash[:],
			OutputIndex: outputIndex,
		},
	)
	if err != nil {
		return fmt.Errorf("check invalid wallet parent: %w", err)
	}

	if hasInvalid {
		return ErrTxInputInvalidParent
	}

	return nil
}
