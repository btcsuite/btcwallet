package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// CreateTx atomically records a wallet-scoped transaction row, its wallet-owned
// credits, and any spend edges created by its inputs.
//
// The full write runs inside ExecuteTx so the transaction row, created UTXOs,
// spent-parent markers, and any required invalidation are either committed
// together or not at all. Received timestamps are normalized to UTC before
// Insert. When the wallet already stores the same unmined transaction hash,
// CreateTx may promote that existing row to confirmed state instead of
// inserting a duplicate.
func (s *Store) CreateTx(ctx context.Context,
	params db.CreateTxParams) error {

	req, err := db.NewCreateTxRequest(params)
	if err != nil {
		return err
	}

	return s.ExecuteTx(ctx, func(qtx *sqlc.Queries) error {
		return db.CreateTxWithOps(ctx, req, &createTxOps{
			invalidateUnminedTxOps: invalidateUnminedTxOps{
				qtx: qtx,
			},
		})
	})
}

// createTxOps adapts sqlite sqlc queries to the shared CreateTx flow.
type createTxOps struct {
	invalidateUnminedTxOps

	blockHeight sql.NullInt64
}

var _ db.CreateTxOps = (*createTxOps)(nil)

// LoadExisting loads any existing wallet-scoped row for the requested tx hash.
func (o *createTxOps) LoadExisting(ctx context.Context,
	req db.CreateTxRequest) (*db.CreateTxExistingTarget, error) {

	meta, err := o.qtx.GetTransactionMetaByHash(
		ctx,
		sqlc.GetTransactionMetaByHashParams{
			WalletID: int64(req.Params.WalletID),
			TxHash:   req.TxHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, db.ErrCreateTxExistingNotFound
		}

		return nil, fmt.Errorf("get tx metadata: %w", err)
	}

	status, err := db.ParseTxStatus(meta.TxStatus)
	if err != nil {
		return nil, err
	}

	return &db.CreateTxExistingTarget{
		ID:         meta.ID,
		Status:     status,
		HasBlock:   meta.BlockHeight.Valid,
		IsCoinbase: meta.IsCoinbase,
	}, nil
}

// ConfirmExisting promotes one existing unmined row to its confirmed state.
func (o *createTxOps) ConfirmExisting(ctx context.Context,
	req db.CreateTxRequest,
	_ db.CreateTxExistingTarget) error {

	blockHeight, err := requireBlockMatches(ctx, o.qtx, req.Params.Block)
	if err != nil {
		return fmt.Errorf("require confirming block: %w", err)
	}

	rows, err := o.qtx.UpdateTransactionStateByHash(
		ctx, sqlc.UpdateTransactionStateByHashParams{
			BlockHeight: sql.NullInt64{Int64: blockHeight, Valid: true},
			Status:      int64(db.TxStatusPublished),
			WalletID:    int64(req.Params.WalletID),
			TxHash:      req.TxHash[:],
		},
	)
	if err != nil {
		return fmt.Errorf("update tx state query: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("tx %s: %w", req.TxHash, db.ErrTxNotFound)
	}

	return nil
}

// PrepareBlock validates the optional confirming block and caches the sqlite
// block-height value that the later Insert query will store.
func (o *createTxOps) PrepareBlock(ctx context.Context,
	req db.CreateTxRequest) error {

	o.blockHeight = sql.NullInt64{}

	if req.Params.Block == nil {
		return nil
	}

	height, err := requireBlockMatches(ctx, o.qtx, req.Params.Block)
	if err != nil {
		return err
	}

	o.blockHeight = sql.NullInt64{Int64: height, Valid: true}

	return nil
}

// ListConflictTxns returns the direct conflict root IDs plus the matching tx
// hashes used for descendant discovery.
func (o *createTxOps) ListConflictTxns(ctx context.Context,
	req db.CreateTxRequest) ([]int64, []chainhash.Hash, error) {

	rootIDs, err := collectConflictRootIDs(ctx, o.qtx, req)
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

	return buildConflictRoots(rows, rootIDs)
}

// collectConflictRootIDs returns the active unmined spender row
// IDs that currently own any wallet-controlled input spent by the incoming tx.
func collectConflictRootIDs(ctx context.Context,
	qtx *sqlc.Queries,
	req db.CreateTxRequest) (map[int64]struct{}, error) {

	if blockchain.IsCoinBaseTx(req.Params.Tx) {
		return map[int64]struct{}{}, nil
	}

	rootIDs := make(map[int64]struct{}, len(req.Params.Tx.TxIn))
	for inputIndex, txIn := range req.Params.Tx.TxIn {
		spentByTxID, err := qtx.GetUtxoSpendByOutpoint(
			ctx, sqlc.GetUtxoSpendByOutpointParams{
				WalletID:    int64(req.Params.WalletID),
				TxHash:      txIn.PreviousOutPoint.Hash[:],
				OutputIndex: int64(txIn.PreviousOutPoint.Index),
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

// buildConflictRoots maps the selected unmined rows into ordered root IDs
// and the matching root hashes used for descendant discovery.
func buildConflictRoots(rows []sqlc.ListUnminedTransactionsRow,
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

// Insert stores one new sqlite transaction row for CreateTx.
func (o *createTxOps) Insert(ctx context.Context,
	req db.CreateTxRequest) (int64, error) {

	txID, err := o.qtx.InsertTransaction(
		ctx,
		sqlc.InsertTransactionParams{
			WalletID:     int64(req.Params.WalletID),
			TxHash:       req.TxHash[:],
			RawTx:        req.RawTx,
			BlockHeight:  o.blockHeight,
			TxStatus:     int64(req.Params.Status),
			ReceivedTime: req.Received,
			IsCoinbase:   req.IsCoinbase,
			TxLabel:      req.Params.Label,
		},
	)
	if err != nil {
		return 0, fmt.Errorf("insert tx row: %w", err)
	}

	return txID, nil
}

// InsertCredits stores any wallet-owned outputs created by the transaction.
func (o *createTxOps) InsertCredits(ctx context.Context,
	req db.CreateTxRequest, txID int64) error {

	return insertCredits(ctx, o.qtx, req.Params, txID)
}

// MarkInputsSpent records wallet-owned inputs spent by the transaction.
func (o *createTxOps) MarkInputsSpent(ctx context.Context,
	req db.CreateTxRequest, txID int64) error {

	return markInputsSpent(ctx, o.qtx, req.Params, txID)
}

// MarkTxnsReplaced marks the provided direct conflict roots replaced in one
// batch update.
func (o *createTxOps) MarkTxnsReplaced(
	ctx context.Context, walletID int64, txIDs []int64) error {

	_, err := o.qtx.UpdateTransactionStatusByIDs(
		ctx, sqlc.UpdateTransactionStatusByIDsParams{
			WalletID: walletID,
			Status:   int64(db.TxStatusReplaced),
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
func (o *createTxOps) InsertReplacementEdges(
	ctx context.Context, walletID int64, replacedTxIDs []int64,
	replacementTxID int64) error {

	for _, replacedTxID := range replacedTxIDs {
		_, err := o.qtx.InsertTxReplacementEdge(
			ctx, sqlc.InsertTxReplacementEdgeParams{
				WalletID:        walletID,
				ReplacedTxID:    replacedTxID,
				ReplacementTxID: replacementTxID,
			},
		)
		if err != nil {
			return fmt.Errorf("insert replacement edge for %d: %w",
				replacedTxID, err)
		}
	}

	return nil
}

// insertCredits inserts one wallet-owned UTXO row for each credited
// output of the transaction being stored.
func insertCredits(ctx context.Context, qtx *sqlc.Queries,
	params db.CreateTxParams, txID int64) error {

	for index := range params.Credits {
		creditExists, err := creditExists(
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
			ctx, sqlc.GetAddressByScriptPubKeyParams{
				ScriptPubKey: pkScript,
				WalletID:     int64(params.WalletID),
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("credit output %d: %w", index,
					db.ErrAddressNotFound)
			}

			return fmt.Errorf("resolve credit address %d: %w", index, err)
		}

		_, err = qtx.InsertUtxo(ctx, sqlc.InsertUtxoParams{
			WalletID:    int64(params.WalletID),
			TxID:        txID,
			OutputIndex: int64(index),
			Amount:      params.Tx.TxOut[index].Value,
			AddressID:   addrRow.ID,
		})
		if err != nil {
			return fmt.Errorf("insert credit output %d: %w", index, err)
		}
	}

	return nil
}

// creditExists reports whether the wallet already has a UTXO row for the
// given credited output, even if that output is now spent by a child tx.
func creditExists(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, txHash chainhash.Hash, outputIndex uint32) (bool, error) {

	_, err := qtx.GetUtxoSpendByOutpoint(
		ctx, sqlc.GetUtxoSpendByOutpointParams{
			WalletID:    int64(walletID),
			TxHash:      txHash[:],
			OutputIndex: int64(outputIndex),
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

// markInputsSpent attaches wallet-owned outpoints spent by the stored
// transaction to its row ID and input indexes.
//
// If another wallet transaction already owns the spend edge for a
// wallet-controlled input, the create path fails with ErrTxInputConflict
// instead of silently storing a second spender. Inputs that reference a
// wallet-owned output whose parent transaction is already invalid fail with
// ErrTxInputInvalidParent.
func markInputsSpent(ctx context.Context, qtx *sqlc.Queries,
	params db.CreateTxParams, txID int64) error {

	if blockchain.IsCoinBaseTx(params.Tx) {
		return nil
	}

	for inputIndex, txIn := range params.Tx.TxIn {
		spentInputIndex := sql.NullInt64{Int64: int64(inputIndex), Valid: true}

		rowsAffected, err := qtx.MarkUtxoSpent(ctx,
			sqlc.MarkUtxoSpentParams{
				WalletID:        int64(params.WalletID),
				TxHash:          txIn.PreviousOutPoint.Hash[:],
				OutputIndex:     int64(txIn.PreviousOutPoint.Index),
				SpentByTxID:     sql.NullInt64{Int64: txID, Valid: true},
				SpentInputIndex: spentInputIndex,
			})
		if err != nil {
			return fmt.Errorf("mark spent input %d: %w", inputIndex, err)
		}

		if rowsAffected == 0 {
			err = ensureSpendConflict(
				ctx, qtx, params.WalletID, txIn.PreviousOutPoint.Hash,
				int64(txIn.PreviousOutPoint.Index), txID,
			)
			if err != nil {
				return fmt.Errorf("mark spent input %d: %w", inputIndex, err)
			}
		}
	}

	return nil
}

// ensureSpendConflict reports ErrTxInputConflict when the referenced
// outpoint is wallet-owned, still eligible for spending, and already attached
// to another transaction. If the wallet owns the parent output but that parent
// is already invalid, the helper returns ErrTxInputInvalidParent instead.
func ensureSpendConflict(ctx context.Context,
	qtx *sqlc.Queries, walletID uint32, txHash chainhash.Hash,
	outputIndex int64, txID int64) error {

	spendByTxID, err := qtx.GetUtxoSpendByOutpoint(
		ctx, sqlc.GetUtxoSpendByOutpointParams{
			WalletID:    int64(walletID),
			TxHash:      txHash[:],
			OutputIndex: outputIndex,
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ensureWalletParentValid(
				ctx, qtx, walletID, txHash, outputIndex,
			)
		}

		return fmt.Errorf("check spend conflict: %w", err)
	}

	if spendByTxID.Valid && spendByTxID.Int64 != txID {
		return db.ErrTxInputConflict
	}

	return nil
}

// ensureWalletParentValid reports ErrTxInputInvalidParent when the
// wallet owns the referenced outpoint but its parent transaction is already
// invalid.
func ensureWalletParentValid(ctx context.Context,
	qtx *sqlc.Queries, walletID uint32, txHash chainhash.Hash,
	outputIndex int64) error {

	hasInvalid, err := qtx.HasInvalidWalletUtxoByOutpoint(
		ctx, sqlc.HasInvalidWalletUtxoByOutpointParams{
			WalletID:    int64(walletID),
			TxHash:      txHash[:],
			OutputIndex: outputIndex,
		},
	)
	if err != nil {
		return fmt.Errorf("check invalid wallet parent: %w", err)
	}

	if hasInvalid {
		return db.ErrTxInputInvalidParent
	}

	return nil
}
