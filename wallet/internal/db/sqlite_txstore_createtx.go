package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chainhash/v2"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// CreateTx atomically records a wallet-scoped transaction row, its wallet-owned
// credits, and any spend edges created by its inputs.
//
// The full write runs inside ExecuteTx so the transaction row, created UTXOs,
// and spent-parent markers are either committed together or not at all.
// Received timestamps are normalized to UTC before insert. CreateTx is
// insert-only and returns ErrTxAlreadyExists if the wallet already stores the
// tx hash.
func (s *SqliteStore) CreateTx(ctx context.Context,
	params CreateTxParams) error {

	req, err := newCreateTxRequest(params)
	if err != nil {
		return err
	}

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		return createTxWithOps(ctx, req, &sqliteCreateTxOps{qtx: qtx})
	})
}

// sqliteCreateTxOps adapts sqlite sqlc queries to the shared CreateTx flow.
type sqliteCreateTxOps struct {
	qtx *sqlcsqlite.Queries

	blockHeight sql.NullInt64
}

var _ createTxOps = (*sqliteCreateTxOps)(nil)

// hasExisting reports whether the wallet already stores the requested tx hash.
func (o *sqliteCreateTxOps) hasExisting(ctx context.Context,
	req createTxRequest) (bool, error) {

	_, err := o.qtx.GetTransactionMetaByHash(
		ctx,
		sqlcsqlite.GetTransactionMetaByHashParams{
			WalletID: int64(req.params.WalletID),
			TxHash:   req.txHash[:],
		},
	)

	// Exit early if there is no error.
	if err == nil {
		return true, nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	return false, fmt.Errorf("get tx metadata: %w", err)
}

// prepareBlock validates the optional confirming block and caches the sqlite
// block-height value that the later insert query will store.
func (o *sqliteCreateTxOps) prepareBlock(ctx context.Context,
	req createTxRequest) error {

	o.blockHeight = sql.NullInt64{}

	if req.params.Block == nil {
		return nil
	}

	height, err := requireBlockMatchesSqlite(ctx, o.qtx, req.params.Block)
	if err != nil {
		return err
	}

	o.blockHeight = sql.NullInt64{Int64: height, Valid: true}

	return nil
}

// insert stores one new sqlite transaction row for CreateTx.
func (o *sqliteCreateTxOps) insert(ctx context.Context,
	req createTxRequest) (int64, error) {

	txID, err := o.qtx.InsertTransaction(
		ctx,
		sqlcsqlite.InsertTransactionParams{
			WalletID:     int64(req.params.WalletID),
			TxHash:       req.txHash[:],
			RawTx:        req.rawTx,
			BlockHeight:  o.blockHeight,
			TxStatus:     int64(req.params.Status),
			ReceivedTime: req.received,
			IsCoinbase:   req.isCoinbase,
			TxLabel:      req.params.Label,
		},
	)
	if err != nil {
		return 0, fmt.Errorf("insert tx row: %w", err)
	}

	return txID, nil
}

// insertCredits stores any wallet-owned outputs created by the transaction.
func (o *sqliteCreateTxOps) insertCredits(ctx context.Context,
	req createTxRequest, txID int64) error {

	return insertCreditsSqlite(ctx, o.qtx, req.params, txID)
}

// markInputsSpent records wallet-owned inputs spent by the transaction.
func (o *sqliteCreateTxOps) markInputsSpent(ctx context.Context,
	req createTxRequest, txID int64) error {

	return markInputsSpentSqlite(ctx, o.qtx, req.params, txID)
}

// insertCreditsSqlite inserts one wallet-owned UTXO row for each credited
// output of the transaction being stored.
func insertCreditsSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	params CreateTxParams, txID int64) error {

	for index := range params.Credits {
		creditExists, err := creditExistsSqlite(
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
			ctx, sqlcsqlite.GetAddressByScriptPubKeyParams{
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

		_, err = qtx.InsertUtxo(ctx, sqlcsqlite.InsertUtxoParams{
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

// creditExistsSqlite reports whether the wallet already has a UTXO row for the
// given credited output, even if that output is now spent by a child tx.
func creditExistsSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	walletID uint32, txHash chainhash.Hash, outputIndex uint32) (bool, error) {

	_, err := qtx.GetUtxoSpendByOutpoint(
		ctx, sqlcsqlite.GetUtxoSpendByOutpointParams{
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

// markInputsSpentSqlite attaches wallet-owned outpoints spent by the stored
// transaction to its row ID and input indexes.
//
// If another wallet transaction already owns the spend edge for a
// wallet-controlled input, the create path fails with ErrTxInputConflict
// instead of silently storing a second spender. Inputs that reference a
// wallet-owned output whose parent transaction is already invalid fail with
// ErrTxInputInvalidParent.
func markInputsSpentSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	params CreateTxParams, txID int64) error {

	if blockchain.IsCoinBaseTx(params.Tx) {
		return nil
	}

	for inputIndex, txIn := range params.Tx.TxIn {
		spentInputIndex := sql.NullInt64{Int64: int64(inputIndex), Valid: true}

		rowsAffected, err := qtx.MarkUtxoSpent(ctx,
			sqlcsqlite.MarkUtxoSpentParams{
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
			err = ensureSpendConflictSqlite(
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

// ensureSpendConflictSqlite reports ErrTxInputConflict when the referenced
// outpoint is wallet-owned, still eligible for spending, and already attached
// to another transaction. If the wallet owns the parent output but that parent
// is already invalid, the helper returns ErrTxInputInvalidParent instead.
func ensureSpendConflictSqlite(ctx context.Context,
	qtx *sqlcsqlite.Queries, walletID uint32, txHash chainhash.Hash,
	outputIndex int64, txID int64) error {

	spendByTxID, err := qtx.GetUtxoSpendByOutpoint(
		ctx, sqlcsqlite.GetUtxoSpendByOutpointParams{
			WalletID:    int64(walletID),
			TxHash:      txHash[:],
			OutputIndex: outputIndex,
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ensureWalletParentValidSqlite(
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

// ensureWalletParentValidSqlite reports ErrTxInputInvalidParent when the
// wallet owns the referenced outpoint but its parent transaction is already
// invalid.
func ensureWalletParentValidSqlite(ctx context.Context,
	qtx *sqlcsqlite.Queries, walletID uint32, txHash chainhash.Hash,
	outputIndex int64) error {

	hasInvalid, err := qtx.HasInvalidWalletUtxoByOutpoint(
		ctx, sqlcsqlite.HasInvalidWalletUtxoByOutpointParams{
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
