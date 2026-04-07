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
// and spent-parent markers are either committed together or not at all.
// Received timestamps are normalized to UTC before insert. CreateTx is
// insert-only and returns ErrTxAlreadyExists if the wallet already stores the
// tx hash.
func (s *PostgresStore) CreateTx(ctx context.Context,
	params CreateTxParams) error {

	req, err := newCreateTxRequest(params)
	if err != nil {
		return err
	}

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		return createTxWithOps(ctx, req, &pgCreateTxOps{
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

var _ createTxOps = (*pgCreateTxOps)(nil)

// hasExisting reports whether the wallet already stores the requested tx hash.
func (o *pgCreateTxOps) hasExisting(ctx context.Context,
	req createTxRequest) (bool, error) {

	_, err := o.qtx.GetTransactionMetaByHash(
		ctx,
		sqlcpg.GetTransactionMetaByHashParams{
			WalletID: int64(req.params.WalletID),
			TxHash:   req.txHash[:],
		},
	)
	if err == nil {
		return true, nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	return false, fmt.Errorf("get tx metadata: %w", err)
}

// prepareBlock validates the optional confirming block and caches the postgres
// block-height value that the later insert query will store.
func (o *pgCreateTxOps) prepareBlock(ctx context.Context,
	req createTxRequest) error {

	o.blockHeight = sql.NullInt32{}

	if req.params.Block == nil {
		return nil
	}

	height, err := requireBlockMatchesPg(ctx, o.qtx, req.params.Block)
	if err != nil {
		return err
	}

	o.blockHeight = sql.NullInt32{Int32: height, Valid: true}

	return nil
}

// insert stores one new postgres transaction row for CreateTx.
func (o *pgCreateTxOps) insert(ctx context.Context,
	req createTxRequest) (int64, error) {

	txID, err := o.qtx.InsertTransaction(ctx, sqlcpg.InsertTransactionParams{
		WalletID:     int64(req.params.WalletID),
		TxHash:       req.txHash[:],
		RawTx:        req.rawTx,
		BlockHeight:  o.blockHeight,
		TxStatus:     int16(req.params.Status),
		ReceivedTime: req.received,
		IsCoinbase:   req.isCoinbase,
		TxLabel:      req.params.Label,
	})
	if err != nil {
		return 0, fmt.Errorf("insert tx row: %w", err)
	}

	return txID, nil
}

// insertCredits stores any wallet-owned outputs created by the transaction.
func (o *pgCreateTxOps) insertCredits(ctx context.Context,
	req createTxRequest, txID int64) error {

	return insertCreditsPg(ctx, o.qtx, req.params, txID)
}

// markInputsSpent records wallet-owned inputs spent by the transaction.
func (o *pgCreateTxOps) markInputsSpent(ctx context.Context,
	req createTxRequest, txID int64) error {

	return markInputsSpentPg(ctx, o.qtx, req.params, txID)
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

		outputIndex, err := uint32ToInt32(index)
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
			return fmt.Errorf("insert credit output %d: %w", index, err)
		}
	}

	return nil
}

// creditExistsPg reports whether the wallet already has a UTXO row for the
// given credited output, even if that output is now spent by a child tx.
func creditExistsPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txHash chainhash.Hash, outputIndex uint32) (bool, error) {

	convertedIndex, err := uint32ToInt32(outputIndex)
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
		outputIndex, err := uint32ToInt32(txIn.PreviousOutPoint.Index)
		if err != nil {
			return fmt.Errorf("convert input outpoint index %d: %w", inputIndex,
				err)
		}

		spentInputIndex, err := int64ToInt32(int64(inputIndex))
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
