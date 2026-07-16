// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sqlstore

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// serializeRecord serializes a wtxmgr transaction record for durable SQL
// storage.
//
//nolint:wsl_v5 // The serialization buffer and operation form one unit.
func serializeRecord(record *wtxmgr.TxRecord) ([]byte, error) {
	if len(record.SerializedTx) != 0 {
		return append([]byte(nil), record.SerializedTx...), nil
	}

	var buffer bytes.Buffer
	err := record.MsgTx.Serialize(&buffer)
	if err != nil {
		return nil, fmt.Errorf("serialize transaction: %w", err)
	}

	return buffer.Bytes(), nil
}

// InsertTx records a mined or unmined transaction incidence.
func (s *txStore) InsertTx(record *wtxmgr.TxRecord,
	block *wtxmgr.BlockMeta) error {

	_, err := s.InsertTxCheckIfExists(record, block)
	return err
}

// InsertTxCheckIfExists records an incidence and reports duplicates.
func (s *txStore) InsertTxCheckIfExists(record *wtxmgr.TxRecord,
	block *wtxmgr.BlockMeta) (bool, error) {

	rawTx, err := serializeRecord(record)
	if err != nil {
		return false, err
	}

	if block == nil {
		return s.insertUnmined(record, rawTx)
	}

	return s.insertMined(record, rawTx, block)
}

// transactionID looks up the mined or unmined SQL identifier for a transaction
// incidence.
func (s *txStore) transactionID(hash chainhash.Hash,
	block *wtxmgr.Block) (int64, error) {

	if block == nil {
		return s.queries.GetUnminedTransactionID(
			s.ctx, s.walletID, hash[:],
		)
	}

	return s.queries.GetMinedTransactionID(
		s.ctx, s.walletID, hash[:], block.Height, block.Hash[:],
	)
}

// insertUnmined records an unmined transaction unless the same incidence
// already exists.
//
//nolint:noinlineerr // Each write failure retains operation-local context.
func (s *txStore) insertUnmined(record *wtxmgr.TxRecord,
	rawTx []byte) (bool, error) {

	_, err := s.transactionID(record.Hash, nil)
	if err == nil {
		return true, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("check unmined transaction: %w", err)
	}

	transactionID, err := s.insertTransaction(record, rawTx, nil, 0)
	if err != nil {
		return false, err
	}

	if err := s.insertTransactionInputs(transactionID, record); err != nil {
		return false, err
	}

	return false, nil
}

// insertMined records a mined transaction incidence and reconciles an existing
// unmined row.
//
//nolint:noinlineerr // Each write failure retains operation-local context.
func (s *txStore) insertMined(record *wtxmgr.TxRecord, rawTx []byte,
	block *wtxmgr.BlockMeta) (bool, error) {

	// An existing incidence is idempotent. A transaction mined in another
	// block remains a distinct incidence and continues through insertion.
	_, err := s.transactionID(record.Hash, &block.Block)
	if err == nil {
		return true, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("check mined transaction: %w", err)
	}

	// Materialize the containing block before any transaction references it.
	err = s.queries.PutBlock(s.ctx, BlockRow{
		Height:    block.Height,
		Hash:      block.Hash[:],
		Timestamp: block.Time.Unix(),
	})
	if err != nil {
		return false, fmt.Errorf("put transaction block: %w", err)
	}

	order, err := s.nextBlockOrder(block.Hash[:])
	if err != nil {
		return false, err
	}

	// Reuse an existing unmined incidence when possible. Otherwise insert the
	// mined row and its input dependencies together.
	transactionID, err := s.promoteUnmined(record.Hash, block, order)
	if errors.Is(err, sql.ErrNoRows) {
		transactionID, err = s.insertTransaction(record, rawTx, block, order)
		if err == nil {
			err = s.insertTransactionInputs(transactionID, record)
		}
	}

	if err != nil {
		return false, err
	}

	// A newly mined spend wins over conflicting unmined transactions and must
	// also activate spends of known wallet credits.
	if err := s.removeMinedConflicts(transactionID, record); err != nil {
		return false, err
	}

	if err := s.recordMinedSpends(transactionID, record); err != nil {
		return false, err
	}

	return false, nil
}

// nextBlockOrder returns the next stable transaction order within a block.
func (s *txStore) nextBlockOrder(blockHash []byte) (int64, error) {
	order, err := s.queries.NextBlockTransactionOrder(
		s.ctx, s.walletID, blockHash,
	)
	if err != nil {
		return 0, fmt.Errorf("get next block transaction order: %w", err)
	}

	return order, nil
}

// insertTransaction inserts one transaction row. The caller records the input
// dependencies after the row exists.
func (s *txStore) insertTransaction(record *wtxmgr.TxRecord, rawTx []byte,
	block *wtxmgr.BlockMeta, order int64) (int64, error) {

	var (
		blockHash  []byte
		blockOrder sql.NullInt64
	)
	if block != nil {
		blockHash = block.Hash[:]
		blockOrder = sql.NullInt64{
			Int64: order,
			Valid: true,
		}
	}

	transactionID, err := s.queries.InsertTransaction(
		s.ctx, InsertTransactionParams{
			WalletID:       s.walletID,
			Hash:           record.Hash[:],
			RawTx:          rawTx,
			Received:       record.Received.Unix(),
			BlockHash:      blockHash,
			ConfirmedOrder: blockOrder,
			IsCoinbase:     blockchain.IsCoinBaseTx(&record.MsgTx),
		},
	)
	if err != nil {
		return 0, fmt.Errorf("insert transaction: %w", err)
	}

	return transactionID, nil
}

// promoteUnmined moves an existing unmined transaction into a mined incidence.
func (s *txStore) promoteUnmined(hash chainhash.Hash,
	block *wtxmgr.BlockMeta, order int64) (int64, error) {

	return s.queries.PromoteUnminedTransaction(
		s.ctx, s.walletID, hash[:], block.Hash[:], order,
	)
}

// insertTransactionInputs records every previous outpoint spent by a
// transaction.
func (s *txStore) insertTransactionInputs(transactionID int64,
	record *wtxmgr.TxRecord) error {

	for index, input := range record.MsgTx.TxIn {
		err := s.queries.InsertTransactionInput(
			s.ctx, transactionID, uint32(index),
			input.PreviousOutPoint.Hash[:], input.PreviousOutPoint.Index,
		)
		if err != nil {
			return fmt.Errorf("insert transaction input %d: %w", index, err)
		}
	}

	return nil
}

// removeMinedConflicts removes unmined transactions that conflict with a newly
// mined transaction.
//
//nolint:wsl_v5 // Conflict recursion and deletion are intentionally adjacent.
func (s *txStore) removeMinedConflicts(transactionID int64,
	record *wtxmgr.TxRecord) error {

	// Track rows across inputs because one conflicting transaction may spend
	// more than one output consumed by the mined transaction.
	removed := make(map[int64]struct{})
	for _, input := range record.MsgTx.TxIn {
		conflicts, err := s.queries.ListUnminedSpenders(
			s.ctx, s.walletID,
			input.PreviousOutPoint.Hash[:], input.PreviousOutPoint.Index,
			transactionID,
		)
		if err != nil {
			return fmt.Errorf("list mined transaction conflicts: %w", err)
		}

		for _, conflict := range conflicts {
			if _, ok := removed[conflict.ID]; ok {
				continue
			}

			removed[conflict.ID] = struct{}{}

			// Descendants depend on the conflicting transaction and must be
			// removed before their parent.
			err := s.removeUnminedDescendants(
				conflict.Hash, removed,
			)
			if err != nil {
				return err
			}
			err = s.deleteTransaction(conflict.ID)

			if err != nil {
				return fmt.Errorf("delete mined conflict: %w", err)
			}
		}
	}

	return nil
}

// recordMinedSpends links known wallet credits to the inputs that spend them.
// Every spent outpoint also loses its lease regardless of wallet ownership.
func (s *txStore) recordMinedSpends(transactionID int64,
	record *wtxmgr.TxRecord) error {

	for index, input := range record.MsgTx.TxIn {
		creditID, err := s.queries.GetActiveCreditID(
			s.ctx, s.walletID,
			input.PreviousOutPoint.Hash[:], input.PreviousOutPoint.Index,
		)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("find spent credit: %w", err)
		}

		// Unknown previous outputs are valid transaction inputs, but only a
		// known wallet credit receives a spend record.
		if err == nil {
			_, err = s.queries.RecordCreditSpend(
				s.ctx, s.walletID, creditID, transactionID,
				uint32(index),
			)
			if err != nil {
				return fmt.Errorf("record credit spend: %w", err)
			}
		}

		// Mining consumes the outpoint, so no lease owner may retain it.
		_, err = s.queries.DeleteOutputLeaseAnyOwner(
			s.ctx, s.walletID,
			input.PreviousOutPoint.Hash[:], input.PreviousOutPoint.Index,
		)
		if err != nil {
			return fmt.Errorf("delete spent output lease: %w", err)
		}
	}

	return nil
}

// AddCredit marks a recorded output as wallet-owned. Repeated calls for the
// same transaction incidence and output index are idempotent.
func (s *txStore) AddCredit(record *wtxmgr.TxRecord,
	block *wtxmgr.BlockMeta, index uint32, change bool) error {

	if index >= uint32(len(record.MsgTx.TxOut)) {
		return fmt.Errorf("transaction output %d does not exist", index)
	}

	var incidence *wtxmgr.Block
	if block != nil {
		incidence = &block.Block
	}

	transactionID, err := s.transactionID(record.Hash, incidence)
	if err != nil {
		return fmt.Errorf("find credit transaction: %w", err)
	}

	// Preserve the existing wtxmgr behavior where adding the same credit more
	// than once succeeds without rewriting it.
	_, err = s.queries.GetCreditID(s.ctx, transactionID, index)
	if err == nil {
		return nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check transaction credit: %w", err)
	}

	output := record.MsgTx.TxOut[index]

	creditID, err := s.queries.InsertCredit(
		s.ctx, s.walletID, transactionID, index, output.Value,
		output.PkScript, change,
	)
	if err != nil {
		return fmt.Errorf("insert transaction credit: %w", err)
	}

	// A credit may appear in multiple transaction incidences. The newly added
	// incidence becomes the active wallet output.
	err = s.queries.SetActiveCreditIncidence(s.ctx, s.walletID, creditID)
	if err != nil {
		return fmt.Errorf("activate transaction credit: %w", err)
	}

	return nil
}

// PutTxLabel validates and stores a transaction label.
func (s *txStore) PutTxLabel(hash chainhash.Hash, label string) error {
	if len(label) == 0 {
		return wtxmgr.ErrEmptyLabel
	}

	if len(label) > wtxmgr.TxLabelLimit {
		return wtxmgr.ErrLabelTooLong
	}

	err := s.queries.PutTransactionLabel(
		s.ctx, s.walletID, hash[:], []byte(label),
	)
	if err != nil {
		return fmt.Errorf("put transaction label: %w", err)
	}

	return nil
}

// RemoveUnminedTx removes an unmined transaction and its descendants.
//
//nolint:noinlineerr // The recursive failure is returned without remapping.
func (s *txStore) RemoveUnminedTx(record *wtxmgr.TxRecord) error {
	transactionID, err := s.transactionID(record.Hash, nil)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("find unmined transaction: %w", err)
	}

	removed := map[int64]struct{}{transactionID: {}}
	if err := s.removeUnminedDescendants(record.Hash[:], removed); err != nil {
		return err
	}

	return s.deleteTransaction(transactionID)
}

// knownOutput reports whether an outpoint belongs to a recorded wallet credit.
func (s *txStore) knownOutput(output wire.OutPoint) (bool, error) {
	return s.queries.IsKnownOutput(
		s.ctx, s.walletID, output.Hash[:], output.Index,
	)
}

// LockOutput leases an output to an owner. The caller may renew its own lease,
// but cannot replace another owner's unexpired lease.
func (s *txStore) LockOutput(id wtxmgr.LockID, output wire.OutPoint,
	duration time.Duration) (time.Time, error) {

	known, err := s.knownOutput(output)
	if err != nil {
		return time.Time{}, fmt.Errorf("check output: %w", err)
	}

	if !known {
		return time.Time{}, wtxmgr.ErrUnknownOutput
	}

	now := time.Now()

	lockedID, expiration, found, err := s.outputLease(output)
	if err != nil {
		return time.Time{}, err
	}

	// An expired lease or a lease held by this owner may be replaced.
	if found && now.Before(expiration) && lockedID != id {
		return time.Time{}, wtxmgr.ErrOutputAlreadyLocked
	}

	expires := now.Add(duration)

	rows, err := s.queries.AcquireOutputLease(
		s.ctx, s.walletID, output.Hash[:], output.Index, id[:],
		expires.Unix(), now.Unix(),
	)
	if err != nil {
		return time.Time{}, fmt.Errorf("lock output: %w", err)
	}

	if rows == 0 {
		return time.Time{}, wtxmgr.ErrOutputAlreadyLocked
	}

	return expires, nil
}

// outputLease loads the current lease owner and expiration for an output.
func (s *txStore) outputLease(output wire.OutPoint) (wtxmgr.LockID,
	time.Time, bool, error) {

	row, err := s.queries.GetOutputLease(
		s.ctx, s.walletID, output.Hash[:], output.Index,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return wtxmgr.LockID{}, time.Time{}, false, nil
	}

	if err != nil {
		return wtxmgr.LockID{}, time.Time{}, false,
			fmt.Errorf("get output lease: %w", err)
	}

	if len(row.LockID) != len(wtxmgr.LockID{}) {
		return wtxmgr.LockID{}, time.Time{}, false,
			fmt.Errorf("invalid output lease id length %d", len(row.LockID))
	}

	var id wtxmgr.LockID
	copy(id[:], row.LockID)

	return id, time.Unix(row.Expiration, 0), true, nil
}

// UnlockOutput releases an output lease held by the owner. Missing and expired
// leases are treated as already unlocked.
func (s *txStore) UnlockOutput(id wtxmgr.LockID, output wire.OutPoint) error {
	known, err := s.knownOutput(output)
	if err != nil {
		return fmt.Errorf("check output: %w", err)
	}

	if !known {
		return wtxmgr.ErrUnknownOutput
	}

	lockedID, expiration, found, err := s.outputLease(output)
	if err != nil {
		return err
	}

	if !found || !time.Now().Before(expiration) {
		return nil
	}

	// Only the current owner may release a live lease.
	if lockedID != id {
		return wtxmgr.ErrOutputUnlockNotAllowed
	}

	_, err = s.queries.DeleteOutputLease(
		s.ctx, s.walletID, output.Hash[:], output.Index, id[:],
	)

	return err
}

// DeleteExpiredLockedOutputs removes expired output leases.
func (s *txStore) DeleteExpiredLockedOutputs() error {
	_, err := s.queries.DeleteExpiredOutputLeases(
		s.ctx, s.walletID, time.Now().Unix(),
	)

	return err
}

// ListLockedOutputs returns all currently active output leases.
func (s *txStore) ListLockedOutputs() ([]*wtxmgr.LockedOutput, error) {
	rows, err := s.queries.ListActiveOutputLeases(
		s.ctx, s.walletID, time.Now().Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("list output leases: %w", err)
	}

	outputs := make([]*wtxmgr.LockedOutput, 0, len(rows))
	for _, row := range rows {
		hash, err := chainhash.NewHash(row.Hash)
		if err != nil {
			return nil, fmt.Errorf("decode leased output hash: %w", err)
		}

		if row.Index < 0 || row.Index > int64(^uint32(0)) {
			return nil, fmt.Errorf("leased output index out of range: %d",
				row.Index)
		}

		if len(row.LockID) != len(wtxmgr.LockID{}) {
			return nil, fmt.Errorf("invalid output lease id length %d",
				len(row.LockID))
		}

		var id wtxmgr.LockID
		copy(id[:], row.LockID)
		outputs = append(outputs, &wtxmgr.LockedOutput{
			Outpoint: wire.OutPoint{
				Hash:  *hash,
				Index: uint32(row.Index),
			},
			LockID:     id,
			Expiration: time.Unix(row.Expiration, 0),
		})
	}

	return outputs, nil
}
