// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"encoding/binary"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// This file defines the prepared inputs and committed results of the Phase 3a
// recovery scan-batch and wallet-rewind semantic operations. They follow the
// Stage 3 contract: the syncer reads a durable snapshot, performs all chain
// I/O, address derivation, and script parsing outside the write transaction,
// and passes the fully prepared, deterministic batch here; the runtime store
// commits one short atomic operation with compare-and-swap guards and returns
// fully materialized committed facts so caches publish and notifications fire
// without another transaction.

// BranchHorizon is one branch-index horizon advance in a scan batch. The
// recovery scan extends an account's lookahead, so the branch next index moves
// from the index observed during preparation to a chosen final index through an
// optimistic compare-and-swap.
type BranchHorizon struct {
	// Scope is the account's key scope.
	Scope waddrmgr.KeyScope

	// Account is the account number within the scope.
	Account uint32

	// Branch is the derivation branch, external or internal.
	Branch uint32

	// ExpectedIndex is the branch's next index observed during preparation.
	// The compare-and-swap advances the branch only while the durable index
	// still equals it, so a concurrent advance is rejected with
	// ErrStaleAccountIndex.
	ExpectedIndex uint32

	// FinalIndex is the branch's next index after the horizon extension. It is
	// the value the compare-and-swap advances the branch to.
	FinalIndex uint32
}

// ScanCredit identifies one wallet-owned output of a scan-batch transaction to
// record as a credit. The output belongs to the incidence of the transaction
// the credit is nested under.
type ScanCredit struct {
	// Index is the transaction output index the credit refers to.
	Index uint32

	// Change reports whether the credit is a change output.
	Change bool
}

// ScanTransaction is one relevant transaction incidence discovered by a scan,
// prepared for the batch. A nil Block records an unmined incidence; a non-nil
// Block records a mined incidence in that block, keyed by the block identity so
// competing same-height blocks remain distinct incidences.
type ScanTransaction struct {
	// Record is the prepared transaction record, serialized outside the write
	// transaction.
	Record *wtxmgr.TxRecord

	// Block is the containing block for a mined incidence, or nil for an
	// unmined incidence.
	Block *wtxmgr.BlockMeta

	// Credits are the wallet-owned outputs of this incidence to record, in
	// output order.
	Credits []ScanCredit
}

// AddressUse is one sticky address-usage mark to apply in a scan batch. Marking
// is monotonic: a used address stays used.
type AddressUse struct {
	// Scope is the address's key scope.
	Scope waddrmgr.KeyScope

	// AddressID is the legacy address identifier, the address's ScriptAddress
	// bytes.
	AddressID []byte
}

// CommitScanResultsRequest is the prepared, deterministic input to a recovery
// scan-batch commit. Every field is computed outside the write transaction: the
// syncer read the base tip, derived the lookahead addresses, ran the chain
// filter, and materialized the discovered transactions and credits. The commit
// applies the whole batch atomically, guarded by the expected base tip
// (ErrStaleTip), the expected branch indexes (ErrStaleAccountIndex), and the
// batch operation identity (SQL journal).
type CommitScanResultsRequest struct {
	// ExpectedTip is the wallet's synced block observed during preparation.
	// The commit advances the synced tip only while the durable synced block
	// still equals it.
	ExpectedTip BlockRef

	// NewTip is the block to advance the wallet's synced tip to after the
	// batch. It is recorded if not already present.
	NewTip BlockRef

	// Blocks are additional block rows to record for the batch, insert-or-
	// return by header hash, so a mined incidence and the new tip reference an
	// existing block. NewTip is always recorded and need not be repeated here.
	Blocks []BlockRef

	// Horizons are the branch-index horizon advances to apply, each an
	// optimistic compare-and-swap guarded on its expected index.
	Horizons []BranchHorizon

	// Addresses are the discovered address rows to insert, in derivation order.
	Addresses []PreparedAddress

	// Transactions are the relevant transaction incidences to record, mined or
	// unmined, in commit order, each with its wallet-owned credits.
	Transactions []ScanTransaction

	// UsedAddresses are the sticky address-usage marks to apply.
	UsedAddresses []AddressUse

	// Guards declares the optional version-domain preconditions applied in the
	// same transaction (SQL only); the KV backend ignores it. It is empty for a
	// plain scan; a caller that must invalidate concurrent preparation sets it.
	Guards Guards

	// OperationID keys the durable journal (SQL only) so a replay is served
	// from the journal instead of reapplying the batch.
	OperationID []byte
}

// CommitScanResultsResult is the committed result of a scan-batch commit,
// materialized so cache publication and notification never need the original
// write transaction. Its events are one relevant-tx event per committed
// transaction incidence followed by the block-connected event for the new tip.
type CommitScanResultsResult struct {
	CommittedFacts

	// Tip is the wallet's synced tip after the batch, equal to the request's
	// new tip.
	Tip BlockRef
}

// CommitWalletRewindRequest is the prepared input to a wallet rewind. A syncer
// located the fork point outside the write transaction; the commit verifies the
// detached tip, reconciles transaction incidences, credits, and spends back to
// the target block, and moves the synced tip to it, guarded by the expected
// current tip (ErrStaleTip).
type CommitWalletRewindRequest struct {
	// ExpectedTip is the wallet's current synced block, the tip being detached.
	// The commit reconciles state only while the durable synced block still
	// equals it.
	ExpectedTip BlockRef

	// TargetBlock is the block to rewind the wallet's synced tip back to. It is
	// the fork point and must be at or below the expected tip and already
	// recorded.
	TargetBlock BlockRef

	// Guards declares the optional version-domain preconditions applied in the
	// same transaction (SQL only); the KV backend ignores it.
	Guards Guards

	// OperationID keys the durable journal (SQL only) so a replay is served
	// from the journal instead of reapplying the rewind.
	OperationID []byte
}

// CommitWalletRewindResult is the committed result of a wallet rewind,
// materialized so cache publication and notification never need the original
// write transaction. Its event is the block-disconnected event for the detached
// tip.
type CommitWalletRewindResult struct {
	CommittedFacts

	// Tip is the wallet's synced tip after the rewind, equal to the request's
	// target block.
	Tip BlockRef
}

// RelevantTxKind is the Kind of the event a scan batch emits for each relevant
// transaction incidence it committed.
const RelevantTxKind = "relevant-tx"

// relevantTxPayloadLen is the byte length of a relevant-tx event payload: the
// 32-byte transaction hash, a mined flag, a big-endian block height, and the
// 32-byte block header hash (zero for an unmined incidence).
const relevantTxPayloadLen = chainhash.HashSize + 1 + 4 + chainhash.HashSize

// RelevantTxEvent builds the fully materialized post-commit event a scan batch
// emits for one relevant transaction incidence. A nil block marks an unmined
// incidence. Both backends derive it from the same payload, so the event
// identity matches across backends and across a journal replay.
func RelevantTxEvent(txHash chainhash.Hash, block *BlockRef) Event {
	payload := make([]byte, relevantTxPayloadLen)
	copy(payload[0:chainhash.HashSize], txHash[:])

	if block != nil {
		payload[chainhash.HashSize] = 1

		//nolint:gosec // A block height is non-negative; the round trip is
		// exact.
		binary.BigEndian.PutUint32(
			payload[chainhash.HashSize+1:], uint32(block.Height),
		)
		copy(payload[chainhash.HashSize+5:], block.Hash[:])
	}

	return Event{
		ID:      DeriveEventID(RelevantTxKind, payload),
		Kind:    RelevantTxKind,
		Payload: payload,
	}
}

// ScanResultEvents materializes the post-commit events a scan batch emits: one
// relevant-tx event per committed transaction incidence, in commit order,
// followed by the block-connected event for the new tip. It is defined in the
// neutral package so the SQL and KV backends build byte-identical events and
// therefore identical event identities for the same batch.
func ScanResultEvents(req CommitScanResultsRequest) []Event {
	events := make([]Event, 0, len(req.Transactions)+1)
	for i := range req.Transactions {
		scanTx := req.Transactions[i]

		var block *BlockRef
		if scanTx.Block != nil {
			block = &BlockRef{
				Height:    scanTx.Block.Height,
				Hash:      scanTx.Block.Hash,
				Timestamp: scanTx.Block.Time,
			}
		}

		events = append(events, RelevantTxEvent(scanTx.Record.Hash, block))
	}

	return append(events, BlockConnectedEvent(req.NewTip))
}
