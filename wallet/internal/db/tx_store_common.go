package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

var (
	// ErrInvalidParam is returned when a TxStore method receives invalid input.
	ErrInvalidParam = errors.New("invalid param")

	// ErrInvalidStatus is returned when a transaction status is unknown or not
	// allowed for the requested operation.
	ErrInvalidStatus = errors.New("invalid transaction status")

	// ErrIndexOutOfRange is returned when a referenced transaction input or
	// output index does not exist.
	ErrIndexOutOfRange = errors.New("index out of range")

	// ErrDuplicateInputOutPoint is returned when CreateTx receives the same
	// previous outpoint more than once.
	ErrDuplicateInputOutPoint = errors.New("duplicate input outpoint")
)

// serializeMsgTx serializes a wire.MsgTx so it can be stored in the
// transactions table.
func serializeMsgTx(tx *wire.MsgTx) ([]byte, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: tx is required", ErrInvalidParam)
	}

	var buf bytes.Buffer

	err := tx.Serialize(&buf)
	if err != nil {
		return nil, fmt.Errorf("serialize tx: %w", err)
	}

	return buf.Bytes(), nil
}

// deserializeMsgTx deserializes a stored transaction payload back into a
// wire.MsgTx.
func deserializeMsgTx(rawTx []byte) (*wire.MsgTx, error) {
	var tx wire.MsgTx

	err := tx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		return nil, fmt.Errorf("deserialize tx: %w", err)
	}

	return &tx, nil
}

// parseTxStatus converts a stored numeric status code into the strongly typed
// TxStatus enum used by the public db API.
func parseTxStatus(status int64) (TxStatus, error) {
	txStatus, err := int64ToUint8(status)
	if err != nil {
		return TxStatus(0), fmt.Errorf("status %d: %w", status,
			ErrInvalidStatus)
	}

	switch TxStatus(txStatus) {
	case TxStatusPending,
		TxStatusPublished,
		TxStatusReplaced,
		TxStatusFailed,
		TxStatusOrphaned:

		return TxStatus(txStatus), nil

	default:
		return TxStatus(0), fmt.Errorf("status %d: %w", status,
			ErrInvalidStatus)
	}
}

// buildTxInfo converts normalized transaction fields into the public TxInfo
// shape returned by the db interfaces.
func buildTxInfo(hash []byte, rawTx []byte, received time.Time, block *Block,
	status int64, label string) (*TxInfo, error) {

	txHash, err := chainhash.NewHash(hash)
	if err != nil {
		return nil, fmt.Errorf("tx hash: %w", err)
	}

	txStatus, err := parseTxStatus(status)
	if err != nil {
		return nil, err
	}

	return &TxInfo{
		Hash:         *txHash,
		SerializedTx: rawTx,
		Received:     received.UTC(),
		Block:        block,
		Status:       txStatus,
		Label:        label,
	}, nil
}

// validateCreateTxParams enforces the CreateTx invariants shared by both SQL
// backends after serializeMsgTx has already verified that params.Tx is non-nil.
func validateCreateTxParams(params CreateTxParams) error {
	isCoinbase := blockchain.IsCoinBaseTx(params.Tx)

	err := validateCreateTxStatus(
		params.Status, params.Block != nil, isCoinbase,
	)
	if err != nil {
		return err
	}

	maxIndex := uint64(len(params.Tx.TxOut))

	for index := range params.Credits {
		if uint64(index) >= maxIndex {
			return fmt.Errorf("%w: credit index %d is out of range: %w",
				ErrInvalidParam, index, ErrIndexOutOfRange)
		}
	}

	// Coinbase transactions only enter wallet history once a block already
	// anchors them, so CreateTx requires the caller to provide that block up
	// front instead of storing a fake unmined intermediate row first.
	if isCoinbase {
		return nil
	}

	seenInputs := make(map[wire.OutPoint]struct{}, len(params.Tx.TxIn))
	for inputIndex, txIn := range params.Tx.TxIn {
		// One transaction cannot spend the same previous outpoint twice.
		// Rejecting duplicate inputs here keeps the later wallet-spend walk
		// simple and avoids writing contradictory spend metadata.
		if _, ok := seenInputs[txIn.PreviousOutPoint]; ok {
			return fmt.Errorf("%w: input %d duplicates a previous outpoint: %w",
				ErrInvalidParam, inputIndex, ErrDuplicateInputOutPoint)
		}

		seenInputs[txIn.PreviousOutPoint] = struct{}{}
	}

	return nil
}

// validateCreateTxStatus checks the status/block combinations that CreateTx may
// store directly.
func validateCreateTxStatus(status TxStatus, hasBlock bool,
	isCoinbase bool) error {

	_, err := parseTxStatus(int64(status))
	if err != nil {
		return fmt.Errorf("%w: status %d is not supported: %w",
			ErrInvalidParam, status, ErrInvalidStatus)
	}

	// Orphaned rows only arise later when rollback disconnects a confirmed
	// coinbase transaction. CreateTx records the initial observed facts, so it
	// never inserts orphaned history directly.
	if status == TxStatusOrphaned {
		return fmt.Errorf("%w: CreateTx cannot insert orphaned txns: %w",
			ErrInvalidParam, ErrInvalidStatus)
	}

	if !hasBlock {
		// Coinbase transactions cannot exist without a confirming block from
		// the store's point of view, so callers must supply that block up
		// front.
		if isCoinbase {
			return fmt.Errorf("%w: coinbase txns require a block: %w",
				ErrInvalidParam, ErrInvalidStatus)
		}

		// Unmined non-coinbase inserts still represent current unmined wallet
		// history, so CreateTx only accepts the two active unmined statuses
		// there.
		if status != TxStatusPending && status != TxStatusPublished {
			return fmt.Errorf("%w: CreateTx requires pending or published: %w",
				ErrInvalidParam, ErrInvalidStatus)
		}

		return nil
	}

	// A non-nil block means the caller already knows the transaction is mined.
	// Mined rows must be published immediately to satisfy the transaction-state
	// invariants enforced by the schema.
	if status != TxStatusPublished {
		return fmt.Errorf("%w: confirmed txns must be published: %w",
			ErrInvalidParam, ErrInvalidStatus)
	}

	return nil
}

// createTxRequest captures the backend-independent CreateTx inputs after the
// shared validation and normalization step has already succeeded.
type createTxRequest struct {
	// params keeps the original public request available for backend helpers
	// that still need the caller-supplied CreateTx metadata.
	params CreateTxParams

	// rawTx stores the serialized transaction bytes once so both backends reuse
	// the same payload throughout the write.
	rawTx []byte

	// txHash avoids recomputing the transaction hash across the shared flow and
	// backend adapters.
	txHash chainhash.Hash

	// received is normalized to UTC before any backend insert logic runs.
	received time.Time

	// isCoinbase caches the consensus coinbase check for backend insert params.
	isCoinbase bool
}

// newCreateTxRequest performs the backend-independent CreateTx preparation
// shared by both SQL stores before they open a write transaction.
func newCreateTxRequest(params CreateTxParams) (createTxRequest, error) {
	rawTx, err := serializeMsgTx(params.Tx)
	if err != nil {
		return createTxRequest{}, err
	}

	err = validateCreateTxParams(params)
	if err != nil {
		return createTxRequest{}, err
	}

	return createTxRequest{
		params:     params,
		rawTx:      rawTx,
		txHash:     params.Tx.TxHash(),
		received:   params.Received.UTC(),
		isCoinbase: blockchain.IsCoinBaseTx(params.Tx),
	}, nil
}

// createTxOps is the small semantic adapter CreateTx needs from one SQL
// backend.
//
// The shared CreateTx algorithm is intentionally linear:
//   - load any existing wallet-scoped row for the same tx hash first
//   - if the same tx is being reconfirmed, update that existing row instead of
//     inserting a duplicate
//   - validate and cache any confirming block metadata before later writes use
//     it
//   - when the incoming tx is confirmed, discover and invalidate any direct
//     conflict roots before the new row claims their wallet-owned inputs
//   - insert the base transaction row exactly once when no existing row can be
//     reused
//   - insert every wallet-owned credited output as a UTXO
//   - attach any wallet-owned spent inputs to that final transaction row
//
// Each backend implements those steps with its own sqlc-generated query types
// while createTxWithOps keeps the high-level sequencing in one place.
// That sequencing matters because confirmation, conflict invalidation, credit
// creation, and spent-input claims must either all observe the same tx row or
// all roll back together.
type createTxOps interface {
	// hasExisting reports whether CreateTx would collide with an existing
	// wallet-scoped transaction row for the same hash.
	hasExisting(ctx context.Context, req createTxRequest) (bool, error)

	// prepareBlock validates and caches any optional confirming block metadata
	// the later insert step needs.
	prepareBlock(ctx context.Context, req createTxRequest) error

	// insert writes the base transaction row and returns its new primary key.
	insert(ctx context.Context, req createTxRequest) (int64, error)

	// insertCredits records every wallet-owned output that the caller
	// marked as a credit for this transaction.
	insertCredits(ctx context.Context, req createTxRequest, txID int64) error

	// markInputsSpent attaches wallet-owned parent outpoints to this
	// transaction row and rejects conflicts or invalid wallet parents.
	markInputsSpent(ctx context.Context, req createTxRequest, txID int64) error
}

// createTxWithOps runs the backend-independent CreateTx orchestration once the
// caller has opened a backend-specific SQL transaction.
//
// The helper inserts the base transaction row before it records credits or
// spent inputs so every later step can point at one stable row ID. If any later
// step fails, ExecuteTx rolls the whole write back.
func createTxWithOps(ctx context.Context, req createTxRequest,
	ops createTxOps) error {

	exists, err := ops.hasExisting(ctx, req)
	if err != nil {
		return fmt.Errorf("prepare create tx: check existing tx: %w", err)
	}

	if exists {
		return fmt.Errorf("prepare create tx: tx %s: %w", req.txHash,
			ErrTxAlreadyExists)
	}

	err = ops.prepareBlock(ctx, req)
	if err != nil {
		return fmt.Errorf("prepare create block assignment: %w", err)
	}

	txID, err := ops.insert(ctx, req)
	if err != nil {
		return fmt.Errorf("insert tx: %w", err)
	}

	err = ops.insertCredits(ctx, req, txID)
	if err != nil {
		return fmt.Errorf("create tx credits: %w", err)
	}

	err = ops.markInputsSpent(ctx, req, txID)
	if err != nil {
		return fmt.Errorf("create tx spends: %w", err)
	}

	return nil
}
