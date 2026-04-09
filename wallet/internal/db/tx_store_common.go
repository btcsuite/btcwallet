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
	ErrInvalidStatus = errors.New("invalid tx status")

	// ErrIndexOutOfRange is returned when a referenced transaction input or
	// output index does not exist.
	ErrIndexOutOfRange = errors.New("index out of range")

	// ErrDuplicateInputOutPoint is returned when CreateTx receives the same
	// previous outpoint more than once.
	ErrDuplicateInputOutPoint = errors.New("duplicate input outpoint")

	// ErrDeleteRequiresUnmined indicates that DeleteTx only accepts unmined
	// transactions.
	ErrDeleteRequiresUnmined = errors.New(
		"delete requires an unmined transaction",
	)

	// ErrDeleteRequiresLeaf indicates that DeleteTx only accepts unmined
	// transactions with no child spenders.
	ErrDeleteRequiresLeaf = errors.New("delete requires a leaf tx")
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

// ParseTxStatus converts a stored numeric status code into the strongly typed
// TxStatus enum used by the public db API.
func ParseTxStatus(status int64) (TxStatus, error) {
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

// BuildTxInfo converts normalized transaction fields into the public TxInfo
// shape returned by the db interfaces.
func BuildTxInfo(hash []byte, rawTx []byte, received time.Time, block *Block,
	status int64, label string) (*TxInfo, error) {

	txHash, err := chainhash.NewHash(hash)
	if err != nil {
		return nil, fmt.Errorf("tx hash: %w", err)
	}

	txStatus, err := ParseTxStatus(status)
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

	_, err := ParseTxStatus(int64(status))
	if err != nil {
		return fmt.Errorf("%w: status %d is not supported: %w",
			ErrInvalidParam, status, ErrInvalidStatus)
	}

	// Orphaned rows only arise later when rollback disconnects a confirmed
	// coinbase transaction. CreateTx records the initial observed facts, so it
	// never inserts orphaned history directly.
	if status == TxStatusOrphaned {
		return fmt.Errorf("%w: CreateTx cannot Insert orphaned txns: %w",
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

// CreateTxRequest captures the backend-independent CreateTx inputs after the
// shared validation and normalization step has already succeeded.
type CreateTxRequest struct {
	// Params keeps the original public request available for backend helpers
	// that still need the caller-supplied CreateTx metadata.
	Params CreateTxParams

	// RawTx stores the serialized transaction bytes once so both backends reuse
	// the same payload throughout the write.
	RawTx []byte

	// TxHash avoids recomputing the transaction hash across the shared flow and
	// backend adapters.
	TxHash chainhash.Hash

	// Received is normalized to UTC before any backend insert logic runs.
	Received time.Time

	// IsCoinbase caches the consensus coinbase check for backend insert params.
	IsCoinbase bool
}

// NewCreateTxRequest performs the backend-independent CreateTx preparation
// shared by both SQL stores before they open a write transaction.
func NewCreateTxRequest(params CreateTxParams) (CreateTxRequest, error) {
	rawTx, err := serializeMsgTx(params.Tx)
	if err != nil {
		return CreateTxRequest{}, err
	}

	err = validateCreateTxParams(params)
	if err != nil {
		return CreateTxRequest{}, err
	}

	return CreateTxRequest{
		Params:     params,
		RawTx:      rawTx,
		TxHash:     params.Tx.TxHash(),
		Received:   params.Received.UTC(),
		IsCoinbase: blockchain.IsCoinBaseTx(params.Tx),
	}, nil
}

// CreateTxExistingTarget is the normalized metadata the shared CreateTx flow
// needs when the wallet already stores the requested tx hash.
type CreateTxExistingTarget struct {
	// ID is the backend row ID.
	ID int64

	// Status is the wallet-relative transaction status.
	Status TxStatus

	// HasBlock reports whether the row already has confirming block metadata.
	HasBlock bool

	// IsCoinbase reports whether the row records coinbase history.
	IsCoinbase bool
}

// ErrCreateTxExistingNotFound reports that CreateTx found no existing row.
var ErrCreateTxExistingNotFound = errors.New("create tx existing target not " +
	"found")

// CreateTxOps is the small semantic adapter CreateTx needs from one SQL
// backend.
//
// The shared CreateTx algorithm is intentionally linear:
//   - load any existing wallet-scoped row for the same tx hash first
//   - if the same tx is being reconfirmed, update that existing row instead of
//     inserting a duplicate
//   - validate and cache any confirming block metadata before later writes use
//     it
//   - Insert the base transaction row exactly once when no existing row can be
//     reused
//   - when the incoming tx is confirmed, discover any direct conflict roots
//     before later writes claim shared inputs or rewrite that branch
//   - if direct conflicts were found, rewrite those roots to replaced state,
//     fail their descendants, and record replacement history before the new
//     row claims their wallet-owned inputs
//   - Insert every wallet-owned credited output as a UTXO
//   - attach any wallet-owned spent inputs to that final transaction row
//
// Each backend implements those steps with its own sqlc-generated query types
// while CreateTxWithOps keeps the high-level sequencing in one place.
// That sequencing matters because confirmation, conflict invalidation, credit
// creation, and spent-input claims must either all observe the same tx row or
// all roll back together.
type CreateTxOps interface {
	InvalidateUnminedTxOps

	// LoadExisting loads any existing wallet-scoped transaction row for the
	// same hash.
	LoadExisting(ctx context.Context, req CreateTxRequest) (
		*CreateTxExistingTarget, error)

	// ConfirmExisting reuses one existing row when CreateTx learns about the
	// same transaction with confirming block context later.
	ConfirmExisting(ctx context.Context, req CreateTxRequest,
		existing CreateTxExistingTarget) error

	// PrepareBlock validates and caches any optional confirming block metadata
	// the later Insert step needs.
	PrepareBlock(ctx context.Context, req CreateTxRequest) error

	// ListConflictTxns returns the direct wallet-owned conflict tx IDs plus the
	// corresponding hashes used for descendant discovery.
	ListConflictTxns(ctx context.Context, req CreateTxRequest) ([]int64,
		[]chainhash.Hash, error)

	// MarkTxnsReplaced batch-marks the provided direct conflict roots
	// as replaced.
	MarkTxnsReplaced(ctx context.Context, walletID int64, txIDs []int64) error

	// InsertReplacementEdges records replacement-history edges from each direct
	// conflict root to the newly inserted confirmed transaction row.
	InsertReplacementEdges(ctx context.Context, walletID int64,
		replacedTxIDs []int64, replacementTxID int64) error

	// Insert writes the base transaction row and returns its new primary key.
	Insert(ctx context.Context, req CreateTxRequest) (int64, error)

	// InsertCredits records every wallet-owned output that the caller
	// marked as a credit for this transaction.
	InsertCredits(ctx context.Context, req CreateTxRequest, txID int64) error

	// MarkInputsSpent attaches wallet-owned parent outpoints to this
	// transaction row and rejects conflicts or invalid wallet parents.
	MarkInputsSpent(ctx context.Context, req CreateTxRequest, txID int64) error
}

// checkReuseCreateTx reports whether CreateTx should reuse an existing wallet-
// scoped row instead of inserting a new one.
func checkReuseCreateTx(req CreateTxRequest,
	existing CreateTxExistingTarget) bool {

	// Only a newly confirmed observation can reuse an existing row.
	// Plain unmined inserts still create fresh unmined history
	// instead of rewriting one existing record in place.
	if req.Params.Block == nil {
		return false
	}

	// Reuse is only for the mined published state that records
	// the wallet's final view of the tx once a block anchors it.
	if req.Params.Status != TxStatusPublished {
		return false
	}

	// A row that already has a confirming block is already in its final mined
	// form, so CreateTx must reject the duplicate instead of mutating it again.
	if existing.HasBlock {
		return false
	}

	// Coinbase rows only reuse the orphaned state. That path restores the same
	// coinbase hash after rollback disconnected its previous confirming block.
	if existing.IsCoinbase {
		// Both sides must still be coinbase history, and the existing
		// row must be the rollback-created orphan that is waiting for a
		// confirming block again.
		return req.IsCoinbase && existing.Status == TxStatusOrphaned
	}

	// Non-coinbase rows only reuse the current unmined states.
	// Once a row is invalidated, UpdateTx/DeleteTx no longer
	// treat it as a live unmined target.
	if !IsUnminedStatus(existing.Status) {
		return false
	}

	return true
}

// loadCreateTxExisting resolves any wallet-scoped row already stored for the
// requested tx hash and reports whether one was found.
func loadCreateTxExisting(ctx context.Context, req CreateTxRequest,
	ops CreateTxOps) (*CreateTxExistingTarget, bool, error) {

	existing, err := ops.LoadExisting(ctx, req)
	if err != nil && !errors.Is(err, ErrCreateTxExistingNotFound) {
		return nil, false, fmt.Errorf("load create tx target: %w", err)
	}

	if errors.Is(err, ErrCreateTxExistingNotFound) {
		return nil, false, nil
	}

	if existing == nil {
		return nil, false, nil
	}

	return existing, true, nil
}

// collectConflictDescendants loads the live unmined graph snapshot and returns
// the descendant tx IDs for the provided direct conflict roots.
//
// NOTE: rootHashes is expected to be a set with unique tx hashes.
func collectConflictDescendants(ctx context.Context, walletID int64,
	rootHashes []chainhash.Hash, rootIDs []int64,
	ops CreateTxOps) ([]int64, error) {

	candidates, err := ops.ListUnminedTxRecords(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("list create tx conflict candidates: %w", err)
	}

	descendantIDs := CollectDescendantTxIDs(rootHashes, rootIDs, candidates)

	return descendantIDs, nil
}

// handleRootTxns clears the direct root spends, marks those rows replaced, and
// records replacement edges to the winning confirmed tx.
func handleRootTxns(ctx context.Context, walletID int64, rootIDs []int64,
	replacementTxID int64, ops CreateTxOps) error {

	for _, rootID := range rootIDs {
		err := ops.ClearSpentUtxos(ctx, walletID, rootID)
		if err != nil {
			return fmt.Errorf("clear replaced root spent utxos: %w", err)
		}
	}

	err := ops.MarkTxnsReplaced(ctx, walletID, rootIDs)
	if err != nil {
		return fmt.Errorf("mark direct conflicts replaced: %w", err)
	}

	err = ops.InsertReplacementEdges(ctx, walletID, rootIDs, replacementTxID)
	if err != nil {
		return fmt.Errorf("record conflict replacement edges: %w", err)
	}

	return nil
}

// handleTxDescendants clears the discovered descendant spends and then marks
// that dependent branch failed.
func handleTxDescendants(ctx context.Context, walletID int64,
	descendantIDs []int64, ops CreateTxOps) error {

	if len(descendantIDs) == 0 {
		return nil
	}

	for _, descendantID := range descendantIDs {
		err := ops.ClearSpentUtxos(ctx, walletID, descendantID)
		if err != nil {
			return fmt.Errorf("clear failed descendant spent utxos: %w", err)
		}
	}

	err := ops.MarkTxnsFailed(ctx, walletID, descendantIDs)
	if err != nil {
		return fmt.Errorf("mark conflict descendants failed: %w", err)
	}

	return nil
}

// handleTxConflicts discovers the direct conflicting roots of a new confirmed
// tx, rewrites them to replaced state, and marks their descendants failed.
//
// The replacement algorithm is intentionally ordered:
//   - load the direct conflicting roots first
//   - load the live unmined graph snapshot used for descendant discovery
//   - discover every descendant that depends on those roots before any mutation
//     starts
//   - handle the direct root txns first
//   - handle the descendant txns second
//
// That sequencing preserves replacement history for the direct conflicts while
// still invalidating the dependent branch atomically inside one SQL
// transaction.
func handleTxConflicts(ctx context.Context, req CreateTxRequest,
	replacementTxID int64, ops CreateTxOps) error {

	// Only confirmed inserts can replace an active unmined branch.
	if req.Params.Block == nil {
		return nil
	}

	// Load the direct roots first so every later step works from the currently
	// visible spend edges on the shared parent inputs.
	rootIDs, rootHashes, err := ops.ListConflictTxns(ctx, req)
	if err != nil {
		return fmt.Errorf("list conflict txns: %w", err)
	}

	// Exit early if there are no conflicts.
	if len(rootIDs) == 0 {
		return nil
	}

	walletID := int64(req.Params.WalletID)

	// Discover descendants before any mutation starts.
	// Later rewrites can otherwise hide part of the displaced
	// branch from the graph walk.
	descendantIDs, err := collectConflictDescendants(
		ctx, walletID, rootHashes, rootIDs, ops,
	)
	if err != nil {
		return err
	}

	// Direct roots keep the replacement state and replacement history.
	err = handleRootTxns(ctx, walletID, rootIDs, replacementTxID, ops)
	if err != nil {
		return err
	}

	// Descendants clear their spend edges and then fall to the failed state.
	err = handleTxDescendants(ctx, walletID, descendantIDs, ops)
	if err != nil {
		return err
	}

	return nil
}

// insertCreateTx completes the fresh-Insert CreateTx path.
//
// The order is important:
//   - Insert first so the new winner row has a stable tx ID
//   - reconcile conflicts next while the displaced unmined branch is still
//     discoverable through the current spend edges
//   - create wallet-owned credits after replacement handling
//   - claim wallet-owned parent inputs last, because that rewires the shared
//     spend edges to the new winner row
func insertCreateTx(ctx context.Context, req CreateTxRequest,
	ops CreateTxOps) error {

	// Insert the winner row first so every later write can point at its stable
	// primary key. In particular, replacement-history edges need the new tx ID.
	txID, err := ops.Insert(ctx, req)
	if err != nil {
		return fmt.Errorf("insert tx: %w", err)
	}

	// Reconcile any conflicting unmined branch before this tx claims the shared
	// parent inputs. Conflict discovery looks at the current spend edges on
	// those parents; once MarkInputsSpent rewires them to this new row, the old
	// branch is no longer discoverable as the direct conflict root.
	err = handleTxConflicts(ctx, req, txID, ops)
	if err != nil {
		return err
	}

	// Credits only describe outputs created by the new tx itself, so they do
	// not interfere with conflict discovery. Keep them after replacement
	// handling so the branch rewrite stays grouped with the shared-input
	// reconciliation.
	err = ops.InsertCredits(ctx, req, txID)
	if err != nil {
		return fmt.Errorf("create tx credits: %w", err)
	}

	// Claim wallet-owned parent inputs last. This is the write that makes the
	// new tx the recorded spender of the shared parents, so doing it earlier
	// would hide the displaced unmined branch from the replacement walk.
	err = ops.MarkInputsSpent(ctx, req, txID)
	if err != nil {
		return fmt.Errorf("create tx spends: %w", err)
	}

	return nil
}

// CreateTxWithOps runs the backend-independent CreateTx orchestration once the
// caller has opened a backend-specific SQL transaction.
//
// The helper can either confirm an existing unmined row or Insert a new row.
// For confirmed inserts it also reconciles any current direct conflict branch
// before the new row claims wallet-owned inputs. The helper owns that ordering
// so the backends only need to supply query wiring and type conversion.
func CreateTxWithOps(ctx context.Context, req CreateTxRequest,
	ops CreateTxOps) error {

	existing, foundExisting, err := loadCreateTxExisting(ctx, req, ops)
	if err != nil {
		return err
	}

	if foundExisting {
		if !checkReuseCreateTx(req, *existing) {
			return fmt.Errorf("tx %s: %w", req.TxHash, ErrTxAlreadyExists)
		}

		err = ops.ConfirmExisting(ctx, req, *existing)
		if err != nil {
			return fmt.Errorf("confirm existing tx: %w", err)
		}

		return nil
	}

	err = ops.PrepareBlock(ctx, req)
	if err != nil {
		return fmt.Errorf("prepare create block assignment: %w", err)
	}

	return insertCreateTx(ctx, req, ops)
}

// validateUpdateTxParams checks that UpdateTx received at least one mutable
// field and that any requested state transition satisfies the transaction table
// invariants.
func validateUpdateTxParams(params UpdateTxParams, isCoinbase bool) error {
	if params.Label == nil && params.State == nil {
		return fmt.Errorf("%w: UpdateTx requires at least one field",
			ErrInvalidParam)
	}

	if params.State != nil {
		return validateUpdateTxState(*params.State, isCoinbase)
	}

	return nil
}

// validateUpdateTxState checks the block/status combinations UpdateTx may store
// on an existing row.
func validateUpdateTxState(state UpdateTxState, isCoinbase bool) error {
	_, err := ParseTxStatus(int64(state.Status))
	if err != nil {
		return fmt.Errorf("%w: status %d is not supported: %w",
			ErrInvalidParam, state.Status, ErrInvalidStatus)
	}

	// UpdateTx is row-local only. Any invalidating or orphaning transition must
	// flow through the event-shaped APIs that also reconcile dependent branch
	// state.
	if state.Status == TxStatusFailed ||
		state.Status == TxStatusReplaced ||
		state.Status == TxStatusOrphaned {

		return fmt.Errorf("%w: UpdateTx cannot invalidate txns: %w",
			ErrInvalidParam, ErrInvalidStatus)
	}

	// Any row with a confirming block represents mined history, and mined
	// wallet history is always published from the wallet's point of view.
	if state.Block != nil && state.Status != TxStatusPublished {
		return fmt.Errorf("%w: confirmed txns must be published: %w",
			ErrInvalidParam, ErrInvalidStatus)
	}

	// Coinbase state transitions are event-shaped only. CreateTx records the
	// mined fact, while RollbackToBlock clears the block reference and rewrites
	// the row orphaned. UpdateTx therefore never patches coinbase state.
	if isCoinbase {
		return fmt.Errorf("%w: UpdateTx cannot patch coinbase tx state: %w",
			ErrInvalidParam, ErrInvalidStatus)
	}

	return nil
}

// UpdateTxOps is the minimal backend adapter the shared UpdateTx workflow
// needs.
//
// The shared UpdateTx algorithm is intentionally ordered:
//   - load the target row metadata first
//   - validate the requested label/state patch against that metadata
//   - prepare any backend-specific block/status params next
//   - apply the label patch if requested
//   - apply the state patch last
//
// Keeping that sequence documented here matters because UpdateTx is
// deliberately row-local. The backend adapters only supply query wiring. The
// shared helper owns the mutation ordering and the invariants that keep
// block/status patches from accidentally turning into graph-level
// reconciliation.
type UpdateTxOps interface {
	// LoadIsCoinbase returns whether the existing row is coinbase history
	// so the shared validation can enforce orphaning rules correctly.
	LoadIsCoinbase(ctx context.Context, walletID uint32,
		txHash chainhash.Hash) (bool, error)

	// PrepareState validates and caches any backend-specific block/status
	// params needed for the later row update.
	PrepareState(ctx context.Context, state UpdateTxState) error

	// UpdateLabel applies one user-visible label patch.
	UpdateLabel(ctx context.Context, walletID uint32, txHash chainhash.Hash,
		label string) error

	// UpdateState applies one block/status patch after PrepareState succeeds.
	UpdateState(ctx context.Context, walletID uint32, txHash chainhash.Hash,
		state UpdateTxState) error
}

// UpdateTxWithOps runs the shared UpdateTx patch workflow inside one backend-
// specific SQL transaction.
//
// The helper validates the existing row first, prepares any requested state
// patch next, and then applies the label patch and state patch in that order.
// That keeps block validation and row mutation inside one transaction while
// still allowing callers to update either field independently.
func UpdateTxWithOps(ctx context.Context, params UpdateTxParams,
	ops UpdateTxOps) error {

	isCoinbase, err := ops.LoadIsCoinbase(ctx, params.WalletID, params.Txid)
	if err != nil {
		return fmt.Errorf("load update tx target: %w", err)
	}

	err = validateUpdateTxParams(params, isCoinbase)
	if err != nil {
		return err
	}

	if params.State != nil {
		err = ops.PrepareState(ctx, *params.State)
		if err != nil {
			return fmt.Errorf("prepare tx state update: %w", err)
		}
	}

	if params.Label != nil {
		err = ops.UpdateLabel(ctx, params.WalletID, params.Txid, *params.Label)
		if err != nil {
			return fmt.Errorf("update tx label: %w", err)
		}
	}

	if params.State != nil {
		err = ops.UpdateState(ctx, params.WalletID, params.Txid, *params.State)
		if err != nil {
			return fmt.Errorf("update tx state: %w", err)
		}
	}

	return nil
}

// DeleteTxOps is the minimal backend adapter the shared DeleteTx workflow
// needs.
//
// The shared delete sequence is:
//   - load and validate the target unmined row
//   - reject deletes that would orphan direct child spenders
//   - restore any wallet-owned parents the tx had marked spent
//   - delete wallet-owned outputs created by the tx itself
//   - delete the transaction row last
//
// DeleteTx is the ordinary leaf-cleanup path, not the invalidation path. The
// shared helper therefore proves the leaf invariant first and only then unwinds
// the wallet-owned state that points at the target row.
type DeleteTxOps interface {
	// LoadDeleteTarget returns the row ID of the unmined transaction
	// DeleteTx is allowed to remove.
	LoadDeleteTarget(ctx context.Context, walletID uint32,
		txHash chainhash.Hash) (int64, error)

	// EnsureLeaf rejects DeleteTx when the target still has direct
	// unmined child spenders.
	EnsureLeaf(ctx context.Context, walletID uint32, txHash chainhash.Hash,
		txID int64) error

	// ClearSpentUtxos restores any wallet-owned parent outputs the
	// transaction had marked spent.
	ClearSpentUtxos(ctx context.Context, walletID uint32, txID int64) error

	// DeleteCreatedUtxos removes any wallet-owned outputs created by the
	// transaction being deleted.
	DeleteCreatedUtxos(ctx context.Context, walletID uint32, txID int64) error

	// DeleteUnminedTransaction removes the target row after its dependent
	// wallet state has been cleaned up.
	DeleteUnminedTransaction(ctx context.Context, walletID uint32,
		txHash chainhash.Hash) (int64, error)
}

// DeleteTxWithOps runs the shared DeleteTx sequence inside a backend-specific
// SQL transaction.
//
// The helper restores wallet-owned parent state before deleting created wallet
// outputs and only removes the transaction row last, so a failed delete cannot
// leave partial wallet bookkeeping behind.
func DeleteTxWithOps(ctx context.Context, params DeleteTxParams,
	ops DeleteTxOps) error {

	txID, err := ops.LoadDeleteTarget(ctx, params.WalletID, params.Txid)
	if err != nil {
		return fmt.Errorf("load delete tx target: %w", err)
	}

	err = ops.EnsureLeaf(ctx, params.WalletID, params.Txid, txID)
	if err != nil {
		return fmt.Errorf("check delete tx leaf: %w", err)
	}

	err = ops.ClearSpentUtxos(ctx, params.WalletID, txID)
	if err != nil {
		return fmt.Errorf("clear spent utxos: %w", err)
	}

	err = ops.DeleteCreatedUtxos(ctx, params.WalletID, txID)
	if err != nil {
		return fmt.Errorf("delete created utxos: %w", err)
	}

	rows, err := ops.DeleteUnminedTransaction(ctx, params.WalletID, params.Txid)
	if err != nil {
		return fmt.Errorf("delete unmined tx: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("tx %s: %w", params.Txid, ErrTxNotFound)
	}

	return nil
}

// UnminedTxRecord is the decoded view of one unmined transaction row used by
// shared descendant checks.
type UnminedTxRecord struct {
	// ID is the backend row ID.
	ID int64

	// Hash is the transaction hash used for graph traversal.
	Hash chainhash.Hash

	// Tx is the decoded transaction payload.
	Tx *wire.MsgTx
}

// ExtractUnminedTxFn projects one backend-specific unmined transaction row into
// the shared `(id, tx_hash, raw_tx)` shape used by the invalidation walk.
type ExtractUnminedTxFn[Row any] func(Row) (int64, []byte, []byte)

// RollbackToBlockOps adapts one SQL backend to the full RollbackToBlock
// sequence, including sync-state rewinds, block deletion, and descendant
// invalidation.
//
// The shared rollback algorithm is intentionally ordered:
//   - collect rollback root hashes before block rows are removed
//   - rewind sync-state heights that still point at the removed blocks
//   - delete the shared block rows at or above the rollback height
//   - mark the disconnected coinbase roots orphaned once their confirming
//     blocks have been removed
//   - walk the disconnected roots and invalidate dependent descendants
//
// The adapter methods map directly to those stages so the shared helper can own
// the rollback sequencing while the backends keep only query details.
type RollbackToBlockOps interface {
	// ListRollbackRootHashes returns the coinbase roots disconnected by the
	// rollback, grouped by wallet for the later descendant walk.
	ListRollbackRootHashes(ctx context.Context,
		height uint32) (map[uint32][]chainhash.Hash, error)

	// RewindWalletSyncStateHeights clamps wallet sync-state references
	// below the rollback boundary before block rows are removed.
	RewindWalletSyncStateHeights(ctx context.Context, height uint32) error

	// DeleteBlocksAtOrAboveHeight removes the shared block rows at or above the
	// rollback boundary after sync-state references have been rewound.
	DeleteBlocksAtOrAboveHeight(ctx context.Context, height uint32) error

	// MarkTxRootsOrphaned rewrites the disconnected coinbase roots to the
	// orphaned state after their confirming blocks are deleted.
	MarkTxRootsOrphaned(ctx context.Context, walletID uint32,
		rootHashes []chainhash.Hash) error

	// ListUnminedTxRecords loads the wallet's current unmined transaction
	// rows in the normalized shape the descendant walk expects.
	ListUnminedTxRecords(ctx context.Context,
		walletID int64) ([]UnminedTxRecord, error)

	// ClearDescendantSpends removes any wallet-owned spend edges claimed by one
	// invalid descendant before its status is rewritten.
	ClearDescendantSpends(ctx context.Context, walletID int64,
		descendantID int64) error

	// MarkDescendantsFailed batch-marks the discovered descendants as
	// failed once every dependent spend edge has been cleared.
	MarkDescendantsFailed(ctx context.Context, walletID int64,
		descendantIDs []int64) error
}

// newUnminedTxRecord decodes one normalized unmined transaction row into the
// shared dependency-walk shape.
func newUnminedTxRecord(id int64, hash []byte,
	rawTx []byte) (UnminedTxRecord, error) {

	txHash, err := chainhash.NewHash(hash)
	if err != nil {
		return UnminedTxRecord{}, fmt.Errorf("tx hash: %w", err)
	}

	tx, err := deserializeMsgTx(rawTx)
	if err != nil {
		return UnminedTxRecord{}, err
	}

	return UnminedTxRecord{ID: id, Hash: *txHash, Tx: tx}, nil
}

// BuildUnminedTxRecords decodes backend-specific unmined transaction rows into
// the shared dependency-walk shape.
func BuildUnminedTxRecords[T any](rows []T,
	extract ExtractUnminedTxFn[T]) ([]UnminedTxRecord, error) {

	records := make([]UnminedTxRecord, 0, len(rows))
	for _, row := range rows {
		id, hash, rawTx := extract(row)

		record, err := newUnminedTxRecord(id, hash, rawTx)
		if err != nil {
			return nil, fmt.Errorf("decode unmined tx %d: %w", id, err)
		}

		records = append(records, record)
	}

	return records, nil
}

// CollectDirectChildTxIDs returns the IDs of unmined transactions that directly
// spend any output created by the provided parent hash.
func CollectDirectChildTxIDs(parentHash chainhash.Hash,
	candidates []UnminedTxRecord) []int64 {

	parentHashes := map[chainhash.Hash]struct{}{
		parentHash: {},
	}

	childIDs := make([]int64, 0, len(candidates))
	for _, candidate := range candidates {
		if txSpendsAnyParent(candidate.Tx, parentHashes) {
			childIDs = append(childIDs, candidate.ID)
		}
	}

	return childIDs
}

// CollectDescendantTxIDs returns every discovered descendant in the original
// candidate order. Any ID also listed in rootIDs is excluded so direct roots
// can keep their own state transition instead of being treated as descendants.
func CollectDescendantTxIDs(rootHashes []chainhash.Hash,
	rootIDs []int64, candidates []UnminedTxRecord) []int64 {

	invalidHashes := make(map[chainhash.Hash]struct{}, len(rootHashes))
	for _, hash := range rootHashes {
		invalidHashes[hash] = struct{}{}
	}

	invalidIDs := make(map[int64]struct{}, len(candidates))

	// Walk the candidate set to a fixed point. Each time we discover one
	// new descendant we add its hash to invalidHashes, which may cause
	// later passes to discover txns that depend on that child.
	for changed := true; changed; {
		changed = false

		for _, candidate := range candidates {
			if _, ok := invalidIDs[candidate.ID]; ok {
				continue
			}

			if !txSpendsAnyParent(candidate.Tx, invalidHashes) {
				continue
			}

			invalidIDs[candidate.ID] = struct{}{}
			invalidHashes[candidate.Hash] = struct{}{}
			changed = true
		}
	}

	// Direct roots are handled separately by the caller, so remove them here
	// before the ordered descendant slice is materialized.
	for _, rootID := range rootIDs {
		delete(invalidIDs, rootID)
	}

	orderedIDs := make([]int64, 0, len(invalidIDs))
	for _, candidate := range candidates {
		if _, ok := invalidIDs[candidate.ID]; ok {
			orderedIDs = append(orderedIDs, candidate.ID)
		}
	}

	return orderedIDs
}

// invalidateRollbackDescendants clears spend edges and marks failed every
// unmined descendant discovered from the provided wallet-scoped rollback roots.
func invalidateRollbackDescendants(ctx context.Context,
	rootHashesByWallet map[uint32][]chainhash.Hash,
	ops RollbackToBlockOps) error {

	for walletID, rootHashes := range rootHashesByWallet {
		walletID64 := int64(walletID)

		candidates, err := ops.ListUnminedTxRecords(ctx, walletID64)
		if err != nil {
			return fmt.Errorf("list unmined rollback descendants for "+
				"wallet %d: %w", walletID, err)
		}

		descendantIDs := CollectDescendantTxIDs(rootHashes, nil, candidates)
		if len(descendantIDs) == 0 {
			continue
		}

		for _, descendantID := range descendantIDs {
			err = ops.ClearDescendantSpends(ctx, walletID64, descendantID)
			if err != nil {
				return fmt.Errorf("clear rollback descendant spends for "+
					"wallet %d: %w", walletID, err)
			}
		}

		err = ops.MarkDescendantsFailed(ctx, walletID64, descendantIDs)
		if err != nil {
			return fmt.Errorf("mark rollback descendants failed for "+
				"wallet %d: %w", walletID, err)
		}
	}

	return nil
}

// MarkTxRootsOrphaned rewrites every disconnected coinbase root to the
// orphaned state before descendant invalidation completes.
func MarkTxRootsOrphaned(ctx context.Context,
	rootHashesByWallet map[uint32][]chainhash.Hash,
	ops RollbackToBlockOps) error {

	for walletID, rootHashes := range rootHashesByWallet {
		err := ops.MarkTxRootsOrphaned(ctx, walletID, rootHashes)
		if err != nil {
			return fmt.Errorf("mark rollback coinbase roots orphaned for "+
				"wallet %d: %w", walletID, err)
		}
	}

	return nil
}

// RollbackToBlockWithOps runs the shared RollbackToBlock sequence inside one
// backend-specific SQL transaction.
//
// The helper rewinds sync-state heights before deleting blocks, then clears and
// fails any now-invalid unmined descendants rooted in disconnected coinbase
// history so rollback cannot leave dangling references behind.
func RollbackToBlockWithOps(ctx context.Context, height uint32,
	ops RollbackToBlockOps) error {

	rootHashesByWallet, err := ops.ListRollbackRootHashes(ctx, height)
	if err != nil {
		return fmt.Errorf("list rollback coinbase roots: %w", err)
	}

	err = ops.RewindWalletSyncStateHeights(ctx, height)
	if err != nil {
		return fmt.Errorf("rewind wallet sync state heights: %w", err)
	}

	err = ops.DeleteBlocksAtOrAboveHeight(ctx, height)
	if err != nil {
		return fmt.Errorf("delete blocks at or above height: %w", err)
	}

	err = MarkTxRootsOrphaned(ctx, rootHashesByWallet, ops)
	if err != nil {
		return err
	}

	err = invalidateRollbackDescendants(ctx, rootHashesByWallet, ops)
	if err != nil {
		return err
	}

	return nil
}

// txSpendsAnyParent reports whether the transaction spends any hash in the
// provided parent set.
func txSpendsAnyParent(tx *wire.MsgTx,
	parentHashes map[chainhash.Hash]struct{}) bool {

	for _, txIn := range tx.TxIn {
		if _, ok := parentHashes[txIn.PreviousOutPoint.Hash]; ok {
			return true
		}
	}

	return false
}

// IsUnminedStatus reports whether a status still represents an unmined
// transaction that DeleteTx may erase.
func IsUnminedStatus(status TxStatus) bool {
	switch status {
	case TxStatusPending, TxStatusPublished:
		return true

	case TxStatusReplaced, TxStatusFailed, TxStatusOrphaned:
		return false

	default:
		return false
	}
}
