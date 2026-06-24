package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
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

// TxDetailBase is the normalized transaction-row metadata the shared detail
// read workflows need from one SQL backend.
type TxDetailBase struct {
	// ID is the backend row identifier for the transaction.
	ID int64

	// Hash is the serialized transaction hash bytes.
	Hash []byte

	// RawTx is the serialized wire transaction payload.
	RawTx []byte

	// Received is when the wallet observed the transaction.
	Received time.Time

	// Block is the normalized confirming block metadata, or nil when
	// the row has no confirming block.
	Block *Block

	// Status is the stored wallet-relative transaction status code.
	Status int64

	// Label is the optional user-supplied transaction label.
	Label string
}

// TxInputOutpoint identifies one transaction input and the previous outpoint it
// spends.
type TxInputOutpoint struct {
	// TxID is the backend row ID of the spending transaction.
	TxID int64

	// InputIndex is the input position within the spending transaction.
	InputIndex uint32

	// PrevTxHash is the hash of the transaction that created the previous
	// output.
	PrevTxHash chainhash.Hash

	// PrevOutputIndex is the output index in the previous transaction.
	PrevOutputIndex uint32
}

// GetTxDetailOps is the small semantic adapter GetTxDetail needs from one SQL
// backend.
//
// The shared GetTxDetail algorithm is intentionally ordered:
//   - load the wallet-scoped base transaction row first
//   - load wallet-owned outputs for that exact row ID next
//   - derive previous outpoints from the raw transaction and load the
//     wallet-owned inputs referenced by those outpoints after that
//   - build the final TxDetailInfo from the normalized row plus those edge sets
//
// Each backend implements those steps with its own sqlc-generated query types,
// nullable field shapes, and row conversion helpers while GetTxDetailWithOps
// keeps the visible sequencing in one place.
type GetTxDetailOps interface {
	// LoadBase loads the normalized base transaction row for one wallet-scoped
	// hash lookup.
	LoadBase(ctx context.Context, query GetTxDetailQuery) (TxDetailBase, error)

	// LoadOwnedOutputs loads every wallet-owned output created by
	// the provided tx row IDs and groups them by creating tx ID.
	LoadOwnedOutputs(ctx context.Context, walletID uint32,
		txIDs []int64) (map[int64][]TxOwnedOutput, error)

	// LoadOwnedInputs loads every wallet-owned input referenced by the provided
	// transaction input outpoints and groups them by spender tx ID.
	LoadOwnedInputs(ctx context.Context, walletID uint32,
		inputOutpoints []TxInputOutpoint) (map[int64][]TxOwnedInput, error)
}

// GetTxDetailWithOps runs the shared GetTxDetail read workflow.
//
// The helper owns the ordering between the base-row load and the owned-edge
// loads so both SQL backends expose the same detailed transaction shape and the
// same wallet-scoped not-found behavior.
func GetTxDetailWithOps(ctx context.Context, query GetTxDetailQuery,
	ops GetTxDetailOps) (*TxDetailInfo, error) {

	base, err := ops.LoadBase(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("load tx detail base: %w", err)
	}

	txIDs := []int64{base.ID}

	ownedOutputs, err := ops.LoadOwnedOutputs(ctx, query.WalletID, txIDs)
	if err != nil {
		return nil, fmt.Errorf("load tx detail outputs: %w", err)
	}

	inputOutpoints, err := txInputOutpointsFromBases([]TxDetailBase{base})
	if err != nil {
		return nil, fmt.Errorf("build tx detail input outpoints: %w", err)
	}

	ownedInputs, err := ops.LoadOwnedInputs(
		ctx, query.WalletID, inputOutpoints,
	)
	if err != nil {
		return nil, fmt.Errorf("load tx detail inputs: %w", err)
	}

	return buildTxDetailInfo(
		base, ownedInputs[base.ID], ownedOutputs[base.ID],
	)
}

// normalizedListTxDetailsQuery captures wallet tx-reader range semantics in one
// simpler shape that the shared ListTxDetails workflow can execute directly.
type normalizedListTxDetailsQuery struct {
	confirmedStart int32
	confirmedEnd   int32
	reverse        bool
	includeUnmined bool
	unminedFirst   bool
	hasConfirmed   bool
}

// ListTxDetailsOps is the small semantic adapter ListTxDetails needs from one
// SQL backend.
//
// The shared ListTxDetails algorithm is intentionally ordered:
//   - normalize the wallet tx-reader range semantics first
//   - load the rows visible to the unmined leg before or after confirmed rows
//     as required by that normalized view
//   - collect the selected tx row IDs in the final output order next
//   - load wallet-owned outputs for that exact ID set
//   - derive previous outpoints from those raw transactions and load any
//     wallet-owned inputs referenced by those outpoints
//   - rebuild the final TxDetailInfo values in the original base-row order
//
// Each backend implements those stages with its own sqlc-generated query types,
// nullable field shapes, and binding helpers while ListTxDetailsWithOps keeps
// the shared sequencing and tx-reader semantics in one place.
type ListTxDetailsOps interface {
	// ListUnmined loads the rows visible to the tx-reader unmined leg. This
	// includes current unmined rows together with any retained history
	// rows that no longer have a confirming block.
	ListUnmined(ctx context.Context, walletID uint32) ([]TxDetailBase, error)

	// ListConfirmed loads the confirmed height-range rows for the normalized
	// query.
	ListConfirmed(ctx context.Context, walletID uint32, startHeight,
		endHeight int32, reverse bool) ([]TxDetailBase, error)

	// LoadOwnedOutputs loads every wallet-owned output created by
	// the provided tx row IDs and groups them by creating tx ID.
	LoadOwnedOutputs(ctx context.Context, walletID uint32,
		txIDs []int64) (map[int64][]TxOwnedOutput, error)

	// LoadOwnedInputs loads every wallet-owned input referenced by the provided
	// transaction input outpoints and groups them by spender tx ID.
	LoadOwnedInputs(ctx context.Context, walletID uint32,
		inputOutpoints []TxInputOutpoint) (map[int64][]TxOwnedInput, error)
}

// ListTxDetailsWithOps runs the shared ListTxDetails read workflow.
//
// The helper owns the range normalization, row-order preservation, and owned-
// edge loading order so both SQL backends expose identical tx-reader behavior.
func ListTxDetailsWithOps(ctx context.Context, query ListTxDetailsQuery,
	ops ListTxDetailsOps) ([]TxDetailInfo, error) {

	normalized := normalizeListTxDetailsQuery(query)

	bases, err := listTxDetailBases(ctx, query.WalletID, normalized, ops)
	if err != nil {
		return nil, err
	}

	if len(bases) == 0 {
		return []TxDetailInfo{}, nil
	}

	txIDs := make([]int64, 0, len(bases))
	for _, base := range bases {
		txIDs = append(txIDs, base.ID)
	}

	ownedOutputs, err := ops.LoadOwnedOutputs(ctx, query.WalletID, txIDs)
	if err != nil {
		return nil, fmt.Errorf("load tx detail outputs: %w", err)
	}

	inputOutpoints, err := txInputOutpointsFromBases(bases)
	if err != nil {
		return nil, fmt.Errorf("build tx detail input outpoints: %w", err)
	}

	ownedInputs, err := ops.LoadOwnedInputs(
		ctx, query.WalletID, inputOutpoints,
	)
	if err != nil {
		return nil, fmt.Errorf("load tx detail inputs: %w", err)
	}

	return buildTxDetailsFromBases(bases, ownedInputs, ownedOutputs)
}

// txInputOutpointsFromBases extracts every previous outpoint referenced by the
// selected transaction rows.
func txInputOutpointsFromBases(bases []TxDetailBase) (
	[]TxInputOutpoint, error) {

	var inputOutpoints []TxInputOutpoint

	for _, base := range bases {
		msgTx, err := deserializeMsgTx(base.RawTx)
		if err != nil {
			return nil, err
		}

		if blockchain.IsCoinBaseTx(msgTx) {
			continue
		}

		for inputIndex, txIn := range msgTx.TxIn {
			index, err := Int64ToUint32(int64(inputIndex))
			if err != nil {
				return nil, fmt.Errorf("input index %d: %w",
					inputIndex, err)
			}

			inputOutpoints = append(inputOutpoints, TxInputOutpoint{
				TxID:            base.ID,
				InputIndex:      index,
				PrevTxHash:      txIn.PreviousOutPoint.Hash,
				PrevOutputIndex: txIn.PreviousOutPoint.Index,
			})
		}
	}

	return inputOutpoints, nil
}

// buildTxDetailInfo rebuilds one TxDetailInfo from one normalized base row and
// its owned input and output edge sets.
func buildTxDetailInfo(base TxDetailBase, ownedInputs []TxOwnedInput,
	ownedOutputs []TxOwnedOutput) (*TxDetailInfo, error) {

	msgTx, err := deserializeMsgTx(base.RawTx)
	if err != nil {
		return nil, err
	}

	txInfo, err := BuildTxInfo(
		base.Hash, base.RawTx, base.Received, base.Block, base.Status,
		base.Label,
	)
	if err != nil {
		return nil, err
	}

	return &TxDetailInfo{
		Hash:         txInfo.Hash,
		MsgTx:        msgTx,
		SerializedTx: txInfo.SerializedTx,
		Received:     txInfo.Received,
		Block:        txInfo.Block,
		Status:       txInfo.Status,
		Label:        txInfo.Label,
		OwnedInputs:  ownedInputs,
		OwnedOutputs: ownedOutputs,
	}, nil
}

// ReverseTxInfosByBlock reverses confirmed block order while preserving the
// transaction order within each block.
func ReverseTxInfosByBlock(infos []TxInfo) {
	reverseByBlock(infos, func(info TxInfo) uint32 {
		if info.Block == nil {
			return 0
		}

		return info.Block.Height
	})
}

// ReverseTxDetailBasesByBlock reverses confirmed block order while preserving
// the transaction order within each block.
func ReverseTxDetailBasesByBlock(bases []TxDetailBase) {
	reverseByBlock(bases, func(base TxDetailBase) uint32 {
		if base.Block == nil {
			return 0
		}

		return base.Block.Height
	})
}

// reverseByBlock reverses contiguous block groups while preserving the original
// order inside each group.
func reverseByBlock[T any](items []T, blockHeight func(T) uint32) {
	slices.Reverse(items)

	for start := 0; start < len(items); {
		end := start + 1

		height := blockHeight(items[start])
		for end < len(items) && blockHeight(items[end]) == height {
			end++
		}

		slices.Reverse(items[start:end])
		start = end
	}
}

// normalizeListTxDetailsQuery converts wallet tx-reader range semantics into
// the internal form used by the shared ListTxDetails workflow.
func normalizeListTxDetailsQuery(
	query ListTxDetailsQuery,
) normalizedListTxDetailsQuery {

	switch {
	case query.StartHeight < 0 && query.EndHeight < 0:
		return normalizedListTxDetailsQuery{
			includeUnmined: true,
			unminedFirst:   true,
		}

	case query.StartHeight < 0:
		return normalizedListTxDetailsQuery{
			confirmedStart: query.EndHeight,
			confirmedEnd:   math.MaxInt32,
			reverse:        true,
			includeUnmined: true,
			unminedFirst:   true,
			hasConfirmed:   true,
		}

	case query.EndHeight < 0:
		return normalizedListTxDetailsQuery{
			confirmedStart: query.StartHeight,
			confirmedEnd:   math.MaxInt32,
			includeUnmined: true,
			hasConfirmed:   true,
		}

	default:
		start := query.StartHeight
		end := query.EndHeight

		reverse := start > end
		if reverse {
			start, end = end, start
		}

		return normalizedListTxDetailsQuery{
			confirmedStart: start,
			confirmedEnd:   end,
			reverse:        reverse,
			hasConfirmed:   true,
		}
	}
}

// listTxDetailBases loads the normalized base rows for one ListTxDetails call
// in the final output order required by the wallet tx reader.
func listTxDetailBases(ctx context.Context, walletID uint32,
	normalized normalizedListTxDetailsQuery,
	ops ListTxDetailsOps) ([]TxDetailBase, error) {

	var bases []TxDetailBase

	if normalized.includeUnmined && normalized.unminedFirst {
		unmined, err := ops.ListUnmined(ctx, walletID)
		if err != nil {
			return nil, fmt.Errorf("list unmined tx details: %w", err)
		}

		bases = append(bases, unmined...)
	}

	if normalized.hasConfirmed {
		confirmed, err := ops.ListConfirmed(
			ctx, walletID, normalized.confirmedStart, normalized.confirmedEnd,
			normalized.reverse,
		)
		if err != nil {
			return nil, fmt.Errorf("list confirmed tx details: %w", err)
		}

		bases = append(bases, confirmed...)
	}

	if normalized.includeUnmined && !normalized.unminedFirst {
		unmined, err := ops.ListUnmined(ctx, walletID)
		if err != nil {
			return nil, fmt.Errorf("list unmined tx details: %w", err)
		}

		bases = append(bases, unmined...)
	}

	return bases, nil
}

// buildTxDetailsFromBases rebuilds the final detail rows in base-row order
// after the owned input and output edges have been grouped by tx id.
func buildTxDetailsFromBases(bases []TxDetailBase,
	ownedInputs map[int64][]TxOwnedInput,
	ownedOutputs map[int64][]TxOwnedOutput) ([]TxDetailInfo, error) {

	details := make([]TxDetailInfo, 0, len(bases))
	for _, base := range bases {
		detail, err := buildTxDetailInfo(
			base, ownedInputs[base.ID], ownedOutputs[base.ID],
		)
		if err != nil {
			return nil, err
		}

		details = append(details, *detail)
	}

	return details, nil
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

// ValidateCreditAddrMembership verifies that a caller-supplied credit address
// is actually paid by the output script it claims to credit. A bad caller
// could otherwise label output N with any wallet address even when TxOut[N]
// pays elsewhere, and the SQL backends would record the output as owned by
// that unrelated address, corrupting UTXO ownership. The kvdb backend already
// enforces the same rule via its own validateCreditAddr, so this keeps the
// backends consistent.
//
// Membership, not strict equality, is required so bare-multisig outputs the
// wallet partly owns still validate: such an output is credited to one of its
// member pubkey addresses, whose own script never equals the full multisig
// output script.
//
// The check is intentionally script-based and chain-parameter free. For a
// single-address output the member's standard script equals the output script
// outright. For a bare-multisig output the member's pubkey is one of the
// script's member operands, and ScriptAddress() exposes that pubkey directly
// without re-deriving a network-encoded address, so no chaincfg.Params is
// needed (the SQL stores do not carry one).
//
// The bare-multisig fallback is gated on the output script actually being a
// standard bare-multisig script (txscript.MultiSigTy). Without that gate any
// script that merely pushes the same bytes - for example a non-paying
// OP_RETURN <pubkey> - would pass, after which InsertUtxo would record that
// unrelated script as wallet-owned. The gate is what distinguishes "a pubkey
// appears somewhere in the script" from "the script pays through bare multisig
// and this pubkey is a member": in a MultiSigTy script the only non-empty data
// pushes are the member pubkey operands (the threshold and key-count small
// integers and OP_CHECKMULTISIG carry no push data), so a data-push match
// against a MultiSigTy script can only be a genuine member.
func ValidateCreditAddrMembership(creditAddr address.Address,
	outputScript []byte) error {

	creditScript, err := txscript.PayToAddrScript(creditAddr)
	if err != nil {
		return fmt.Errorf("%w: build credit address script: %w",
			ErrInvalidParam, err)
	}

	// A single-address output is credited to the very address its script
	// pays, so the member's standard script equals the output script.
	if bytes.Equal(creditScript, outputScript) {
		return nil
	}

	// Otherwise the only supported shape is a standard bare-multisig output
	// the wallet partly owns, credited to one of its member pubkeys. Require
	// the output script to classify as bare multisig before trusting any
	// pushed-member match, so a non-multisig script that happens to push the
	// pubkey bytes (such as OP_RETURN <pubkey>) is rejected rather than
	// recorded as wallet-owned.
	if txscript.GetScriptClass(outputScript) != txscript.MultiSigTy {
		return fmt.Errorf("%w: credit address %s is not paid by the "+
			"output script", ErrInvalidParam, creditAddr.EncodeAddress())
	}

	// The output is a bare-multisig script, whose only data pushes are its
	// member pubkey operands, so the credited pubkey must appear as one of
	// those pushes to be a member.
	memberPubKey := creditAddr.ScriptAddress()
	if len(memberPubKey) != 0 && scriptPushesData(outputScript, memberPubKey) {
		return nil
	}

	return fmt.Errorf("%w: credit address %s is not a member of the "+
		"bare-multisig output script", ErrInvalidParam,
		creditAddr.EncodeAddress())
}

// scriptPushesData reports whether script contains a data push equal to want.
// It is used to detect a bare-multisig member pubkey inside a multisig output
// script without depending on chain parameters.
func scriptPushesData(script, want []byte) bool {
	const scriptVersion = 0

	tokenizer := txscript.MakeScriptTokenizer(scriptVersion, script)
	for tokenizer.Next() {
		if bytes.Equal(tokenizer.Data(), want) {
			return true
		}
	}

	// A malformed or non-matching script yields no match; the caller then
	// rejects the credit as a non-member rather than trusting it.
	return false
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

	// BlockHeight is the confirmed block height when HasBlock is true.
	BlockHeight *uint32

	// BlockHash is the confirmed block hash when HasBlock is true.
	BlockHash *chainhash.Hash

	// IsCoinbase reports whether the row records coinbase history.
	IsCoinbase bool

	// Label is the stored user-visible transaction label.
	Label string
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

// createTxBlockMatches reports whether a stored row carries the same block
// assignment as the incoming CreateTx observation.
func createTxBlockMatches(req CreateTxRequest,
	existing CreateTxExistingTarget) bool {

	if req.Params.Block == nil {
		return !existing.HasBlock
	}

	if !existing.HasBlock || existing.BlockHeight == nil ||
		existing.BlockHash == nil {

		return false
	}

	return *existing.BlockHeight == req.Params.Block.Height &&
		*existing.BlockHash == req.Params.Block.Hash
}

// checkIdempotentCreateTx reports whether the incoming CreateTx observation is
// already fully reflected by the stored row.
func checkIdempotentCreateTx(req CreateTxRequest,
	existing CreateTxExistingTarget) bool {

	if req.Params.Status != existing.Status {
		return false
	}

	if req.IsCoinbase != existing.IsCoinbase {
		return false
	}

	if req.Params.Label != existing.Label {
		return false
	}

	return createTxBlockMatches(req, existing)
}

// validateCreateTxCreditRequests validates every caller-supplied credit before
// an existing tx row is treated as an idempotent duplicate.
func validateCreateTxCreditRequests(req CreateTxRequest) error {
	for index, addr := range req.Params.Credits {
		if addr == nil {
			continue
		}

		err := ValidateCreditAddrMembership(
			addr, req.Params.Tx.TxOut[index].PkScript,
		)
		if err != nil {
			return fmt.Errorf("credit output %d: %w", index, err)
		}
	}

	return nil
}

// canIgnoreUnminedConfirmedDuplicate reports whether an unmined observation may
// be ignored because the same transaction is already recorded as confirmed.
func canIgnoreUnminedConfirmedDuplicate(req CreateTxRequest,
	existing CreateTxExistingTarget) bool {

	return req.Params.Block == nil && existing.HasBlock
}

// CanSkipCreateTxDuplicate reports whether a batch insert may treat an
// ErrTxAlreadyExists result as an idempotent no-op. Only the exact current row
// shape is skippable: duplicates must carry the same label, unmined duplicates
// must have the same coinbase flag, same live status, and no block, while mined
// duplicates must be published in the same block. Terminal history such as
// failed, replaced, or orphaned rows must not be skipped because doing so would
// leave stale state in place.
func CanSkipCreateTxDuplicate(req CreateTxRequest, status TxStatus,
	label string, isCoinbase bool, block *Block) bool {

	if req.Params.Label != label {
		return false
	}

	if req.IsCoinbase != isCoinbase {
		return false
	}

	if req.Params.Block == nil {
		return block == nil && status == req.Params.Status
	}

	if req.Params.Status != TxStatusPublished {
		return false
	}

	if status != TxStatusPublished || block == nil {
		return false
	}

	return block.Height == req.Params.Block.Height &&
		block.Hash == req.Params.Block.Hash
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

// ReplaceUnminedTxConflicts rewrites direct unmined conflict roots displaced by
// the provided replacement transaction.
//
// Callers use this when the direct conflict roots were discovered outside the
// normal spend-edge lookup path, such as when a parent credit is learned after
// its children have already been stored as external-input spends. The function
// preserves the standard replacement ordering: discover descendants from a
// stable graph snapshot, mark direct roots replaced, then mark dependent
// descendants failed.
func ReplaceUnminedTxConflicts(ctx context.Context, walletID int64,
	rootIDs []int64, rootHashes []chainhash.Hash, replacementTxID int64,
	ops CreateTxOps) error {

	if len(rootIDs) == 0 {
		return nil
	}

	if len(rootIDs) != len(rootHashes) {
		return fmt.Errorf("%w: conflict roots and hashes differ",
			ErrInvalidParam)
	}

	descendantIDs, err := collectConflictDescendants(
		ctx, walletID, rootHashes, rootIDs, ops,
	)
	if err != nil {
		return err
	}

	err = handleRootTxns(ctx, walletID, rootIDs, replacementTxID, ops)
	if err != nil {
		return err
	}

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

	err = recordCreateTxEdges(ctx, req, txID, ops)
	if err != nil {
		return err
	}

	return nil
}

// recordCreateTxEdges records wallet-owned credits and spent-input edges for a
// transaction row that already exists in the backend.
func recordCreateTxEdges(ctx context.Context, req CreateTxRequest, txID int64,
	ops CreateTxOps) error {

	// Credits only describe outputs created by the tx itself, so they do not
	// interfere with conflict discovery. Keep them after replacement handling
	// so the branch rewrite stays grouped with the shared-input reconciliation.
	err := ops.InsertCredits(ctx, req, txID)
	if err != nil {
		return fmt.Errorf("create tx credits: %w", err)
	}

	// Claim wallet-owned parent inputs last. This is the write that makes this
	// tx the recorded spender of the shared parents, so doing it earlier would
	// hide a displaced unmined branch from the replacement walk.
	err = ops.MarkInputsSpent(ctx, req, txID)
	if err != nil {
		return fmt.Errorf("create tx spends: %w", err)
	}

	return nil
}

// handleExistingCreateTx handles a CreateTx request for a transaction hash that
// already has a wallet-scoped row.
func handleExistingCreateTx(ctx context.Context, req CreateTxRequest,
	existing CreateTxExistingTarget, ops CreateTxOps) error {

	if canIgnoreUnminedConfirmedDuplicate(req, existing) {
		return nil
	}

	if checkIdempotentCreateTx(req, existing) {
		return replayIdempotentCreateTx(ctx, req, existing, ops)
	}

	if !checkReuseCreateTx(req, existing) {
		return fmt.Errorf("tx %s: %w", req.TxHash, ErrTxAlreadyExists)
	}

	err := ops.ConfirmExisting(ctx, req, existing)
	if err != nil {
		return fmt.Errorf("confirm existing tx: %w", err)
	}

	err = handleTxConflicts(ctx, req, existing.ID, ops)
	if err != nil {
		return err
	}

	err = recordCreateTxEdges(ctx, req, existing.ID, ops)
	if err != nil {
		return fmt.Errorf("replay confirmed tx edges: %w", err)
	}

	return nil
}

// replayIdempotentCreateTx validates and records any edge writes that an
// idempotent duplicate transaction notification may still need.
func replayIdempotentCreateTx(ctx context.Context, req CreateTxRequest,
	existing CreateTxExistingTarget, ops CreateTxOps) error {

	err := validateCreateTxCreditRequests(req)
	if err != nil {
		return err
	}

	if req.Params.Block != nil {
		err = ops.PrepareBlock(ctx, req)
		if err != nil {
			return fmt.Errorf("prepare duplicate block assignment: %w", err)
		}
	}

	err = recordCreateTxEdges(ctx, req, existing.ID, ops)
	if err != nil {
		return fmt.Errorf("replay duplicate tx edges: %w", err)
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

	if !foundExisting {
		err = ops.PrepareBlock(ctx, req)
		if err != nil {
			return fmt.Errorf("prepare create block assignment: %w", err)
		}

		return insertCreateTx(ctx, req, ops)
	}

	return handleExistingCreateTx(ctx, req, *existing, ops)
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

// InvalidateRollbackDescendants clears spend edges and fails unmined
// descendants rooted in disconnected coinbase transactions. Wallet-scoped
// rewind paths use this without deleting shared block rows.
func InvalidateRollbackDescendants(ctx context.Context,
	rootHashesByWallet map[uint32][]chainhash.Hash,
	ops RollbackToBlockOps) error {

	return invalidateRollbackDescendants(ctx, rootHashesByWallet, ops)
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

// ValidateBatchTransactionsWalletID rejects a batch whose transactions are not
// all owned by batchWalletID. A batch applies sync state (sync tip or scan
// horizons) to batchWalletID but records each transaction under that
// transaction's own WalletID, so a mismatched member would let one wallet's
// sync state advance atomically with another wallet's transaction write. The
// check runs before any backend write so the batch invariant is enforced
// up front, before horizon derivation or synced-block work is wasted.
func ValidateBatchTransactionsWalletID(batchWalletID uint32,
	txs []CreateTxParams) error {

	for i := range txs {
		if txs[i].WalletID == batchWalletID {
			continue
		}

		return fmt.Errorf("%w: transaction %d wallet id %d does not "+
			"match batch wallet id %d", ErrInvalidParam, i,
			txs[i].WalletID, batchWalletID)
	}

	return nil
}

// ValidateBatchTransactionsTx rejects a batch in which any transaction has a
// nil Tx. A batch is reordered parents-first by SortTxBatchParentsFirst before
// it is applied, and that sort dereferences each transaction's Tx to read its
// hash and inputs. Per-transaction NewCreateTxRequest validation would catch a
// nil Tx, but only inside the apply loop that runs after the sort, so a nil Tx
// would panic during reordering. Running this check up front, before the sort,
// turns that into the same ErrInvalidParam every backend returns uniformly.
func ValidateBatchTransactionsTx(txs []CreateTxParams) error {
	for i := range txs {
		if txs[i].Tx != nil {
			continue
		}

		return fmt.Errorf("%w: transaction %d tx is required",
			ErrInvalidParam, i)
	}

	return nil
}

// SortTxBatchParentsFirst returns the batch transactions reordered so that any
// transaction creating an output another batch member spends is positioned
// before that spending member, regardless of the caller's original order.
//
// The SQL backends record a transaction's wallet-owned credits and then claim
// its spent parent inputs in the same per-transaction step. Claiming a spent
// input is an UPDATE on the parent credit's UTXO row, so the parent credit must
// already exist when the child is recorded; otherwise the UPDATE matches no row
// and, finding no conflicting spend either, silently drops the spend edge and
// leaves the parent credit unspent. Applying a batch in caller order is
// therefore unsafe whenever a child is listed before its in-batch parent.
//
// This makes ApplyTxBatch order-independent: it stably topologically sorts the
// batch so every in-batch parent precedes its children while preserving the
// caller's relative order among transactions that have no in-batch dependency.
// A batch that is already parents-first, has a single transaction, or has no
// in-batch parent/child edges is returned unchanged. Edges to outpoints created
// outside the batch impose no ordering, since those parent rows either already
// exist or never will.
//
// The returned slice is a fresh reordering of the same CreateTxParams values;
// the input slice is not mutated.
func SortTxBatchParentsFirst(txs []CreateTxParams) []CreateTxParams {
	// Nothing to reorder: a single transaction (or none) cannot list a
	// child ahead of an in-batch parent.
	if len(txs) <= 1 {
		return txs
	}

	children, inDegree := buildTxBatchDependencyGraph(txs)
	order := topoSortTxBatchOrder(children, inDegree)

	ordered := make([]CreateTxParams, 0, len(txs))
	for _, idx := range order {
		ordered = append(ordered, txs[idx])
	}

	return ordered
}

// buildTxBatchDependencyGraph builds the parent->child dependency edges of a
// transaction batch. children[p] lists the positions of the batch transactions
// spending an output of txs[p], and inDegree[c] counts the distinct in-batch
// parents of txs[c]. Outpoints created outside the batch contribute no edge.
func buildTxBatchDependencyGraph(txs []CreateTxParams) ([][]int, []int) {
	// Map every in-batch transaction hash to its position so input lookups
	// can tell an in-batch parent from an external outpoint. A hash that
	// repeats in the batch keeps its first position; a later duplicate is
	// rejected by CreateTxWithOps regardless of order, so the dependency
	// edge only needs to point at one occurrence.
	indexByHash := make(map[chainhash.Hash]int, len(txs))
	for i := range txs {
		hash := txs[i].Tx.TxHash()
		if _, ok := indexByHash[hash]; !ok {
			indexByHash[hash] = i
		}
	}

	children := make([][]int, len(txs))

	inDegree := make([]int, len(txs))
	for child := range txs {
		// Deduplicate parents within one child so a child spending two
		// outputs of the same in-batch parent only adds one edge, which
		// keeps the in-degree bookkeeping exact.
		seen := make(map[int]struct{})
		for _, txIn := range txs[child].Tx.TxIn {
			parent, ok := indexByHash[txIn.PreviousOutPoint.Hash]
			if !ok || parent == child {
				continue
			}

			if _, dup := seen[parent]; dup {
				continue
			}

			seen[parent] = struct{}{}
			children[parent] = append(children[parent], child)
			inDegree[child]++
		}
	}

	return children, inDegree
}

// topoSortTxBatchOrder returns batch transaction positions in a stable
// parents-first topological order using Kahn's algorithm with an
// ascending-index ready set: among transactions whose in-batch parents are all
// already emitted, the one with the lowest original position goes next. That
// keeps the caller's relative order for independent transactions and leaves an
// already parents-first batch unchanged.
//
// A dependency cycle is impossible for real transactions, since an output
// cannot be spent before the transaction creating it exists. If a malformed
// batch still encodes one, the cyclic members never reach the ready set; they
// are appended in their original order so no transaction is dropped and
// CreateTxWithOps can reject the bad input downstream.
func topoSortTxBatchOrder(children [][]int, inDegree []int) []int {
	total := len(inDegree)

	ready := make([]int, 0, total)
	for i := range inDegree {
		if inDegree[i] == 0 {
			ready = append(ready, i)
		}
	}

	order := make([]int, 0, total)

	emitted := make([]bool, total)
	for len(ready) > 0 {
		node := popLowestIndex(&ready)
		order = append(order, node)
		emitted[node] = true

		for _, child := range children[node] {
			inDegree[child]--
			if inDegree[child] == 0 {
				ready = append(ready, child)
			}
		}
	}

	// Append any cyclic leftover in original order.
	if len(order) != total {
		for i := range total {
			if !emitted[i] {
				order = append(order, i)
			}
		}
	}

	return order
}

// popLowestIndex removes and returns the smallest value from ready, preserving
// the order of the remaining elements.
func popLowestIndex(ready *[]int) int {
	r := *ready

	lowest := 0
	for i := 1; i < len(r); i++ {
		if r[i] < r[lowest] {
			lowest = i
		}
	}

	node := r[lowest]
	r = append(r[:lowest], r[lowest+1:]...)
	*ready = r

	return node
}
