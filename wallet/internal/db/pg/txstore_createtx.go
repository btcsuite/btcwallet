package pg

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// CreateTx atomically records a wallet-scoped transaction row, its
// wallet-owned credits, and any spend edges created by its inputs.
//
// The full write runs inside the shared write helper so the transaction row,
// created UTXOs, spent-parent markers, and any required invalidation are
// either committed together or not at all. Received timestamps are normalized
// to UTC before Insert. When the wallet already stores the same unmined
// transaction hash, CreateTx may promote that existing row to confirmed state
// instead of inserting a duplicate.
func (s *Store) CreateTx(ctx context.Context,
	params db.CreateTxParams) error {

	req, err := db.NewCreateTxRequest(params)
	if err != nil {
		return err
	}

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		return db.CreateTxWithOps(ctx, req, &createTxOps{
			invalidateUnminedTxOps: invalidateUnminedTxOps{
				qtx: qtx,
			},
		})
	})
}

// createTxOps adapts postgres sqlc queries to the shared CreateTx flow.
type createTxOps struct {
	invalidateUnminedTxOps

	blockHeight sql.NullInt32
}

var _ db.CreateTxOps = (*createTxOps)(nil)

// LoadExisting loads any existing wallet-scoped row for the requested tx hash.
func (o *createTxOps) LoadExisting(ctx context.Context,
	req db.CreateTxRequest) (*db.CreateTxExistingTarget, error) {

	row, err := o.qtx.GetTransactionByHash(
		ctx,
		sqlc.GetTransactionByHashParams{
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

	status, err := db.ParseTxStatus(int64(row.TxStatus))
	if err != nil {
		return nil, err
	}

	var (
		blockHeight *uint32
		blockHash   *chainhash.Hash
	)
	if row.BlockHeight.Valid {
		block, err := buildBlock(
			row.BlockHeight, row.BlockHash, row.BlockTimestamp,
		)
		if err != nil {
			return nil, err
		}

		height := block.Height
		blockHeight = &height

		hash := block.Hash
		blockHash = &hash
	}

	return &db.CreateTxExistingTarget{
		ID:          row.ID,
		Status:      status,
		HasBlock:    row.BlockHeight.Valid,
		BlockHeight: blockHeight,
		BlockHash:   blockHash,
		IsCoinbase:  row.IsCoinbase,
		Label:       row.TxLabel,
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
			BlockHeight: sql.NullInt32{Int32: blockHeight, Valid: true},
			Status:      int16(db.TxStatusPublished),
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

// PrepareBlock validates the optional confirming block and caches the postgres
// block-height value that the later Insert query will store.
func (o *createTxOps) PrepareBlock(ctx context.Context,
	req db.CreateTxRequest) error {

	o.blockHeight = sql.NullInt32{}

	if req.Params.Block == nil {
		return nil
	}

	height, err := requireBlockMatches(ctx, o.qtx, req.Params.Block)
	if err != nil {
		return err
	}

	o.blockHeight = sql.NullInt32{Int32: height, Valid: true}

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

// collectConflictRootIDs returns the active unmined spender row IDs
// that currently own any wallet-controlled input spent by the incoming tx.
func collectConflictRootIDs(ctx context.Context, qtx *sqlc.Queries,
	req db.CreateTxRequest) (map[int64]struct{}, error) {

	if blockchain.IsCoinBaseTx(req.Params.Tx) {
		return map[int64]struct{}{}, nil
	}

	rootIDs := make(map[int64]struct{}, len(req.Params.Tx.TxIn))
	for inputIndex, txIn := range req.Params.Tx.TxIn {
		outputIndex, err := db.Uint32ToInt32(txIn.PreviousOutPoint.Index)
		if err != nil {
			return nil, fmt.Errorf("convert input outpoint index %d: %w",
				inputIndex, err)
		}

		spend, err := qtx.GetUtxoSpendByOutpoint(
			ctx, sqlc.GetUtxoSpendByOutpointParams{
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

		if !spend.SpentByTxID.Valid {
			continue
		}

		rootIDs[spend.SpentByTxID.Int64] = struct{}{}
	}

	return rootIDs, nil
}

// buildConflictRoots maps the selected unmined rows into ordered root IDs and
// the matching root hashes used for descendant discovery.
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

// Insert stores one new postgres transaction row for CreateTx.
func (o *createTxOps) Insert(ctx context.Context,
	req db.CreateTxRequest) (int64, error) {

	txID, err := o.qtx.InsertTransaction(ctx, sqlc.InsertTransactionParams{
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
		return 0, fmt.Errorf("insert tx row: %w", err)
	}

	return txID, nil
}

// InsertCredits stores any wallet-owned outputs created by the transaction.
func (o *createTxOps) InsertCredits(ctx context.Context,
	req db.CreateTxRequest, txID int64) error {

	return insertCredits(ctx, o, req.Params, txID)
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
			Status:   int16(db.TxStatusReplaced),
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

// creditLookupScript returns the script_pub_key used to resolve the owning
// address row for the credited output at the given index.
//
// When the caller supplied a resolved credit address, ownership is keyed on
// that address's own script (PayToAddrScript). This mirrors the kvdb backend,
// which validates the credit as a member of the output script and then looks
// the address up directly: a bare-multisig output the wallet partly owns is
// stored against the wallet-owned member rather than the full multisig script,
// which no address row would ever match. For a single-address output the
// member script equals the output script, so the lookup is unchanged.
//
// When the credit address is nil the caller has no resolved owner, so the
// on-chain output script is used directly, preserving the store's original
// behavior.
//
// NOTE: This only selects the address-ownership lookup key. The stored UTXO
// always records the on-chain output script (TxOut[index].PkScript) via
// InsertUtxo's amount/output-index, never the member script.
func creditLookupScript(params db.CreateTxParams, index uint32) ([]byte,
	error) {

	creditAddr := params.Credits[index]
	if creditAddr == nil {
		return params.Tx.TxOut[index].PkScript, nil
	}

	// A non-nil credit address is authoritative for ownership, so reject it
	// unless the output it claims to credit actually pays to it. Without this
	// check a caller could point output N at any wallet address and have the
	// store record a UTXO owned by an address the output never pays,
	// corrupting ownership. Membership (not equality) keeps bare-multisig
	// member credits valid.
	err := db.ValidateCreditAddrMembership(
		creditAddr, params.Tx.TxOut[index].PkScript,
	)
	if err != nil {
		return nil, fmt.Errorf("credit output %d: %w", index, err)
	}

	lookupScript, err := txscript.PayToAddrScript(creditAddr)
	if err != nil {
		return nil, fmt.Errorf("credit output %d: build address script: "+
			"%w", index, err)
	}

	return lookupScript, nil
}

// existingChildSpend describes one already-stored active transaction input that
// spends an output whose wallet ownership was discovered later.
type existingChildSpend struct {
	// id is the stored child transaction row ID.
	id int64

	// hash is the child transaction hash used for descendant discovery.
	hash chainhash.Hash

	// confirmed reports whether the child row has confirming block metadata.
	confirmed bool

	// inputIndex is the input index that spends prevOut.
	inputIndex int

	// prevOut is the parent output spent by the child input.
	prevOut wire.OutPoint
}

// insertCredits inserts one wallet-owned UTXO row for each credited output of
// the transaction being stored.
func insertCredits(ctx context.Context, ops *createTxOps,
	params db.CreateTxParams, txID int64) error {

	for index := range params.Credits {
		err := insertCredit(ctx, ops.qtx, params, txID, index)
		if err != nil {
			return err
		}
	}

	err := markExistingChildSpends(ctx, ops, params, txID)
	if err != nil {
		return err
	}

	return nil
}

// insertCredit inserts or validates one wallet-owned UTXO row for a credited
// output.
func insertCredit(ctx context.Context, qtx *sqlc.Queries,
	params db.CreateTxParams, txID int64, index uint32) error {

	lookupScript, err := creditLookupScript(params, index)
	if err != nil {
		return err
	}

	creditExists, existingScript, err := creditExists(
		ctx, qtx, params.WalletID, params.Tx.TxHash(), index,
	)
	if err != nil {
		return err
	}

	if creditExists {
		if !bytes.Equal(existingScript, lookupScript) {
			return fmt.Errorf("credit output %d owner mismatch: %w",
				index, db.ErrTxAlreadyExists)
		}

		return nil
	}

	addrRow, err := qtx.GetAddressByScriptPubKey(
		ctx, sqlc.GetAddressByScriptPubKeyParams{
			ScriptPubKey: lookupScript,
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

	outputIndex, err := db.Uint32ToInt32(index)
	if err != nil {
		return fmt.Errorf("convert credit index %d: %w", index, err)
	}

	_, err = qtx.InsertUtxo(ctx, sqlc.InsertUtxoParams{
		WalletID:    int64(params.WalletID),
		TxID:        txID,
		OutputIndex: outputIndex,
		Amount:      params.Tx.TxOut[index].Value,
		AddressID:   addrRow.ID,
	})
	if err != nil {
		return fmt.Errorf("insert credit output %d: %w", index, err)
	}

	return nil
}

// markExistingChildSpends attaches already-stored active child transaction
// inputs to any credited outputs created by params.Tx.
func markExistingChildSpends(ctx context.Context, ops *createTxOps,
	params db.CreateTxParams, txID int64) error {

	if len(params.Credits) == 0 {
		return nil
	}

	qtx := ops.qtx

	rows, err := qtx.ListActiveTransactionRaws(ctx, int64(params.WalletID))
	if err != nil {
		return fmt.Errorf("list active txns: %w", err)
	}

	parentHash := params.Tx.TxHash()

	childSpends, err := collectExistingChildSpends(
		rows, parentHash, params, txID,
	)
	if err != nil {
		return err
	}

	outPoints := make([]wire.OutPoint, 0, len(childSpends))
	for outPoint := range childSpends {
		outPoints = append(outPoints, outPoint)
	}

	sort.Slice(outPoints, func(i, j int) bool {
		return outPoints[i].Index < outPoints[j].Index
	})

	activeSpends := make(map[wire.OutPoint][]existingChildSpend, len(outPoints))
	for _, outPoint := range outPoints {
		spends, err := activeExistingChildSpends(
			ctx, qtx, params.WalletID, childSpends[outPoint],
		)
		if err != nil {
			return err
		}

		activeSpends[outPoint] = spends
	}

	scheduledReplacements, err := validateExistingChildSpendGroups(
		activeSpends,
	)
	if err != nil {
		return err
	}

	appliedReplacements := make(map[int64]struct{}, len(scheduledReplacements))
	for _, outPoint := range outPoints {
		spends := activeSpends[outPoint]

		err = reconcileExistingChildSpends(
			ctx, ops, params, spends, scheduledReplacements,
			appliedReplacements,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateExistingChildSpendGroups validates every credited-output spend group
// before reconciliation mutates any spend edges.
func validateExistingChildSpendGroups(
	groups map[wire.OutPoint][]existingChildSpend) (map[int64]struct{}, error) {

	scheduledReplacements := make(map[int64]struct{})
	for _, spends := range groups {
		confirmed, unmined := splitExistingChildSpends(spends)
		if len(confirmed) > 1 {
			return nil, db.ErrTxInputConflict
		}

		if len(confirmed) == 0 {
			continue
		}

		for _, spend := range unmined {
			scheduledReplacements[spend.id] = struct{}{}
		}
	}

	for _, spends := range groups {
		confirmed, unmined := splitExistingChildSpends(spends)
		if len(confirmed) != 0 {
			continue
		}

		unmined = filterExistingChildSpendsByID(
			unmined, scheduledReplacements,
		)
		if len(unmined) > 1 {
			return nil, db.ErrTxInputConflict
		}
	}

	return scheduledReplacements, nil
}

// filterExistingChildSpendsByID removes spends whose child transaction ID is in
// the skip set.
func filterExistingChildSpendsByID(spends []existingChildSpend,
	skip map[int64]struct{}) []existingChildSpend {

	filtered := spends[:0]
	for _, spend := range spends {
		if _, ok := skip[spend.id]; ok {
			continue
		}

		filtered = append(filtered, spend)
	}

	return filtered
}

// collectExistingChildSpends groups active children by the credited parent
// outpoint they spend.
func collectExistingChildSpends(rows []sqlc.ListActiveTransactionRawsRow,
	parentHash chainhash.Hash, params db.CreateTxParams, txID int64) (
	map[wire.OutPoint][]existingChildSpend, error) {

	spends := make(map[wire.OutPoint][]existingChildSpend)
	for _, row := range rows {
		if row.ID == txID {
			continue
		}

		txHash, err := chainhash.NewHash(row.TxHash)
		if err != nil {
			return nil, fmt.Errorf("active child tx hash %d: %w", row.ID,
				err)
		}

		childTx, err := deserializeActiveTx(row.ID, row.RawTx)
		if err != nil {
			return nil, err
		}

		addChildInputSpends(
			spends, childTx, parentHash, params, row.ID, *txHash,
			row.BlockHeight.Valid,
		)
	}

	return spends, nil
}

// activeExistingChildSpends filters one snapshot group to children that still
// belong to the active spend set.
func activeExistingChildSpends(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, spends []existingChildSpend) ([]existingChildSpend,
	error) {

	active := make([]existingChildSpend, 0, len(spends))
	for _, spend := range spends {
		row, err := qtx.GetTransactionByHash(
			ctx, sqlc.GetTransactionByHashParams{
				WalletID: int64(walletID),
				TxHash:   spend.hash[:],
			},
		)
		if err != nil {
			return nil, fmt.Errorf("refresh existing child %d: %w",
				spend.id, err)
		}

		status, err := db.ParseTxStatus(int64(row.TxStatus))
		if err != nil {
			return nil, fmt.Errorf("refresh existing child %d: %w",
				spend.id, err)
		}

		if !db.IsUnminedStatus(status) {
			continue
		}

		spend.confirmed = row.BlockHeight.Valid
		active = append(active, spend)
	}

	return active, nil
}

// addChildInputSpends appends child inputs that spend credited parent outputs.
func addChildInputSpends(spends map[wire.OutPoint][]existingChildSpend,
	childTx *wire.MsgTx, parentHash chainhash.Hash, params db.CreateTxParams,
	childTxID int64, childHash chainhash.Hash, confirmed bool) {

	for inputIndex, txIn := range childTx.TxIn {
		prevOut := txIn.PreviousOutPoint
		if prevOut.Hash != parentHash {
			continue
		}

		if _, ok := params.Credits[prevOut.Index]; !ok {
			continue
		}

		spends[prevOut] = append(spends[prevOut], existingChildSpend{
			id:         childTxID,
			hash:       childHash,
			confirmed:  confirmed,
			inputIndex: inputIndex,
			prevOut:    prevOut,
		})
	}
}

// deserializeActiveTx deserializes one active transaction row.
func deserializeActiveTx(txID int64, rawTx []byte) (*wire.MsgTx, error) {
	var msgTx wire.MsgTx

	err := msgTx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		return nil, fmt.Errorf("deserialize active tx %d: %w", txID, err)
	}

	return &msgTx, nil
}

// reconcileExistingChildSpends reconciles all active children that spend one
// newly discovered parent credit before any spend edge is mutated.
func reconcileExistingChildSpends(ctx context.Context, ops *createTxOps,
	params db.CreateTxParams, spends []existingChildSpend,
	scheduledReplacements, appliedReplacements map[int64]struct{}) error {

	confirmed, unmined := splitExistingChildSpends(spends)
	if len(confirmed) > 1 {
		return db.ErrTxInputConflict
	}

	if len(confirmed) == 0 {
		unmined = filterExistingChildSpendsByID(
			unmined, scheduledReplacements,
		)
		if len(unmined) == 0 {
			return nil
		}

		if len(unmined) != 1 {
			return db.ErrTxInputConflict
		}

		return markChildInputSpent(ctx, ops.qtx, params, unmined[0])
	}

	confirmedSpend := confirmed[0]

	unmined = filterExistingChildSpendsByID(unmined, appliedReplacements)
	if len(unmined) > 0 {
		err := replaceUnminedChildSpends(
			ctx, ops, params, confirmedSpend.id, unmined,
		)
		if err != nil {
			return err
		}

		for _, spend := range unmined {
			appliedReplacements[spend.id] = struct{}{}
		}
	}

	return markChildInputSpent(ctx, ops.qtx, params, confirmedSpend)
}

// splitExistingChildSpends separates confirmed child spends from unmined child
// spends.
func splitExistingChildSpends(spends []existingChildSpend) (
	[]existingChildSpend, []existingChildSpend) {

	confirmed := make([]existingChildSpend, 0, len(spends))
	unmined := make([]existingChildSpend, 0, len(spends))

	for _, spend := range spends {
		if spend.confirmed {
			confirmed = append(confirmed, spend)

			continue
		}

		unmined = append(unmined, spend)
	}

	return confirmed, unmined
}

// replaceUnminedChildSpends marks unmined child spends replaced by a confirmed
// child spend.
func replaceUnminedChildSpends(ctx context.Context, ops *createTxOps,
	params db.CreateTxParams, confirmedTxID int64,
	unmined []existingChildSpend) error {

	rootIDs := make([]int64, 0, len(unmined))
	rootHashes := make([]chainhash.Hash, 0, len(unmined))

	for _, spend := range unmined {
		rootIDs = append(rootIDs, spend.id)
		rootHashes = append(rootHashes, spend.hash)
	}

	err := db.ReplaceUnminedTxConflicts(
		ctx, int64(params.WalletID), rootIDs, rootHashes, confirmedTxID,
		ops,
	)
	if err != nil {
		return fmt.Errorf("replace existing child spends: %w", err)
	}

	return nil
}

// markChildInputSpent attaches one child input to its credited parent output.
func markChildInputSpent(ctx context.Context, qtx *sqlc.Queries,
	params db.CreateTxParams, spend existingChildSpend) error {

	outputIndex, err := db.Uint32ToInt32(spend.prevOut.Index)
	if err != nil {
		return fmt.Errorf("convert child outpoint index %d: %w",
			spend.inputIndex, err)
	}

	spentInputIndex, err := db.Int64ToInt32(int64(spend.inputIndex))
	if err != nil {
		return fmt.Errorf("convert child input index %d: %w",
			spend.inputIndex, err)
	}

	rowsAffected, err := qtx.MarkUtxoSpent(
		ctx, sqlc.MarkUtxoSpentParams{
			WalletID:    int64(params.WalletID),
			TxHash:      spend.prevOut.Hash[:],
			OutputIndex: outputIndex,
			SpentByTxID: sql.NullInt64{
				Int64: spend.id,
				Valid: true,
			},
			SpentInputIndex: sql.NullInt32{
				Int32: spentInputIndex,
				Valid: true,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("mark existing child %d input %d: %w",
			spend.id, spend.inputIndex, err)
	}

	if rowsAffected != 0 {
		return nil
	}

	err = ensureSpendConflict(
		ctx, qtx, params.WalletID, spend.prevOut.Hash, outputIndex,
		spend.id,
	)
	if err != nil {
		return fmt.Errorf("mark existing child %d input %d: %w",
			spend.id, spend.inputIndex, err)
	}

	return nil
}

// creditExists reports whether the wallet already has a UTXO row for the given
// credited output, even if that output is now spent by a child tx. When the row
// exists, it also returns the script used to resolve the owner address.
func creditExists(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, txHash chainhash.Hash, outputIndex uint32) (bool, []byte,
	error) {

	convertedIndex, err := db.Uint32ToInt32(outputIndex)
	if err != nil {
		return false, nil, fmt.Errorf("convert credit index %d: %w",
			outputIndex, err)
	}

	row, err := qtx.GetUtxoSpendByOutpoint(
		ctx, sqlc.GetUtxoSpendByOutpointParams{
			WalletID:    int64(walletID),
			TxHash:      txHash[:],
			OutputIndex: convertedIndex,
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil, nil
		}

		return false, nil, fmt.Errorf("lookup credit output %d: %w",
			outputIndex, err)
	}

	return true, row.ScriptPubKey, nil
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
		outputIndex, err := db.Uint32ToInt32(txIn.PreviousOutPoint.Index)
		if err != nil {
			return fmt.Errorf("convert input outpoint index %d: %w", inputIndex,
				err)
		}

		spentInputIndex, err := db.Int64ToInt32(int64(inputIndex))
		if err != nil {
			return fmt.Errorf("convert input index %d: %w", inputIndex, err)
		}

		rowsAffected, err := qtx.MarkUtxoSpent(ctx, sqlc.MarkUtxoSpentParams{
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
			err = ensureSpendConflict(
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

// ensureSpendConflict reports ErrTxInputConflict when the referenced outpoint
// is wallet-owned, still eligible for spending, and already attached to another
// transaction. If the wallet owns the parent output but that parent is already
// invalid, the helper returns ErrTxInputInvalidParent instead.
func ensureSpendConflict(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, txHash chainhash.Hash, outputIndex int32,
	txID int64) error {

	spend, err := qtx.GetUtxoSpendByOutpoint(
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

	if spend.SpentByTxID.Valid && spend.SpentByTxID.Int64 != txID {
		return db.ErrTxInputConflict
	}

	return nil
}

// ensureWalletParentValid reports ErrTxInputInvalidParent when the wallet
// owns the referenced outpoint but its parent transaction is already invalid.
func ensureWalletParentValid(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, txHash chainhash.Hash, outputIndex int32) error {

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
