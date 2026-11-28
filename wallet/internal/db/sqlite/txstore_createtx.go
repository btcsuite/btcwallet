package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// CreateTx records a wallet transaction, its owned credits and input facts.
// Confirming it also marks unconfirmed competing transactions Replaced and
// their dependent transactions Failed, in the same database write.
//
// The shared write commits all changes or none. Received times are normalized
// to UTC. A current block can confirm retained Replaced/Failed history using
// its existing row and credits; an unconfirmed observation cannot revive it.
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

// createTxOps adapts sqlite sqlc queries to the shared CreateTx flow.
type createTxOps struct {
	invalidateUnminedTxOps

	blockHeight sql.NullInt64
}

var _ db.CreateTxOps = (*createTxOps)(nil)

// DeleteSpentLeases deletes the leases on outputs spent by txHash if that
// transaction is confirmed.
func (o *createTxOps) DeleteSpentLeases(ctx context.Context, walletID uint32,
	txHash chainhash.Hash) error {

	return deleteSpentLeases(ctx, o.qtx, walletID, txHash)
}

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

	status, err := db.ParseTxStatus(row.TxStatus)
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

	blockHeight, err := requireBlockMatches(
		ctx, o.qtx, req.Params.WalletID, req.Params.Block,
	)
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

	height, err := requireBlockMatches(
		ctx, o.qtx, req.Params.WalletID, req.Params.Block,
	)
	if err != nil {
		return err
	}

	o.blockHeight = sql.NullInt64{Int64: height, Valid: true}

	return nil
}

// ListConflictTxns returns unconfirmed transactions sharing inputs with req.
// Parent credits need not be known; the hashes allow descendants to be found.
func (o *createTxOps) ListConflictTxns(ctx context.Context,
	req db.CreateTxRequest) ([]int64, []chainhash.Hash, error) {

	rows, err := o.qtx.ListConflictingTransactions(
		ctx, sqlc.ListConflictingTransactionsParams{
			WalletID: int64(req.Params.WalletID), TxHash: req.TxHash[:],
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("list input conflicts: %w", err)
	}

	ids := make([]int64, 0, len(rows))
	hashes := make([]chainhash.Hash, 0, len(rows))

	for _, row := range rows {
		hash, err := chainhash.NewHash(row.TxHash)
		if err != nil {
			return nil, nil, fmt.Errorf("tx hash: %w", err)
		}

		ids = append(ids, row.ID)
		hashes = append(hashes, *hash)
	}

	return ids, hashes, nil
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

// InsertInputs indexes actual prevouts without requiring parent credit rows.
// The input-position key makes recording and replay share one immutable fact.
func (o *createTxOps) InsertInputs(ctx context.Context,
	req db.CreateTxRequest, txID int64) error {

	for index, input := range req.Params.Tx.TxIn {
		err := o.qtx.InsertTxInput(ctx, sqlc.InsertTxInputParams{
			WalletID:        int64(req.Params.WalletID),
			TxID:            txID,
			InputIndex:      int64(index),
			PrevTxHash:      input.PreviousOutPoint.Hash[:],
			PrevOutputIndex: int64(input.PreviousOutPoint.Index),
		})
		if err != nil {
			return fmt.Errorf("index input %d: %w", index, err)
		}
	}

	return nil
}

// GetInputValidity loads the invalid-parent and confirmed-competing-spender
// facts, in that order, without applying transaction admission policy.
func (o *createTxOps) GetInputValidity(ctx context.Context,
	req db.CreateTxRequest) (bool, bool, error) {

	// Retained prevouts expose conflicts before parent credit discovery.
	inp, err := o.qtx.GetTxInputValidity(
		ctx, sqlc.GetTxInputValidityParams{
			WalletID: int64(req.Params.WalletID),
			TxHash:   req.TxHash[:],
		},
	)
	if err != nil {
		return false, false,
			fmt.Errorf("check transaction input claims: %w", err)
	}

	return inp.HasInvalidParent, inp.HasConfirmedConflict, nil
}

// InsertCredits stores any wallet-owned outputs created by the transaction.
func (o *createTxOps) InsertCredits(ctx context.Context,
	req db.CreateTxRequest, txID int64) error {

	return insertCredits(ctx, o, req.Params, txID)
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

// insertCredits inserts one wallet-owned UTXO row for each credited
// output of the transaction being stored.
func insertCredits(ctx context.Context, ops *createTxOps,
	params db.CreateTxParams, txID int64) error {

	for index := range params.Credits {
		err := insertCredit(ctx, ops.qtx, params, txID, index)
		if err != nil {
			return err
		}
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

	return nil
}

// creditExists reports whether the wallet already has a UTXO row for the given
// credited output, even if that output is now spent by a child tx. When the row
// exists, it also returns the script used to resolve the owner address.
func creditExists(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, txHash chainhash.Hash, outputIndex uint32) (bool, []byte,
	error) {

	row, err := qtx.GetWalletCreditByOutpoint(
		ctx, sqlc.GetWalletCreditByOutpointParams{
			WalletID:    int64(walletID),
			TxHash:      txHash[:],
			OutputIndex: int64(outputIndex),
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil, nil
		}

		return false, nil, fmt.Errorf("lookup credit output %d: %w",
			outputIndex, err)
	}

	return true, row, nil
}
