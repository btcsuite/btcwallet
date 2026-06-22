package kvdb

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// A compile-time assertion to ensure Store implements the transaction store.
var _ db.TxStore = (*Store)(nil)

// errLegacyHeightOverflow reports that one db height cannot fit into the
// signed legacy wtxmgr height domain.
var errLegacyHeightOverflow = errors.New("legacy height overflows int32")

// legacyTxLabelsBucketKey is the private wtxmgr tx-label bucket name. The
// legacy module exposes label writes but not deletes, while the db.Store
// contract treats an empty label as clearing the label.
var legacyTxLabelsBucketKey = []byte("l")

// CreateTx records an unmined transaction through the legacy wtxmgr path.
//
// Unlike the SQL backends, kvdb does NOT route through the shared
// db.CreateTxWithOps orchestration, and this divergence is deliberate. That
// shared flow owns the full CreateTx contract: confirmed-transaction inserts,
// input-conflict discovery, invalidation/replacement of the displaced unmined
// branch, and wallet-owned spent-input marking. The legacy wtxmgr data model
// underneath kvdb is unmined-only and has no representation for that
// confirmed-history, replacement, or spend-edge bookkeeping, so an adapter for
// the shared ops would collapse most stages to notImplemented and add
// boilerplate without sharing meaningful logic.
//
// kvdb therefore implements only the unmined-insertion path directly and
// returns an explicit unsupported error for confirmed inserts (Block != nil)
// below. It still reuses the shared, backend-independent request preparation
// (db.NewCreateTxRequest) so parameter validation stays uniform across
// backends; only the post-validation write sequencing is bespoke.
func (s *Store) CreateTx(ctx context.Context,
	params db.CreateTxParams) error {

	req, err := db.NewCreateTxRequest(params)
	if err != nil {
		return fmt.Errorf("create tx request: %w", err)
	}

	if req.Params.Block != nil {
		return notImplemented(ctx, "CreateTx confirmed")
	}

	if len(req.Params.Credits) > 0 && s.addrStore == nil {
		return fmt.Errorf("kvdb.Store.CreateTx: %w", errMissingAddrStore)
	}

	txRec, err := wtxmgr.NewTxRecordFromMsgTx(req.Params.Tx, req.Received)
	if err != nil {
		return fmt.Errorf("build tx record: %w", err)
	}

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		return s.createTxWithTx(tx, txRec, req.Params)
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.CreateTx: %w", err)
	}

	return nil
}

// createTxWithTx records a transaction within one legacy walletdb update.
func (s *Store) createTxWithTx(tx walletdb.ReadWriteTx,
	txRec *wtxmgr.TxRecord, params db.CreateTxParams) error {

	// The waddrmgr namespace is only consulted when recording credits, so
	// only require it then. This mirrors the credit-gated addrStore guard
	// in CreateTx and lets a credit-less (sweep) tx be recorded without the
	// address-manager bucket.
	var addrmgrNs walletdb.ReadWriteBucket
	if len(params.Credits) > 0 {
		addrmgrNs = tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if addrmgrNs == nil {
			return errMissingAddrmgrNamespace
		}
	}

	txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
	if txmgrNs == nil {
		return errMissingTxmgrNamespace
	}

	exists, err := s.txStore.InsertTxCheckIfExists(
		txmgrNs, txRec, nil,
	)
	if err != nil {
		return fmt.Errorf("insert transaction: %w", err)
	}

	if exists {
		return db.ErrTxAlreadyExists
	}

	if len(params.Label) != 0 {
		err := s.txStore.PutTxLabel(
			txmgrNs, txRec.Hash, params.Label,
		)
		if err != nil {
			return fmt.Errorf("put transaction label: %w", err)
		}
	}

	return s.addCreateTxCredits(
		addrmgrNs, txmgrNs, txRec, params.Credits,
	)
}

// addCreateTxCredits records wallet-owned outputs for a legacy transaction.
func (s *Store) addCreateTxCredits(addrmgrNs,
	txmgrNs walletdb.ReadWriteBucket, txRec *wtxmgr.TxRecord,
	credits map[uint32]address.Address) error {

	if len(credits) == 0 {
		return nil
	}

	// CreateTx guarantees a non-nil addrStore whenever there are credits,
	// so it is safe to read chain params here.
	chainParams := s.addrStore.ChainParams()

	// Record each credit individually. The per-credit body lives in
	// addCreateTxCredit so this loop stays a thin driver and neither
	// function exceeds the cyclomatic-complexity budget.
	for index, addr := range credits {
		err := s.addCreateTxCredit(
			addrmgrNs, txmgrNs, txRec, index, addr, chainParams,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// addCreateTxCredit records a single wallet-owned output for a legacy
// transaction, resolving ownership either from the caller-supplied address or,
// when none is given, from the output's own script.
func (s *Store) addCreateTxCredit(addrmgrNs,
	txmgrNs walletdb.ReadWriteBucket, txRec *wtxmgr.TxRecord, index uint32,
	addr address.Address, chainParams *chaincfg.Params) error {

	// A nil credit address means the caller has no resolved owner for this
	// output, so the Store contract (CreateTxParams.Credits) keys ownership
	// on the output's own script. SQL implements this fallback, so kvdb
	// must match it rather than panic: record the credit straight from the
	// output index without an address-manager lookup or used-marking, and
	// skip membership validation, which has no caller address to check.
	// Reaching validateCreditAddr with a nil addr would otherwise panic on
	// addr.EncodeAddress().
	if addr == nil {
		if int(index) >= len(txRec.MsgTx.TxOut) {
			return fmt.Errorf("credit output %d: %w: index out of "+
				"range", index, db.ErrInvalidParam)
		}

		// change is false: with no resolved internal/external address
		// there is no derivation branch to consult, and the legacy
		// wtxmgr credit only needs the output index.
		err := s.txStore.AddCredit(txmgrNs, txRec, nil, index, false)
		if err != nil {
			return fmt.Errorf("add credit output %d: %w", index, err)
		}

		return nil
	}

	// Validate the caller-supplied credit against the actual output script
	// before trusting it. Otherwise a caller could credit output N with any
	// wallet address even when TxOut[N] pays elsewhere, corrupting UTXO
	// ownership.
	err := validateCreditAddr(txRec.MsgTx, index, addr, chainParams)
	if err != nil {
		return err
	}

	managedAddr, err := s.addrStore.Address(addrmgrNs, addr)
	if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
		return fmt.Errorf("credit output %d: %w", index,
			db.ErrAddressNotFound)
	}

	if err != nil {
		return fmt.Errorf("lookup credit address %d: %w", index, err)
	}

	err = s.txStore.AddCredit(
		txmgrNs, txRec, nil, index, managedAddr.Internal(),
	)
	if err != nil {
		return fmt.Errorf("add credit output %d: %w", index, err)
	}

	err = s.addrStore.MarkUsed(addrmgrNs, addr)
	if err != nil {
		return fmt.Errorf("mark credit address used %d: %w", index, err)
	}

	return nil
}

// validateCreditAddr verifies that the caller-supplied credit address is one of
// the addresses encoded in the output script it claims to credit. Membership
// (not equality) is required so bare-multisig scripts, where the wallet owns
// one of several pubkeys, still validate.
func validateCreditAddr(msgTx wire.MsgTx, index uint32, addr address.Address,
	chainParams *chaincfg.Params) error {

	if int(index) >= len(msgTx.TxOut) {
		return fmt.Errorf("credit output %d: %w: index out of range",
			index, db.ErrInvalidParam)
	}

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		msgTx.TxOut[index].PkScript, chainParams,
	)
	if err != nil {
		return fmt.Errorf("credit output %d: extract script addrs: %w",
			index, err)
	}

	want := addr.EncodeAddress()
	for _, scriptAddr := range addrs {
		if scriptAddr.EncodeAddress() == want {
			return nil
		}
	}

	return fmt.Errorf("credit output %d: %w: address %s not paid by "+
		"output script", index, db.ErrInvalidParam, want)
}

// UpdateTx re-implements the legacy kvdb label update path through the
// transitional Store interface.
//
// This preserves the existing kvdb scope: only label-only updates are supported
// here. Non-empty label validation remains owned by wtxmgr.PutTxLabel, while an
// empty label clears the legacy label bucket entry to match the Store contract.
//
// NOTE: The legacy kvdb backend only supports a single wallet instance, so the
// WalletID field is ignored.
func (s *Store) UpdateTx(_ context.Context, params db.UpdateTxParams) error {
	label, err := validateUpdateTxParams(params)
	if err != nil {
		return err
	}

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return fmt.Errorf(
				"wtxmgr namespace: %w", walletdb.ErrBucketNotFound,
			)
		}

		details, err := s.txStore.TxDetails(ns, &params.Txid)
		if err != nil {
			return fmt.Errorf("lookup transaction details: %w", err)
		}

		if details == nil {
			return db.ErrTxNotFound
		}

		err = s.updateLegacyTxLabel(ns, params.Txid, *label)
		if err != nil {
			return fmt.Errorf("update transaction label: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.UpdateTx: %w", err)
	}

	return nil
}

// updateLegacyTxLabel writes or clears one transaction label through the legacy
// wtxmgr label bucket.
func (s *Store) updateLegacyTxLabel(txmgrNs walletdb.ReadWriteBucket,
	txid chainhash.Hash, label string) error {

	if len(label) != 0 {
		return s.txStore.PutTxLabel(txmgrNs, txid, label)
	}

	labelBucket := txmgrNs.NestedReadWriteBucket(legacyTxLabelsBucketKey)
	if labelBucket == nil {
		return nil
	}

	return labelBucket.Delete(txid[:])
}

// GetTx retrieves one wallet-scoped transaction snapshot through the legacy
// wtxmgr query path.
func (s *Store) GetTx(_ context.Context, query db.GetTxQuery) (
	*db.TxInfo, error) {

	var info *db.TxInfo

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return fmt.Errorf(
				"wtxmgr namespace: %w", walletdb.ErrBucketNotFound,
			)
		}

		details, err := s.txStore.TxDetails(ns, &query.Txid)
		if err != nil {
			return fmt.Errorf("lookup transaction details: %w", err)
		}

		if details == nil {
			return db.ErrTxNotFound
		}

		info = kvdbTxInfo(details)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetTx: %w", err)
	}

	return info, nil
}

// ListTxns lists wallet-scoped transaction summaries through the legacy wtxmgr
// range query path.
func (s *Store) ListTxns(_ context.Context, query db.ListTxnsQuery) (
	[]db.TxInfo, error) {

	var infos []db.TxInfo

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return fmt.Errorf(
				"wtxmgr namespace: %w", walletdb.ErrBucketNotFound,
			)
		}

		if query.UnminedOnly {
			var err error

			infos, err = s.listTxnsRange(ns, -1, -1, nil)

			return err
		}

		begin, end, err := kvdbConfirmedTxnsRange(query)
		if err != nil {
			return err
		}

		infos, err = s.listTxnsRange(ns, begin, end, nil)

		return err
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.ListTxns: %w", err)
	}

	if len(infos) == 0 {
		return []db.TxInfo{}, nil
	}

	return infos, nil
}

// listTxnsRange appends one legacy wtxmgr range scan to the result set.
func (s *Store) listTxnsRange(ns walletdb.ReadBucket, begin, end int32,
	infos []db.TxInfo) ([]db.TxInfo, error) {

	err := s.txStore.RangeTransactions(
		ns, begin, end,
		func(txDetails []wtxmgr.TxDetails) (bool, error) {
			for i := range txDetails {
				infos = append(infos, *kvdbTxInfo(&txDetails[i]))
			}

			return false, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("range txns %d to %d: %w", begin, end, err)
	}

	return infos, nil
}

// GetTxDetail retrieves one detailed wallet-scoped transaction view through the
// legacy wtxmgr query path.
func (s *Store) GetTxDetail(_ context.Context, query db.GetTxDetailQuery) (
	*db.TxDetailInfo, error) {

	var detail *db.TxDetailInfo

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return fmt.Errorf(
				"wtxmgr namespace: %w", walletdb.ErrBucketNotFound,
			)
		}

		txDetails, err := s.txStore.TxDetails(ns, &query.Txid)
		if err != nil {
			return fmt.Errorf("lookup transaction details: %w", err)
		}

		if txDetails == nil {
			return db.ErrTxNotFound
		}

		detail = kvdbTxDetailInfo(txDetails)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetTxDetail: %w", err)
	}

	return detail, nil
}

// ListTxDetails lists detailed wallet-scoped transaction views through the
// legacy wtxmgr range path.
func (s *Store) ListTxDetails(_ context.Context, query db.ListTxDetailsQuery) (
	[]db.TxDetailInfo, error) {

	var details []db.TxDetailInfo

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return fmt.Errorf(
				"wtxmgr namespace: %w", walletdb.ErrBucketNotFound,
			)
		}

		return s.txStore.RangeTransactions(
			ns, query.StartHeight, query.EndHeight,
			func(txDetails []wtxmgr.TxDetails) (bool, error) {
				for i := range txDetails {
					details = append(
						details, *kvdbTxDetailInfo(&txDetails[i]),
					)
				}

				return false, nil
			},
		)
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.ListTxDetails: %w", err)
	}

	if len(details) == 0 {
		return []db.TxDetailInfo{}, nil
	}

	return details, nil
}

// DeleteTx is not yet implemented for kvdb.
func (s *Store) DeleteTx(ctx context.Context, _ db.DeleteTxParams) error {
	return notImplemented(ctx, "DeleteTx")
}

// InvalidateUnminedTx invalidates an unmined tx through the legacy wtxmgr path.
func (s *Store) InvalidateUnminedTx(_ context.Context,
	params db.InvalidateUnminedTxParams) error {

	err := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return errMissingTxmgrNamespace
		}

		details, err := s.txStore.TxDetails(ns, &params.Txid)
		if err != nil {
			return fmt.Errorf("lookup transaction details: %w", err)
		}

		if details == nil {
			return db.ErrTxNotFound
		}

		if details.Block.Height >= 0 {
			return fmt.Errorf("tx %s is confirmed: %w", params.Txid,
				db.ErrInvalidateTx)
		}

		return s.txStore.RemoveUnminedTx(ns, &details.TxRecord)
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.InvalidateUnminedTx: %w", err)
	}

	return nil
}

// RollbackToBlock atomically rolls legacy transaction state back to the
// provided height and rewinds wallet sync metadata to the same fork point in
// one walletdb update, mirroring the legacy SetSyncedTo + wtxmgr Rollback
// rewind.
//
// It is the chain-reorg rollback API: a rewind must move the sync tip back and
// disconnect the now-orphaned blocks and transactions together. Performing the
// sync-tip update and the rollback as two separate writes is unsafe, because a
// failure between them would leave the wallet sync tip rewound while
// transaction state still referenced the abandoned chain (or vice versa). Both
// effects therefore share one write transaction so the rewind is
// all-or-nothing.
//
// The new sync tip and birthday block are derived from the greatest retained
// block below the rollback boundary. Each field is only rewound when it points
// at or above the rollback boundary, matching the SQL backends, which clamp
// only affected wallet sync-state heights.
func (s *Store) RollbackToBlock(_ context.Context, height uint32) error {
	height32, err := db.Uint32ToInt32(height)
	if err != nil {
		return fmt.Errorf("kvdb.Store.RollbackToBlock: height: %w", err)
	}

	var target *rollbackTarget

	// Hold the Store write lock through the commit-failure restore below. This
	// keeps the cache restore ordered before a following Store write can commit
	// the same tip and create an ABA match.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if txmgrNs == nil {
			return errMissingTxmgrNamespace
		}

		target, err = s.computeRollbackTarget(tx, height, height32)
		if err != nil {
			return err
		}

		err = s.txStore.Rollback(txmgrNs, target.txHeight)
		if err != nil {
			return err
		}

		// Rewind live wallet metadata only after transaction rollback
		// succeeds. SetSyncedTo updates the address manager's in-memory tip
		// immediately after its DB write, so doing this last avoids leaving
		// memory rewound if the transaction rollback fails.
		return s.rewindRollbackState(tx, txmgrNs, target)
	})
	if err != nil {
		s.restoreRollbackState(target)

		return fmt.Errorf("kvdb.Store.RollbackToBlock: %w", err)
	}

	return nil
}

// rollbackTarget is the effective transaction and sync-state target for one
// rollback request.
type rollbackTarget struct {
	// txHeight is the height passed to wtxmgr.Rollback.
	txHeight int32

	// rewindSyncTip reports whether the wallet sync tip should be rewound.
	rewindSyncTip bool

	// currentTip is the live sync tip before the rewind starts.
	currentTip waddrmgr.BlockStamp

	// rewoundTip is the live sync tip after a successful SetSyncedTo inside the
	// walletdb update.
	rewoundTip waddrmgr.BlockStamp

	// currentBirthdayBlock is the birthday block before the rewind starts.
	currentBirthdayBlock waddrmgr.BlockStamp

	// currentBirthdayBlockVerified is the prior birthday block's verified
	// flag.
	currentBirthdayBlockVerified bool

	// currentBirthdayBlockSet reports whether a birthday block existed before
	// the rewind starts.
	currentBirthdayBlockSet bool

	// syncTipMutated reports whether SetSyncedTo succeeded inside the
	// walletdb update. If the enclosing commit fails after that point, the
	// live address-manager cache must be restored to currentTip when it still
	// matches rewoundTip.
	syncTipMutated bool

	// rewindBirthdayBlock reports whether the birthday block should be rewound.
	rewindBirthdayBlock bool

	// birthdayBlockMutated reports whether the birthday-block bucket was
	// updated inside the walletdb update.
	birthdayBlockMutated bool

	// forkBlock is the retained block below the rollback boundary. A nil
	// block with rewindSyncTip set means the sync tip should reset to the
	// start block.
	forkBlock *waddrmgr.BlockStamp
}

// computeRollbackTarget derives the effective rollback target from the caller's
// rollback boundary and any retained fork block below it.
func (s *Store) computeRollbackTarget(tx walletdb.ReadWriteTx, height uint32,
	height32 int32) (*rollbackTarget, error) {

	target := &rollbackTarget{txHeight: height32}

	// Without an address manager there is no wallet sync state to rewind in
	// this store, so the rollback is transaction-only.
	if s.addrStore == nil {
		return target, nil
	}

	target.currentTip = s.addrStore.SyncedTo()

	addrmgrNs := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
	if addrmgrNs == nil {
		return nil, errMissingAddrmgrNamespace
	}

	err := s.computeRollbackBirthdayBlockTarget(
		addrmgrNs, height32, target,
	)
	if err != nil {
		return nil, err
	}

	// A rollback to height zero removes all transaction blocks and resets the
	// wallet sync tip to the stored start block. Any birthday block also points
	// at a block being disconnected, so delete it with the rest of the state.
	if height == 0 {
		target.rewindSyncTip = true

		return target, nil
	}

	return s.computeRollbackForkTarget(addrmgrNs, height, height32, target)
}

// computeRollbackForkTarget completes a non-zero rollback target by looking up
// the retained fork block when sync metadata crosses the rollback boundary.
func (s *Store) computeRollbackForkTarget(ns walletdb.ReadBucket,
	height uint32, height32 int32,
	target *rollbackTarget) (*rollbackTarget, error) {

	rewindSyncTip := target.currentTip.Height >= height32
	if !rewindSyncTip && !target.rewindBirthdayBlock {
		return target, nil
	}

	// Only sync tips or birthday blocks at or above the rollback boundary need
	// a fork lookup. If neither does, the transaction rollback should keep
	// using the requested boundary.
	forkBlock, foundFork, err := s.rollbackForkBlock(ns, height)
	if err != nil {
		return nil, err
	}

	target.rewindSyncTip = rewindSyncTip
	if !foundFork {
		return target, nil
	}

	target.forkBlock = forkBlock

	return target, nil
}

// computeRollbackBirthdayBlockTarget records the prior birthday block and marks
// whether it should be rewound below the rollback boundary.
func (s *Store) computeRollbackBirthdayBlockTarget(ns walletdb.ReadBucket,
	height int32, target *rollbackTarget) error {

	birthdayBlock, verified, err := s.addrStore.BirthdayBlock(ns)
	switch {
	case err == nil:
		target.currentBirthdayBlock = birthdayBlock
		target.currentBirthdayBlockVerified = verified
		target.currentBirthdayBlockSet = true
		target.rewindBirthdayBlock = birthdayBlock.Height >= height

		return nil

	case waddrmgr.IsError(err, waddrmgr.ErrBirthdayBlockNotSet):
		return nil

	default:
		return fmt.Errorf("snapshot birthday block: %w", err)
	}
}

// rewindRollbackState applies all live wallet metadata changes for a rollback.
func (s *Store) rewindRollbackState(tx walletdb.ReadWriteTx,
	txmgrNs walletdb.ReadBucket, target *rollbackTarget) error {

	err := s.populateRollbackForkTimestamp(txmgrNs, target)
	if err != nil {
		return err
	}

	if target.rewindSyncTip && target.currentBirthdayBlockSet {
		err = s.deleteRollbackBirthdayBlock(tx, target)
		if err != nil {
			return err
		}
	}

	if target.rewindSyncTip {
		err = s.rewindSyncTip(tx, target)
		if err != nil {
			return err
		}

		return s.rewindBirthdayBlockAfterSyncTip(tx, target)
	}

	err = s.rewindBirthdayBlock(tx, target)
	if err != nil {
		return err
	}

	return s.rewindSyncTip(tx, target)
}

// rewindBirthdayBlockAfterSyncTip restores the birthday-block bucket after a
// sync-tip rewind. Any existing birthday block was cleared before SetSyncedTo
// so sparse predecessor validation cannot reject the sync-tip update.
func (s *Store) rewindBirthdayBlockAfterSyncTip(tx walletdb.ReadWriteTx,
	target *rollbackTarget) error {

	if !target.rewindBirthdayBlock {
		return s.restoreCurrentBirthdayBlock(tx, target)
	}

	if target.forkBlock == nil {
		return nil
	}

	return s.setRollbackBirthdayBlock(tx, target)
}

// restoreCurrentBirthdayBlock writes the pre-rollback birthday block back after
// temporarily clearing it for SetSyncedTo predecessor validation.
func (s *Store) restoreCurrentBirthdayBlock(tx walletdb.ReadWriteTx,
	target *rollbackTarget) error {

	if !target.currentBirthdayBlockSet {
		return nil
	}

	addrmgrNs, err := rollbackAddrmgrNamespace(tx)
	if err != nil {
		return err
	}

	err = s.addrStore.SetBirthdayBlock(
		addrmgrNs, target.currentBirthdayBlock,
		target.currentBirthdayBlockVerified,
	)
	if err != nil {
		return fmt.Errorf("restore birthday block after sync rewind: %w", err)
	}

	target.birthdayBlockMutated = true

	return nil
}

// populateRollbackForkTimestamp fills the retained fork block's timestamp when
// rollback needs that block for a sync-tip or birthday-block rewrite.
func (s *Store) populateRollbackForkTimestamp(txmgrNs walletdb.ReadBucket,
	target *rollbackTarget) error {

	if target.forkBlock == nil {
		return nil
	}

	if !target.rewindSyncTip && !target.rewindBirthdayBlock {
		return nil
	}

	forkBlock := *target.forkBlock

	forkTimestamp, err := s.forkBlockTimestamp(
		txmgrNs, forkBlock.Height, forkBlock.Hash,
	)
	if err != nil {
		return err
	}

	forkBlock.Timestamp = forkTimestamp
	target.forkBlock = &forkBlock

	return nil
}

// rollbackAddrmgrNamespace returns the address-manager bucket for a rollback
// write.
func rollbackAddrmgrNamespace(tx walletdb.ReadWriteTx) (
	walletdb.ReadWriteBucket, error) {

	addrmgrNs := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
	if addrmgrNs == nil {
		return nil, errMissingAddrmgrNamespace
	}

	return addrmgrNs, nil
}

// rewindBirthdayBlock applies the birthday-block half of a computed rollback
// target. If no retained block survives below the rollback boundary, the
// birthday block is cleared to match SQL's NULL clamp.
func (s *Store) rewindBirthdayBlock(tx walletdb.ReadWriteTx,
	target *rollbackTarget) error {

	if !target.rewindBirthdayBlock {
		return nil
	}

	if target.forkBlock == nil {
		return s.deleteRollbackBirthdayBlock(tx, target)
	}

	return s.setRollbackBirthdayBlock(tx, target)
}

// deleteRollbackBirthdayBlock clears the birthday block during rollback and
// records that the bucket was mutated for the error-restore path.
func (s *Store) deleteRollbackBirthdayBlock(tx walletdb.ReadWriteTx,
	target *rollbackTarget) error {

	addrmgrNs, err := rollbackAddrmgrNamespace(tx)
	if err != nil {
		return err
	}

	err = waddrmgr.DeleteBirthdayBlock(addrmgrNs)
	if err != nil {
		return fmt.Errorf("delete birthday block: %w", err)
	}

	target.birthdayBlockMutated = true

	return nil
}

// setRollbackBirthdayBlock rewrites the birthday block to the retained fork
// block and records that the bucket was mutated for the error-restore path.
func (s *Store) setRollbackBirthdayBlock(tx walletdb.ReadWriteTx,
	target *rollbackTarget) error {

	if target.forkBlock == nil {
		return nil
	}

	addrmgrNs, err := rollbackAddrmgrNamespace(tx)
	if err != nil {
		return err
	}

	err = s.addrStore.SetBirthdayBlock(
		addrmgrNs, *target.forkBlock,
		target.currentBirthdayBlockVerified,
	)
	if err != nil {
		return fmt.Errorf("set birthday block: %w", err)
	}

	target.birthdayBlockMutated = true

	return nil
}

// resetSyncTipToStart resets the wallet sync tip back to the stored start
// block for a rollback to height zero. SetSyncedTo(nil) rewinds both the live
// addrStore cache and the persisted walletdb state to the unsynced start
// point, matching the SQL backends that clamp the synced height to NULL.
func (s *Store) resetSyncTipToStart(tx walletdb.ReadWriteTx,
	target *rollbackTarget) error {

	addrmgrNs := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
	if addrmgrNs == nil {
		return errMissingAddrmgrNamespace
	}

	err := s.addrStore.SetSyncedTo(addrmgrNs, nil)
	if err != nil {
		return fmt.Errorf("reset synced to: %w", err)
	}

	target.rewoundTip = s.addrStore.SyncedTo()
	target.syncTipMutated = true

	return nil
}

// rewindSyncTip applies the sync-tip half of a computed rollback target.
func (s *Store) rewindSyncTip(tx walletdb.ReadWriteTx,
	target *rollbackTarget) error {

	if !target.rewindSyncTip {
		return nil
	}

	if target.forkBlock == nil {
		return s.resetSyncTipToStart(tx, target)
	}

	addrmgrNs := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
	if addrmgrNs == nil {
		return errMissingAddrmgrNamespace
	}

	err := s.addrStore.SetSyncedTo(addrmgrNs, target.forkBlock)
	if err != nil {
		return fmt.Errorf("set synced to: %w", err)
	}

	target.rewoundTip = *target.forkBlock
	target.syncTipMutated = true

	return nil
}

// restoreRollbackState restores live address-manager rollback state when the
// walletdb update fails after mutating SetSyncedTo's in-memory cache.
func (s *Store) restoreRollbackState(target *rollbackTarget) {
	if s.addrStore == nil || target == nil {
		return
	}

	if !target.syncTipMutated {
		return
	}

	s.addrStore.RestoreSyncedToIfCurrent(
		target.currentTip, target.rewoundTip,
	)
}

// rollbackForkBlock returns the greatest stored block below the rollback
// boundary and reports whether any retained block survives below that boundary.
func (s *Store) rollbackForkBlock(ns walletdb.ReadBucket,
	height uint32) (*waddrmgr.BlockStamp, bool, error) {

	for searchHeight := height - 1; ; searchHeight-- {
		forkHeight, err := db.Uint32ToInt32(searchHeight)
		if err != nil {
			return nil, false, fmt.Errorf("fork height: %w", err)
		}

		forkHash, err := s.addrStore.BlockHash(ns, forkHeight)
		if err == nil {
			return &waddrmgr.BlockStamp{
				Height: forkHeight,
				Hash:   *forkHash,
			}, true, nil
		}

		if !waddrmgr.IsError(err, waddrmgr.ErrBlockNotFound) {
			return nil, false, fmt.Errorf("fork block at height %d: %w",
				forkHeight, err)
		}

		if searchHeight == 0 {
			return nil, false, nil
		}
	}
}

// forkBlockTimestamp returns the legacy tx-store timestamp for the surviving
// fork block when that block contains wallet transactions. The address manager
// keeps historical block hashes but not historical timestamps for empty wallet
// blocks, so an empty timestamp is used when no retained metadata exists rather
// than carrying a disconnected tip timestamp forward.
func (s *Store) forkBlockTimestamp(txmgrNs walletdb.ReadBucket,
	forkHeight int32, forkHash chainhash.Hash) (time.Time, error) {

	forkTimestamp := time.Unix(0, 0).UTC()

	err := s.txStore.RangeTransactions(
		txmgrNs, forkHeight, forkHeight,
		func(txDetails []wtxmgr.TxDetails) (bool, error) {
			for i := range txDetails {
				block := txDetails[i].Block
				if block.Height == forkHeight && block.Hash == forkHash {
					forkTimestamp = block.Time

					return true, nil
				}
			}

			return false, nil
		},
	)
	if err != nil {
		return time.Time{}, fmt.Errorf("fork block timestamp: %w", err)
	}

	return forkTimestamp, nil
}

// validateUpdateTxParams checks whether one UpdateTx request matches the legacy
// kvdb label-only behavior preserved by this adapter.
func validateUpdateTxParams(params db.UpdateTxParams) (*string, error) {
	if params.Label == nil && params.State == nil {
		return nil, fmt.Errorf("kvdb.Store.UpdateTx: %w: UpdateTx requires at "+
			"least one field", db.ErrInvalidParam)
	}

	if params.State != nil {
		return nil, fmt.Errorf("kvdb.Store.UpdateTx: state patch: %w",
			errNotImplemented)
	}

	if params.Label == nil {
		return nil, fmt.Errorf("kvdb.Store.UpdateTx: label patch required: %w",
			db.ErrInvalidParam)
	}

	return params.Label, nil
}

// kvdbTxInfo maps legacy wtxmgr detail data into the lightweight db-native
// transaction summary model.
func kvdbTxInfo(details *wtxmgr.TxDetails) *db.TxInfo {
	var block *db.Block
	if details.Block.Height >= 0 {
		block = &db.Block{
			Hash:      details.Block.Hash,
			Height:    nonNegativeInt32ToUint32(details.Block.Height),
			Timestamp: details.Block.Time,
		}
	}

	return &db.TxInfo{
		Hash:         details.Hash,
		SerializedTx: append([]byte(nil), details.SerializedTx...),
		Received:     details.Received.UTC(),
		Block:        block,

		// Legacy wtxmgr only exposes transactions it still treats as valid,
		// and it does not persist pending/replaced/failed/orphaned state.
		Status: db.TxStatusPublished,
		Label:  details.Label,
	}
}

// kvdbTxDetailInfo maps legacy wtxmgr detail data into the db-native
// transaction detail model used by wallet tx-reader code.
func kvdbTxDetailInfo(details *wtxmgr.TxDetails) *db.TxDetailInfo {
	var block *db.Block
	if details.Block.Height >= 0 {
		block = &db.Block{
			Hash:      details.Block.Hash,
			Height:    nonNegativeInt32ToUint32(details.Block.Height),
			Timestamp: details.Block.Time,
		}
	}

	ownedInputs := make([]db.TxOwnedInput, 0, len(details.Debits))
	for _, debit := range details.Debits {
		ownedInputs = append(ownedInputs, db.TxOwnedInput{
			Index:  debit.Index,
			Amount: debit.Amount,
		})
	}

	ownedOutputs := make([]db.TxOwnedOutput, 0, len(details.Credits))
	for _, credit := range details.Credits {
		ownedOutputs = append(ownedOutputs, db.TxOwnedOutput{
			Index:  credit.Index,
			Amount: credit.Amount,
		})
	}

	msgTx := details.MsgTx

	return &db.TxDetailInfo{
		Hash:         details.Hash,
		MsgTx:        &msgTx,
		SerializedTx: append([]byte(nil), details.SerializedTx...),
		Received:     details.Received.UTC(),
		Block:        block,

		// Legacy wtxmgr only exposes transactions it still treats as valid,
		// and it does not persist pending/replaced/failed/orphaned state.
		Status:       db.TxStatusPublished,
		Label:        details.Label,
		OwnedInputs:  ownedInputs,
		OwnedOutputs: ownedOutputs,
	}
}

// kvdbConfirmedTxnsRange converts the confirmed query heights into the legacy
// wtxmgr range arguments used by the kvdb adapter.
func kvdbConfirmedTxnsRange(query db.ListTxnsQuery) (int32, int32, error) {
	startHeight, err := uint32ToLegacyHeight(query.StartHeight)
	if err != nil {
		return 0, 0, fmt.Errorf("convert start height: %w", err)
	}

	endHeight, err := uint32ToLegacyHeight(query.EndHeight)
	if err != nil {
		return 0, 0, fmt.Errorf("convert end height: %w", err)
	}

	return startHeight, endHeight, nil
}

// uint32ToLegacyHeight converts a db height into the signed height domain used
// by the legacy wtxmgr range API.
func uint32ToLegacyHeight(height uint32) (int32, error) {
	if height > math.MaxInt32 {
		return 0, fmt.Errorf("%w: %d", errLegacyHeightOverflow, height)
	}

	return int32(height), nil
}

// nonNegativeInt32ToUint32 converts a non-negative int32 to uint32.
func nonNegativeInt32ToUint32(value int32) uint32 {
	if value < 0 {
		return 0
	}

	return uint32(value)
}
