package kvdb

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
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
	credits map[uint32]btcutil.Address) error {

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
	addr btcutil.Address, chainParams *chaincfg.Params) error {

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
func validateCreditAddr(msgTx wire.MsgTx, index uint32, addr btcutil.Address,
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
// This preserves the existing kvdb behavior: only label-only updates are
// supported here, and label validation remains owned by wtxmgr.PutTxLabel.
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

		err = s.txStore.PutTxLabel(ns, params.Txid, *label)
		if err != nil {
			return fmt.Errorf("put transaction label: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.UpdateTx: %w", err)
	}

	return nil
}

// ApplyTxBatch atomically records transactions and an optional sync-tip update
// through the legacy walletdb managers.
func (s *Store) ApplyTxBatch(_ context.Context,
	params db.TxBatchParams) error {

	// A batch with no transactions and no sync-tip update has nothing to
	// persist. Return before the addrStore guard and walletdb.Update so an
	// empty batch neither requires an address manager nor opens a write
	// transaction.
	if len(params.Transactions) == 0 && params.SyncedTo == nil {
		return nil
	}

	if s.addrStore == nil {
		return fmt.Errorf("kvdb.Store.ApplyTxBatch: %w",
			errMissingAddrStore)
	}

	err := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if addrmgrNs == nil {
			return errMissingAddrmgrNamespace
		}

		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if txmgrNs == nil {
			return errMissingTxmgrNamespace
		}

		err := s.applyLegacyTxBatch(
			addrmgrNs, txmgrNs, params.Transactions,
		)
		if err != nil {
			return err
		}

		return s.applyLegacyBatchSyncTip(addrmgrNs, params)
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.ApplyTxBatch: %w", err)
	}

	return nil
}

// applyLegacyBatchSyncTip applies the optional sync-tip update for a legacy
// transaction batch.
func (s *Store) applyLegacyBatchSyncTip(ns walletdb.ReadWriteBucket,
	params db.TxBatchParams) error {

	if params.SyncedTo == nil {
		return nil
	}

	block, err := db.BlockStampFromBlock(params.SyncedTo)
	if err != nil {
		return err
	}

	err = s.addrStore.SetSyncedTo(ns, &block)
	if err != nil {
		return fmt.Errorf("set synced tip: %w", err)
	}

	return nil
}

// applyLegacyTxBatch records one batch of relevant transaction notifications.
func (s *Store) applyLegacyTxBatch(addrmgrNs walletdb.ReadWriteBucket,
	txmgrNs walletdb.ReadWriteBucket, transactions []db.CreateTxParams) error {

	for i := range transactions {
		req, err := db.NewCreateTxRequest(transactions[i])
		if err != nil {
			return fmt.Errorf("validate tx %d: %w", i, err)
		}

		err = s.applyLegacyTxNotification(addrmgrNs, txmgrNs, req)
		if err != nil {
			return fmt.Errorf("apply tx %d: %w", i, err)
		}
	}

	return nil
}

// scanHorizonRollback records one horizon extension's pre-batch state so its
// in-memory side effects can be undone if the surrounding batch is rolled back.
type scanHorizonRollback struct {
	// scope is the key scope whose scoped manager performed the extension.
	scope db.KeyScope

	// account is the account whose branch was extended.
	account uint32

	// branch is the extended branch number.
	branch uint32

	// fromIndex is the branch's next index before the extension, i.e. the
	// first child the extension may have derived.
	fromIndex uint32

	// toIndex is the branch's next index after the extension, i.e. one past
	// the last child the extension may have derived.
	toIndex uint32
}

// ApplyScanBatch atomically applies recovery scan writes through the legacy
// walletdb managers.
func (s *Store) ApplyScanBatch(_ context.Context,
	params db.ScanBatchParams) error {

	if s.addrStore == nil {
		return fmt.Errorf("kvdb.Store.ApplyScanBatch: %w",
			errMissingAddrStore)
	}

	// The horizon extensions and synced-block updates below mutate the live
	// address manager's in-memory state synchronously, before this batch
	// commits, yet walletdb only rolls back the backing bucket writes on
	// failure. Snapshot the pre-batch synced tip and accumulate the horizon
	// ranges actually extended so a rolled-back batch can undo exactly those
	// in-memory advances.
	preBatchSyncedTo := s.addrStore.SyncedTo()

	var horizonRollbacks []scanHorizonRollback

	err := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if addrmgrNs == nil {
			return errMissingAddrmgrNamespace
		}

		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if txmgrNs == nil {
			return errMissingTxmgrNamespace
		}

		// Horizons are extended first because the transaction batch
		// below resolves every scan-discovered credit against the
		// address manager, so a freshly derived address must already be
		// written to the addrmgr bucket before its crediting transaction
		// is recorded.
		err := s.applyLegacyScanHorizons(
			addrmgrNs, params.Horizons, &horizonRollbacks,
		)
		if err != nil {
			return err
		}

		err = s.applyLegacyTxBatch(
			addrmgrNs, txmgrNs, params.Transactions,
		)
		if err != nil {
			return err
		}

		return s.applyLegacySyncedBlocks(addrmgrNs, params.SyncedBlocks)
	})
	if err != nil {
		// walletdb has rolled the addrmgr bucket back, but the in-memory
		// side effects of the horizon extensions and synced-block
		// updates survive. Undo them so the live manager matches the
		// persisted (rolled-back) state on the next access.
		s.rollbackScanBatchCaches(horizonRollbacks, preBatchSyncedTo)

		return fmt.Errorf("kvdb.Store.ApplyScanBatch: %w", err)
	}

	return nil
}

// rollbackScanBatchCaches reverts the in-memory address-manager state advanced
// by a failed ApplyScanBatch. The batch wrote the addrmgr bucket, which
// walletdb has since rolled back, but the live manager retains the matching
// in-memory mutations: extended horizons bumped the cached next indices,
// inserted scan-derived addresses into the recent-address cache, and queued
// pending unlock-derivation entries, while connected synced blocks advanced the
// in-memory synced tip. This restores the manager to its pre-batch state so no
// unpersisted advance stays observable.
func (s *Store) rollbackScanBatchCaches(rollbacks []scanHorizonRollback,
	preBatchSyncedTo waddrmgr.BlockStamp) {

	for _, rollback := range rollbacks {
		scopedMgr, err := s.addrStore.FetchScopedKeyManager(
			waddrmgr.KeyScope(rollback.scope),
		)
		if err != nil {
			// The scope resolved while applying the batch, so a
			// lookup miss here is unexpected; skip it as there is no
			// cache to revert for an unknown scope.
			continue
		}

		// Evict the derived addresses before invalidating the account
		// cache: eviction re-derives the rolled-back children from the
		// cached account info to compute their cache keys, so it must run
		// while that account info is still present. Eviction removes the
		// children from the recent-address cache and the pending
		// unlock-derivation queue; invalidating the account cache then
		// reloads the persisted next indices on the next access.
		scopedMgr.EvictDerivedAddresses(
			rollback.account, rollback.branch, rollback.fromIndex,
			rollback.toIndex,
		)
		scopedMgr.InvalidateAccountCache(rollback.account)
	}

	// Restore the in-memory synced tip to the pre-batch value. Any
	// synced-block update that advanced it had its bucket write rolled back,
	// so leaving the in-memory tip advanced would let the next scan decision
	// start from a tip that was never persisted.
	s.addrStore.RestoreSyncedTo(preBatchSyncedTo)
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
// provided height and rewinds the wallet sync tip to the same fork point in one
// walletdb update, mirroring the legacy SetSyncedTo + wtxmgr Rollback rewind.
//
// It is the chain-reorg rollback API: a rewind must move the sync tip back and
// disconnect the now-orphaned blocks and transactions together. Performing the
// sync-tip update and the rollback as two separate writes is unsafe, because a
// failure between them would leave the wallet sync tip rewound while
// transaction state still referenced the abandoned chain (or vice versa). Both
// effects therefore share one write transaction so the rewind is
// all-or-nothing.
//
// The new sync tip is derived from the stored fork-point block at height-1. The
// sync tip is only rewound when the wallet is currently synced at or above the
// rollback boundary, matching the SQL backends, which clamp only wallet sync
// states whose synced height is at or above the rollback height.
func (s *Store) RollbackToBlock(_ context.Context, height uint32) error {
	height32, err := db.Uint32ToInt32(height)
	if err != nil {
		return fmt.Errorf("kvdb.Store.RollbackToBlock: height: %w", err)
	}

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if txmgrNs == nil {
			return errMissingTxmgrNamespace
		}

		// Rewind the wallet sync tip to the fork point before rolling
		// transaction state back, so a reorg cannot disconnect blocks
		// without also moving the sync tip in the same write.
		err := s.rewindSyncTip(tx, height)
		if err != nil {
			return err
		}

		return s.txStore.Rollback(txmgrNs, height32)
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.RollbackToBlock: %w", err)
	}

	return nil
}

// rewindSyncTip rewinds the wallet sync tip to the fork point at height-1
// within the rollback transaction. It is a no-op when no address manager is
// configured (transaction-only rollback) or when the wallet is already synced
// below the rollback boundary, matching the SQL backends, which only clamp
// wallet sync states at or above the rollback height.
func (s *Store) rewindSyncTip(tx walletdb.ReadWriteTx, height uint32) error {
	// Without an address manager there is no wallet sync state to rewind in
	// this store, so the rollback is transaction-only.
	if s.addrStore == nil {
		return nil
	}

	// A rollback to genesis has no surviving fork block to rewind the sync
	// tip to, and the reorg path never rolls back below the first block, so
	// leave the sync tip untouched.
	if height == 0 {
		return nil
	}

	rollbackHeight, err := db.Uint32ToInt32(height)
	if err != nil {
		return fmt.Errorf("rollback height: %w", err)
	}

	// Only wallets synced at or above the rollback boundary are affected; a
	// sync tip already below the fork point needs no rewind.
	if s.addrStore.SyncedTo().Height < rollbackHeight {
		return nil
	}

	addrmgrNs := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
	if addrmgrNs == nil {
		return errMissingAddrmgrNamespace
	}

	forkHeight, err := db.Uint32ToInt32(height - 1)
	if err != nil {
		return fmt.Errorf("fork height: %w", err)
	}

	// Derive the new sync tip from the stored fork-point block. The block at
	// height-1 survives the rollback, so a missing hash means the stored
	// chain view is inconsistent.
	forkHash, err := s.addrStore.BlockHash(addrmgrNs, forkHeight)
	if err != nil {
		return fmt.Errorf("%w: fork block at height %d: %w",
			db.ErrBlockNotFound, forkHeight, err)
	}

	forkBlock := waddrmgr.BlockStamp{
		Height: forkHeight,
		Hash:   *forkHash,
	}

	err = s.addrStore.SetSyncedTo(addrmgrNs, &forkBlock)
	if err != nil {
		return fmt.Errorf("set synced to: %w", err)
	}

	return nil
}

// classifyLegacyHorizonBranch validates a scan horizon's branch and reports
// whether it is the internal branch. Any value other than the canonical
// external/internal pair is rejected before the manager is touched: the legacy
// ExtendAddresses treats every non-internal value as external, which would
// silently coerce a malformed branch and diverge from the SQL backend's
// ExtendScanHorizon.
func classifyLegacyHorizonBranch(branch uint32) (bool, error) {
	internal := branch == waddrmgr.InternalBranch
	if branch != waddrmgr.ExternalBranch && !internal {
		return false, fmt.Errorf("%w: horizon branch %d is neither "+
			"external nor internal", db.ErrInvalidParam, branch)
	}

	return internal, nil
}

// resolveLegacyHorizonAccount resolves the real waddrmgr account number a scan
// horizon targets. horizon.Account is only a fast path: the AccountInfo
// contract masks an imported account's number to 0, so a horizon emitted for an
// imported account would otherwise resolve to the default derived account (also
// account 0) and silently extend the wrong account. The durable, scope-unique
// account name is the source of truth, so it is preferred whenever set and the
// number is used only when no name accompanies the horizon.
func resolveLegacyHorizonAccount(ns walletdb.ReadWriteBucket,
	scopedMgr waddrmgr.AccountStore, horizon db.ScanHorizon) (uint32, error) {

	if horizon.AccountName == "" {
		return horizon.Account, nil
	}

	account, err := scopedMgr.LookupAccount(ns, horizon.AccountName)
	if err != nil {
		// A lookup miss means the named account no longer exists (e.g. a
		// rename raced this scan). Failing here is mandatory: silently
		// falling back to horizon.Account would extend the default
		// account (0) with another account's addresses.
		return 0, fmt.Errorf("lookup account %q: %w",
			horizon.AccountName, err)
	}

	return account, nil
}

// applyLegacyScanHorizons extends legacy address branches for scan hits. For
// every branch it extends it appends a rollback range to rollbacks so the
// caller can undo the extension's in-memory side effects if the surrounding
// batch fails; rollbacks accumulates across all horizons, including the one
// that triggered a mid-batch failure.
func (s *Store) applyLegacyScanHorizons(ns walletdb.ReadWriteBucket,
	horizons []db.ScanHorizon, rollbacks *[]scanHorizonRollback) error {

	for _, horizon := range horizons {
		internal, err := classifyLegacyHorizonBranch(horizon.Branch)
		if err != nil {
			return err
		}

		scopedMgr, err := s.addrStore.FetchScopedKeyManager(
			waddrmgr.KeyScope(horizon.Scope),
		)
		if err != nil {
			return fmt.Errorf("fetch scoped manager: %w", err)
		}

		account, err := resolveLegacyHorizonAccount(ns, scopedMgr, horizon)
		if err != nil {
			return err
		}

		// Capture the branch's next index before extending so a
		// rollback knows the first child this extension may have
		// derived. Read it now, while the cache still mirrors the
		// persisted state, since ExtendAddresses advances it in place.
		props, err := scopedMgr.AccountProperties(ns, account)
		if err != nil {
			return fmt.Errorf("account properties: %w", err)
		}

		fromIndex := props.ExternalKeyCount
		if internal {
			fromIndex = props.InternalKeyCount
		}

		err = scopedMgr.ExtendAddresses(
			ns, account, horizon.Index, horizon.Branch,
		)
		if err != nil {
			return fmt.Errorf("extend addresses: %w", err)
		}

		// ExtendAddresses derives at least through horizon.Index, but it
		// skips HD-invalid children, so the branch's next index can land
		// past horizon.Index+1. Re-read the post-extension next index so
		// the rollback range covers every child this extension may have
		// cached, not just the requested one.
		props, err = scopedMgr.AccountProperties(ns, account)
		if err != nil {
			return fmt.Errorf("account properties: %w", err)
		}

		toIndex := props.ExternalKeyCount
		if internal {
			toIndex = props.InternalKeyCount
		}

		*rollbacks = append(*rollbacks, scanHorizonRollback{
			scope:     horizon.Scope,
			account:   account,
			branch:    horizon.Branch,
			fromIndex: fromIndex,
			toIndex:   toIndex,
		})
	}

	return nil
}

// applyLegacySyncedBlocks connects a sequence of legacy synced blocks.
func (s *Store) applyLegacySyncedBlocks(ns walletdb.ReadWriteBucket,
	blocks []db.Block) error {

	for i := range blocks {
		block, err := db.BlockStampFromBlock(&blocks[i])
		if err != nil {
			return err
		}

		err = s.addrStore.SetSyncedTo(ns, &block)
		if err != nil {
			return fmt.Errorf("set synced block %d: %w", i, err)
		}
	}

	return nil
}

// applyLegacyTxNotification records one relevant transaction notification using
// legacy wtxmgr semantics.
func (s *Store) applyLegacyTxNotification(addrmgrNs walletdb.ReadWriteBucket,
	txmgrNs walletdb.ReadWriteBucket, req db.CreateTxRequest) error {

	txRec, err := wtxmgr.NewTxRecordFromMsgTx(
		req.Params.Tx, req.Received,
	)
	if err != nil {
		return fmt.Errorf("build tx record: %w", err)
	}

	credits, err := s.legacyCreditEntries(addrmgrNs, req)
	if err != nil {
		return err
	}

	if req.Params.Block == nil {
		err := s.txStore.InsertUnconfirmedTx(txmgrNs, txRec, credits)
		if err != nil {
			return fmt.Errorf("insert unconfirmed tx: %w", err)
		}

		return nil
	}

	block, err := kvdbTxBlockMeta(req.Params.Block)
	if err != nil {
		return err
	}

	err = s.txStore.InsertConfirmedTx(txmgrNs, txRec, block, credits)
	if err != nil {
		return fmt.Errorf("insert confirmed tx: %w", err)
	}

	return nil
}

// legacyCreditEntries converts db-native credit addresses into legacy credit
// entries and marks resolved addresses as used.
//
// Each non-nil credit is validated against the output script it claims to
// credit using the same membership check the CreateTx path applies in
// addCreateTxCredit, so the batch path cannot record a UTXO owned by an
// address the output does not pay. A nil credit means the caller has no
// resolved owner, so ownership is keyed on the output's own script: the entry
// is recorded from the output index alone, with no address-manager lookup or
// used-marking, matching CreateTx and the SQL backends.
func (s *Store) legacyCreditEntries(addrmgrNs walletdb.ReadWriteBucket,
	req db.CreateTxRequest) ([]wtxmgr.CreditEntry, error) {

	chainParams := s.addrStore.ChainParams()

	credits := make([]wtxmgr.CreditEntry, 0, len(req.Params.Credits))
	for index, addr := range req.Params.Credits {
		// A nil credit address has no owner to resolve, so key the
		// credit on the output's own script: record it from the index
		// with change cleared, skipping the address-manager lookup and
		// the membership check that has no caller address to validate.
		if addr == nil {
			if int(index) >= len(req.Params.Tx.TxOut) {
				return nil, fmt.Errorf("credit output %d: %w: "+
					"index out of range", index,
					db.ErrInvalidParam)
			}

			credits = append(credits, wtxmgr.CreditEntry{
				Index:  index,
				Change: false,
			})

			continue
		}

		// Validate the caller-supplied credit against the actual output
		// script before trusting it, rejecting a mismatch with the same
		// error CreateTx uses.
		err := validateCreditAddr(
			*req.Params.Tx, index, addr, chainParams,
		)
		if err != nil {
			return nil, err
		}

		managedAddr, err := s.addrStore.Address(addrmgrNs, addr)
		if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
			return nil, fmt.Errorf("credit output %d: %w", index,
				db.ErrAddressNotFound)
		}

		if err != nil {
			return nil, fmt.Errorf("lookup credit address %d: %w",
				index, err)
		}

		credits = append(credits, wtxmgr.CreditEntry{
			Index:  index,
			Change: managedAddr.Internal(),
		})

		err = s.addrStore.MarkUsed(addrmgrNs, addr)
		if err != nil {
			return nil, fmt.Errorf("mark credit address used %d: %w",
				index, err)
		}
	}

	return credits, nil
}

// kvdbTxBlockMeta converts store block metadata into legacy transaction block
// metadata.
func kvdbTxBlockMeta(block *db.Block) (*wtxmgr.BlockMeta, error) {
	height, err := db.Uint32ToInt32(block.Height)
	if err != nil {
		return nil, fmt.Errorf("convert block height: %w", err)
	}

	return &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   block.Hash,
			Height: height,
		},
		Time: block.Timestamp,
	}, nil
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
