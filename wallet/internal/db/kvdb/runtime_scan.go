// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kvdb

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

// CommitScanResults commits one prepared recovery scan batch in a single Bolt
// write transaction, using the managers' natural records as the preconditions.
// It revalidates the synced tip against the expected base tip and each
// account's branch index against its expected index, then applies the batch:
// horizon advances, discovered addresses, transaction incidences with their
// credits and spends, sticky usage marks, and the synced-tip advance. A stale
// precondition rolls the whole transaction back, so the shared orchestration
// re-prepares. A KV commit is never ambiguous or replayed from a journal, so
// the result's Replayed flag is always false.
func (r *runtimeStore) CommitScanResults(ctx context.Context,
	req walletstore.CommitScanResultsRequest) (
	walletstore.CommitScanResultsResult, error) {

	if err := ctx.Err(); err != nil {
		return walletstore.CommitScanResultsResult{}, err
	}

	fp := walletstore.FailpointsFromContext(ctx)
	fp.RunOnTxAttempt(0)

	var out walletstore.CommitScanResultsResult

	err := walletdb.Update(r.db, func(tx walletdb.ReadWriteTx) error {
		store := waddrmgr.BindManagerReadWriteStore(
			tx.ReadWriteBucket(addrmgrNamespaceKey),
		)
		txNS := tx.ReadWriteBucket(txmgrNamespaceKey)

		// Natural guards, read-only, fail fast before any mutation: the synced
		// tip must still equal the expected base tip and each branch index its
		// expected value.
		state, err := store.SyncState()
		if err != nil {
			return err
		}

		if err := checkKVSyncedTip(state, req.ExpectedTip); err != nil {
			return err
		}

		if err := checkKVHorizons(store, req.Horizons); err != nil {
			return err
		}

		if err := fp.RunBeforeStatement(); err != nil {
			return err
		}

		if err := r.applyScanBatch(store, txNS, req); err != nil {
			return err
		}

		// Advance the synced tip to the new tip. PutSyncState records the block
		// and swaps the synced-to reference without the incremental predecessor
		// check, matching the SQL reference swap for a multi-block batch.
		if err := setKVSyncedTip(store, state, req.NewTip); err != nil {
			return err
		}

		out = walletstore.CommitScanResultsResult{
			CommittedFacts: walletstore.CommittedFacts{
				Events: walletstore.ScanResultEvents(req),
			},
			Tip: req.NewTip,
		}

		return fp.RunBeforeCommit()
	})
	if err != nil {
		return walletstore.CommitScanResultsResult{}, err
	}

	if err := fp.RunAfterCommit(); err != nil {
		return walletstore.CommitScanResultsResult{}, err
	}

	return out, nil
}

// applyScanBatch applies the mutating half of a scan batch: horizon advances,
// discovered addresses, transaction incidences with their credits, and sticky
// usage marks. The guards were already checked, so a mutation error rolls the
// whole Bolt transaction back.
func (r *runtimeStore) applyScanBatch(store waddrmgr.ManagerReadWriteStore,
	txNS walletdb.ReadWriteBucket,
	req walletstore.CommitScanResultsRequest) error {

	for _, horizon := range req.Horizons {
		if err := advanceKVHorizon(store, horizon); err != nil {
			return err
		}
	}

	for _, prepared := range req.Addresses {
		err := store.PutAddress(prepared.AddressID, prepared.State)
		if err != nil {
			return err
		}
	}

	for i := range req.Transactions {
		scanTx := req.Transactions[i]

		_, err := r.txStore.InsertTxCheckIfExists(
			txNS, scanTx.Record, scanTx.Block,
		)
		if err != nil {
			return fmt.Errorf("insert scan transaction: %w", err)
		}

		for _, credit := range scanTx.Credits {
			err := r.txStore.AddCredit(
				txNS, scanTx.Record, scanTx.Block, credit.Index,
				credit.Change,
			)
			if err != nil {
				return fmt.Errorf("add scan credit: %w", err)
			}
		}
	}

	for _, used := range req.UsedAddresses {
		if err := store.MarkAddressUsed(used.Scope, used.AddressID); err != nil {
			return err
		}
	}

	return nil
}

// LookupScanResults always reports no committed batch: the KV backend keeps no
// operation journal because its commits are never ambiguous, so the shared
// orchestration never needs a durable reread here.
func (r *runtimeStore) LookupScanResults(_ context.Context, _ []byte) (
	walletstore.CommitScanResultsResult, bool, error) {

	return walletstore.CommitScanResultsResult{}, false, nil
}

// CommitWalletRewind reconciles the wallet back to a target block in a single
// Bolt write transaction, using the synced tip as the natural precondition. It
// verifies the detached tip against the expected tip, rolls back every mined
// incidence above the target through the shared wtxmgr rollback, and moves the
// synced tip back to the target. A stale tip rolls the whole transaction back.
func (r *runtimeStore) CommitWalletRewind(ctx context.Context,
	req walletstore.CommitWalletRewindRequest) (
	walletstore.CommitWalletRewindResult, error) {

	if err := ctx.Err(); err != nil {
		return walletstore.CommitWalletRewindResult{}, err
	}

	fp := walletstore.FailpointsFromContext(ctx)
	fp.RunOnTxAttempt(0)

	var out walletstore.CommitWalletRewindResult

	err := walletdb.Update(r.db, func(tx walletdb.ReadWriteTx) error {
		store := waddrmgr.BindManagerReadWriteStore(
			tx.ReadWriteBucket(addrmgrNamespaceKey),
		)
		txNS := tx.ReadWriteBucket(txmgrNamespaceKey)

		state, err := store.SyncState()
		if err != nil {
			return err
		}

		if err := checkKVSyncedTip(state, req.ExpectedTip); err != nil {
			return err
		}

		if err := fp.RunBeforeStatement(); err != nil {
			return err
		}

		// Roll back every mined incidence above the target block.
		err = r.txStore.Rollback(txNS, req.TargetBlock.Height+1)
		if err != nil {
			return fmt.Errorf("rollback transactions: %w", err)
		}

		if err := setKVSyncedTip(store, state, req.TargetBlock); err != nil {
			return err
		}

		out = walletstore.CommitWalletRewindResult{
			CommittedFacts: walletstore.CommittedFacts{
				Events: []walletstore.Event{
					walletstore.BlockDisconnectedEvent(req.ExpectedTip),
				},
			},
			Tip: req.TargetBlock,
		}

		return fp.RunBeforeCommit()
	})
	if err != nil {
		return walletstore.CommitWalletRewindResult{}, err
	}

	if err := fp.RunAfterCommit(); err != nil {
		return walletstore.CommitWalletRewindResult{}, err
	}

	return out, nil
}

// LookupWalletRewind always reports no committed rewind: the KV backend has no
// operation journal, so the shared orchestration never needs a durable reread
// here.
func (r *runtimeStore) LookupWalletRewind(_ context.Context, _ []byte) (
	walletstore.CommitWalletRewindResult, bool, error) {

	return walletstore.CommitWalletRewindResult{}, false, nil
}

// checkKVSyncedTip enforces the natural synced-tip guard: the stored synced
// block must still equal the expected tip, else the prepared batch is stale.
func checkKVSyncedTip(state waddrmgr.SyncState,
	expected walletstore.BlockRef) error {

	synced := state.SyncedTo
	if synced.Height != expected.Height || synced.Hash != expected.Hash {
		return fmt.Errorf("expected synced tip %v, have %v: %w",
			expected.Hash, synced.Hash, walletstore.ErrStaleTip)
	}

	return nil
}

// checkKVHorizons enforces the natural branch-index guard for every horizon:
// each account's stored branch index must still equal the expected index, else
// the prepared batch is stale.
func checkKVHorizons(store waddrmgr.ManagerReadWriteStore,
	horizons []walletstore.BranchHorizon) error {

	for _, horizon := range horizons {
		acct, err := store.Account(horizon.Scope, horizon.Account)
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return fmt.Errorf("account %d: %w", horizon.Account,
				walletstore.ErrStaleAccountIndex)
		}
		if err != nil {
			return err
		}

		current, err := branchNextIndex(acct, horizon.Branch)
		if err != nil {
			return err
		}

		if current != horizon.ExpectedIndex {
			return fmt.Errorf("account %d branch %d expected index %d, "+
				"have %d: %w", horizon.Account, horizon.Branch,
				horizon.ExpectedIndex, current,
				walletstore.ErrStaleAccountIndex)
		}
	}

	return nil
}

// advanceKVHorizon advances one branch's next index to its final index. It
// re-reads the account so a prior horizon on the other branch of the same
// account is preserved, since the KV write sets both branch indexes at once.
func advanceKVHorizon(store waddrmgr.ManagerReadWriteStore,
	horizon walletstore.BranchHorizon) error {

	acct, err := store.Account(horizon.Scope, horizon.Account)
	if err != nil {
		return err
	}

	external, internal := acct.NextExternalIndex, acct.NextInternalIndex
	if horizon.Branch == waddrmgr.ExternalBranch {
		external = horizon.FinalIndex
	} else {
		internal = horizon.FinalIndex
	}

	return store.SetAccountIndexes(
		horizon.Scope, horizon.Account, external, internal,
	)
}

// setKVSyncedTip moves the wallet's synced tip to the given block, preserving
// the rest of the durable sync state. It uses PutSyncState, which records the
// block and swaps the synced-to reference without the incremental predecessor
// check, so a batch that advances across many blocks is a plain reference swap.
func setKVSyncedTip(store waddrmgr.ManagerReadWriteStore,
	state waddrmgr.SyncState, tip walletstore.BlockRef) error {

	state.SyncedTo = waddrmgr.BlockStamp{
		Height:    tip.Height,
		Hash:      tip.Hash,
		Timestamp: tip.Timestamp,
	}

	return store.PutSyncState(state)
}
