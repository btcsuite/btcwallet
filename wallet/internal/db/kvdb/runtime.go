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
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// runtimeStore implements the semantic walletstore.RuntimeStore over walletdb
// (Bolt). It is deliberately asymmetric to the SQL runtime store: Bolt is a
// single writer with atomic, non-retried transactions, so each semantic
// operation commits in one walletdb.Update that revalidates its preconditions
// from the managers' natural records and mutates them in place. There is no
// operation journal, no result-fact table, and no persisted runtime-state
// version, because full rollback plus re-preparation already makes each commit
// idempotent, and there is never an ambiguous commit to resolve. The shared
// runtime.Coordinator drives this store and the SQL store identically; the
// stale and guard signals are internal here and never differ observably.
type runtimeStore struct {
	db walletdb.DB

	// txStore is the transaction manager the scan and rewind operations bind
	// to the wtxmgr bucket, so they reuse the same incidence, credit, spend,
	// and rollback logic as the legacy store. The index, account, tip, and
	// snapshot operations do not need it.
	txStore *wtxmgr.Store
}

// Compile-time assertion that the KV runtime store implements the neutral
// RuntimeStore contract.
var _ walletstore.RuntimeStore = (*runtimeStore)(nil)

// NewRuntimeStore constructs a semantic RuntimeStore over a walletdb database.
// It binds the legacy address-manager bucket for each operation, so it composes
// with the existing managers without a separate schema. The transaction store
// is bound to the wtxmgr bucket by the scan and rewind operations; the other
// operations ignore it and it may be nil for a store that never runs them.
//
//nolint:ireturn // The runtime contract is returned as its neutral interface.
func NewRuntimeStore(db walletdb.DB,
	txStore *wtxmgr.Store) walletstore.RuntimeStore {

	return &runtimeStore{db: db, txStore: txStore}
}

// branchNextIndex returns the account's next index for one branch.
func branchNextIndex(acct waddrmgr.AccountState, branch uint32) (uint32, error) {
	switch branch {
	case waddrmgr.ExternalBranch:
		return acct.NextExternalIndex, nil

	case waddrmgr.InternalBranch:
		return acct.NextInternalIndex, nil

	default:
		return 0, fmt.Errorf("unsupported branch %d", branch)
	}
}

// CurrentBranchIndex reads a durable snapshot of the account's next index for
// one branch from the natural account record in a read transaction.
func (r *runtimeStore) CurrentBranchIndex(ctx context.Context,
	scope waddrmgr.KeyScope, account, branch uint32) (uint32, error) {

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	var index uint32

	err := walletdb.View(r.db, func(tx walletdb.ReadTx) error {
		store := waddrmgr.BindManagerReadStore(
			tx.ReadBucket(addrmgrNamespaceKey),
		)

		acct, err := store.Account(scope, account)
		if err != nil {
			return err
		}

		index, err = branchNextIndex(acct, branch)

		return err
	})
	if err != nil {
		return 0, err
	}

	return index, nil
}

// ReserveNextBranchIndex advances the account's next index for one branch in a
// single Bolt write transaction, using the account record's stored index as the
// natural precondition. It returns ErrStaleAccountIndex when the stored index no
// longer matches the caller's expected value, on which the whole transaction
// rolls back and the shared orchestration re-prepares. A KV commit is never
// ambiguous and is never replayed from a journal, so Replayed is always false.
func (r *runtimeStore) ReserveNextBranchIndex(ctx context.Context,
	req walletstore.ReserveBranchIndexRequest) (
	walletstore.ReserveBranchIndexResult, error) {

	if err := ctx.Err(); err != nil {
		return walletstore.ReserveBranchIndexResult{}, err
	}

	fp := walletstore.FailpointsFromContext(ctx)
	fp.RunOnTxAttempt(0)

	var out walletstore.ReserveBranchIndexResult

	err := walletdb.Update(r.db, func(tx walletdb.ReadWriteTx) error {
		store := waddrmgr.BindManagerReadWriteStore(
			tx.ReadWriteBucket(addrmgrNamespaceKey),
		)

		acct, err := store.Account(req.Scope, req.Account)
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return fmt.Errorf("account %d: %w", req.Account,
				walletstore.ErrStaleAccountIndex)
		}
		if err != nil {
			return err
		}

		current, err := branchNextIndex(acct, req.Branch)
		if err != nil {
			return err
		}

		// The natural guard: advance only while the stored index still
		// equals the caller's expected value.
		if current != req.ExpectedIndex {
			return fmt.Errorf("account %d branch %d expected index "+
				"%d, have %d: %w", req.Account, req.Branch,
				req.ExpectedIndex, current,
				walletstore.ErrStaleAccountIndex)
		}

		if err := fp.RunBeforeStatement(); err != nil {
			return err
		}

		next := req.ExpectedIndex + 1
		external, internal := acct.NextExternalIndex, acct.NextInternalIndex
		if req.Branch == waddrmgr.ExternalBranch {
			external = next
		} else {
			internal = next
		}

		err = store.SetAccountIndexes(
			req.Scope, req.Account, external, internal,
		)
		if err != nil {
			return err
		}

		out = walletstore.ReserveBranchIndexResult{
			AllocatedIndex: req.ExpectedIndex,
			NextIndex:      next,
		}

		return fp.RunBeforeCommit()
	})
	if err != nil {
		return walletstore.ReserveBranchIndexResult{}, err
	}

	if err := fp.RunAfterCommit(); err != nil {
		return walletstore.ReserveBranchIndexResult{}, err
	}

	return out, nil
}

// LookupBranchIndexReservation always reports no committed reservation: the KV
// backend keeps no operation journal because its commits are never ambiguous,
// so the shared orchestration never needs a durable reread here.
func (r *runtimeStore) LookupBranchIndexReservation(_ context.Context,
	_ []byte) (walletstore.ReserveBranchIndexResult, bool, error) {

	return walletstore.ReserveBranchIndexResult{}, false, nil
}

// CurrentSyncedTip reads a durable snapshot of the wallet's synced block from
// the natural sync-state record in a read transaction.
func (r *runtimeStore) CurrentSyncedTip(ctx context.Context) (
	walletstore.BlockRef, error) {

	if err := ctx.Err(); err != nil {
		return walletstore.BlockRef{}, err
	}

	var tip walletstore.BlockRef

	err := walletdb.View(r.db, func(tx walletdb.ReadTx) error {
		store := waddrmgr.BindManagerReadStore(
			tx.ReadBucket(addrmgrNamespaceKey),
		)

		state, err := store.SyncState()
		if err != nil {
			return err
		}

		tip = syncedTipRef(state)

		return nil
	})
	if err != nil {
		return walletstore.BlockRef{}, err
	}

	return tip, nil
}

// AdvanceWalletTip advances the wallet's synced tip in a single Bolt write
// transaction, using the sync-state record's stored synced block as the natural
// precondition. It returns ErrNonContiguousTip when the new tip does not extend
// the expected tip, and ErrStaleTip when the stored synced block no longer
// matches the expected tip, on which the whole transaction rolls back. The
// existing SetSyncedTo records the new block, so no separate block-identity
// write is needed. Version guards do not apply to KV, so req.Guards is ignored.
func (r *runtimeStore) AdvanceWalletTip(ctx context.Context,
	req walletstore.AdvanceTipRequest) (walletstore.AdvanceTipResult, error) {

	if err := ctx.Err(); err != nil {
		return walletstore.AdvanceTipResult{}, err
	}

	if req.NewTip.Height != req.ExpectedTip.Height+1 {
		return walletstore.AdvanceTipResult{}, fmt.Errorf(
			"new tip height %d does not follow expected height %d: %w",
			req.NewTip.Height, req.ExpectedTip.Height,
			walletstore.ErrNonContiguousTip,
		)
	}

	fp := walletstore.FailpointsFromContext(ctx)
	fp.RunOnTxAttempt(0)

	var out walletstore.AdvanceTipResult

	err := walletdb.Update(r.db, func(tx walletdb.ReadWriteTx) error {
		store := waddrmgr.BindManagerReadWriteStore(
			tx.ReadWriteBucket(addrmgrNamespaceKey),
		)

		state, err := store.SyncState()
		if err != nil {
			return err
		}

		// The natural guard: advance only while the stored synced block
		// still equals the caller's expected tip.
		synced := state.SyncedTo
		if synced.Height != req.ExpectedTip.Height ||
			synced.Hash != req.ExpectedTip.Hash {

			return fmt.Errorf("expected synced tip %v, have %v: %w",
				req.ExpectedTip.Hash, synced.Hash,
				walletstore.ErrStaleTip)
		}

		if err := fp.RunBeforeStatement(); err != nil {
			return err
		}

		block := &waddrmgr.BlockStamp{
			Height:    req.NewTip.Height,
			Hash:      req.NewTip.Hash,
			Timestamp: req.NewTip.Timestamp,
		}
		if err := store.SetSyncedTo(block); err != nil {
			return err
		}

		out = walletstore.AdvanceTipResult{
			CommittedFacts: walletstore.CommittedFacts{
				Events: []walletstore.Event{
					walletstore.WalletTipEvent(req.NewTip),
				},
			},
			Tip: req.NewTip,
		}

		return fp.RunBeforeCommit()
	})
	if err != nil {
		return walletstore.AdvanceTipResult{}, err
	}

	if err := fp.RunAfterCommit(); err != nil {
		return walletstore.AdvanceTipResult{}, err
	}

	return out, nil
}

// LookupTipAdvance always reports no committed advance: the KV backend keeps no
// operation journal, so the shared orchestration never needs a durable reread
// here.
func (r *runtimeStore) LookupTipAdvance(_ context.Context,
	_ []byte) (walletstore.AdvanceTipResult, bool, error) {

	return walletstore.AdvanceTipResult{}, false, nil
}

// LoadManagerSnapshot reads the durable manager root state, chain sync state,
// and every key scope with its accounts from the bound address-manager bucket
// in one read transaction, so a restarting wallet reconstructs its caches
// through the semantic contract identically to the SQL backend.
func (r *runtimeStore) LoadManagerSnapshot(ctx context.Context) (
	walletstore.ManagerSnapshot, error) {

	if err := ctx.Err(); err != nil {
		return walletstore.ManagerSnapshot{}, err
	}

	var snapshot walletstore.ManagerSnapshot

	err := walletdb.View(r.db, func(tx walletdb.ReadTx) error {
		store := waddrmgr.BindManagerReadStore(
			tx.ReadBucket(addrmgrNamespaceKey),
		)

		manager, err := store.ManagerState()
		if err != nil {
			return err
		}

		syncState, err := store.SyncState()
		if err != nil {
			return err
		}

		scopes, err := store.KeyScopes()
		if err != nil {
			return err
		}

		snapshot = walletstore.ManagerSnapshot{
			Manager:   manager,
			SyncState: syncState,
		}
		for _, scope := range scopes {
			accounts, err := store.Accounts(scope.Scope)
			if err != nil {
				return err
			}

			snapshot.Scopes = append(
				snapshot.Scopes, walletstore.ScopeSnapshot{
					Scope:    scope,
					Accounts: accounts,
				},
			)
		}

		return nil
	})
	if err != nil {
		return walletstore.ManagerSnapshot{}, err
	}

	return snapshot, nil
}

// syncedTipRef projects the synced block of a sync-state record into a neutral
// block reference.
func syncedTipRef(state waddrmgr.SyncState) walletstore.BlockRef {
	return walletstore.BlockRef{
		Height:    state.SyncedTo.Height,
		Hash:      state.SyncedTo.Hash,
		Timestamp: state.SyncedTo.Timestamp,
	}
}
