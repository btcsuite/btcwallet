// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

const (
	// birthdayBlockDelta is the maximum time delta allowed between our
	// birthday timestamp and our birthday block's timestamp when searching
	// for a better birthday block candidate (if possible).
	birthdayBlockDelta = 2 * time.Hour
)

// StorePlanStaleError reports that durable wallet state changed after an RPC
// plan was prepared but before its database-only apply began.
type StorePlanStaleError struct {
	// Operation identifies the synchronization operation that became stale.
	Operation string

	// Reason describes the durable state mismatch.
	Reason string
}

// Error describes the stale Store plan.
func (e *StorePlanStaleError) Error() string {
	return fmt.Sprintf("%s plan is stale: %s", e.Operation, e.Reason)
}

// UnresolvedStoreCommitError reports a Store commit whose durable outcome
// could not be distinguished without risking replay of chain RPCs.
type UnresolvedStoreCommitError struct {
	// Operation identifies the synchronization operation being reconciled.
	Operation string

	// Err is the ambiguous commit or reconciliation failure.
	Err error
}

// Error describes the unresolved Store commit.
func (e *UnresolvedStoreCommitError) Error() string {
	return fmt.Sprintf("%s commit outcome is unresolved: %v", e.Operation,
		e.Err)
}

// Unwrap returns the ambiguous commit or reconciliation failure.
func (e *UnresolvedStoreCommitError) Unwrap() error {
	return e.Err
}

type storePlanStatus uint8

const (
	storePlanAbsent storePlanStatus = iota
	storePlanCommitted
	storePlanConflict
)

// sameBlockPosition reports whether two stamps identify the same chain block.
func sameBlockPosition(a, b waddrmgr.BlockStamp) bool {
	return a.Height == b.Height && a.Hash == b.Hash
}

// refreshStorePlanCaches reloads sync state and invalidates account-index
// caches after an ambiguous commit has been reconciled as durable.
func (w *Wallet) refreshStorePlanCaches(ctx context.Context,
	accounts []waddrmgr.KeyScope) error {

	var syncState waddrmgr.SyncState
	err := w.store.View(ctx, func(tx walletstore.ReadTx) error {
		var err error
		syncState, err = tx.Addr().SyncState()
		return err
	}, func() {
		syncState = waddrmgr.SyncState{}
	})
	if err != nil {
		return err
	}

	w.Manager.ApplySyncStateFromStore(syncState)
	for _, scope := range accounts {
		w.Manager.MarkAccountCacheStale(
			scope, waddrmgr.DefaultAccountNum,
		)
	}

	return nil
}

// invalidateStorePlanCaches prevents an unresolved commit from leaving
// optimistic account or sync positions in memory.
func (w *Wallet) invalidateStorePlanCaches(accounts []waddrmgr.KeyScope) {
	w.Manager.InvalidateSyncStateCache()
	for _, scope := range accounts {
		w.Manager.MarkAccountCacheStale(
			scope, waddrmgr.DefaultAccountNum,
		)
	}
}

// applyStorePlan applies a database-only plan once and reconciles an ambiguous
// commit without rebuilding or replaying its RPC portion.
func (w *Wallet) applyStorePlan(ctx context.Context, operation string,
	body func(walletstore.ReadWriteTx) error,
	status func(walletstore.ReadTx) (storePlanStatus, error),
	accounts []waddrmgr.KeyScope) error {

	for {
		err := w.store.UpdateOnce(ctx, body, nil)
		if err == nil {
			return nil
		}

		var retryable *walletstore.RetryableTransactionError
		if errors.As(err, &retryable) {
			continue
		}

		var ambiguous *walletstore.AmbiguousCommitError
		if !errors.As(err, &ambiguous) {
			return err
		}

		outcome := storePlanConflict
		viewErr := w.store.View(ctx, func(tx walletstore.ReadTx) error {
			var err error
			outcome, err = status(tx)
			return err
		}, func() {
			outcome = storePlanConflict
		})
		if viewErr != nil {
			w.invalidateStorePlanCaches(accounts)
			return &UnresolvedStoreCommitError{
				Operation: operation,
				Err: errors.Join(
					err, fmt.Errorf("reconcile commit: %w", viewErr),
				),
			}
		}

		switch outcome {
		case storePlanAbsent:
			continue

		case storePlanCommitted:
			ambiguous.ApplyCommitHooks()
			if err := w.refreshStorePlanCaches(ctx, accounts); err != nil {
				w.invalidateStorePlanCaches(accounts)
				return &UnresolvedStoreCommitError{
					Operation: operation,
					Err:       errors.Join(ambiguous, err),
				}
			}

			return nil

		default:
			w.invalidateStorePlanCaches(accounts)
			return &UnresolvedStoreCommitError{
				Operation: operation,
				Err:       ambiguous,
			}
		}
	}
}

// storePlanCommitStatus classifies a plan by comparing the durable tip with
// its exact starting and terminal positions.
func storePlanCommitStatus(tx walletstore.ReadTx, start,
	target waddrmgr.BlockStamp) (storePlanStatus, error) {

	state, err := tx.Addr().SyncState()
	if err != nil {
		return storePlanConflict, err
	}

	switch {
	case sameBlockPosition(state.SyncedTo, target):
		return storePlanCommitted, nil

	case sameBlockPosition(state.SyncedTo, start):
		return storePlanAbsent, nil

	default:
		return storePlanConflict, nil
	}
}

// fetchStoreCatchUpPlan retrieves and validates a contiguous chain segment
// without holding a Store transaction.
func fetchStoreCatchUpPlan(client chain.Interface, start waddrmgr.BlockStamp,
	height int32, finalHash *chainhash.Hash) ([]waddrmgr.BlockStamp, error) {

	if height <= start.Height {
		if finalHash == nil {
			return nil, nil
		}

		var hash *chainhash.Hash
		if height == start.Height {
			hash = &start.Hash
		} else {
			var err error
			hash, err = client.GetBlockHash(int64(height))
			if err != nil {
				return nil, err
			}
		}
		if *hash != *finalHash {
			return nil, fmt.Errorf("rescan final hash %v does not match %v",
				*finalHash, *hash)
		}

		return nil, nil
	}

	plan := make([]waddrmgr.BlockStamp, 0, height-start.Height)
	previousHash := start.Hash
	for blockHeight := start.Height + 1; blockHeight <= height; blockHeight++ {

		hash, err := client.GetBlockHash(int64(blockHeight))
		if err != nil {
			return nil, err
		}
		header, err := client.GetBlockHeader(hash)
		if err != nil {
			return nil, err
		}
		if header.BlockHash() != *hash {
			return nil, fmt.Errorf("header hash does not match block %v", hash)
		}
		if header.PrevBlock != previousHash {
			return nil, fmt.Errorf("block %d does not link to %v",
				blockHeight, previousHash)
		}

		plan = append(plan, waddrmgr.BlockStamp{
			Height:    blockHeight,
			Hash:      *hash,
			Timestamp: header.Timestamp,
		})
		previousHash = *hash
	}

	if finalHash != nil && plan[len(plan)-1].Hash != *finalHash {
		return nil, fmt.Errorf("rescan final hash %v does not match %v",
			*finalHash, plan[len(plan)-1].Hash)
	}

	return plan, nil
}

// catchUpHashes persists all block stamps through a rescan notification. Store
// wallets fetch and validate the complete plan before opening the write.
func (w *Wallet) catchUpHashes(client chain.Interface, height int32,
	finalHash *chainhash.Hash) error {

	log.Infof("Catching up block hashes to height %d, this might take a while",
		height)

	var err error
	if w.db != nil {
		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			startBlock := w.Manager.SyncedTo()

			for i := startBlock.Height + 1; i <= height; i++ {
				hash, err := client.GetBlockHash(int64(i))
				if err != nil {
					return err
				}
				header, err := client.GetBlockHeader(hash)
				if err != nil {
					return err
				}

				err = w.Manager.SetSyncedTo(ns, &waddrmgr.BlockStamp{
					Height:    i,
					Hash:      *hash,
					Timestamp: header.Timestamp,
				})
				if err != nil {
					return err
				}
			}

			return nil
		})
	} else {
		err = w.catchUpHashesFromStore(client, height, finalHash)
	}
	if err != nil {
		log.Errorf("Failed to update address manager sync state for height "+
			"%d: %v", height, err)
		return err
	}

	log.Info("Done catching up block hashes")
	return nil
}

// catchUpHashesFromStore prepares an exact contiguous block plan and applies
// it only if the durable starting tip remains unchanged.
func (w *Wallet) catchUpHashesFromStore(client chain.Interface, height int32,
	finalHash *chainhash.Hash) error {

	var start waddrmgr.BlockStamp
	err := w.store.View(context.Background(), func(tx walletstore.ReadTx) error {
		state, err := tx.Addr().SyncState()
		if err != nil {
			return err
		}
		start = state.SyncedTo
		return nil
	}, func() {
		start = waddrmgr.BlockStamp{}
	})
	if err != nil {
		return err
	}

	plan, err := fetchStoreCatchUpPlan(client, start, height, finalHash)
	if err != nil || len(plan) == 0 {
		return err
	}
	target := plan[len(plan)-1]

	return w.applyStorePlan(
		context.Background(), "catch-up", func(tx walletstore.ReadWriteTx) error {
			state, err := tx.Addr().SyncState()
			if err != nil {
				return err
			}
			if !sameBlockPosition(state.SyncedTo, start) {
				return &StorePlanStaleError{
					Operation: "catch-up",
					Reason: fmt.Sprintf("starting tip is %d:%v, want %d:%v",
						state.SyncedTo.Height, state.SyncedTo.Hash,
						start.Height, start.Hash),
				}
			}

			for i := range plan {
				if err := w.Manager.SetSyncedToFromStore(
					tx.Addr(), &plan[i],
				); err != nil {

					return err
				}
			}

			return nil
		}, func(tx walletstore.ReadTx) (storePlanStatus, error) {
			return storePlanCommitStatus(tx, start, target)
		}, nil,
	)
}

// updateChainStore reconciles an ambiguous chain update before deferred cache
// and notification hooks are published. An absent atomic update is safe to
// retry, while a durable update applies its captured hooks exactly once.
func (w *Wallet) updateChainStore(ctx context.Context,
	body func(walletstore.ReadWriteTx) error,
	committed func(walletstore.ReadTx) (bool, error)) error {

	for {
		err := w.store.Update(ctx, body, nil)
		if err == nil {
			return nil
		}

		var ambiguous *walletstore.AmbiguousCommitError
		if !errors.As(err, &ambiguous) {
			return err
		}

		var durable bool

		viewErr := w.store.View(ctx, func(tx walletstore.ReadTx) error {
			var err error

			durable, err = committed(tx)

			return err
		}, func() {
			durable = false
		})
		if viewErr != nil {
			return errors.Join(
				err, fmt.Errorf("reconcile chain commit: %w", viewErr),
			)
		}

		if durable {
			ambiguous.ApplyCommitHooks()
			return nil
		}
	}
}

// syncBlockCommitted reports whether the durable wallet tip is the expected
// block.
func syncBlockCommitted(tx walletstore.ReadTx,
	block wtxmgr.BlockMeta) (bool, error) {

	state, err := tx.Addr().SyncState()
	if err != nil {
		return false, err
	}

	return state.SyncedTo.Height == block.Height &&
		state.SyncedTo.Hash == block.Hash, nil
}

// relevantTxCommitted reports whether one transaction incidence is durable.
func relevantTxCommitted(tx walletstore.ReadTx, record *wtxmgr.TxRecord,
	block *wtxmgr.BlockMeta) (bool, error) {

	var incidence *wtxmgr.Block
	if block != nil {
		incidence = &block.Block
	}

	details, err := tx.Tx().UniqueTxDetails(&record.Hash, incidence)
	if err != nil {
		return false, err
	}

	return details != nil, nil
}

// handleChainNotifications processes notifications from the active chain
// backend until the wallet shuts down.
func (w *Wallet) handleChainNotifications() {
	defer w.wg.Done()

	chainClient, err := w.requireChainClient()
	if err != nil {
		log.Errorf("handleChainNotifications called without RPC client")
		return
	}

	waitForSync := func(birthdayBlock *waddrmgr.BlockStamp) error {
		// We start with a retry delay of 0 to execute the first attempt
		// immediately.
		var retryDelay time.Duration
		for {
			select {
			case <-time.After(retryDelay):
				// Set the delay to the configured value in case
				// we actually need to re-try.
				retryDelay = w.syncRetryInterval

				// Sync may be interrupted by actions such as
				// locking the wallet. Try again after waiting a
				// bit.
				err = w.syncWithChain(birthdayBlock)
				if err != nil {
					if w.ShuttingDown() {
						return ErrWalletShuttingDown
					}

					log.Errorf("Unable to synchronize "+
						"wallet to chain, trying "+
						"again in %s: %v",
						w.syncRetryInterval, err)

					continue
				}

				return nil

			case <-w.quitChan():
				return ErrWalletShuttingDown
			}
		}
	}

	for {
		select {
		case n, ok := <-chainClient.Notifications():
			if !ok {
				return
			}

			var notificationName string
			var err error
			switch n := n.(type) {
			case chain.ClientConnected:
				// Before attempting to sync with our backend,
				// we'll make sure that our birthday block has
				// been set correctly to potentially prevent
				// missing relevant events.
				birthdayStore := &walletBirthdayStore{
					db:      w.db,
					store:   w.store,
					manager: w.Manager,
				}
				birthdayBlock, err := birthdaySanityCheck(
					chainClient, birthdayStore,
				)
				if err != nil && !waddrmgr.IsError(
					err, waddrmgr.ErrBirthdayBlockNotSet,
				) {

					log.Errorf("Unable to sanity check "+
						"wallet birthday block: %v",
						err)
				}

				err = waitForSync(birthdayBlock)
				if err != nil {
					log.Infof("Stopped waiting for wallet "+
						"sync due to error: %v", err)

					return
				}

			case chain.BlockConnected:
				if w.db != nil {
					err = walletdb.Update(
						w.db, func(tx walletdb.ReadWriteTx) error {
							return w.connectBlock(
								tx, wtxmgr.BlockMeta(n),
							)
						},
					)
				} else {
					err = w.updateChainStore(
						context.Background(),
						func(tx walletstore.ReadWriteTx) error {
							return w.connectBlockFromStore(
								tx, wtxmgr.BlockMeta(n),
							)
						}, func(tx walletstore.ReadTx) (bool, error) {
							return syncBlockCommitted(
								tx, wtxmgr.BlockMeta(n),
							)
						},
					)
				}

				notificationName = "block connected"

			case chain.BlockDisconnected:
				err = w.processBlockDisconnected(
					chainClient, wtxmgr.BlockMeta(n),
				)

				notificationName = "block disconnected"

			case chain.RelevantTx:
				if w.db != nil {
					err = walletdb.Update(
						w.db, func(tx walletdb.ReadWriteTx) error {
							return w.addRelevantTx(
								tx, n.TxRecord, n.Block,
							)
						},
					)
				} else {
					err = w.updateChainStore(
						context.Background(),
						func(tx walletstore.ReadWriteTx) error {
							return w.addRelevantTxFromStore(
								tx, n.TxRecord, n.Block,
							)
						}, func(tx walletstore.ReadTx) (bool, error) {
							return relevantTxCommitted(
								tx, n.TxRecord, n.Block,
							)
						},
					)
				}

				notificationName = "relevant transaction"

			case chain.FilteredBlockConnected:
				// Atomically update for the whole block.
				if len(n.RelevantTxs) > 0 {
					if w.db != nil {
						err = walletdb.Update(w.db, func(
							tx walletdb.ReadWriteTx) error {
							for _, rec := range n.RelevantTxs {
								err := w.addRelevantTx(
									tx, rec, n.Block,
								)
								if err != nil {
									return err
								}
							}
							return nil
						})
					} else {
						err = w.updateChainStore(
							context.Background(),
							func(tx walletstore.ReadWriteTx) error {
								for _, rec := range n.RelevantTxs {
									err := w.addRelevantTxFromStore(
										tx, rec, n.Block,
									)
									if err != nil {
										return err
									}
								}
								return nil
							}, func(tx walletstore.ReadTx) (bool, error) {
								for _, record := range n.RelevantTxs {
									committed, err := relevantTxCommitted(
										tx, record, n.Block,
									)
									if err != nil || !committed {
										return committed, err
									}
								}

								return true, nil
							},
						)
					}
				}

				notificationName = "filtered block connected"

			// The following require some database maintenance, but also
			// need to be reported to the wallet's rescan goroutine.
			case *chain.RescanProgress:
				err = w.catchUpHashes(chainClient, n.Height, &n.Hash)
				notificationName = "rescan progress"
				if err == nil {
					select {
					case w.rescanNotifications <- n:
					case <-w.quitChan():
						return
					}
				}
			case *chain.RescanFinished:
				err = w.catchUpHashes(chainClient, n.Height, n.Hash)
				notificationName = "rescan finished"
				if err == nil {
					w.SetChainSynced(true)
					select {
					case w.rescanNotifications <- n:
					case <-w.quitChan():
						return
					}
				}
			}

			if err != nil {
				// If we received a block connected notification
				// while rescanning, then we can ignore logging
				// the error as we'll properly catch up once we
				// process the RescanFinished notification.
				if notificationName == "block connected" &&
					waddrmgr.IsError(err, waddrmgr.ErrBlockNotFound) &&
					!w.ChainSynced() {

					log.Debugf("Received block connected "+
						"notification for height %v "+
						"while rescanning",
						n.(chain.BlockConnected).Height)
					continue
				}

				log.Errorf("Unable to process chain backend "+
					"%v notification: %v", notificationName,
					err)
			}
		case <-w.quit:
			return
		}
	}
}

// processBlockDisconnected routes a disconnect through the active persistence
// backend and publishes a detached notification only after an actual rewind.
func (w *Wallet) processBlockDisconnected(client chain.Interface,
	block wtxmgr.BlockMeta) error {

	if w.db != nil {
		return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			return w.disconnectBlockLegacy(tx, block)
		})
	}

	rewound, err := w.disconnectBlockFromStore(client, block)
	if err != nil || !rewound {
		return err
	}

	hash := block.Hash
	w.NtfnServer.notifyDetachedBlock(&hash)
	return nil
}

// connectBlock handles a chain server notification by marking a wallet
// that's currently in-sync with the chain server as being synced up to
// the passed block.
func (w *Wallet) connectBlock(dbtx walletdb.ReadWriteTx,
	b wtxmgr.BlockMeta) error {

	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

	bs := waddrmgr.BlockStamp{
		Height:    b.Height,
		Hash:      b.Hash,
		Timestamp: b.Time,
	}
	err := w.Manager.SetSyncedTo(addrmgrNs, &bs)
	if err != nil {
		return err
	}

	// Notify interested clients of the connected block.
	//
	// TODO: move all notifications outside of the database transaction.
	w.NtfnServer.notifyAttachedBlock(dbtx, &b)
	return nil
}

// connectBlockFromStore persists a connected block through the backend-neutral
// manager transaction.
func (w *Wallet) connectBlockFromStore(dbtx walletstore.ReadWriteTx,
	b wtxmgr.BlockMeta) error {

	err := w.Manager.SetSyncedToFromStore(
		dbtx.Addr(), &waddrmgr.BlockStamp{
			Height:    b.Height,
			Hash:      b.Hash,
			Timestamp: b.Time,
		},
	)
	if err != nil {
		return err
	}

	dbtx.Addr().OnCommit(func() {
		w.NtfnServer.notifyAttachedBlockFromStore(&b)
	})

	return nil
}

// disconnectBlockLegacy preserves the walletdb disconnect behavior, including
// its chain-header lookup inside the legacy database transaction.
func (w *Wallet) disconnectBlockLegacy(dbtx walletdb.ReadWriteTx,
	b wtxmgr.BlockMeta) error {

	if !w.ChainSynced() {
		return nil
	}

	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
	if b.Height > w.Manager.SyncedTo().Height {
		return nil
	}

	hash, err := w.Manager.BlockHash(addrmgrNs, b.Height)
	if err != nil {
		return err
	}
	if !bytes.Equal(hash[:], b.Hash[:]) {
		return nil
	}

	stamp := waddrmgr.BlockStamp{Height: b.Height - 1}
	hash, err = w.Manager.BlockHash(addrmgrNs, stamp.Height)
	if err != nil {
		return err
	}
	header, err := w.ChainClient().GetBlockHeader(hash)
	if err != nil {
		return err
	}
	b.Hash = *hash
	stamp.Hash = *hash
	stamp.Timestamp = header.Timestamp

	if err := w.Manager.SetSyncedTo(addrmgrNs, &stamp); err != nil {
		return err
	}
	if err := w.TxStore.Rollback(txmgrNs, b.Height); err != nil {
		return err
	}

	w.NtfnServer.notifyDetachedBlock(&b.Hash)
	return nil
}

// disconnectBlockFromStore prepares a parent stamp without a transaction and
// atomically rewinds manager and transaction state if the exact tip is current.
func (w *Wallet) disconnectBlockFromStore(client chain.Interface,
	b wtxmgr.BlockMeta) (bool, error) {

	if !w.ChainSynced() || b.Height <= 0 {
		return false, nil
	}

	var (
		start       waddrmgr.BlockStamp
		blockHash   chainhash.Hash
		parentHash  chainhash.Hash
		shouldApply bool
	)
	err := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			state, err := tx.Addr().SyncState()
			if err != nil {
				return err
			}
			start = state.SyncedTo
			if b.Height > start.Height {
				return nil
			}

			durableHash, err := tx.Addr().BlockHash(b.Height)
			if err != nil {
				return err
			}
			blockHash = *durableHash
			if blockHash != b.Hash {
				return nil
			}

			durableParent, err := tx.Addr().BlockHash(b.Height - 1)
			if err != nil {
				return err
			}
			parentHash = *durableParent
			shouldApply = true

			return nil
		}, func() {
			start = waddrmgr.BlockStamp{}
			blockHash = chainhash.Hash{}
			parentHash = chainhash.Hash{}
			shouldApply = false
		},
	)
	if err != nil || !shouldApply {
		return false, err
	}

	header, err := client.GetBlockHeader(&parentHash)
	if err != nil {
		return false, err
	}
	if header.BlockHash() != parentHash {
		return false, fmt.Errorf("parent header hash does not match %v",
			parentHash)
	}
	target := waddrmgr.BlockStamp{
		Height:    b.Height - 1,
		Hash:      parentHash,
		Timestamp: header.Timestamp,
	}

	err = w.applyStorePlan(
		context.Background(), "disconnect",
		func(tx walletstore.ReadWriteTx) error {
			state, err := tx.Addr().SyncState()
			if err != nil {
				return err
			}
			if !sameBlockPosition(state.SyncedTo, start) {
				return &StorePlanStaleError{
					Operation: "disconnect",
					Reason: fmt.Sprintf("starting tip is %d:%v, want %d:%v",
						state.SyncedTo.Height, state.SyncedTo.Hash,
						start.Height, start.Hash),
				}
			}

			currentHash, err := tx.Addr().BlockHash(b.Height)
			if err != nil {
				return err
			}
			if *currentHash != blockHash || *currentHash != b.Hash {
				return &StorePlanStaleError{
					Operation: "disconnect",
					Reason:    "disconnected block hash changed",
				}
			}
			currentParent, err := tx.Addr().BlockHash(target.Height)
			if err != nil {
				return err
			}
			if *currentParent != parentHash {
				return &StorePlanStaleError{
					Operation: "disconnect",
					Reason:    "parent block hash changed",
				}
			}

			if err := w.Manager.SetSyncedToFromStore(
				tx.Addr(), &target,
			); err != nil {

				return err
			}

			return tx.Tx().Rollback(b.Height)
		}, func(tx walletstore.ReadTx) (storePlanStatus, error) {
			return storePlanCommitStatus(tx, start, target)
		}, nil,
	)
	if err != nil {
		return false, err
	}

	return true, nil
}

// addRelevantTx records a relevant transaction and marks wallet-owned outputs
// and spent inputs.
//
//nolint:cyclop // The branches preserve existing output classification.
func (w *Wallet) addRelevantTx(dbtx walletdb.ReadWriteTx, rec *wtxmgr.TxRecord,
	block *wtxmgr.BlockMeta) error {

	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	// At the moment all notified transactions are assumed to actually be
	// relevant.  This assumption will not hold true when SPV support is
	// added, but until then, simply insert the transaction because there
	// should either be one or more relevant inputs or outputs.
	exists, err := w.TxStore.InsertTxCheckIfExists(txmgrNs, rec, block)
	if err != nil {
		return err
	}

	// If the transaction has already been recorded, we can return early.
	// Note: Returning here is safe as we're within the context of an atomic
	// database transaction, so we don't need to worry about the MarkUsed
	// calls below.
	if exists {
		return nil
	}

	// Check every output to determine whether it is controlled by a wallet
	// key.  If so, mark the output as a credit.
	for i, output := range rec.MsgTx.TxOut {
		credited := false
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript,
			w.chainParams)
		if err != nil {
			// Non-standard outputs are skipped.
			log.Warnf("Cannot extract non-std pkScript=%x",
				output.PkScript)

			continue
		}

		for _, addr := range addrs {
			ma, err := w.Manager.Address(addrmgrNs, addr)

			switch {
			// Missing addresses are skipped.
			case waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound):
				continue

			// Other errors should be propagated.
			case err != nil:
				return err
			}

			// Prevent addresses from non-default scopes to be
			// detected here. We don't watch funds sent to
			// non-default scopes in other places either, so
			// detecting them here would mean we'd also not properly
			// detect them as spent later.
			scopedManager, account, err := w.Manager.AddrAccount(
				addrmgrNs, addr,
			)
			if err != nil {
				return err
			}
			if !waddrmgr.IsDefaultScope(scopedManager.Scope()) {
				log.Debugf("Skipping non-default scope "+
					"address %v", addr)

				continue
			}

			// TODO: Credits should be added with the
			// account they belong to, so wtxmgr is able to
			// track per-account balances.
			err = w.TxStore.AddCredit(
				txmgrNs, rec, block, uint32(i), ma.Internal(),
			)
			if err != nil {
				return err
			}
			if !credited {
				hash := rec.Hash
				index := uint32(i)
				dbtx.OnCommit(func() {
					w.NtfnServer.notifyUnspentOutput(
						account, &hash, index,
					)
				})
				credited = true
			}
			err = w.Manager.MarkUsed(addrmgrNs, addr)
			if err != nil {
				return err
			}
			log.Debugf("Marked address %v used", addr)
		}
	}

	// Send notification of mined or unmined transaction to any interested
	// clients.
	//
	// TODO: Avoid the extra db hits.
	if block == nil {
		w.NtfnServer.notifyUnminedTransaction(dbtx, txmgrNs, rec.Hash)
	} else {
		w.NtfnServer.notifyMinedTransaction(
			dbtx, txmgrNs, rec.Hash, block,
		)
	}

	return nil
}

// addRelevantTxFromStore records a relevant transaction and wallet credits
// through the backend-neutral manager transaction.
//
//nolint:cyclop // The branches preserve existing output classification.
func (w *Wallet) addRelevantTxFromStore(dbtx walletstore.ReadWriteTx,
	rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta) error {

	addrStore := dbtx.Addr()
	txStore := dbtx.Tx()
	exists, err := txStore.InsertTxCheckIfExists(rec, block)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	for i, output := range rec.MsgTx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams,
		)
		if err != nil {
			log.Warnf("Cannot extract non-std pkScript=%x",
				output.PkScript)
			continue
		}

		for _, addr := range addrs {
			managed, err := w.Manager.AddressFromStore(addrStore, addr)
			switch {
			case waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound):
				continue

			case err != nil:
				return err
			}

			scopedManager, account, err := w.Manager.AddrAccountFromStore(
				addrStore, addr,
			)
			if err != nil {
				return err
			}
			if !waddrmgr.IsDefaultScope(scopedManager.Scope()) {
				log.Debugf("Skipping non-default scope address %v", addr)
				continue
			}

			isNew, err := txStore.AddCredit(
				rec, block, uint32(i), managed.Internal(),
			)
			if err != nil {

				return err
			}
			if isNew {
				hash := rec.Hash
				index := uint32(i)
				addrStore.OnCommit(func() {
					w.NtfnServer.notifyUnspentOutput(
						account, &hash, index,
					)
				})
			}
			if err := w.Manager.MarkUsedFromStore(addrStore, addr); err != nil {
				return err
			}
			log.Debugf("Marked address %v used", addr)
		}
	}

	hash := rec.Hash
	var committedBlock *wtxmgr.BlockMeta
	if block != nil {
		blockCopy := *block
		committedBlock = &blockCopy
	}
	addrStore.OnCommit(func() {
		if committedBlock == nil {
			w.NtfnServer.notifyUnminedTransactionFromStore(hash)
			return
		}

		w.NtfnServer.notifyMinedTransactionFromStore(hash, committedBlock)
	})

	return nil
}

// chainConn is an interface that abstracts the chain connection logic required
// to perform a wallet's birthday block sanity check.
type chainConn interface {
	// GetBestBlock returns the hash and height of the best block known to
	// the backend.
	GetBestBlock() (*chainhash.Hash, int32, error)

	// GetBlockHash returns the hash of the block with the given height.
	GetBlockHash(int64) (*chainhash.Hash, error)

	// GetBlockHeader returns the header for the block with the given hash.
	GetBlockHeader(*chainhash.Hash) (*wire.BlockHeader, error)
}

// birthdayStore is an interface that abstracts the wallet's sync-related
// information required to perform a birthday block sanity check.
type birthdayStore interface {
	// Birthday returns the birthday timestamp of the wallet.
	Birthday() time.Time

	// BirthdayBlock returns the birthday block of the wallet. The boolean
	// returned should signal whether the wallet has already verified the
	// correctness of its birthday block.
	BirthdayBlock() (waddrmgr.BlockStamp, bool, error)

	// SetBirthdayBlock updates the birthday block of the wallet to the
	// given block. The boolean can be used to signal whether this block
	// should be sanity checked the next time the wallet starts.
	//
	// NOTE: This should also set the wallet's synced tip to reflect the new
	// birthday block. This will allow the wallet to rescan from this point
	// to detect any potentially missed events.
	SetBirthdayBlock(waddrmgr.BlockStamp) error
}

// walletBirthdayStore is a wrapper around the wallet's database and address
// manager that satisfies the birthdayStore interface.
type walletBirthdayStore struct {
	db      walletdb.DB
	store   walletstore.Store
	manager *waddrmgr.Manager
}

var _ birthdayStore = (*walletBirthdayStore)(nil)

// Birthday returns the birthday timestamp of the wallet.
func (s *walletBirthdayStore) Birthday() time.Time {
	return s.manager.Birthday()
}

// BirthdayBlock returns the birthday block of the wallet.
func (s *walletBirthdayStore) BirthdayBlock() (waddrmgr.BlockStamp, bool,
	error) {

	var (
		birthdayBlock         waddrmgr.BlockStamp
		birthdayBlockVerified bool
	)

	var err error
	if s.db != nil {
		err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
			var err error
			ns := tx.ReadBucket(waddrmgrNamespaceKey)
			birthdayBlock, birthdayBlockVerified, err =
				s.manager.BirthdayBlock(ns)
			return err
		})
	} else {
		err = s.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				var err error
				birthdayBlock, birthdayBlockVerified, err =
					s.manager.BirthdayBlockFromStore(tx.Addr())
				return err
			}, func() {
				birthdayBlock = waddrmgr.BlockStamp{}
				birthdayBlockVerified = false
			},
		)
	}

	return birthdayBlock, birthdayBlockVerified, err
}

// SetBirthdayBlock updates the birthday block of the wallet to the
// given block. The boolean can be used to signal whether this block
// should be sanity checked the next time the wallet starts.
//
// NOTE: This should also set the wallet's synced tip to reflect the new
// birthday block. This will allow the wallet to rescan from this point
// to detect any potentially missed events.
func (s *walletBirthdayStore) SetBirthdayBlock(
	block waddrmgr.BlockStamp) error {

	if s.db == nil {
		return s.store.UpdateOnce(
			context.Background(),
			func(tx walletstore.ReadWriteTx) error {
				err := s.manager.SetBirthdayBlockFromStore(
					tx.Addr(), block, true,
				)
				if err != nil {
					return err
				}

				return s.manager.SetSyncedToFromStore(
					tx.Addr(), &block,
				)
			}, nil,
		)
	}

	return walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		err := s.manager.SetBirthdayBlock(ns, block, true)
		if err != nil {
			return err
		}
		return s.manager.SetSyncedTo(ns, &block)
	})
}

// birthdaySanityCheck is a helper function that ensures a birthday block
// correctly reflects the birthday timestamp within a reasonable timestamp
// delta. It's intended to be run after the wallet establishes its connection
// with the backend, but before it begins syncing. This is done as the second
// part to the wallet's address manager migration where we populate the birthday
// block to ensure we do not miss any relevant events throughout rescans.
// waddrmgr.ErrBirthdayBlockNotSet is returned if the birthday block has not
// been set yet.
func birthdaySanityCheck(chainConn chainConn,
	birthdayStore birthdayStore) (*waddrmgr.BlockStamp, error) {

	// We'll start by fetching our wallet's birthday timestamp and block.
	birthdayTimestamp := birthdayStore.Birthday()
	birthdayBlock, birthdayBlockVerified, err := birthdayStore.BirthdayBlock()
	if err != nil {
		return nil, err
	}

	// If the birthday block has already been verified to be correct, we can
	// exit our sanity check to prevent potentially fetching a better
	// candidate.
	if birthdayBlockVerified {
		log.Debugf("Birthday block has already been verified: "+
			"height=%d, hash=%v", birthdayBlock.Height,
			birthdayBlock.Hash)

		return &birthdayBlock, nil
	}

	// Otherwise, we'll attempt to locate a better one now that we have
	// access to the chain.
	newBirthdayBlock, err := locateBirthdayBlock(chainConn, birthdayTimestamp)
	if err != nil {
		return nil, err
	}

	if err := birthdayStore.SetBirthdayBlock(*newBirthdayBlock); err != nil {
		return nil, err
	}

	return newBirthdayBlock, nil
}
