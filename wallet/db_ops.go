// Package wallet provides the implementation of a Bitcoin wallet.
//
// TODO(yy): This file will be removed once the Store implementation is
// finished.
package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/walletdb/migration"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// ErrMissingAddressManager is returned when the address manager namespace
	// is missing from the database.
	ErrMissingAddressManager = errors.New("missing address manager namespace")

	// ErrMissingTxManager is returned when the transaction manager namespace is
	// missing from the database.
	ErrMissingTxManager = errors.New("missing transaction manager namespace")
)

// DBCreateWallet initializes the database structure for a new wallet.
func DBCreateWallet(cfg Config, params CreateWalletParams,
	rootKey *hdkeychain.ExtendedKey) error {

	err := walletdb.Update(cfg.DB, func(tx walletdb.ReadWriteTx) error {
		// Create the top-level bucket for the address manager.
		addrMgrNs, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return fmt.Errorf("create addr mgr bucket: %w", err)
		}

		// Create the top-level bucket for the transaction manager.
		txMgrNs, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if err != nil {
			return fmt.Errorf("create tx mgr bucket: %w", err)
		}

		// Initialize the address manager in the database. This sets up
		// the master keys and the initial account structure.
		err = waddrmgr.Create(
			addrMgrNs, rootKey, params.PubPassphrase, params.PrivatePassphrase,
			cfg.ChainParams, nil, params.Birthday,
		)
		if err != nil {
			return fmt.Errorf("create addr mgr: %w", err)
		}

		// Initialize the transaction manager in the database.
		err = wtxmgr.Create(txMgrNs)
		if err != nil {
			return fmt.Errorf("create tx mgr: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	return nil
}

// DBLoadWallet initializes the database and returns the address and transaction
// managers.
func DBLoadWallet(cfg Config) (*waddrmgr.Manager, *wtxmgr.Store, error) {
	var (
		addrMgr *waddrmgr.Manager
		txMgr   *wtxmgr.Store
	)

	// Before attempting to open the wallet, we'll check if there are any
	// database upgrades for us to proceed. We'll also create our references
	// to the address and transaction managers, as they are backed by the
	// database.
	err := walletdb.Update(cfg.DB, func(tx walletdb.ReadWriteTx) error {
		addrMgrBucket := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if addrMgrBucket == nil {
			return ErrMissingAddressManager
		}

		txMgrBucket := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if txMgrBucket == nil {
			return ErrMissingTxManager
		}

		addrMgrUpgrader := waddrmgr.NewMigrationManager(addrMgrBucket)
		txMgrUpgrader := wtxmgr.NewMigrationManager(txMgrBucket)

		err := migration.Upgrade(txMgrUpgrader, addrMgrUpgrader)
		if err != nil {
			return fmt.Errorf("failed to upgrade database: %w", err)
		}

		addrMgr, err = waddrmgr.Open(
			addrMgrBucket, cfg.PubPassphrase, cfg.ChainParams,
		)
		if err != nil {
			return fmt.Errorf("failed to open address manager: %w", err)
		}

		txMgr, err = wtxmgr.Open(txMgrBucket, cfg.ChainParams)
		if err != nil {
			return fmt.Errorf("failed to open transaction manager: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load wallet: %w", err)
	}

	return addrMgr, txMgr, nil
}

// DBGetBirthdayBlock retrieves the current birthday block from the database.
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `GetWallet` to get the birthday info.
func (w *Wallet) DBGetBirthdayBlock(_ context.Context) (waddrmgr.BlockStamp,
	bool, error) {

	var (
		birthdayBlock waddrmgr.BlockStamp
		verified      bool
	)

	err := walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
		var err error

		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		birthdayBlock, verified, err = w.addrStore.BirthdayBlock(ns)
		if err != nil {
			return fmt.Errorf("get birthday block: %w", err)
		}

		return nil
	})
	if err != nil {
		return waddrmgr.BlockStamp{}, false, fmt.Errorf("view: %w", err)
	}

	return birthdayBlock, verified, nil
}

// DBPutBirthdayBlock updates the wallet's birthday block in the database
// and marks it as verified.
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `UpdateWallet` to set the birthday info.
func (w *Wallet) DBPutBirthdayBlock(_ context.Context,
	block waddrmgr.BlockStamp) error {

	err := walletdb.Update(w.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := w.addrStore.SetBirthdayBlock(ns, block, true)
		if err != nil {
			return fmt.Errorf("set birthday block: %w", err)
		}

		return w.addrStore.SetSyncedTo(ns, &block)
	})
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	return nil
}

// DBDeleteExpiredLockedOutputs removes any expired output locks from the
// transaction store.
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `UpdateUTXOs` instead.
func (w *Wallet) DBDeleteExpiredLockedOutputs(_ context.Context) error {
	err := walletdb.Update(w.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		return w.txStore.DeleteExpiredLockedOutputs(txmgrNs)
	})
	if err != nil {
		return fmt.Errorf("cleanup expired locks: %w", err)
	}

	return nil
}

// DBUnlock attempts to unlock the wallet's address manager with the provided
// passphrase.
//
// TODO(yy): Refactor this in the `Store` implementation - the only db
// operation needed is to load the account info and derive the private keys.
func (w *Wallet) DBUnlock(_ context.Context, passphrase []byte) error {
	err := walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		return w.addrStore.Unlock(addrmgrNs, passphrase)
	})
	if err != nil {
		return fmt.Errorf("view: %w", err)
	}

	return nil
}

// DBPutPassphrase updates the wallet's public or private passphrases.
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `UpdateWallet` instead.
func (w *Wallet) DBPutPassphrase(_ context.Context,
	req ChangePassphraseRequest) error {

	err := walletdb.Update(w.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		if req.ChangePublic {
			err := w.addrStore.ChangePassphrase(
				addrmgrNs, req.PublicOld, req.PublicNew,
				false, &waddrmgr.DefaultScryptOptions,
			)
			if err != nil {
				return fmt.Errorf("change public passphrase: "+
					"%w", err)
			}
		}

		if req.ChangePrivate {
			err := w.addrStore.ChangePassphrase(
				addrmgrNs, req.PrivateOld,
				req.PrivateNew, true,
				&waddrmgr.DefaultScryptOptions,
			)
			if err != nil {
				return fmt.Errorf("change private passphrase: "+
					"%w", err)
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	return nil
}

// DBGetAllAccounts ensures all account properties are loaded into the address
// manager's cache.
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `ListAccounts` instead, without the balance info.
func (w *Wallet) DBGetAllAccounts(_ context.Context) error {
	scopes := w.addrStore.ActiveScopedKeyManagers()

	err := walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		for _, scopedMgr := range scopes {
			lastAccount, err := scopedMgr.LastAccount(addrmgrNs)
			if err != nil {
				if waddrmgr.IsError(
					err, waddrmgr.ErrAccountNotFound,
				) {

					continue
				}

				return fmt.Errorf("last account: %w", err)
			}

			for i := uint32(0); i <= lastAccount; i++ {
				_, err := scopedMgr.AccountProperties(
					addrmgrNs, i,
				)
				if err != nil {
					return fmt.Errorf("account: %w", err)
				}
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("load all accounts: %w", err)
	}

	return nil
}

// DBGetUnminedTxns retrieves all transactions currently held in the
// wallet's unmined (mempool) store.
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `ListTxns` instead.
func (s *syncer) DBGetUnminedTxns(_ context.Context) ([]*wire.MsgTx, error) {
	var txs []*wire.MsgTx

	err := walletdb.View(
		s.cfg.DB, func(tx walletdb.ReadTx) error {
			txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

			var err error

			txs, err = s.txStore.UnminedTxs(txmgrNs)
			if err != nil {
				return fmt.Errorf("unmined txs: %w",
					err)
			}

			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("view: %w", err)
	}

	return txs, nil
}

// DBPutBlocks atomically processes a filtered block connected notification
// by inserting relevant transactions and updating the sync tip.
//
// NOTE: This method is used for notifications (not scans). It performs an
// extra step to resolve address scopes (via putRelevantTxns) before
// committing, as notification data does not include scope information.
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `UpdateWallet` instead.
func (s *syncer) DBPutBlocks(ctx context.Context,
	matches TxEntries, block *wtxmgr.BlockMeta) error {

	err := walletdb.Update(s.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		if len(matches) > 0 {
			err := s.putRelevantTxns(
				ctx, tx, matches, block,
			)
			if err != nil {
				return err
			}
		}

		return s.putSyncTip(ctx, tx, *block)
	})
	if err != nil {
		return fmt.Errorf("process filtered block: %w", err)
	}

	return nil
}

// DBPutTxns parses a batch of relevant transactions, identifies their
// relevant outputs, and commits them to the database.
//
// NOTE: This method is used for notifications (not scans). It performs an
// extra step to resolve address scopes (via putRelevantTxns) before
// committing, as notification data does not include scope information.
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `UpdateUTXOs` instead.
func (s *syncer) DBPutTxns(ctx context.Context, matches TxEntries,
	block *wtxmgr.BlockMeta) error {

	err := walletdb.Update(s.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		return s.putRelevantTxns(ctx, tx, matches, block)
	})
	if err != nil {
		return fmt.Errorf("process txns: %w", err)
	}

	return nil
}

// DBGetScanData retrieves all necessary data from the database to initialize
// the recovery state. This includes account horizons, active addresses, and
// unspent outputs to watch.
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `ListUTXOx+ListAddress` instead, or build a dedicated sql query.
func (s *syncer) DBGetScanData(_ context.Context,
	targets []waddrmgr.AccountScope) ([]*waddrmgr.AccountProperties,
	[]btcutil.Address, []wtxmgr.Credit, error) {

	var (
		horizonData    []*waddrmgr.AccountProperties
		initialAddrs   []btcutil.Address
		initialUnspent []wtxmgr.Credit
	)

	// Perform all database reads in a single read-only transaction.
	//
	// TODO(yy): Refactor to build a single SQL query for these data
	// fetches instead of multiple smaller operations within the
	// transaction.
	//
	// NOTE: RecoveryState initialization and mutation are intentionally
	// kept outside this transaction to strictly separate database I/O from
	// in-memory state management.
	err := walletdb.View(s.cfg.DB, func(dbtx walletdb.ReadTx) error {
		addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		// 1. Collect Horizons.
		for _, target := range targets {
			scopedMgr, err := s.addrStore.FetchScopedKeyManager(
				target.Scope,
			)
			if err != nil {
				return fmt.Errorf("fetch scoped manager: %w",
					err)
			}

			props, err := scopedMgr.AccountProperties(
				addrmgrNs, target.Account,
			)
			if err != nil {
				return fmt.Errorf("account properties: %w", err)
			}

			horizonData = append(horizonData, props)
		}

		// 2. Load Active Addresses.
		err := s.addrStore.ForEachRelevantActiveAddress(
			addrmgrNs, func(addr btcutil.Address) error {
				initialAddrs = append(initialAddrs, addr)
				return nil
			},
		)
		if err != nil {
			return fmt.Errorf("for each relevant address: %w", err)
		}

		// 3. Load UTXOs.
		initialUnspent, err = s.txStore.OutputsToWatch(txmgrNs)
		if err != nil {
			return fmt.Errorf("outputs to watch: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load recovery state: %w", err)
	}

	return horizonData, initialAddrs, initialUnspent, nil
}

// DBGetSyncedBlocks retrieves a batch of block hashes from the wallet's
// database for the range [startHeight, endHeight].
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `ListSyncedBlocks` instead on `WalletStore`?
func (s *syncer) DBGetSyncedBlocks(_ context.Context, startHeight,
	endHeight int32) ([]*chainhash.Hash, error) {

	var localHashes []*chainhash.Hash

	err := walletdb.View(s.cfg.DB, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		count := endHeight - startHeight + 1
		localHashes = make([]*chainhash.Hash, 0, count)

		// We fetch from startHeight to endHeight to match the order
		// we'll get from the chain backend (ascending).
		for h := startHeight; h <= endHeight; h++ {
			hash, err := s.addrStore.BlockHash(addrmgrNs, h)
			if err != nil {
				return fmt.Errorf("get block hash %d: %w",
					h, err)
			}

			localHashes = append(localHashes, hash)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("fetch synced block hashes: %w", err)
	}

	return localHashes, nil
}

// DBPutRewind rewinds the wallet state to the specified fork point.
//
// TODO(yy): Refactor this in the `Store` implementation - we need to define a
// new method and build customized query for this.
func (s *syncer) DBPutRewind(_ context.Context,
	bs waddrmgr.BlockStamp) error {

	// SetSyncedTo below writes the addrmgr bucket and advances the live
	// manager's in-memory synced tip immediately. If the subsequent
	// Rollback fails, walletdb rolls the bucket write back but the in-memory
	// tip stays rewound to a fork point that was never persisted. Snapshot
	// the pre-rewind tip so a failed update can restore it.
	preRewindTip := s.addrStore.SyncedTo()

	err := walletdb.Update(s.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		err := s.addrStore.SetSyncedTo(addrmgrNs, &bs)
		if err != nil {
			return fmt.Errorf("set synced to: %w", err)
		}

		return s.txStore.Rollback(txmgrNs, bs.Height+1)
	})
	if err != nil {
		// walletdb rolled the addrmgr bucket back, but any synced-tip
		// advance from SetSyncedTo survives in memory. Restore the
		// pre-rewind tip so the live manager matches the persisted
		// (rolled-back) state on the next access.
		s.addrStore.RestoreSyncedTo(preRewindTip)

		return fmt.Errorf("rollback wallet: %w", err)
	}

	return nil
}

// DBPutSyncBatch updates the database with the results of a batch scan. It
// handles persisting address horizons, transactions, and connecting blocks.
//
// TODO(yy): Refactor this in the `Store` implementation - we need a dedicated
// query for this on `WalletStore`?
func (s *syncer) DBPutSyncBatch(ctx context.Context,
	results []scanResult) error {

	// TODO(yy): build a single SQL query for this.
	err := walletdb.Update(s.cfg.DB, func(dbtx walletdb.ReadWriteTx) error {
		addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

		// 1. Update Address State (Horizons).
		err := s.putAddrHorizons(ctx, addrmgrNs, results)
		if err != nil {
			return err
		}

		// 2. Update UTXO State (Transactions).
		err = s.putScanTxns(ctx, dbtx, results)
		if err != nil {
			return err
		}

		// 3. Connect Blocks.
		// We must process blocks in order and connect each one to
		// ensure the address manager's block index remains contiguous.
		//
		// TODO(yy): This is inefficient as it performs a DB
		// write/check for each block. Implement a batch write method
		// in waddrmgr (or wait for SQL migration) to validate and
		// insert the entire chain segment at once.
		for _, res := range results {
			err = s.putSyncTip(ctx, dbtx, *res.meta)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("process scan batch: %w", err)
	}

	return nil
}

// DBPutTargetedBatch updates the database with the results of a targeted
// rescan. It persists address horizons and transactions but does NOT connect
// blocks or update the wallet's synced tip.
//
// TODO(yy): Refactor this in the `Store` implementation - we need a dedicated
// query for this on `WalletStore`?
func (s *syncer) DBPutTargetedBatch(ctx context.Context,
	results []scanResult) error {

	err := walletdb.Update(s.cfg.DB, func(dbtx walletdb.ReadWriteTx) error {
		addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

		// 1. Update Address State (Horizons).
		err := s.putAddrHorizons(ctx, addrmgrNs, results)
		if err != nil {
			return err
		}

		// 2. Update UTXO State (Transactions).
		err = s.putScanTxns(ctx, dbtx, results)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("process rescan batch: %w", err)
	}

	return nil
}

// DBPutSyncTip handles a chain server notification by marking a wallet
// that's currently in-sync with the chain server as being synced up to the
// passed block.
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `UpdateWallet` instead.
func (s *syncer) DBPutSyncTip(ctx context.Context,
	b wtxmgr.BlockMeta) error {

	err := walletdb.Update(s.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		return s.putSyncTip(ctx, tx, b)
	})
	if err != nil {
		return fmt.Errorf("commit sync tip: %w", err)
	}

	return nil
}

// putRelevantTxns identifies the branch scopes for a batch of relevant
// transactions received from notifications (not scans), resolves them, and
// commits them to the database.
func (s *syncer) putRelevantTxns(ctx context.Context,
	dbtx walletdb.ReadWriteTx, matches TxEntries,
	block *wtxmgr.BlockMeta) error {

	// 1. Resolution: Resolve scopes and finalize entries.
	err := s.resolveTxMatches(ctx, dbtx, matches)
	if err != nil {
		return err
	}

	// 2. Commit: Insert each transaction with its resolved credits.
	return s.putTxns(ctx, dbtx, matches, block)
}

// resolveTxMatches identifies the branch scopes for a batch of pre-extracted
// transactions and address entries, filtering out invalid ones.
func (s *syncer) resolveTxMatches(ctx context.Context,
	dbtx walletdb.ReadTx, matches TxEntries) error {

	// 1. Resolution: Resolve scopes for all unique addresses.
	scopeMap, err := s.filterBranchScopes(ctx, dbtx, matches)
	if err != nil {
		return err
	}

	// 2. Construction: Finalize entries by applying resolved scopes.
	for i := range matches {
		match := &matches[i]

		valid := make([]AddrEntry, 0, len(match.Entries))
		for _, entry := range match.Entries {
			scope, ok := scopeMap[entry.Address.String()]
			if !ok {
				continue
			}

			entry.Credit.Change = scope.Branch ==
				waddrmgr.InternalBranch

			valid = append(valid, entry)
		}

		match.Entries = valid
	}

	return nil
}

// putSyncTip handles a chain server notification by marking a wallet that's
// currently in-sync with the chain server as being synced up to the passed
// block.
func (s *syncer) putSyncTip(_ context.Context,
	dbtx walletdb.ReadWriteTx, b wtxmgr.BlockMeta) error {

	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	bs := waddrmgr.BlockStamp{
		Height:    b.Height,
		Hash:      b.Hash,
		Timestamp: b.Time,
	}

	err := s.addrStore.SetSyncedTo(addrmgrNs, &bs)
	if err != nil {
		return fmt.Errorf("failed to set synced to: %w", err)
	}

	return nil
}

// filterBranchScopes retrieves the branch scope for a given set of address
// entries. It returns a map where the key is the address string and the value
// is the corresponding branch scope.
func (s *syncer) filterBranchScopes(_ context.Context, dbtx walletdb.ReadTx,
	matches TxEntries) (map[string]waddrmgr.BranchScope, error) {

	ns := dbtx.ReadBucket(waddrmgrNamespaceKey)

	// Deduplicate addresses from the input entries to minimize expensive
	// database lookups for transactions with multiple outputs to the same
	// address.
	uniqueAddrs := make(map[string]btcutil.Address)
	for _, match := range matches {
		for _, entry := range match.Entries {
			uniqueAddrs[entry.Address.String()] = entry.Address
		}
	}

	// Resolve the branch scope (Scope, Account, Branch) for each unique
	// address. Addresses not found in the manager are skipped.
	scopes := make(map[string]waddrmgr.BranchScope, len(uniqueAddrs))
	for addrStr, addr := range uniqueAddrs {
		ma, err := s.addrStore.Address(ns, addr)
		if err != nil {
			if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
				continue
			}

			return nil, fmt.Errorf("get address info: %w", err)
		}

		scopedManager, account, err := s.addrStore.AddrAccount(ns, addr)
		if err != nil {
			return nil, fmt.Errorf("get addr account: %w", err)
		}

		branch := waddrmgr.ExternalBranch
		if ma.Internal() {
			branch = waddrmgr.InternalBranch
		}

		scopes[addrStr] = waddrmgr.BranchScope{
			Scope:   scopedManager.Scope(),
			Account: account,
			Branch:  branch,
		}
	}

	return scopes, nil
}

// putAddrHorizons aggregates found address horizons from the scan
// results and updates the address manager state (extends horizons) in the
// database.
//
// Unlike the store path (scanHorizonParams), this legacy path does not need an
// account name: it resolves each horizon directly against the live waddrmgr
// ScopedKeyManager and extends by account number. The store-backend masking
// of imported account numbers to 0 -- which forces name-based resolution
// there -- does not apply to the in-memory waddrmgr, whose account numbers are
// authoritative, so the BranchScope number is the correct identity here.
func (s *syncer) putAddrHorizons(_ context.Context,
	ns walletdb.ReadWriteBucket, results []scanResult) error {

	// Aggregate Horizon Expansion.
	batchHorizons := make(map[waddrmgr.BranchScope]uint32)
	for _, res := range results {
		for bs, idx := range res.FoundHorizons {
			if current, ok := batchHorizons[bs]; !ok ||
				idx > current {

				batchHorizons[bs] = idx
			}
		}
	}

	if len(batchHorizons) == 0 {
		return nil
	}
	// Update the database.
	for bs, maxFoundIndex := range batchHorizons {
		scopedMgr, err := s.addrStore.FetchScopedKeyManager(bs.Scope)
		if err != nil {
			return fmt.Errorf("fetch scoped manager: %w", err)
		}

		err = scopedMgr.ExtendAddresses(
			ns, bs.Account, maxFoundIndex, bs.Branch,
		)
		if err != nil {
			return fmt.Errorf("extend addresses: %w", err)
		}
	}

	return nil
}

// putScanTxns processes relevant transactions found during the scan
// and inserts them into the transaction store (and address manager for usage).
func (s *syncer) putScanTxns(ctx context.Context,
	dbtx walletdb.ReadWriteTx, results []scanResult) error {

	for _, result := range results {
		matches := result.RelevantOutputs

		// The RelevantTxs in scanResult are *btcutil.Tx. We need to
		// ensure the TxEntries have the correct *wtxmgr.TxRecord.
		for i := range matches {
			matches[i].Rec.Received = result.meta.Time
		}

		err := s.putTxns(ctx, dbtx, matches, result.meta)
		if err != nil {
			return err
		}
	}

	return nil
}

// putTxns inserts relevant transactions and their credits into the wallet
// using pre-matched output data.
func (s *syncer) putTxns(_ context.Context, dbtx walletdb.ReadWriteTx,
	matches TxEntries, block *wtxmgr.BlockMeta) error {

	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

	for _, match := range matches {
		rec := match.Rec
		entries := match.Entries

		credits := make([]wtxmgr.CreditEntry, 0, len(entries))
		for _, entry := range entries {
			credits = append(credits, entry.Credit)

			err := s.addrStore.MarkUsed(addrmgrNs, entry.Address)
			if err != nil {
				return fmt.Errorf("mark used: %w", err)
			}
		}

		var err error
		if block != nil {
			err = s.txStore.InsertConfirmedTx(
				txmgrNs, rec, block, credits,
			)
		} else {
			err = s.txStore.InsertUnconfirmedTx(
				txmgrNs, rec, credits,
			)
		}

		if err != nil {
			return fmt.Errorf("insert tx: %w", err)
		}
	}

	return nil
}
