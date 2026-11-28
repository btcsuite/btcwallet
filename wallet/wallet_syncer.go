package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/btcsuite/btcd/btcutil/v2/gcs/builder"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/addresstype"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// ErrCFiltersUnavailable is returned when the chain backend cannot
	// serve compact filters.
	ErrCFiltersUnavailable = errors.New("cfilters unavailable")

	// ErrUnknownSyncMethod is returned when an unknown synchronization
	// method is specified.
	ErrUnknownSyncMethod = errors.New("unknown sync method")

	// ErrScanBatchEmpty is returned when a scan batch contains no blocks.
	ErrScanBatchEmpty = errors.New("scan batch empty")

	// ErrUnknownRescanJobType is returned when an unknown rescan job type
	// is encountered.
	ErrUnknownRescanJobType = errors.New("unknown rescan job type")

	// ErrInvalidStartHeight is returned when a resync or rescan is
	// requested with an invalid start height (e.g., zero if not allowed).
	ErrInvalidStartHeight = errors.New("invalid start height")

	// ErrStartHeightTooHigh is returned when a resync or rescan is
	// requested with a start height that is greater than the current
	// chain tip.
	ErrStartHeightTooHigh = errors.New("start height is greater than " +
		"current chain tip")

	// ErrStartHeightTooLarge is returned when a resync or rescan is
	// requested with a start height that exceeds the maximum value of
	// an int32, which is the underlying type for block heights.
	ErrStartHeightTooLarge = errors.New("start height too large, exceeds " +
		"maximum int32 value")

	// ErrNoScanTargets is returned when a targeted rescan is requested with
	// no targets.
	ErrNoScanTargets = errors.New("at least one target must be specified")
)

const (
	// syncStateSwitchThreshold is the number of blocks behind the chain
	// tip at which the wallet switches to the "Syncing" state. Gaps
	// smaller than this are handled silently (blocking DB lock) to avoid
	// disrupting UX with "Wallet Busy" errors for minor lags.
	//
	// Value 6 (approx 1 hour) is chosen based on a balance of two factors:
	//
	// 1. Database Contention: Synchronization requires a database write
	//    lock. Processing 6 blocks typically takes less than 1 second,
	//    which is an acceptable duration for other operations (like
	//    CreateTx) to block (wait) on the database lock. Gaps larger than
	//    this would result in noticeable UI hangs, so we switch to the
	//    explicit "Syncing" state which allows the wallet to return an
	//    immediate error instead of blocking.
	//
	// 2. Data Integrity vs. UX: While in a silent sync, the wallet might
	//    allow the user to initiate actions based on slightly outdated
	//    data (e.g., spending an output that was actually spent in one of
	//    the missing blocks). For a 6-block gap, the risk is minimal, and
	//    such transactions would be rejected by the network mempool or
	//    miners. However, for large gaps, the risk of false "Insufficient
	//    Funds" errors or extremely inaccurate fee estimates increases,
	//    making the explicit "Syncing" state a necessary safeguard.
	syncStateSwitchThreshold = 6

	// scanAddressPageLimit is the store page size used when loading recovery
	// scan addresses.
	scanAddressPageLimit = 1000
)

// syncState represents the synchronization status of the wallet with the
// blockchain.
type syncState uint32

const (
	// syncStateBackendSyncing indicates the wallet is waiting for the
	// chain backend to finish syncing.
	syncStateBackendSyncing syncState = iota

	// syncStateSyncing indicates live processing is not ready while the
	// wallet catches up, rewinds, or waits to retry a failed sync worker.
	syncStateSyncing

	// syncStateSynced indicates the wallet is running and synced to the
	// chain tip.
	syncStateSynced

	// syncStateRescanning indicates a historical scan of user-provided
	// targets without rewinding the Wallet's live synchronization tip.
	syncStateRescanning
)

// String returns the string representation of a syncState.
func (s syncState) String() string {
	switch s {
	case syncStateBackendSyncing:
		return "backend-syncing"

	case syncStateSyncing:
		return "syncing"

	case syncStateSynced:
		return "synced"

	case syncStateRescanning:
		return "rescanning"

	default:
		return "unknown sync state"
	}
}

// scanType represents the type of rescan being requested.
type scanType uint8

const (
	// scanTypeRewind represents a full rescan which rewinds the wallet's
	// state to a specific point and scans forward.
	scanTypeRewind scanType = iota

	// scanTypeTargeted represents a targeted rescan for specific addresses
	// or accounts without altering the global sync state.
	scanTypeTargeted
)

// scanReq is an internal request to perform a rescan.
type scanReq struct {
	// typ specifies the type of rescan to perform.
	typ scanType

	// startBlock specifies the block height and hash to start the rescan
	// from.
	startBlock waddrmgr.BlockStamp

	// targets specifies the accounts to scan for. This is only used for
	// targeted rescans.
	targets []waddrmgr.AccountScope
}

// scanTarget is the internal, identity-aware form of a targeted-rescan
// account. The public Rescan API accepts waddrmgr.AccountScope, which only
// carries (scope, number). That is ambiguous for numberless imports: Store
// backends mask an unknown account number to 0, and GetAccount rejects a
// number lookup that resolves to a numberless row, so such an imported target
// cannot be loaded by number at all. scanTarget resolves the durable,
// non-masked identity up front -- before any horizon load -- so the targeted
// path can carry AccountName as the source of truth and never mis-resolve an
// imported target by number.
type scanTarget struct {
	// Scope is the key scope of the targeted account.
	Scope waddrmgr.KeyScope

	// Account is the requested account number. For the keyless legacy
	// imported-address bucket it is waddrmgr.ImportedAddrAccount; for every
	// other target it is the non-masked number the caller supplied, which
	// stays the recovery key for that account.
	Account uint32

	// AccountName is the durable, scope-unique account identity resolved
	// from the account snapshot. It is empty only for the keyless
	// imported-address bucket, which is never resolved. Store horizon
	// loading prefers this name over Account so a masked imported number
	// can never collide with the default derived account.
	AccountName string
}

// storeScanAccount is one recovery account snapshot loaded through the Store.
// It carries the two identities waddrmgr.AccountProperties cannot: the durable
// store row ID stamped onto every horizon the scan emits, and the real BIP44
// account number a store-native deriver records in its derivation params.
type storeScanAccount struct {
	// props is the horizon snapshot recovery state consumes. Its
	// AccountNumber is the key recovery state indexes the account by: the
	// caller's account number for a targeted scan, and the durable store row
	// ID for an untargeted full scan, where an imported account would
	// otherwise collide with a derived account owning the same BIP44 number.
	props *waddrmgr.AccountProperties

	// accountID is the durable store row identity of the account, or nil
	// when the backend exposes none. It is stamped onto emitted horizons so
	// a later account rename cannot break horizon extension.
	accountID *uint32

	// derivedAccountNumber is the known BIP44 component, nil only for a
	// numberless import. A known imported number does not mean the wallet
	// derived the account key; lookahead still uses the account's own xpub.
	derivedAccountNumber *uint32
}

// scanResult holds the result of processing a single block during a batch
// scan.
type scanResult struct {
	// BlockProcessResult embeds the results of filtering the block.
	*BlockProcessResult

	// meta contains block metadata (hash, height, time).
	meta *wtxmgr.BlockMeta

	// parentHash preserves fetched ancestry until the live commit boundary.
	parentHash chainhash.Hash
}

// chainProcessor abstracts Wallet event processing and recovery, allowing
// Wallet and controller tests to replace the existing worker.
type chainProcessor interface {
	// run executes the main synchronization loop.
	run(ctx context.Context) error

	// waitForRetry services eligible events until the Wallet's retry timer
	// expires or its lifetime ends.
	waitForRetry(ctx context.Context, retry <-chan time.Time) error

	// requestScan submits a rescan job to the syncer.
	requestScan(ctx context.Context, req *scanReq) error

	// syncState returns the current synchronization state.
	syncState() syncState

	// syncedTo reads the processed wallet tip with the caller's context so
	// eligibility decisions use committed wallet state.
	syncedTo(ctx context.Context) (waddrmgr.BlockStamp, error)

	// watchAddrs registers newly derived, imported, or published addresses
	// on the active subscription, or marks any in-flight catch-up scan
	// stale when no subscription is open.
	watchAddrs(ctx context.Context, addrs []address.Address) error
}

// txManager combines the Wallet capabilities used by the syncer for
// publication and notification after successful commits.
type txManager interface {
	txRebroadcaster
	txNotifier
}

// Wallet supplies both capabilities through the same private dependency.
var _ txManager = (*Wallet)(nil)

// syncer is a stateless blocking worker responsible for synchronizing the
// wallet with the blockchain. It operates within the lifecycle provided by the
// caller via context and manages the chain loop, scanning, and reorg handling.
type syncer struct {
	// cfg holds the configuration parameters for the syncer.
	cfg Config

	// addrStore is the address and key manager.
	addrStore waddrmgr.AddrStore

	// txStore is the transaction manager.
	txStore wtxmgr.TxStore

	// store is the transitional database store used by migrated runtime paths.
	store db.Store

	// walletID is the database wallet identifier used by store-backed paths.
	walletID uint32

	// state tracks the chain synchronization status.
	state atomic.Uint32

	// scanReqChan is the internal mailbox used to receive scan requests
	// from the controller. It is buffered to ensure that submitting a
	// request does not unnecessarily block the calling goroutine.
	scanReqChan chan *scanReq

	// txManager rebroadcasts unmined transactions and announces committed
	// observations while Wallet retains subscriber state and lifecycle.
	txManager txManager

	// chainSyncer owns subscriptions and prepares live matches for this
	// processor; every maintained Wallet receives its Manager's instance.
	chainSyncer    chainRouter
	chainEventChan <-chan chainEvent

	// sub holds the active per-Wallet chain event subscription while
	// synced, or nil while catching up, rewinding, or waiting for retry.
	sub atomic.Pointer[chain.EventSubscription]

	// scanAddrsStale records that watchAddrs observed no active
	// subscription (or a subscription retired for resync) after persisting
	// addresses to the Store, so an in-flight scanBatch retries with a
	// fresh address snapshot before advancing SyncedTo.
	scanAddrsStale atomic.Bool

	// pendingDisconnect retains the first failed live disconnect so the
	// next initialization replays it before startup rollback or later
	// mailbox events can overtake it.
	pendingDisconnect *wtxmgr.BlockMeta
}

// A compile-time assertion to ensure that syncer implements chainProcessor.
var _ chainProcessor = (*syncer)(nil)

// currentSub returns the active chain event subscription, or nil while the
// syncer is catching up, rewinding, or waiting for retry.
func (s *syncer) currentSub() chain.EventSubscription {
	sub := s.sub.Load()
	if sub == nil {
		return nil
	}

	return *sub
}

// closeSubscription retires any active chain event subscription so live
// notifications stop arriving while the syncer catches up, rewinds, or exits.
func (s *syncer) closeSubscription() {
	sub := s.sub.Swap(nil)
	if sub != nil {
		(*sub).Cancel()
	}
}

// watchAddrs registers addresses on the active subscription when synced. While
// no subscription is active (or if the active subscription was retired for
// resync), it marks any in-flight catch-up batch stale so the scan reloads the
// persisted addresses before advancing SyncedTo.
func (s *syncer) watchAddrs(ctx context.Context,
	addrs []address.Address) error {

	err := ctx.Err()
	if err != nil {
		return err
	}

	sub := s.currentSub()
	if sub == nil {
		if len(addrs) > 0 {
			s.scanAddrsStale.Store(true)
		}

		return nil
	}

	err = sub.WatchAddrs(ctx, addrs)
	if err == nil {
		return nil
	}

	if ctx.Err() != nil {
		return err
	}

	// If the subscription ended due to syncer cancellation or BlockEvents
	// overflow and rejected registration for that retirement (rather than
	// returning an in-flight backend RPC error), catch-up will reload the
	// persisted watch set before re-entering Synced.
	if isSubRetiredForResync(sub) && isSubRetirementErr(err) {
		if len(addrs) > 0 {
			s.scanAddrsStale.Store(true)
		}

		return nil
	}

	return err
}

// isSubRetirementErr reports whether err is a subscription-retirement error
// returned by EventSubscription.WatchAddrs rather than a backend RPC failure.
func isSubRetirementErr(err error) bool {
	return errors.Is(err, chain.ErrEventSubscriptionBufferFull) ||
		errors.Is(err, context.Canceled)
}

// isSubRetiredForResync reports whether a subscription ended because the syncer
// canceled it or because its BlockEvents buffer overflowed (triggering resync).
func isSubRetiredForResync(sub chain.EventSubscription) bool {
	select {
	case <-sub.Done():
		return isSubRetirementErr(sub.Err())
	default:
		return false
	}
}

// refreshLiveWatches registers stored addresses and outpoints for transaction
// notifications. The Store selects the addresses and outputs to watch.
func (s *syncer) refreshLiveWatches(ctx context.Context) error {
	// Read both interest groups together so retries cannot combine address
	// and output selections from separately timed storage snapshots.
	watches, err := s.store.LoadWatchSet(ctx, s.walletID)
	if err != nil {
		return fmt.Errorf("read watch set: %w", err)
	}

	var addrs []address.Address
	// Preserve the existing nil-address registration for empty snapshots.
	if len(watches.AddressScripts) > 0 {
		addrs = make([]address.Address, len(watches.AddressScripts))
	}

	for i, script := range watches.AddressScripts {
		addr, err := s.watchAddress(script)
		if err != nil {
			return fmt.Errorf("watch address script: %w", err)
		}

		addrs[i] = addr
	}

	// Wallet shutdown must still cancel registration. A later sync
	// initialization reads the persisted watch set again.
	err = s.chainSyncer.watchAddresses(ctx, s.walletID, addrs)
	if err != nil {
		return fmt.Errorf("register addresses: %w", err)
	}

	if len(watches.OutPoints) == 0 {
		return nil
	}

	// Bind each registration pointer to its distinct output in the snapshot.
	outpoints := make([]*wire.OutPoint, 0, len(watches.OutPoints))
	for i := range watches.OutPoints {
		outpoints = append(outpoints, &watches.OutPoints[i])
	}

	return s.chainSyncer.watchOutpoints(ctx, s.walletID, outpoints)
}

// watchAddress decodes a receiving script for live and recovery watches.
// Both paths select the first address using this Wallet's network.
func (s *syncer) watchAddress(script []byte) (address.Address, error) {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(script, s.cfg.ChainParams)
	if err != nil {
		return nil, err
	}

	// Imported rows can contain non-address scripts. Reject these rather
	// than indexing an empty decoded address list in either watch loader.
	if len(addrs) == 0 {
		return nil, db.ErrAddressNotFound
	}

	return addrs[0], nil
}

// newSyncer creates a new syncer instance. The Store and its wallet ID are
// mandatory: every migrated runtime path reads and writes through the Store,
// so there is no nil-store fallback. The notifier observes successful commits
// without owning persistence or scan lifecycle. The Manager's required routing
// owner and inbox supply prepared live events to this existing worker.
func newSyncer(cfg Config, addrStore waddrmgr.AddrStore,
	txStore wtxmgr.TxStore, txManager txManager, store db.Store,
	walletID uint32, chainSyncer chainRouter,
	events <-chan chainEvent) *syncer {

	return &syncer{
		cfg:            cfg,
		addrStore:      addrStore,
		txStore:        txStore,
		scanReqChan:    make(chan *scanReq, 1),
		txManager:      txManager,
		store:          store,
		walletID:       walletID,
		chainSyncer:    chainSyncer,
		chainEventChan: events,
	}
}

// syncState returns the current synchronization state of the wallet.
func (s *syncer) syncState() syncState {
	return syncState(s.state.Load())
}

// initChainSync performs the initial setup for the chain synchronization loop.
// This includes waiting for the backend to sync, checking for rollbacks, and
// enabling block notifications. It returns an error if any of these setup
// steps fail.
func (s *syncer) initChainSync(ctx context.Context) error {
	// Wait for the backend to be synced to the network. We require the
	// backend to be synced before we start scanning to ensure we have a
	// consistent view of the chain and can perform recovery correctly.
	s.state.Store(uint32(syncStateBackendSyncing))

	err := s.waitUntilBackendSynced(ctx)
	if err != nil {
		return fmt.Errorf("unable to wait for backend sync: %w", err)
	}

	// Retry a previously failed live disconnect before startup rollback so
	// an orphaned confirmation above the saved checkpoint is not dropped.
	if s.pendingDisconnect != nil {
		err = s.disconnectBlock(ctx, *s.pendingDisconnect)
		if err != nil {
			return fmt.Errorf("retry pending disconnect: %w", err)
		}
	}

	// Check for any reorgs that happened while we were down.
	err = s.checkRollback(ctx)
	if err != nil {
		return fmt.Errorf("unable to check for rollback: %w", err)
	}

	// A retry may follow a committed scan whose registration failed.
	// Register stored addresses and outpoints even if the tip is current.
	//
	// TODO(yy): Avoid rereading and registering the full set on each retry
	// while preserving registration that failed after a committed scan.
	err = s.refreshLiveWatches(ctx)
	if err != nil {
		return err
	}

	// Explicitly request connected/disconnected block notifications. Only
	// the bitcoind and neutrino wrappers enable block notifications as a
	// side effect of NotifyReceived; btcd's NotifyReceived (the embedded
	// rpcclient method) registers only address notifications, so without
	// this call a btcd-backed wallet would stop receiving live block
	// connect/disconnect events. The call is idempotent on the wrappers
	// that already enabled notifications, so it is safe for all backends.
	err = s.chainSyncer.notifyBlocks(ctx)
	if err != nil {
		return fmt.Errorf("unable to start block "+
			"notifications: %w", err)
	}

	return nil
}

// waitForRetry lets the worker service mailbox events across retries while the
// Wallet controls the retry deadline.
func (s *syncer) waitForRetry(ctx context.Context,
	retry <-chan time.Time) error {

	for {
		// Pause mailbox reads while a failed disconnect awaits retry so
		// queued events cannot overtake the pending rewind.
		events := s.chainEventChan
		if s.pendingDisconnect != nil {
			events = nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-retry:
			return nil

		case event := <-events:
			err := s.processChainEventBeforeSync(ctx, event)
			if ctx.Err() != nil {
				return ctx.Err()
			}

			if err != nil {
				log.Errorf("Chain event processing failed "+
					"during retry: %v", err)
			}
		}
	}
}

// waitUntilBackendSynced blocks until the chain backend considers itself
// "current".
func (s *syncer) waitUntilBackendSynced(ctx context.Context) error {
	// Check immediately if the backend is already synced.
	if s.cfg.Chain.IsCurrent() {
		return nil
	}

	// We'll poll every second to determine if our chain considers itself
	// "current".
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		// Pause mailbox reads while a failed disconnect awaits retry so
		// queued events cannot overtake the pending rewind.
		events := s.chainEventChan
		if s.pendingDisconnect != nil {
			events = nil
		}

		select {
		case event := <-events:
			err := s.processChainEventBeforeSync(ctx, event)
			if err != nil {
				return err
			}

		case <-t.C:
			if s.cfg.Chain.IsCurrent() {
				return nil
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// checkRollback ensures the wallet is synchronized with the current chain tip.
// It checks if the wallet's synced tip is still on the main chain, and if not,
// rewinds the wallet state to the common ancestor.
// If no recorded ancestor is found for a non-genesis tip, it returns
// db.ErrBlockNotFound without rewinding.
func (s *syncer) checkRollback(ctx context.Context) error {
	// Keep traversal tied to the committed Wallet tip; individual batches
	// retain their existing Store reads and atomic Store rewind boundary.
	syncedTo, err := s.syncedTo(ctx)
	if err != nil {
		return err
	}

	syncedHeight := syncedTo.Height

	// A saved non-genesis tip must also search genesis for an ancestor.
	for syncedTo.Height > 0 && syncedHeight >= 0 {
		var done bool

		syncedHeight, done, err = s.checkRollbackBatch(
			ctx, syncedTo, syncedHeight,
		)
		if done {
			return err
		}
	}

	// A non-genesis tip needs a proven ancestor before Store can rewind.
	// Fail an exhausted search instead of accepting an abandoned branch;
	// a genesis tip has no earlier history to compare.
	if syncedTo.Height > 0 {
		return fmt.Errorf("no recorded common ancestor: %w",
			db.ErrBlockNotFound)
	}

	return nil
}

// checkRollbackBatch compares one recorded range within the remote tip;
// a common ancestor is rewound synchronously through the existing Store.
// With done false, it returns the next end height and a nil error; -1 marks
// exhausted history. With done true, the error is the final outcome: nil for
// a confirmed tip or successful rewind, otherwise the read or rewind failure.
func (s *syncer) checkRollbackBatch(ctx context.Context,
	syncedTo waddrmgr.BlockStamp, endHeight int32) (int32, bool, error) {

	// Bound backward RPC batches while searching for a recorded ancestor.
	const batchSize = 10

	startHeight := max(0, endHeight-batchSize+1)

	localHashes, startHeight, err := s.syncedBlockHashes(
		ctx, startHeight, endHeight,
	)
	if err != nil {
		return 0, true, s.resolveMissingHistoricalBlock(err, syncedTo)
	}

	// A shorter current branch cannot serve hashes above its own tip.
	// Preserve local-read order; a higher batch retries from that tip.
	bestHash, bestHeight, err := s.cfg.Chain.GetBestBlock()
	if err != nil {
		return 0, true, fmt.Errorf("get rollback chain tip: %w", err)
	}

	if startHeight > bestHeight {
		return bestHeight, false, nil
	}

	remoteHashes, err := s.cfg.Chain.GetBlockHashes(
		int64(startHeight), int64(min(endHeight, bestHeight)),
	)
	if err != nil {
		return 0, true, fmt.Errorf("remote get block hashes: %w", err)
	}

	matchIndex := s.findForkPoint(localHashes, remoteHashes)

	// Only a match at the saved tip avoids rewind; a shorter current branch
	// cannot confirm that tip.
	if endHeight == syncedTo.Height && bestHeight >= syncedTo.Height &&
		matchIndex == len(localHashes)-1 {

		return 0, true, nil
	}

	// The common ancestor lies deeper, so continue below this entire batch.
	if matchIndex == -1 {
		return startHeight - 1, false, nil
	}

	// Resolve the matching ancestor before entering persistence or the
	// Store rollback, so backend I/O never holds a storage transaction.
	// matchIndex < batchSize (10).
	forkHeight := startHeight + int32(matchIndex)
	forkHash := localHashes[matchIndex]
	log.Infof("Rollback detected! Rewinding to height %d (%v)",
		forkHeight, forkHash)

	header, err := s.cfg.Chain.GetBlockHeader(forkHash)
	if err != nil {
		return 0, true, fmt.Errorf("get fork header: %w", err)
	}

	observed := db.OptionalBlockFromBlockStamp(syncedTo)
	fork := waddrmgr.BlockStamp{
		Height:    forkHeight,
		Hash:      *forkHash,
		Timestamp: header.Timestamp,
	}
	source := waddrmgr.BlockStamp{Hash: *bestHash, Height: bestHeight}

	return 0, true, s.applyDisconnect(
		ctx, *observed, syncedTo.Height, fork, source,
	)
}

// resolveMissingHistoricalBlock accepts a missing historical block when the
// persisted synced tip matches the chain backend.
func (s *syncer) resolveMissingHistoricalBlock(listErr error,
	syncedTo waddrmgr.BlockStamp) error {

	if !errors.Is(listErr, db.ErrBlockNotFound) {
		return listErr
	}

	remoteHash, err := s.cfg.Chain.GetBlockHash(int64(syncedTo.Height))
	if err != nil {
		return fmt.Errorf("get synced block hash: %w", err)
	}

	if syncedTo.Hash.IsEqual(remoteHash) {
		return nil
	}

	return listErr
}

// rewindWallet rewinds this wallet's sync and transaction state for a manual
// rescan without requiring a DB-wide block rollback.
func (s *syncer) rewindWallet(ctx context.Context,
	block waddrmgr.BlockStamp) error {

	storeBlock, err := s.resolveRewindBlock(block)
	if err != nil {
		return fmt.Errorf("rewind wallet block: %w", err)
	}

	err = s.store.RewindWallet(ctx, db.RewindWalletParams{
		WalletID: s.walletID,
		Block:    *storeBlock,
	})
	if err != nil {
		return fmt.Errorf("rewind wallet: %w", err)
	}

	return nil
}

// resolveRewindBlock resolves the requested manual-rewind height into the
// canonical block metadata recorded as the wallet's new synced tip.
func (s *syncer) resolveRewindBlock(
	block waddrmgr.BlockStamp) (*db.Block, error) {

	if block.Hash != (chainhash.Hash{}) && !block.Timestamp.IsZero() {
		storeBlock, err := db.BlockFromBlockStamp(block)
		if err != nil {
			return nil, fmt.Errorf("convert rewind block: %w", err)
		}

		return storeBlock, nil
	}

	hash, err := s.cfg.Chain.GetBlockHash(int64(block.Height))
	if err != nil {
		return nil, fmt.Errorf("get rewind block hash: %w", err)
	}

	header, err := s.cfg.Chain.GetBlockHeader(hash)
	if err != nil {
		return nil, fmt.Errorf("get rewind block header: %w", err)
	}

	storeBlock, err := db.BlockFromBlockStamp(waddrmgr.BlockStamp{
		Height:    block.Height,
		Hash:      *hash,
		Timestamp: header.Timestamp,
	})
	if err != nil {
		return nil, fmt.Errorf("convert resolved rewind block: %w", err)
	}

	return storeBlock, nil
}

// syncedBlockHashes returns the wallet's synced block hashes for the inclusive
// height range and its actual start. Retry only the end row when
// pre-birthday history is absent, keeping remote comparison aligned with it.
func (s *syncer) syncedBlockHashes(ctx context.Context, startHeight,
	endHeight int32) ([]*chainhash.Hash, int32, error) {

	start, err := db.Int64ToUint32(int64(startHeight))
	if err != nil {
		return nil, startHeight, fmt.Errorf("start height %d: %w",
			startHeight, err)
	}

	end, err := db.Int64ToUint32(int64(endHeight))
	if err != nil {
		return nil, startHeight, fmt.Errorf("end height %d: %w", endHeight,
			err)
	}

	blocks, err := s.store.ListSyncedBlocks(
		ctx, db.ListSyncedBlocksQuery{
			WalletID:    s.walletID,
			StartHeight: start,
			EndHeight:   end,
		},
	)
	if startHeight < endHeight &&
		errors.Is(err, db.ErrBlockNotFound) {

		// One singleton retry preserves the stored endpoint without
		// requiring missing pre-birthday rows; it cannot recurse again.
		return s.syncedBlockHashes(ctx, endHeight, endHeight)
	}

	if err != nil {
		return nil, startHeight, fmt.Errorf("list synced blocks: %w", err)
	}

	hashes := make([]*chainhash.Hash, len(blocks))
	for i := range blocks {
		hashes[i] = &blocks[i].Hash
	}

	return hashes, startHeight, nil
}

// syncedTo returns the wallet's current synced-to block from the Store.
func (s *syncer) syncedTo(ctx context.Context) (waddrmgr.BlockStamp, error) {
	walletInfo, err := s.store.GetWallet(ctx, s.cfg.Name)
	if err != nil {
		return waddrmgr.BlockStamp{}, fmt.Errorf("get wallet sync tip: %w",
			err)
	}

	syncedTo, err := db.OptionalBlockStampFromBlock(walletInfo.SyncedTo)
	if err != nil {
		return waddrmgr.BlockStamp{}, fmt.Errorf("decode wallet sync tip: %w",
			err)
	}

	return syncedTo, nil
}

// findForkPoint compares local and remote block hashes to find the last
// matching block (fork point). It returns the index of the last match in the
// slices, or -1 if no match is found.
func (s *syncer) findForkPoint(localHashes []*chainhash.Hash,
	remoteHashes []chainhash.Hash) int {

	// Compare up to the length of the shortest slice to avoid
	// out-of-bounds panics if the chain backend returns fewer hashes than
	// expected.
	minLen := min(len(localHashes), len(remoteHashes))

	for i := minLen - 1; i >= 0; i-- {
		if localHashes[i].IsEqual(&remoteHashes[i]) {
			return i
		}
	}

	return -1
}

// run executes the main synchronization loop.
func (s *syncer) run(ctx context.Context) error {
	// Initialize the chain sync state.
	err := s.initChainSync(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, ErrWalletShuttingDown) {

			return nil
		}

		return fmt.Errorf("initialize chain sync: %w", err)
	}

	for {
		err := s.runSyncStep(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, ErrWalletShuttingDown) {

				return nil
			}

			s.state.Store(uint32(syncStateSyncing))

			return err
		}
	}
}

// runSyncStep performs a single iteration of the synchronization loop. It
// advances the chain sync state, broadcasts unmined transactions, and then
// waits for the next event (notification or job).
func (s *syncer) runSyncStep(ctx context.Context) error {
	// Attempt to advance the wallet's sync state.
	syncFinished, err := s.advanceChainSync(ctx)
	if err != nil {
		return fmt.Errorf("advance chain sync: %w", err)
	}

	if !syncFinished {
		return nil
	}

	// Rebroadcast unmined transactions.
	err = s.broadcastUnminedTxns(ctx)
	if err != nil {
		return fmt.Errorf("broadcast unmined txns: %w", err)
	}

	// Proceed to idle mode, waiting for notifications or jobs.
	err = s.waitForEvent(ctx)
	if err != nil {
		return err
	}

	return nil
}

// requestScan submits a rescan job to the syncer.
func (s *syncer) requestScan(ctx context.Context, req *scanReq) error {
	select {
	case s.scanReqChan <- req:
		return nil

	case <-ctx.Done():
		return ctx.Err()
	}
}

// broadcastUnminedTxns retrieves all unmined transactions from the wallet and
// retries their publication without recreating history deleted after the read.
func (s *syncer) broadcastUnminedTxns(ctx context.Context) error {
	txs, err := s.unminedTxns(ctx)
	if err != nil {
		log.Errorf("Unable to retrieve unconfirmed transactions to "+
			"resend: %v", err)

		return fmt.Errorf("failed to retrieve unconfirmed txs: %w", err)
	}

	for _, tx := range txs {
		err := s.txManager.rebroadcast(ctx, tx)
		if err != nil {
			log.Warnf("Unable to rebroadcast tx %v: %v",
				tx.TxHash(), err)
		}
	}

	return nil
}

// unminedTxns returns transactions that are still active in the wallet's
// unmined set.
func (s *syncer) unminedTxns(ctx context.Context) ([]*wire.MsgTx, error) {
	infos, err := s.store.ListTxns(
		ctx, db.ListTxnsQuery{
			WalletID:    s.walletID,
			UnminedOnly: true,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list unmined txns: %w", err)
	}

	txSet := make(map[chainhash.Hash]*wire.MsgTx, len(infos))
	for i := range infos {
		info := infos[i]
		if info.Status != db.TxStatusPublished {
			continue
		}

		var tx wire.MsgTx

		err := tx.Deserialize(bytes.NewReader(info.SerializedTx))
		if err != nil {
			return nil, fmt.Errorf("deserialize unmined tx %v: %w",
				info.Hash, err)
		}

		txHash := tx.TxHash()
		txSet[txHash] = &tx
	}

	return wtxmgr.DependencySort(txSet), nil
}

// prepareTxMatches decodes each transaction's output addresses and indices for
// Wallet Store application.
func prepareTxMatches(recs []*wtxmgr.TxRecord,
	params *chaincfg.Params) TxEntries {

	matches := make(TxEntries, 0, len(recs))
	for _, rec := range recs {
		matches = append(matches, TxEntry{
			Rec:     rec,
			Entries: extractAddrEntries(rec.MsgTx.TxOut, params),
		})
	}

	return matches
}

// extractAddrEntries collects all addresses from transaction outputs and
// creates initial AddrEntry objects with output indices.
func extractAddrEntries(txOuts []*wire.TxOut,
	params *chaincfg.Params) []AddrEntry {

	var entries []AddrEntry
	for i, output := range txOuts {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, params,
		)
		if err != nil {
			log.Warnf("Cannot extract non-std pkScript=%x",
				output.PkScript)

			continue
		}

		for _, addr := range addrs {
			entries = append(entries, AddrEntry{
				Address: addr,
				Credit: wtxmgr.CreditEntry{
					// Output index fits in uint32.
					Index: uint32(i),
				},
			})
		}
	}

	return entries
}

// putTxNotifications records relevant transaction notifications through the
// store.
func (s *syncer) putTxNotifications(ctx context.Context,
	matches TxEntries, blockMeta *wtxmgr.BlockMeta) error {

	var block *db.Block
	if blockMeta != nil {
		var err error

		block, err = storeBlockFromBlockMeta(*blockMeta)
		if err != nil {
			return err
		}
	}

	return s.applyStoreTxBatch(ctx, matches, block, nil)
}

// putBlockNotifications records filtered block notifications through the store.
func (s *syncer) putBlockNotifications(ctx context.Context,
	matches TxEntries, blockMeta *wtxmgr.BlockMeta) error {

	if blockMeta == nil {
		return fmt.Errorf("filtered block is missing metadata: %w",
			db.ErrInvalidParam)
	}

	current, err := s.syncedTo(ctx)
	if err != nil {
		return err
	}

	// Only the exact next block may advance the checkpoint. Catch-up handles
	// gaps, while later representations may supplement committed payloads.
	if blockMeta.Height > current.Height+1 {
		return nil
	}

	block, err := storeBlockFromBlockMeta(*blockMeta)
	if err != nil {
		return err
	}

	if blockMeta.Height == current.Height+1 {
		return s.putNextBlockNotification(
			ctx, matches, *blockMeta, block, current,
		)
	}

	return s.putSupplementalBlockMatches(ctx, matches, block, current)
}

// putSupplementalBlockMatches records matched transactions for an already
// synced height on the committed branch without advancing SyncedTo.
func (s *syncer) putSupplementalBlockMatches(ctx context.Context,
	matches TxEntries, block *db.Block,
	current waddrmgr.BlockStamp) error {

	// Empty supplemental payloads cannot add effects, so they need no
	// historical lookup after the checkpoint has already passed them.
	if len(matches) == 0 {
		return nil
	}

	// Supplemental payloads may add effects only on the committed branch.
	onBranch, err := s.blockMatchesCheckpoint(ctx, *block, current)
	if err != nil || !onBranch {
		return err
	}

	return s.applyStoreTxBatch(ctx, matches, block, nil)
}

// putNextBlockNotification verifies parent continuity for a live next-height
// block and commits its transactions and new checkpoint when connected.
func (s *syncer) putNextBlockNotification(ctx context.Context,
	matches TxEntries, blockMeta wtxmgr.BlockMeta, block *db.Block,
	current waddrmgr.BlockStamp) error {

	extends, err := s.verifyBlockParent(ctx, blockMeta, current)
	if err != nil || !extends {
		return err
	}

	return s.applyStoreTxBatch(ctx, matches, block, block)
}

// verifyBlockParent checks that a live next-height block connects directly to
// the wallet's current synced tip. When the parent hash differs (for example,
// a fork whose disconnect has not yet arrived), it returns false without error
// so the caller does not advance SyncedTo onto a forked branch.
func (s *syncer) verifyBlockParent(ctx context.Context,
	blockMeta wtxmgr.BlockMeta, current waddrmgr.BlockStamp) (bool, error) {

	// Genesis has no parent block to compare against.
	if blockMeta.Height == 0 {
		return true, nil
	}

	// Check cancellation before calling GetBlockHeader, which accepts no
	// context.
	err := ctx.Err()
	if err != nil {
		return false, err
	}

	header, err := s.cfg.Chain.GetBlockHeader(&blockMeta.Hash)
	if err != nil {
		return false, fmt.Errorf("get block header %v: %w",
			blockMeta.Hash, err)
	}

	return header.PrevBlock == current.Hash, nil
}

// blockMatchesCheckpoint checks a queued live block against this Wallet's
// checkpoint or stored history before recording its payments.
func (s *syncer) blockMatchesCheckpoint(ctx context.Context, block db.Block,
	current waddrmgr.BlockStamp) (bool, error) {

	committedHash := current.Hash
	// The tip hash identifies only its own height; older payloads must match
	// the recorded hash at their height before adding confirmed effects.
	if int64(block.Height) < int64(current.Height) {
		blocks, err := s.store.ListSyncedBlocks(
			ctx, db.ListSyncedBlocksQuery{
				WalletID:    s.walletID,
				StartHeight: block.Height,
				EndHeight:   block.Height,
			},
		)
		// Missing history cannot authorize effects, whether the Store uses
		// the SQL sentinel or wraps the legacy address manager's error.
		var managerErr waddrmgr.ManagerError
		if errors.Is(err, db.ErrBlockNotFound) ||
			errors.As(err, &managerErr) &&
				managerErr.ErrorCode == waddrmgr.ErrBlockNotFound {

			return false, nil
		}

		if err != nil {
			return false, fmt.Errorf("list committed block %d: %w",
				block.Height, err)
		}

		// An empty successful read likewise supplies no committed identity.
		if len(blocks) == 0 {
			return false, nil
		}

		committedHash = blocks[0].Hash
	}

	return block.Hash == committedHash, nil
}

// applyStoreTxBatch writes transaction matches through the store batch API.
func (s *syncer) applyStoreTxBatch(ctx context.Context,
	matches TxEntries, block *db.Block, syncedTo *db.Block) error {

	transactions := make([]db.CreateTxParams, 0, len(matches))
	for i := range matches {
		match := matches[i]
		creditCandidates := make(
			map[uint32][]address.Address, len(match.Entries),
		)

		for _, entry := range match.Entries {
			index := entry.Credit.Index
			if uint64(index) >= uint64(len(match.Rec.MsgTx.TxOut)) {
				return fmt.Errorf("credit output %d: %w", index,
					db.ErrInvalidParam)
			}

			creditCandidates[index] = append(
				creditCandidates[index], entry.Address,
			)
		}

		// Observation labels are omitted so the batch reconciles current
		// user metadata atomically instead of validating a stale snapshot.

		transactions = append(transactions, db.CreateTxParams{
			WalletID:         s.walletID,
			Tx:               &match.Rec.MsgTx,
			Received:         match.Rec.Received,
			Block:            block,
			Status:           db.TxStatusPublished,
			CreditCandidates: creditCandidates,
		})
	}

	err := s.store.ApplyTxBatch(
		ctx, db.TxBatchParams{
			WalletID:     s.walletID,
			Transactions: transactions,
			SyncedTo:     syncedTo,
		},
	)
	if err != nil {
		return fmt.Errorf("apply tx batch: %w", err)
	}

	// Announce only successful commits; delivery cannot replace a write error
	// or make this batch depend on subscribers consuming their queues.
	for _, tx := range transactions {
		s.txManager.notifyTx(ctx, tx.Tx.TxHash())
	}

	return nil
}

// putSyncBatch records recovery scan results and synced blocks through the
// store.
func (s *syncer) putSyncBatch(ctx context.Context, scanState *RecoveryState,
	results []scanResult) error {

	// Check for rollback before committing. If a disconnect is queued,
	// process it and abort the batch. Any non-disconnect event stays out of
	// the sync batch so historical recovery does not advance past it.
	pending, err := s.checkForRollbackBeforeCommit(ctx)
	if err != nil {
		return err
	}

	err = s.commitSyncBatch(ctx, scanState, results)
	if pending.notification != nil {
		err = errors.Join(
			err, s.processChainEventBeforeSync(ctx, pending),
		)
	}

	return err
}

// commitSyncBatch persists one recovery scan batch, announces committed
// transactions, and refreshes live watches when horizons or transactions
// changed.
func (s *syncer) commitSyncBatch(ctx context.Context,
	scanState *RecoveryState, results []scanResult) error {

	params, err := s.storeScanBatchParams(scanState, results, true)
	if err != nil {
		return err
	}

	refreshWatches := len(params.Horizons) > 0 ||
		len(params.Transactions) > 0
	if refreshWatches {
		// Clear readiness before publishing the tip. Normal catch-up
		// restores it only after watch registration succeeds.
		s.state.Store(uint32(syncStateSyncing))
	}

	// ApplyScanBatch persists the batch's synced blocks and advances the
	// wallet's synced tip. advanceChainSync reads the next batch's start
	// height back through s.syncedTo, which is Store-backed here, so the
	// loop makes forward progress regardless of whether a given backend
	// also mirrors the tip into the legacy addrStore.
	err = s.store.ApplyScanBatch(ctx, params)
	if err != nil {
		return fmt.Errorf("apply sync scan batch: %w", err)
	}

	// The existing Store commit owns persistence and tip advancement. The
	// Wallet notifier only reads the result and offers best-effort delivery.
	for _, tx := range params.Transactions {
		s.txManager.notifyTx(ctx, tx.Tx.TxHash())
	}

	if !refreshWatches {
		return nil
	}

	return s.refreshLiveWatches(ctx)
}

// putTargetedBatch records targeted recovery scan results through the store.
func (s *syncer) putTargetedBatch(ctx context.Context,
	scanState *RecoveryState, results []scanResult) error {

	params, err := s.storeScanBatchParams(scanState, results, false)
	if err != nil {
		return err
	}

	// Cover the commit boundary as well as registration: Info treats an
	// ordinary rescan as live-ready even when both tips match.
	s.state.Store(uint32(syncStateSyncing))

	err = s.store.ApplyScanBatch(ctx, params)
	if err != nil {
		// An unknown commit outcome may have persisted new watches. Keep
		// readiness revoked so initialization rereads them; only definite
		// write failures can restore readiness without registration.
		if !errors.Is(err, dbruntime.ErrAmbiguousTxCommit) {
			s.state.Store(uint32(syncStateRescanning))
		}

		return fmt.Errorf("apply targeted scan batch: %w", err)
	}

	// Historical observations use the same Wallet payload and queue policy,
	// without adding notification state to scan readiness or rollback.
	for _, tx := range params.Transactions {
		s.txManager.notifyTx(ctx, tx.Tx.TxHash())
	}

	// Targeted scans can also store new addresses and outputs. Register
	// them after the commit using the scan worker's lifetime context.
	if len(params.Horizons) > 0 || len(params.Transactions) > 0 {
		return s.refreshLiveWatches(ctx)
	}

	return nil
}

// mergeScanHorizons records the highest discovered child index per branch scope
// into the running horizon map.
func mergeScanHorizons(horizons map[waddrmgr.BranchScope]uint32,
	found map[waddrmgr.BranchScope]uint32) {

	for bs, index := range found {
		if current, ok := horizons[bs]; !ok || index > current {
			horizons[bs] = index
		}
	}
}

// scanHorizonParams flattens the merged horizon map into store scan horizon
// params, stamping every horizon with the account identity resolved into the
// recovery state.
//
// AccountID is the stable Store row identity that SQL backends use to resolve
// the horizon's owning account. AccountName is retained as metadata and as a
// compatibility fallback for backends that do not expose AccountID.
//
// Fail-safe: if the recovery state has no name for a branch's account, we
// leave AccountName empty and let the backend fall back to its number-based
// behavior. The recovery state derives the horizon map from the same account
// properties that seed accountNames, so a miss is not expected in practice;
// emitting a wrong name would be worse than the number fallback.
func scanHorizonParams(scanState *RecoveryState,
	horizons map[waddrmgr.BranchScope]uint32) []db.ScanHorizon {

	params := make([]db.ScanHorizon, 0, len(horizons))
	for bs, index := range horizons {
		name, _ := scanState.AccountName(bs.Scope, bs.Account)
		accountID, _ := scanState.AccountID(bs.Scope, bs.Account)

		params = append(params, db.ScanHorizon{
			Scope:       db.KeyScope(bs.Scope),
			AccountID:   accountID,
			Account:     bs.Account,
			AccountName: name,
			Branch:      bs.Branch,
			Index:       index,
		})
	}

	return params
}

// appendScanTxParams appends store transaction params for every relevant output
// in the scan result, attaching the resolved store block. It validates that
// each credit index is within the transaction's output range. Candidates let
// the Store apply receiving policy after persisting the scan horizons.
func (s *syncer) appendScanTxParams(params *db.ScanBatchParams,
	result scanResult, block *db.Block) error {

	for _, match := range result.RelevantOutputs {
		candidates := make(
			map[uint32][]address.Address, len(match.Entries),
		)
		for _, entry := range match.Entries {
			index := entry.Credit.Index
			if uint64(index) >= uint64(len(match.Rec.MsgTx.TxOut)) {
				return fmt.Errorf("credit output %d: %w", index,
					db.ErrInvalidParam)
			}

			candidates[index] = append(candidates[index], entry.Address)
		}

		params.Transactions = append(
			params.Transactions, db.CreateTxParams{
				WalletID:         s.walletID,
				Tx:               &match.Rec.MsgTx,
				Received:         result.meta.Time,
				Block:            block,
				Status:           db.TxStatusPublished,
				CreditCandidates: candidates,
			},
		)
	}

	return nil
}

// storeScanBatchParams converts recovery scan results into store batch params.
// scanState is the recovery state that produced the results; it carries the
// account identity snapshot used to stamp every emitted horizon with the stable
// AccountID SQL backends require for horizon extension.
func (s *syncer) storeScanBatchParams(scanState *RecoveryState,
	results []scanResult, includeSyncedBlocks bool) (db.ScanBatchParams,
	error) {

	params := db.ScanBatchParams{WalletID: s.walletID}
	horizons := make(map[waddrmgr.BranchScope]uint32)

	for _, result := range results {
		blockNeeded := includeSyncedBlocks
		if result.BlockProcessResult != nil &&
			len(result.RelevantOutputs) > 0 {

			blockNeeded = true
		}

		var block *db.Block
		if blockNeeded {
			var err error

			block, err = storeBlockFromScanResult(result)
			if err != nil {
				return db.ScanBatchParams{}, err
			}
		}

		if includeSyncedBlocks {
			params.SyncedBlocks = append(params.SyncedBlocks, *block)
		}

		if result.BlockProcessResult == nil {
			continue
		}

		mergeScanHorizons(horizons, result.FoundHorizons)

		err := s.appendScanTxParams(&params, result, block)
		if err != nil {
			return db.ScanBatchParams{}, err
		}
	}

	params.Horizons = scanHorizonParams(scanState, horizons)

	return params, nil
}

// storeBlockFromBlockMeta converts chain notification block metadata into the
// store block shape.
func storeBlockFromBlockMeta(block wtxmgr.BlockMeta) (*db.Block, error) {
	height, err := db.Int64ToUint32(int64(block.Height))
	if err != nil {
		return nil, fmt.Errorf("block height %d: %w", block.Height, err)
	}

	return &db.Block{
		Hash:      block.Hash,
		Height:    height,
		Timestamp: block.Time,
	}, nil
}

// storeBlockFromScanResult converts scan result block metadata into the store
// block shape.
func storeBlockFromScanResult(result scanResult) (*db.Block, error) {
	if result.meta == nil {
		return nil, fmt.Errorf("scan result is missing block metadata: %w",
			db.ErrInvalidParam)
	}

	return storeBlockFromBlockMeta(*result.meta)
}

// scanBatchHeadersOnly performs a lightweight scan by only fetching block
// headers. This is used when the wallet has no addresses or outpoints to
// watch, allowing it to fast-forward its sync state.
func (s *syncer) scanBatchHeadersOnly(_ context.Context,
	startHeight, endHeight int32) ([]scanResult, error) {

	// Batch 1: Fetch Block Hashes.
	hashes, err := s.cfg.Chain.GetBlockHashes(
		int64(startHeight), int64(endHeight),
	)
	if err != nil {
		return nil, fmt.Errorf("batch get block hashes: %w", err)
	}

	// Batch 2: Fetch Block Headers (for timestamps).
	headers, err := s.cfg.Chain.GetBlockHeaders(hashes)
	if err != nil {
		return nil, fmt.Errorf("batch get block headers: %w", err)
	}

	results := make([]scanResult, 0, len(hashes))
	for i := range hashes {
		hash := hashes[i]
		header := headers[i]

		// i is bounded by batch size (2000), so addition to startHeight
		// won't overflow int32.
		height := startHeight + int32(i)

		meta := &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Hash: hash, Height: height},
			Time:  header.Timestamp,
		}

		results = append(results, scanResult{
			meta:       meta,
			parentHash: header.PrevBlock,
			// We provide an empty BlockProcessResult to avoid nil
			// pointer dereferences when accessing embedded fields
			// (like RelevantTxs) in commitSyncBatch. This
			// effectively acts as a "no-op" result.
			BlockProcessResult: &BlockProcessResult{},
		})
	}

	return results, nil
}

// loadFullScanState initializes a fresh recovery state for a new batch scan.
// It loads active data, syncs horizons from DB, and prepares the initial
// lookahead window.
func (s *syncer) loadFullScanState(
	ctx context.Context) (*RecoveryState, error) {

	accounts, initialAddrs, initialUnspent, err := s.loadWalletScanData(ctx)
	if err != nil {
		return nil, err
	}

	return s.newStoreScanState(accounts, initialAddrs, initialUnspent)
}

// newStoreScanState builds a fresh recovery state for accounts loaded through
// the Store. Each account's store identities are registered before the batch
// snapshot is initialized, because initialization derives the lookahead window
// and therefore needs the store-native deriver already in place.
func (s *syncer) newStoreScanState(accounts []storeScanAccount,
	initialAddrs []address.Address,
	initialUnspent []wtxmgr.Credit) (*RecoveryState, error) {

	// Use a fresh recovery state for this batch to ensure no stale state
	// leaks between batches.
	scanState := NewRecoveryState(
		s.cfg.RecoveryWindow, s.cfg.ChainParams, s.addrStore,
	)

	// Existing child counts also cause horizon initialization to derive.
	// Omit horizons entirely at zero; persisted targets need no deriver.
	if s.cfg.RecoveryWindow == 0 {
		accounts = nil
	}

	props := make([]*waddrmgr.AccountProperties, 0, len(accounts))
	for _, account := range accounts {
		err := scanState.setStoreAccount(
			account.props, account.accountID,
			account.derivedAccountNumber,
		)
		if err != nil {
			return nil, err
		}

		props = append(props, account.props)
	}

	// Initialize Batch State (History + Lookahead).
	err := scanState.Initialize(props, initialAddrs, initialUnspent)
	if err != nil {
		return nil, fmt.Errorf("init scan state: %w", err)
	}

	return scanState, nil
}

// scanBatchWithFullBlocks implements the fallback scanning by downloading and
// checking every block in the batch.
func (s *syncer) scanBatchWithFullBlocks(_ context.Context,
	scanState *RecoveryState, startHeight int32,
	hashes []chainhash.Hash) ([]scanResult, error) {

	results := make([]scanResult, 0, len(hashes))

	// 1. Fetch ALL Blocks.
	blocks, err := s.cfg.Chain.GetBlocks(hashes)
	if err != nil {
		return nil, fmt.Errorf("batch get blocks (fallback): %w", err)
	}

	// Iterate and Process Blocks. Now that all blocks in the batch have
	// been fetched, process each block individually. This involves
	// creating the necessary block metadata and then feeding the full
	// block into the recovery state for filtering and horizon expansion.
	for i := range hashes {
		hash := hashes[i]
		block := blocks[i]

		// i is bounded by batch size (2000), so addition to startHeight
		// won't overflow int32.
		height := startHeight + int32(i)

		meta := &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Hash: hash, Height: height},
			Time:  block.Header.Timestamp,
		}

		// Process the block using the recovery state. This involves:
		// 1. Filtering the block for relevant transactions.
		// 2. Expanding the address lookahead horizons if new addresses
		//    are found.
		// 3. Re-filtering if horizons were expanded to ensure we catch
		//    all transactions relevant to the newly derived addresses.
		res, err := scanState.ProcessBlock(block)
		if err != nil {
			return nil, fmt.Errorf("process block %d (%s): %w",
				height, hash, err)
		}

		results = append(results, scanResult{
			meta:               meta,
			parentHash:         block.Header.PrevBlock,
			BlockProcessResult: res,
		})
	}

	return results, nil
}

// initResultsForCFilterScan fetches block headers for the given hashes and
// initializes a slice of scanResult with basic metadata (hash, height, time).
// This is a preparatory step specifically for CFilter-based scans.
func (s *syncer) initResultsForCFilterScan(_ context.Context,
	startHeight int32, hashes []chainhash.Hash) ([]scanResult, error) {

	headers, err := s.cfg.Chain.GetBlockHeaders(hashes)
	if err != nil {
		return nil, fmt.Errorf("batch get block headers: %w", err)
	}

	results := make([]scanResult, len(hashes))
	for i := range hashes {
		results[i] = scanResult{
			parentHash: headers[i].PrevBlock,
			meta: &wtxmgr.BlockMeta{
				Block: wtxmgr.Block{
					Hash: hashes[i],

					// i is bounded by batch size (2000),
					// so addition to startHeight won't
					// overflow int32.
					Height: startHeight + int32(i),
				},
				Time: headers[i].Timestamp,
			},
			// Initialize with empty result to avoid nil
			// dereference if block is not processed.
			BlockProcessResult: &BlockProcessResult{},
		}
	}

	return results, nil
}

// filterBatch iterates over the scan results and matches them against the
// provided filters using the watchlist. It returns a list of block hashes that
// matched the filter.
func (s *syncer) filterBatch(ctx context.Context, results []scanResult,
	filters []*gcs.Filter,
	blockMap map[chainhash.Hash]*wire.MsgBlock,
	watchList [][]byte) ([]chainhash.Hash, error) {

	var matchedHashes []chainhash.Hash
	for i := range results {
		// Check context cancellation.
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context done: %w", ctx.Err())
		default:
		}

		// Skip if we already fetched this block.
		if _, ok := blockMap[results[i].meta.Hash]; ok {
			continue
		}

		filter := filters[i]

		// If the filter is nil or has no elements (N=0), it indicates
		// a potential issue with the chain backend (e.g., filter not
		// available, corrupted, or for an invalid block). While N=0 is
		// theoretically impossible for valid Bitcoin blocks with
		// regular filters (due to coinbase transactions), we
		// conservatively treat both cases as a match to ensure no
		// relevant transactions are missed. This prioritizes safety
		// over strict filter efficiency, forcing the download of the
		// full block for later processing.
		if filter == nil || filter.N() == 0 {
			var n uint32
			if filter != nil {
				n = filter.N()
			}

			log.Errorf("Filter missing or empty for block %v "+
				"(nil=%v, N=%d), forcing download",
				results[i].meta.Hash, filter == nil, n)

			matchedHashes = append(
				matchedHashes, results[i].meta.Hash,
			)

			continue
		}

		key := builder.DeriveKey(&results[i].meta.Hash)

		matched, err := filter.MatchAny(key, watchList)
		if err != nil {
			return nil, fmt.Errorf("filter match failed: %w", err)
		}

		if matched {
			matchedHashes = append(
				matchedHashes, results[i].meta.Hash,
			)
		}
	}

	return matchedHashes, nil
}

// matchAndFetchBatch performs the core logic of matching CFilters against the
// wallet's watchlist and fetching the corresponding blocks. It iterates over
// the provided `results`, checking filters for each. Blocks that match (and
// haven't been fetched yet) are downloaded and added to the `blockMap`.
//
// NOTE: This method mutates the provided `blockMap` parameter by adding new
// blocks to it.
func (s *syncer) matchAndFetchBatch(ctx context.Context, state *RecoveryState,
	results []scanResult,
	filters []*gcs.Filter,
	blockMap map[chainhash.Hash]*wire.MsgBlock) error {

	// Generate the watchlist for CFilter matching.
	watchList, err := state.BuildCFilterData()
	if err != nil {
		return fmt.Errorf("build cfilter data: %w", err)
	}

	matchedHashes, err := s.filterBatch(
		ctx, results, filters, blockMap, watchList,
	)
	if err != nil {
		return err
	}

	// Fetch Matched Blocks.
	if len(matchedHashes) > 0 {
		blocks, err := s.cfg.Chain.GetBlocks(matchedHashes)
		if err != nil {
			return fmt.Errorf("batch get blocks: %w", err)
		}

		for i, block := range blocks {
			blockMap[matchedHashes[i]] = block
		}
	}

	return nil
}

// scanBatchWithCFilters implements the fast-path scanning using Compact
// Filters. It fetches filters, matches them locally, fetches only matched
// blocks, and handles horizon expansion with an in-place resume logic.
func (s *syncer) scanBatchWithCFilters(ctx context.Context,
	scanState *RecoveryState, startHeight int32,
	hashes []chainhash.Hash) ([]scanResult, error) {

	// Fetch CFilters for the batch.
	filters, err := s.cfg.Chain.GetCFilters(
		hashes, wire.GCSFilterRegular,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCFiltersUnavailable, err)
	}

	// Fetch headers and initialize results with metadata.
	results, err := s.initResultsForCFilterScan(ctx, startHeight, hashes)
	if err != nil {
		return nil, err
	}

	// blockMap serves as a cache for full block data that has been
	// fetched. It is populated by `matchAndFetchBatch` during both the
	// initial matching phase and any subsequent re-matching due to horizon
	// expansion. This map ensures that once a block is identified as
	// relevant and downloaded, it's available for processing without
	// redundant network requests, maintaining I/O efficiency across the
	// processing loops.
	blockMap := make(map[chainhash.Hash]*wire.MsgBlock, len(hashes))

	// Initial Match: Optimistically match the entire batch of filters
	// against the current watchlist. This allows us to fetch all likely
	// relevant blocks in a single batch operation, maximizing I/O
	// parallelism.
	err = s.matchAndFetchBatch(ctx, scanState, results, filters, blockMap)
	if err != nil {
		return nil, err
	}

	// Process Blocks: Iterate through the results and process any blocks
	// that were matched and fetched.
	for i := range results {
		res := &results[i]
		block := blockMap[res.meta.Hash]

		// If block was not matched/fetched, skip processing.
		if block == nil {
			continue
		}

		processRes, err := scanState.ProcessBlock(block)
		if err != nil {
			return nil, fmt.Errorf("process block %d (%s): %w",
				res.meta.Height, res.meta.Hash, err)
		}

		// Attach the real result to the pre-allocated scanResult.
		res.BlockProcessResult = processRes

		// Move to the next if the horizon is not expanded.
		if !processRes.Expanded {
			continue
		}

		log.Debugf("Horizon expanded at height %d, updating filters",
			res.meta.Height)

		// If the horizon expanded, our watchlist has changed. We must
		// re-evaluate the remaining filters in the batch (i+1 onwards)
		// against the new addresses or outpoints to ensure we don't
		// miss any relevant transactions that were previously skipped.
		// This "in-place resume" logic ensures correctness despite the
		// batch pre-fetching optimization.
		err = s.matchAndFetchBatch(
			ctx, scanState, results[i+1:], filters[i+1:], blockMap,
		)
		if err != nil {
			return nil, err
		}
	}

	return results, nil
}

// fetchAndFilterBlocks retrieves and processes a batch of blocks from the
// chain backend. It handles CFilter matching, block fetching, local filtering,
// and dynamic address discovery (expanding horizons in memory/read-only DB).
func (s *syncer) fetchAndFilterBlocks(ctx context.Context,
	scanState *RecoveryState, startHeight, chainTip int32) (
	[]scanResult, error) {

	// Cap the batch size to recoveryBatchSize to manage memory usage.
	endHeight := min(startHeight+int32(recoveryBatchSize)-1, chainTip)

	// Optimization: If we have nothing to watch, performing a
	// "header-only" scan to advance the wallet's sync state without
	// downloading full blocks or filters.
	//
	// NOTE: A targeted rescan can also be empty when neither eligible
	// horizons nor persisted addresses or outputs remain.
	if scanState.Empty() {
		log.Debugf("Performing header-only scan for %d blocks",
			endHeight-startHeight+1)

		return s.scanBatchHeadersOnly(ctx, startHeight, endHeight)
	}

	log.Debugf("Scanning %d blocks (height %d to %d) with %s",
		endHeight-startHeight+1, startHeight, endHeight, scanState)

	// Batch 1: Fetch all Block Hashes.
	// TODO: Pass ctx when chainClient supports it.
	hashes, err := s.cfg.Chain.GetBlockHashes(
		int64(startHeight), int64(endHeight),
	)
	if err != nil {
		return nil, fmt.Errorf("batch get block hashes: %w", err)
	}

	return s.dispatchScanStrategy(ctx, scanState, startHeight, hashes)
}

// defaultMaxCFilterItems is the heuristic threshold for the number of items
// (addresses + outpoints) in the watchlist at which the cost of client-side
// GCS filter matching exceeds the cost of downloading and parsing full blocks.
//
// Calculation:
//   - CFilter Match: ~50ns per item (SIP hash). 100k items = 5ms per block.
//   - Full Block: ~10ms transfer (local) + ~10ms parse. Total ~20ms per block.
//
// While 100k items suggests ~5ms matching time, this is for a single filter.
// In a batch of 200 blocks, total matching time is 1 second. However, if the
// match rate is non-zero, we incur additional block download costs.
//
// At >100k items, the CPU load of matching becomes significant enough that
// bypassing filters and streaming full blocks (especially from a local node)
// is often more performant and uses less CPU time overall. This threshold is
// conservative to favor CFilters for typical wallet sizes (<10k items).
const defaultMaxCFilterItems uint32 = 100000

// dispatchScanStrategy chooses and executes the appropriate scanning strategy
// based on the wallet's configuration and heuristics.
func (s *syncer) dispatchScanStrategy(ctx context.Context,
	scanState *RecoveryState, startHeight int32,
	hashes []chainhash.Hash) ([]scanResult, error) {

	switch s.cfg.SyncMethod {
	case SyncMethodFullBlocks:
		return s.scanBatchWithFullBlocks(
			ctx, scanState, startHeight, hashes,
		)

	// Attempt to use CFilters. If this fails (e.g. not supported by
	// backend), we return the error directly as the user explicitly
	// requested this method.
	case SyncMethodCFilters:
		return s.scanBatchWithCFilters(
			ctx, scanState, startHeight, hashes,
		)

	case SyncMethodAuto:
		// Check address/UTXO count heuristic. If we have > 100k items
		// to watch, full block scanning is likely faster due to
		// client-side filter matching CPU bottleneck.
		threshold := s.cfg.MaxCFilterItems
		if threshold == 0 {
			threshold = defaultMaxCFilterItems
		}

		watchListSize := scanState.WatchListSize()
		if int64(watchListSize) > int64(threshold) {
			log.Infof("Auto sync: Watchlist size %d > %d, "+
				"switching to full blocks for performance",
				watchListSize, threshold)

			return s.scanBatchWithFullBlocks(
				ctx, scanState, startHeight, hashes,
			)
		}

		// Try CFilters (Fast Path).
		results, err := s.scanBatchWithCFilters(
			ctx, scanState, startHeight, hashes,
		)
		if err == nil {
			return results, nil
		}

		// If CFilters are unavailable (e.g. backend doesn't support
		// them), fall back to full block scanning.
		if errors.Is(err, ErrCFiltersUnavailable) {
			log.Warnf("Batch GetCFilters unavailable: %v. "+
				"Falling back to full block download.", err)

			return s.scanBatchWithFullBlocks(
				ctx, scanState, startHeight, hashes,
			)
		}

		// If scanBatchWithCFilters failed for another reason, return
		// the error.
		return nil, err

	default:
		return nil, fmt.Errorf("%w: %v", ErrUnknownSyncMethod,
			s.cfg.SyncMethod)
	}
}

// advanceChainSync checks if the wallet is behind the chain tip and processes
// a batch of blocks if necessary. It returns (syncFinished, error) where
// syncFinished is true if the wallet is caught up to the best known tip, and
// false if a sync operation was performed (or attempted) indicating that the
// caller should continue polling.
func (s *syncer) advanceChainSync(ctx context.Context) (bool, error) {
	// Check the chain tip.
	bestHash, bestHeight, err := s.cfg.Chain.GetBestBlock()
	if err != nil {
		// An error getting best block height means we couldn't
		// determine sync status. We are NOT finished, and an error
		// occurred. Caller should retry.
		return false, fmt.Errorf("unable to get best block height: %w",
			err)
	}

	// Determine our current sync state. This reads the synced tip from the
	// Store rather than the legacy addrStore, so the next batch's start
	// height no longer depends on ApplyScanBatch having mirrored the tip
	// back into the legacy addrStore.
	syncedTo, err := s.syncedTo(ctx)
	if err != nil {
		return false, err
	}

	// If the wallet is caught up to the best known tip, log this and
	// return.
	if syncedTo.Height >= bestHeight {
		return s.ensureSyncedAtTip(ctx, syncedTo, bestHash, bestHeight)
	}

	// Calculate the gap.
	gap := bestHeight - syncedTo.Height

	// If the gap is large (> 6 blocks), we treat it as a major event
	// requiring Syncing state protection. Smaller gaps keep requests available
	// until putSyncBatch clears readiness for watch registration at commit.
	isLargeGap := gap > syncStateSwitchThreshold

	if isLargeGap {
		s.state.Store(uint32(syncStateSyncing))
	}

	// Wallet is behind, log the sync range and attempt to scan a batch.
	log.Infof("Wallet is in syncing mode: from height %d to %d (gap=%d)",
		syncedTo.Height+1, bestHeight, gap)

	err = s.scanBatch(ctx, syncedTo, bestHeight)
	if err != nil {
		// Scan failed. Sync operation was attempted but not finished
		// due to error.
		return false, fmt.Errorf("failed to process batch: %w", err)
	}

	// Scan successful, but wallet might still be behind. Synchronization
	// is NOT finished. Caller should continue looping to process the next
	// batch.
	return false, nil
}

// ensureSyncedAtTip verifies exact tip equality and transitions the syncer to
// Synced when caught up to the best known block.
func (s *syncer) ensureSyncedAtTip(_ context.Context,
	syncedTo waddrmgr.BlockStamp, bestHash *chainhash.Hash,
	bestHeight int32) (bool, error) {

	if syncedTo.Height != bestHeight ||
		bestHash == nil || syncedTo.Hash != *bestHash {

		return false, fmt.Errorf("wallet tip %d (%v) diverges from "+
			"chain tip %d (%v): %w", syncedTo.Height,
			syncedTo.Hash, bestHeight, bestHash, ErrStateChanged)
	}

	s.state.Store(uint32(syncStateSynced))
	log.Infof("Wallet is synced to chain tip: height=%d", syncedTo.Height)

	return true, nil
}

// scanBatch fetches and processes a batch of blocks from the chain backend. It
// handles fetching, CFilter matching, and DB updates.
func (s *syncer) scanBatch(ctx context.Context, syncedTo waddrmgr.BlockStamp,
	bestHeight int32) error {

	// Clear the stale marker before loading the wallet's persisted scan
	// state. Any concurrent watchAddrs call while no subscription is active
	// sets this flag after persisting its addresses to the Store.
	s.scanAddrsStale.Store(false)

	// Prepare the full recovery state for syncing.
	scanState, err := s.loadFullScanState(ctx)
	if err != nil {
		return err
	}

	// Fetch and Filter Blocks. The `fetchAndFilterBlocks` method is
	// responsible for fetching a batch of blocks from the chain backend,
	// filtering them for relevant transactions, and expanding address
	// horizons. This phase primarily involves network I/O and in-memory
	// processing. While it internally performs brief read-only database
	// accesses (e.g., in `loadFullScanState`), it avoids holding
	// long-lived write locks during potentially extensive network
	// operations.
	results, err := s.fetchAndFilterBlocks(
		ctx, scanState, syncedTo.Height+1, bestHeight,
	)
	if err != nil {
		return err
	}
	// Batch might be empty if:
	// 1. We were interrupted by a quit signal or rescan job (handled
	//    above).
	// 2. We encountered a backend error fetching the first block
	//    hash or filter (loop broke early).
	// In either case, we return an error to let the chain loop sleep and
	// retry.
	if len(results) == 0 {
		return fmt.Errorf("%w: scan batch empty", ErrScanBatchEmpty)
	}

	// A reorg can overtake a disconnect or occur between hash lookups. Commit
	// only a batch that extends the wallet tip block by block; otherwise let
	// rollback find any fork and retry with freshly fetched hashes.
	parent := syncedTo.Hash
	for i := range results {
		if results[i].parentHash != parent {
			return s.checkRollback(ctx)
		}

		parent = results[i].meta.Hash
	}

	// If new addresses were persisted and registered while no subscription
	// was active during this batch scan, retry this batch with a fresh
	// scan snapshot instead of advancing SyncedTo past those addresses.
	if s.scanAddrsStale.Load() {
		return nil
	}

	// Process Batch (Update). We do this in a single DB transaction.
	return s.putSyncBatch(ctx, scanState, results)
}

// handleChainUpdate logs legacy rescan progress. The Wallet worker applies
// disconnects and matching payments before they reach this handler.
func (s *syncer) handleChainUpdate(n any) {
	switch msg := n.(type) {
	case *chain.RescanProgress:
		log.Debugf("Rescanned through block %v (height %d)",
			msg.Hash, msg.Height)

	// Consume and log the legacy RescanFinished notification. We no longer
	// perform state updates here as the new controller- driven sync loop
	// manages wallet synchronization.
	case *chain.RescanFinished:
		log.Debugf("Received legacy RescanFinished notification for "+
			"block %v (height %d). No wallet state updates "+
			"performed.", msg.Hash, msg.Height)
	}
}

// processChainEventBeforeSync handles initialization, retry and scan-time
// observations without checkpointing past payments omitted by live watches.
func (s *syncer) processChainEventBeforeSync(ctx context.Context,
	event chainEvent) error {

	// Known matches are safe to record, but historical scanning must still
	// visit this height after recovery and watch registration finish. Leave
	// malformed metadata to the ordinary handler's existing validation.
	if block, ok := event.notification.(chain.FilteredBlockConnected); ok &&
		block.Block != nil {

		return s.putTxNotifications(ctx, event.matches, block.Block)
	}

	return s.processChainEvent(ctx, event)
}

// processChainEvent orders a Wallet rewind with the same worker's payment
// and historical writes. Manager supplies the matches for this stream.
func (s *syncer) processChainEvent(ctx context.Context,
	event chainEvent) error {

	switch n := event.notification.(type) {
	case chain.BlockDisconnected:
		return s.disconnectBlock(ctx, wtxmgr.BlockMeta(n))

	case chain.RelevantTx:
		return s.putTxNotifications(ctx, event.matches, n.Block)

	case chain.FilteredBlockConnected:
		return s.putBlockNotifications(ctx, event.matches, n.Block)

	default:
		s.handleChainUpdate(event.notification)

		return nil
	}
}

// processBlockEventBeforeSync handles scan-time block observations without
// checkpointing past payments omitted by live watches or persisting blocks
// above the synced tip or on a detached branch.
func (s *syncer) processBlockEventBeforeSync(ctx context.Context,
	event chain.Event) error {

	if event.Type != chain.EventBlockConnected || event.Block == nil {
		return s.processBlockEvent(ctx, event)
	}

	if len(event.RelevantTxs) == 0 {
		return nil
	}

	current, err := s.syncedTo(ctx)
	if err != nil {
		return err
	}

	// Leave heights above SyncedTo for advanceChainSync so a disconnected
	// uncheckpointed block row can never linger above the tip if the
	// subscription is later retired.
	if event.Block.Height > current.Height {
		return nil
	}

	block, err := storeBlockFromBlockMeta(*event.Block)
	if err != nil {
		return err
	}

	matches := prepareTxMatches(event.RelevantTxs, s.cfg.ChainParams)

	return s.putSupplementalBlockMatches(ctx, matches, block, current)
}

// processBlockEvent orders a Wallet rewind with the same worker's payment
// and historical writes for one strictly-ordered block lifecycle event.
func (s *syncer) processBlockEvent(ctx context.Context,
	event chain.Event) error {

	switch event.Type {
	case chain.EventBlockDisconnected:
		return s.disconnectBlock(ctx, *event.Block)

	case chain.EventBlockConnected:
		matches := prepareTxMatches(
			event.RelevantTxs, s.cfg.ChainParams,
		)

		return s.putBlockNotifications(ctx, matches, event.Block)

	case chain.EventUnknown:
		return nil

	default:
		return nil
	}
}

// processMempoolTx records one best-effort unconfirmed transaction from the
// active subscription. Because MempoolTxns is delivered independently of
// BlockEvents, a late mempool notification for an already-confirmed or
// superseded transaction is ignored rather than restarting the sync loop.
func (s *syncer) processMempoolTx(ctx context.Context,
	rec *wtxmgr.TxRecord) error {

	matches := prepareTxMatches([]*wtxmgr.TxRecord{rec}, s.cfg.ChainParams)

	err := s.putTxNotifications(ctx, matches, nil)
	if isStaleMempoolTxErr(err) {
		log.Debugf("Ignoring stale mempool tx %v: %v", rec.Hash, err)

		return nil
	}

	return err
}

// isStaleMempoolTxErr reports whether a mempool write failed because confirmed
// chain state has already recorded, conflicted with, or invalidated the tx.
func isStaleMempoolTxErr(err error) bool {
	return errors.Is(err, db.ErrTxAlreadyExists) ||
		errors.Is(err, db.ErrTxInputConflict) ||
		errors.Is(err, db.ErrTxInputInvalidParent)
}

// handleSubClosed reconciles a closed live subscription. BlockEvents buffer
// overflow reconciles any reorg and triggers an immediate self-healing catch-up
// and re-subscription; unexpected backend closure returns an error so the sync
// loop backs off.
func (s *syncer) handleSubClosed(ctx context.Context,
	sub chain.EventSubscription) error {

	s.closeSubscription()
	s.state.Store(uint32(syncStateSyncing))

	select {
	case <-sub.Done():
	case <-ctx.Done():
		return ctx.Err()
	}

	err := ctx.Err()
	if err != nil {
		return err
	}

	subErr := sub.Err()
	if errors.Is(subErr, chain.ErrEventSubscriptionBufferFull) {
		log.Warnf("Chain block event buffer overflowed; resyncing "+
			"and resubscribing: %v", subErr)

		// A reorg to an equal or shorter height during overflow cannot
		// be discovered by forward catch-up alone, so reconcile any
		// fork before returning to advanceChainSync.
		if s.cfg.Chain.IsCurrent() {
			return s.checkRollback(ctx)
		}

		return nil
	}

	if subErr != nil {
		return fmt.Errorf("chain event subscription closed: %w", subErr)
	}

	return errors.New("chain event subscription closed")
}

// handleScanReq processes a user-initiated rescan request.
func (s *syncer) handleScanReq(ctx context.Context,
	req *scanReq) error {

	// Existing sync or scan work must finish before another scan can run.
	state := s.syncState()
	if state == syncStateSyncing || state == syncStateRescanning {
		return fmt.Errorf("%w: wallet is currently %s",
			ErrStateForbidden, state)
	}

	if req.typ == scanTypeTargeted {
		return s.scanWithTargets(ctx, req)
	}

	return s.scanWithRewind(ctx, req)
}

// checkForRollbackBeforeCommit handles a queued disconnect before a
// scan commits. It returns ordinary queued events unprocessed; callers apply
// them after the batch attempt, preserving prepared matches and result order.
func (s *syncer) checkForRollbackBeforeCommit(ctx context.Context) (
	chainEvent, error) {

	select {
	case event := <-s.chainEventChan:
		if _, ok := event.notification.(chain.BlockDisconnected); !ok {
			return event, nil
		}

		err := s.processChainEvent(ctx, event)
		if err != nil {
			return chainEvent{}, err
		}

		// Rollback has completed, invalidating this batch's fetched history.
		// ErrStateChanged makes targeted scans reload and refetch their range;
		// normal catch-up restarts through its existing retry/backoff loop.
		return chainEvent{}, ErrStateChanged

	default:
		return chainEvent{}, nil
	}
}

// waitForEvent blocks until a notification, rescan job, or context
// cancellation occurs, processing the event accordingly.
func (s *syncer) waitForEvent(ctx context.Context) error {
	select {
	case event := <-s.chainEventChan:
		return s.processChainEvent(ctx, event)

	// Handle synchronous rescan or resync requests submitted via the
	// controller.
	case job := <-s.scanReqChan:
		return s.handleScanEvent(ctx, job)

	// Exit gracefully if the context is canceled or the wallet is shutting
	// down.
	case <-ctx.Done():
		return ctx.Err()
	}
}

// handleScanEvent preserves asynchronous scan error policy: a failed watch
// refresh restarts initialization, while ordinary targeted failures remain
// local because submission already returned before worker execution.
func (s *syncer) handleScanEvent(ctx context.Context, job *scanReq) error {
	err := s.handleScanReq(ctx, job)
	if err == nil {
		return nil
	}

	if errors.Is(err, context.Canceled) ||
		errors.Is(err, ErrWalletShuttingDown) {

		return err
	}

	// A committed scan can leave live watches unregistered. Let that
	// failure restart initialization instead of bypassing its retry.
	if job.typ == scanTypeTargeted &&
		s.syncState() != syncStateSyncing {

		// Rescan returns once the request is queued, so this
		// execution failure cannot reach its caller. For now,
		// it is visible only in the logs; swallow it here to
		// keep live notification processing running.
		log.Errorf("Targeted rescan failed: %v", err)

		return nil
	}

	return err
}

// scanWithRewind rewinds the wallet's sync status to the requested start
// block.
func (s *syncer) scanWithRewind(ctx context.Context, req *scanReq) error {
	// Read the synced tip through syncedTo so a Store-backed backend uses
	// the Store's tip rather than the legacy addrStore tip. A backend that
	// does not mirror ApplyScanBatch/RewindWallet into the legacy manager
	// would otherwise compare against a stale legacy height and could
	// wrongly conclude there is nothing to rewind for a full rescan.
	current, err := s.syncedTo(ctx)
	if err != nil {
		return err
	}

	if req.startBlock.Height >= current.Height {
		// Requested start is ahead of or equal to current sync.
		// Nothing to do (we are already synced past it).
		return nil
	}

	log.Infof("Rewinding sync status from %d to %d for rescan",
		current.Height, req.startBlock.Height)

	err = s.rewindWallet(ctx, req.startBlock)
	if err != nil {
		log.Errorf("Failed to rewind sync status: %v", err)

		return err
	}

	return nil
}

// loadTargetedScanTip rebuilds the requested horizons and reads their scan
// bound on initial entry and after rollback, using the same readiness policy.
func (s *syncer) loadTargetedScanTip(ctx context.Context,
	targets []waddrmgr.AccountScope) (*RecoveryState, int32, error) {

	state, err := s.loadTargetedScanState(ctx, targets)
	if err != nil {
		return nil, 0, err
	}

	s.state.Store(uint32(syncStateRescanning))

	_, height, err := s.cfg.Chain.GetBestBlock()
	if err != nil {
		return nil, 0, fmt.Errorf("get best block: %w", err)
	}

	return state, height, nil
}

// scanWithTargets performs a targeted rescan for specific accounts without
// rewinding the global sync state.
func (s *syncer) scanWithTargets(ctx context.Context, req *scanReq) error {
	err, eventErr := s.runTargetedScan(ctx, req)
	if eventErr != nil {
		s.state.Store(uint32(syncStateSyncing))
		err = errors.Join(err, eventErr)
	}

	// Failed registration or retained live-event errors keep readiness
	// revoked until initialization retries.
	s.state.CompareAndSwap(
		uint32(syncStateRescanning), uint32(syncStateSynced),
	)

	return err
}

// runTargetedScan executes the targeted batch scan loop, separating scan range
// errors from retained live-event errors so a failed live observation does not
// abort the remaining account scan.
func (s *syncer) runTargetedScan(ctx context.Context,
	req *scanReq) (error, error) {

	var eventErr error

	scanState, bestHeight, err := s.loadTargetedScanTip(ctx, req.targets)
	if err != nil {
		return err, nil
	}

	startHeight := req.startBlock.Height

	log.Infof("Starting targeted rescan from height %d to %d for %d "+
		"accounts", startHeight, bestHeight, len(req.targets))

	// Loop until caught up. We use an inclusive condition (<=) because
	// startHeight represents the first block of the missing range and
	// bestHeight is the last block (the chain tip). If we used a strict
	// inequality (<), the tip would be skipped when the wallet is only one
	// block behind.
	for startHeight <= bestHeight {
		// Cap end height.
		endHeight := min(
			startHeight+int32(recoveryBatchSize)-1, bestHeight,
		)

		// Use fetchAndFilterBlocks directly.
		results, err := s.fetchAndFilterBlocks(
			ctx, scanState, startHeight, endHeight,
		)
		if err != nil {
			return err, eventErr
		}

		if len(results) == 0 {
			return fmt.Errorf("%w: fetchAndFilterBlocks returned "+
				"0 results", ErrScanBatchEmpty), eventErr
		}

		batchErr, pendingErr := s.applyTargetedBatch(
			ctx, scanState, results,
		)
		eventErr = errors.Join(eventErr, pendingErr)

		if errors.Is(batchErr, ErrStateChanged) {
			// A rollback discards this attempt, not the accepted request.
			// Reload horizons and refetch its original range on the new tip.
			scanState, bestHeight, err = s.loadTargetedScanTip(
				ctx, req.targets,
			)
			if err != nil {
				return err, eventErr
			}

			startHeight = req.startBlock.Height

			continue
		}

		if batchErr != nil {
			return batchErr, eventErr
		}

		s.state.Store(uint32(syncStateRescanning))

		// Advance startHeight; batch size is bounded.
		startHeight += int32(len(results))
	}

	log.Infof("Targeted rescan complete")

	return nil, eventErr
}

// applyTargetedBatch checks for a queued disconnect before committing one
// targeted batch, then replays any retained non-disconnect live event without
// advancing SyncedTo.
func (s *syncer) applyTargetedBatch(ctx context.Context,
	scanState *RecoveryState, results []scanResult) (error, error) {

	// Keep the range's own result separate from retained live work: a
	// failed observation must not discard the remaining account scan.
	pending, err := s.checkForRollbackBeforeCommit(ctx)
	if err == nil {
		err = s.putTargetedBatch(ctx, scanState, results)
	}

	// The selected accounts cannot prove full-wallet historical coverage.
	// Replay known matches without a checkpoint; preserve any error until
	// this accepted range finishes. An empty event remains a no-op.
	pendingErr := s.processChainEventBeforeSync(ctx, pending)

	return err, pendingErr
}

// storeScanHorizons loads account horizon data through the store. Targets are
// the identity-aware scanTargets produced by resolveScanTargets, so each one
// already carries the durable AccountName that lets the Store resolve an
// imported account without colliding with the default derived account at the
// masked number 0.
func (s *syncer) storeScanHorizons(ctx context.Context,
	targets []scanTarget) ([]storeScanAccount, error) {

	if len(targets) == 0 {
		return s.storeFullScanHorizons(ctx)
	}

	return s.storeTargetedScanHorizons(ctx, targets)
}

// storeFullScanHorizons loads eligible recovery accounts from the Store,
// skipping the keyless raw-import bucket. The scan selects no account by
// number here, so each one is keyed on its durable store row ID and an imported
// account cannot overwrite a derived account owning the same BIP44 number in
// the same scope.
func (s *syncer) storeFullScanHorizons(
	ctx context.Context) ([]storeScanAccount, error) {

	// Select eligible accounts in SQL before building recovery horizons;
	// key-only accounts must never seed lookahead derivation.
	accounts, err := s.store.ListAccounts(ctx, db.ListAccountsQuery{
		WalletID:      s.walletID,
		SkipBalance:   true,
		ChainSyncOnly: true,
	})
	if err != nil {
		return nil, fmt.Errorf("list scan accounts: %w", err)
	}

	scanAccounts := make([]storeScanAccount, 0, len(accounts))
	for i := range accounts {
		// The keyless imported-address bucket has no xpub to derive
		// lookahead addresses from. Its materialized addresses are still
		// watched by storeScanAddresses.
		if keylessImportedAccount(accounts[i]) {
			continue
		}

		if accounts[i].AccountID == nil {
			return nil, fmt.Errorf("scan account %q has no store "+
				"account id", accounts[i].AccountName)
		}

		scanAccount, err := s.storeScanAccount(
			accounts[i], *accounts[i].AccountID,
		)
		if err != nil {
			return nil, err
		}

		scanAccounts = append(scanAccounts, scanAccount)
	}

	return scanAccounts, nil
}

// storeTargetedScanHorizons loads recovery horizon accounts for already
// resolved scan targets. Each target keeps the account number the caller named
// as its recovery key, while the Store lookup itself prefers the durable name.
func (s *syncer) storeTargetedScanHorizons(ctx context.Context,
	targets []scanTarget) ([]storeScanAccount, error) {

	scanAccounts := make([]storeScanAccount, 0, len(targets))
	for _, target := range targets {
		// The legacy imported-address bucket is a keyless
		// pseudo-account, not a numeric HD account, and
		// resolveScanTargets leaves its AccountName empty. Skip it
		// before any Store lookup: its addresses are already watched
		// through storeScanAddresses, and the backend has no row keyed
		// by its reserved number.
		if target.Account == waddrmgr.ImportedAddrAccount {
			continue
		}

		info, err := s.storeScanHorizonAccount(ctx, target)
		if err != nil {
			return nil, err
		}

		// The keyless imported-address bucket has no xpub to derive
		// lookahead addresses from. Its materialized addresses are still
		// watched by storeScanAddresses.
		if keylessImportedAccount(*info) {
			continue
		}

		scanAccount, err := s.storeScanAccount(*info, target.Account)
		if err != nil {
			return nil, err
		}

		scanAccounts = append(scanAccounts, scanAccount)
	}

	return scanAccounts, nil
}

// storeScanHorizonAccount resolves one targeted scanTarget into its Store
// account row. The lookup prefers the durable AccountName when set, mirroring
// the ScanHorizon contract: backends mask an unknown imported number to 0
// and GetAccount rejects a number lookup that resolves to a numberless row, so
// resolving a numberless target by number could fail or select the default
// account. A number lookup is therefore issued only for a derived target whose
// name resolution is unavailable.
func (s *syncer) storeScanHorizonAccount(ctx context.Context,
	target scanTarget) (*db.AccountInfo, error) {

	query := db.GetAccountQuery{
		WalletID:    s.walletID,
		Scope:       db.KeyScope(target.Scope),
		SkipBalance: true,
	}

	// Prefer the scope-unique name so a masked unknown imported number can
	// never resolve to the default derived account; fall back to the number
	// only when no name was resolved.
	if target.AccountName != "" {
		query.Name = &target.AccountName
	} else {
		account := target.Account
		query.AccountNumber = &account
	}

	info, err := s.store.GetAccount(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("get scan account: %w", err)
	}

	return info, nil
}

// storeScanAccount converts store account metadata into the recovery state
// horizon shape. recoveryKey is the identity recovery state indexes the account
// by; the account's own store row ID and BIP44 number are carried alongside,
// because a horizon must be persisted against the durable row and a
// store-native deriver must record the real account number.
func (s *syncer) storeScanAccount(info db.AccountInfo,
	recoveryKey uint32) (storeScanAccount, error) {

	accountPubKey, err := storeAccountPubKey(info)
	if err != nil {
		return storeScanAccount{}, err
	}

	addrSchema, err := storeAccountAddrSchema(info.AddrSchema)
	if err != nil {
		return storeScanAccount{}, err
	}

	var masterFingerprint uint32
	if info.MasterKeyFingerprint != nil {
		masterFingerprint = *info.MasterKeyFingerprint
	}

	return storeScanAccount{
		props: &waddrmgr.AccountProperties{
			AccountNumber:        recoveryKey,
			AccountName:          info.AccountName,
			ExternalKeyCount:     info.ExternalKeyCount,
			InternalKeyCount:     info.InternalKeyCount,
			ImportedKeyCount:     info.ImportedKeyCount,
			MasterKeyFingerprint: masterFingerprint,
			KeyScope:             waddrmgr.KeyScope(info.KeyScope),
			IsWatchOnly:          info.IsWatchOnly,
			AccountPubKey:        accountPubKey,
			AddrSchema:           addrSchema,
		},
		accountID:            info.AccountID,
		derivedAccountNumber: info.AccountNumber,
	}, nil
}

// storeAccountPubKey parses the account public key loaded from the store into
// the legacy AccountProperties shape recovery still uses as its snapshot type.
func storeAccountPubKey(
	info db.AccountInfo) (*hdkeychain.ExtendedKey, error) {

	if len(info.PublicKey) == 0 {
		return nil, nil //nolint:nilnil
	}

	key, err := hdkeychain.NewKeyFromString(string(info.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("parse account public key: %w", err)
	}

	return key, nil
}

// storeAccountAddrSchema converts the db-native account address schema into the
// AccountProperties schema recovery consumes.
func storeAccountAddrSchema(
	schema db.ScopeAddrSchema) (*waddrmgr.ScopeAddrSchema, error) {

	external, err := addresstype.ToWallet(schema.ExternalAddrType, false)
	if err != nil {
		return nil, fmt.Errorf("external address type: %w", err)
	}

	internal, err := addresstype.ToWallet(schema.InternalAddrType, false)
	if err != nil {
		return nil, fmt.Errorf("internal address type: %w", err)
	}

	return &waddrmgr.ScopeAddrSchema{
		ExternalAddrType: external,
		InternalAddrType: internal,
	}, nil
}

// keylessImportedAccount reports whether an account is the reserved raw-import
// alias. The bucket has no account xpub, so it cannot seed recovery horizons;
// its materialized addresses are loaded separately by storeScanAddresses.
func keylessImportedAccount(info db.AccountInfo) bool {
	return info.IsImported && len(info.PublicKey) == 0
}

// storeScanAddresses loads active scan addresses through the store, paging per
// (key scope, account) pair because ListAddresses is scoped to a single pair.
//
// For KVDB, this reproduces the legacy ForEachRelevantActiveAddress filtering
// used by the old scan-data reader: for default scopes every active address is
// watched, while for non-default key scopes only internal-branch (change)
// addresses are watched. The non-default external branches are intentionally
// skipped because they only ever existed due to a since-fixed bug, and
// watching them would diverge from the legacy recovery set.
// SQL watches persisted addresses from both branches in every eligible scope.
func (s *syncer) storeScanAddresses(
	ctx context.Context) ([]address.Address, error) {

	// Apply the account policy before paging addresses so key-only scripts
	// never become scan watches, even when the recovery window is zero.
	accounts, err := s.store.ListAccounts(ctx, db.ListAccountsQuery{
		WalletID:      s.walletID,
		SkipBalance:   true,
		ChainSyncOnly: true,
	})
	if err != nil {
		return nil, fmt.Errorf("list scan accounts: %w", err)
	}

	var addrs []address.Address
	for i := range accounts {
		if keylessImportedAccount(accounts[i]) {
			continue
		}

		accountAddrs, err := s.storeAccountScanAddresses(
			ctx, accounts[i],
		)
		if err != nil {
			return nil, err
		}

		addrs = append(addrs, accountAddrs...)
	}

	importedAddrs, err := s.storeImportedScanAddresses(ctx)
	if err != nil {
		return nil, err
	}

	addrs = append(addrs, importedAddrs...)

	return addrs, nil
}

// storeImportedScanAddresses loads raw imported addresses through the
// accountless query shape that ListAccounts intentionally omits.
func (s *syncer) storeImportedScanAddresses(
	ctx context.Context) ([]address.Address, error) {

	return s.storeAccountScanAddresses(ctx, db.AccountInfo{
		AccountName: db.DefaultImportedAccountName,
		IsImported:  true,
	})
}

// storeScanAddressRelevant reports whether a stored address row belongs in the
// recovery scan set for its account shape and key scope.
func (s *syncer) storeScanAddressRelevant(isRawImported, isDefaultScope bool,
	info db.AddressInfo) bool {

	// SQL has no legacy branch restriction on persisted account addresses.
	if s.addrStore == nil || isRawImported || isDefaultScope {
		return true
	}

	return info.Branch == waddrmgr.InternalBranch
}

// storeAccountScanAddresses pages through a single account's addresses,
// converting each stored script into its wallet address. KVDB mirrors legacy
// ForEachRelevantActiveAddress filtering: addresses in default key scopes are
// all relevant, while non-default key scopes only contribute their
// internal-branch (change) addresses.
func (s *syncer) storeAccountScanAddresses(ctx context.Context,
	account db.AccountInfo) ([]address.Address, error) {

	pageReq, err := page.NewRequest[uint32](scanAddressPageLimit)
	if err != nil {
		return nil, err
	}

	// In KVDB, outside the default key scopes only the internal (change)
	// branch is relevant, matching ForEachRelevantActiveAddress's handling of
	// change addresses that a since-fixed bug created in non-default scopes.
	isDefaultScope := waddrmgr.IsDefaultScope(
		waddrmgr.KeyScope(account.KeyScope),
	)
	isRawImported := keylessImportedAccount(account)

	query := db.ListAddressesQuery{
		WalletID: s.walletID,
		Page:     pageReq,
	}
	if !isRawImported {
		scope := account.KeyScope
		accountName := account.AccountName

		query.Scope = &scope
		query.AccountName = &accountName
	}

	var addrs []address.Address
	for {
		result, err := s.store.ListAddresses(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("list scan addresses: %w", err)
		}

		for _, info := range result.Items {
			// Retain legacy branch relevance only for KVDB. SQL must
			// watch persisted external children in custom scopes too.
			if !s.storeScanAddressRelevant(
				isRawImported, isDefaultScope, info,
			) {

				continue
			}

			addr, err := s.watchAddress(info.ScriptPubKey)
			if err != nil {
				return nil, fmt.Errorf("scan address script: %w", err)
			}

			addrs = append(addrs, addr)
		}

		if result.Next == nil {
			return addrs, nil
		}

		query.Page.After = result.Next
	}
}

// storeScanUnspent loads UTXOs that recovery scans should watch through the
// store.
func (s *syncer) storeScanUnspent(ctx context.Context) (
	[]wtxmgr.Credit, error) {

	utxos, err := s.store.ListOutputsToWatch(ctx, s.walletID)
	if err != nil {
		return nil, fmt.Errorf("list outputs to watch: %w", err)
	}

	credits := make([]wtxmgr.Credit, 0, len(utxos))
	for i := range utxos {
		credit, err := storeScanCredit(utxos[i])
		if err != nil {
			return nil, err
		}

		credits = append(credits, credit)
	}

	return credits, nil
}

// storeScanCredit converts one store UTXO row into the recovery scan credit
// shape.
func storeScanCredit(utxo db.UtxoInfo) (wtxmgr.Credit, error) {
	height := int32(-1)
	if utxo.Height != db.UnminedHeight {
		var err error

		height, err = db.Uint32ToInt32(utxo.Height)
		if err != nil {
			return wtxmgr.Credit{}, fmt.Errorf("utxo height: %w", err)
		}
	}

	return wtxmgr.Credit{
		OutPoint: utxo.OutPoint,
		BlockMeta: wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Height: height},
		},
		Amount:       utxo.Amount,
		PkScript:     utxo.PkScript,
		Received:     utxo.Received,
		FromCoinBase: utxo.FromCoinBase,
	}, nil
}

// loadStoreScanData retrieves recovery scan initialization data through the
// store. Targets are the identity-aware scanTargets resolved up front; an
// empty slice loads horizons for every account (the untargeted path).
func (s *syncer) loadStoreScanData(ctx context.Context,
	targets []scanTarget) ([]storeScanAccount, []address.Address,
	[]wtxmgr.Credit, error) {

	horizons, err := s.storeScanHorizons(ctx, targets)
	if err != nil {
		return nil, nil, nil, err
	}

	addrs, err := s.storeScanAddresses(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	unspent, err := s.storeScanUnspent(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	return horizons, addrs, unspent, nil
}

// loadTargetedScanState initializes a recovery state for a targeted rescan of
// specific accounts.
func (s *syncer) loadTargetedScanState(ctx context.Context,
	targets []waddrmgr.AccountScope) (*RecoveryState, error) {

	accounts, initialAddrs, initialUnspent, err := s.loadTargetedScanData(
		ctx, targets,
	)
	if err != nil {
		return nil, err
	}

	return s.newStoreScanState(accounts, initialAddrs, initialUnspent)
}

// loadTargetedScanData retrieves all necessary data from the database to
// initialize the recovery state for a targeted rescan.
//
// It first resolves the public AccountScope targets into identity-aware
// scanTargets so it never resolves an imported account by its masked number,
// then loads the scan data through the Store.
func (s *syncer) loadTargetedScanData(ctx context.Context,
	targets []waddrmgr.AccountScope) ([]storeScanAccount,
	[]address.Address, []wtxmgr.Credit, error) {

	resolved, err := s.resolveScanTargets(ctx, targets)
	if err != nil {
		return nil, nil, nil, err
	}

	return s.loadStoreScanData(ctx, resolved)
}

// resolveScanTargets converts the public AccountScope rescan targets into the
// internal, identity-aware scanTargets used by the Store path. It reads one
// account snapshot and indexes it by the identity the caller actually names,
// then carries the durable AccountName forward so Store horizon loading can key
// on the name instead of the maskable number.
//
// The keyless legacy imported-address bucket is carried through with an empty
// AccountName so storeScanHorizons skips it before any lookup; every other
// target must match a row in the snapshot.
func (s *syncer) resolveScanTargets(ctx context.Context,
	targets []waddrmgr.AccountScope) ([]scanTarget, error) {

	if len(targets) == 0 {
		return nil, nil
	}

	names, err := s.scanTargetNames(ctx)
	if err != nil {
		return nil, err
	}

	resolved := make([]scanTarget, 0, len(targets))
	for _, target := range targets {
		// The keyless imported-address bucket has no resolvable name;
		// carry it verbatim so the Store path skips it before any
		// lookup.
		if target.Account == waddrmgr.ImportedAddrAccount {
			resolved = append(resolved, scanTarget{
				Scope:   target.Scope,
				Account: target.Account,
			})

			continue
		}

		name, ok := names[target]
		if !ok {
			return nil, fmt.Errorf("resolve scan target account "+
				"%d: %w", target.Account, db.ErrAccountNotFound)
		}

		resolved = append(resolved, scanTarget{
			Scope:       target.Scope,
			Account:     target.Account,
			AccountName: name,
		})
	}

	return resolved, nil
}

// scanTargetNames indexes one account snapshot by the (scope, number) identity
// a rescan caller names, mapping each to the account's durable name.
//
// An account with a known path is indexed by its public AccountNumber,
// including imported accounts. A numberless import uses its store
// AccountID -- but only for kvdb, recognized by the legacy address manager
// being present. There AccountID is waddrmgr's own internal, non-masked account
// number, which is exactly the selector the caller supplies, so this is a
// format-boundary adaptation rather than a store-identity selector. SQL sets
// AccountID from a relational row ID unrelated to any BIP44 number, so matching
// it would let a request for a nonexistent account select an unrelated imported
// row; there an unmatched numeric target is simply not found, and targeting a
// numberless import by number stays unsupported. A numbered row wins if a
// malformed snapshot ever presents both.
func (s *syncer) scanTargetNames(
	ctx context.Context) (map[waddrmgr.AccountScope]string, error) {

	// Resolve targets only from eligible SQL rows. An excluded explicit
	// target then follows the existing missing-account error path.
	accounts, err := s.store.ListAccounts(ctx, db.ListAccountsQuery{
		WalletID:      s.walletID,
		SkipBalance:   true,
		ChainSyncOnly: true,
	})
	if err != nil {
		return nil, fmt.Errorf("list scan accounts: %w", err)
	}

	legacyNumbering := s.addrStore != nil

	names := make(map[waddrmgr.AccountScope]string, len(accounts))
	for i := range accounts {
		info := accounts[i]

		scope := waddrmgr.KeyScope(info.KeyScope)

		if info.AccountNumber != nil {
			names[waddrmgr.AccountScope{
				Scope:   scope,
				Account: *info.AccountNumber,
			}] = info.AccountName

			continue
		}

		if !info.IsImported || !legacyNumbering ||
			info.AccountID == nil {

			continue
		}

		key := waddrmgr.AccountScope{
			Scope:   scope,
			Account: *info.AccountID,
		}
		if _, ok := names[key]; ok {
			continue
		}

		names[key] = info.AccountName
	}

	return names, nil
}

// loadWalletScanData retrieves all necessary data from the database to
// initialize the recovery state. This includes account horizons, active
// addresses, and unspent outputs to watch.
func (s *syncer) loadWalletScanData(ctx context.Context) ([]storeScanAccount,
	[]address.Address, []wtxmgr.Credit, error) {

	return s.loadStoreScanData(ctx, nil)
}

// findDisconnectFork finds the latest retained Wallet block on the current
// chain at or below forkHeight. Higher blocks cannot be the rewind point.
// Sparse history falls back to single reads within each bounded window.
func (s *syncer) findDisconnectFork(ctx context.Context,
	forkHeight, sourceHeight int32, synced waddrmgr.BlockStamp) (
	waddrmgr.BlockStamp, error) {

	const batchSize = 10

	height := min(forkHeight, synced.Height, sourceHeight)

	for height >= 0 {
		// Revisit no part of a failed window: overlapping range retries
		// would multiply Store reads while descending through pruned rows.
		end := uint32(height)
		start := end - min(end, batchSize-1)
		blocks, err := s.store.ListSyncedBlocks(
			ctx, db.ListSyncedBlocksQuery{
				WalletID:    s.walletID,
				StartHeight: start,
				EndHeight:   end,
			},
		)

		sparse := errors.Is(err, db.ErrBlockNotFound)
		for offset := range end - start + 1 {
			h := end - offset
			index := h - start

			if sparse {
				// A missing range can still contain retained rows. Probe
				// only its current height and preserve real read failures.
				blocks, err = s.store.ListSyncedBlocks(
					ctx, db.ListSyncedBlocksQuery{
						WalletID:    s.walletID,
						StartHeight: h, EndHeight: h,
					},
				)
				if errors.Is(err, db.ErrBlockNotFound) {
					continue
				}

				index = 0
			}

			if err != nil {
				return waddrmgr.BlockStamp{}, err
			}

			// Prove membership before fetching a header: Neutrino may
			// already have discarded headers from the abandoned branch.
			hash, err := s.cfg.Chain.GetBlockHash(int64(h))
			if err != nil {
				return waddrmgr.BlockStamp{}, fmt.Errorf(
					"disconnect fork hash: %w", err,
				)
			}

			if *hash == blocks[index].Hash {
				return s.resolveDisconnectFork(blocks[index], synced)
			}
		}

		height = max(0, height-batchSize+1) - 1
	}

	return waddrmgr.BlockStamp{Height: -1}, nil
}

// resolveDisconnectFork restores the already-proven matching block's stamp.
// Keep the cached tip intact; older KVDB rows need their native header time.
func (s *syncer) resolveDisconnectFork(block db.Block,
	synced waddrmgr.BlockStamp) (waddrmgr.BlockStamp, error) {

	if int64(block.Height) == int64(synced.Height) {
		return synced, nil
	}

	header, err := s.cfg.Chain.GetBlockHeader(&block.Hash)
	if err != nil {
		return waddrmgr.BlockStamp{}, fmt.Errorf("disconnect fork header: %w",
			err)
	}

	block.Timestamp = header.Timestamp

	return db.BlockStampFromBlock(&block)
}

// findCanonicalBlockHashes binds the affected Wallet heights and candidate
// fork to one source tip. Hashes read by height can span different branches.
// On success, a present nil entry proves absence above the captured tip.
// On error, callers must discard the map because it may contain partial proof.
func (s *syncer) findCanonicalBlockHashes(ctx context.Context,
	observed uint32, committedHeight int32,
	fork, source waddrmgr.BlockStamp) (map[uint32]*chainhash.Hash, error) {

	// Widen before adding one so a fork at MaxInt32 cannot overflow.
	start, err := db.Int64ToUint32(int64(fork.Height) + 1)
	if err != nil {
		return nil, fmt.Errorf("disconnect history start: %w", err)
	}

	tip, err := db.Int64ToUint32(int64(source.Height))
	if err != nil {
		return nil, fmt.Errorf("disconnect history tip: %w", err)
	}

	history, err := s.store.ListTxns(ctx, db.ListTxnsQuery{
		WalletID: s.walletID, StartHeight: start, EndHeight: math.MaxInt32,
	})
	if err != nil {
		return nil, fmt.Errorf("disconnect history: %w", err)
	}

	// Include empty committed blocks and confirmations that were learned
	// before a scan reached them. Above-tip entries stay explicitly absent.
	canonical := map[uint32]*chainhash.Hash{observed: nil}
	for h := start; int64(h) <= int64(committedHeight); h++ {
		canonical[h] = nil
	}

	for _, tx := range history {
		canonical[tx.Block.Height] = nil
	}

	// The fork anchors the destination of the rewind as well as the
	// branch whose higher blocks the Store may invalidate.
	lowest := tip
	if fork.Height >= 0 {
		lowest = start - 1
	}

	for h := range canonical {
		lowest = min(lowest, h)
	}

	return canonical, s.verifyDisconnectAncestry(
		ctx, lowest, tip, fork, source, canonical,
	)
}

// verifyDisconnectAncestry reads every header from the captured tip back to
// the fork before writing. A Wallet catching up after a long outage pays
// for the full gap, checking cancellation between recoveryBatchSize batches.
// Rechecking its tip also validates absent heights above a shortened chain.
func (s *syncer) verifyDisconnectAncestry(ctx context.Context,
	lowest, tip uint32, fork, source waddrmgr.BlockStamp,
	canonical map[uint32]*chainhash.Hash) error {

	parent := source.Hash
	for high := tip; high > lowest; {
		low := high - min(high-lowest, uint32(recoveryBatchSize)) + 1

		next, err := s.readDisconnectWindow(
			ctx, low, high, parent, canonical,
		)
		if err != nil {
			return err
		}

		parent, high = next, low-1
	}

	// The last parent identifies the lowest block without fetching a
	// redundant header. A different destination invalidates the whole proof.
	if fork.Height >= 0 && parent != fork.Hash {
		return fmt.Errorf("disconnect fork %d changed", fork.Height)
	}

	if _, needed := canonical[lowest]; needed {
		canonical[lowest] = &parent
	}

	// A current source can reorganize during proof collection. Even a tip
	// extension can invalidate evidence that an observed height was absent.
	tipHash, tipHeight, err := s.cfg.Chain.GetBestBlock()
	if err != nil {
		return fmt.Errorf("recheck disconnect source tip: %w", err)
	}

	if tipHeight != source.Height || *tipHash != source.Hash {
		return fmt.Errorf("disconnect source tip changed from %s at %d "+
			"to %s at %d", source.Hash, source.Height, tipHash, tipHeight)
	}

	return nil
}

// readDisconnectWindow verifies one bounded range against its expected high
// hash. Its return value anchors the next range to this one's lowest header.
func (s *syncer) readDisconnectWindow(ctx context.Context, low, high uint32,
	parent chainhash.Hash,
	canonical map[uint32]*chainhash.Hash) (chainhash.Hash, error) {

	// Stop between batches so a deep fork does not hold Wallet shutdown.
	err := ctx.Err()
	if err != nil {
		return parent, err
	}

	// The reverse walk indexes both results by height. It needs one
	// hash per height and one header at the same index for each hash.
	hashes, err := s.cfg.Chain.GetBlockHashes(int64(low), int64(high))
	if err != nil {
		return parent, fmt.Errorf("disconnect block hashes: %w", err)
	}

	if int64(len(hashes)) != int64(high-low+1) {
		return parent, fmt.Errorf("incomplete disconnect hashes at %d", low)
	}

	headers, err := s.cfg.Chain.GetBlockHeaders(hashes)
	if err != nil {
		return parent, fmt.Errorf("disconnect block headers: %w", err)
	}

	if len(headers) != len(hashes) {
		return parent, fmt.Errorf("incomplete disconnect headers at %d", low)
	}

	// Point lookup and bulk lookup can straddle a reorg. A key is usable
	// only when the higher, already anchored header names that exact hash.
	for i := len(hashes) - 1; i >= 0; i-- {
		if hashes[i] != parent {
			return parent, fmt.Errorf(
				"disconnect ancestry changed at %d", high,
			)
		}

		if _, needed := canonical[high]; needed {
			hash := parent
			canonical[high] = &hash
		}

		parent = headers[i].PrevBlock
		high--
	}

	return parent, nil
}

// disconnectBlock resolves canonical evidence before atomically rewinding this
// Wallet. Its single worker orders this operation with live and scanned writes.
func (s *syncer) disconnectBlock(ctx context.Context,
	event wtxmgr.BlockMeta) error {

	source, err := s.reconcileDisconnect(ctx, event)
	if err != nil {
		// Do not schedule or keep a retry after an indeterminate
		// commit: the Store write may have committed and Store
		// prohibits retrying the mutation.
		if errors.Is(err, db.ErrIndeterminateCommit) {
			s.pendingDisconnect = nil
		} else if s.pendingDisconnect == nil {
			// Retain the first failed disconnect so the next
			// initChainSync replays it before checkRollback or
			// later mailbox events.
			pending := event
			s.pendingDisconnect = &pending
		}

		s.state.Store(uint32(syncStateSyncing))

		return err
	}

	s.pendingDisconnect = nil

	state := s.syncState()
	if state != syncStateSynced && state != syncStateRescanning {
		return nil
	}

	tip, err := s.syncedTo(ctx)
	if err != nil || tip.Height != source.Height || tip.Hash != source.Hash {
		s.state.Store(uint32(syncStateSyncing))
	}

	return err
}

// reconcileDisconnect verifies the stored history against the captured chain
// tip and applies the rewind. Its caller uses that tip to check readiness.
func (s *syncer) reconcileDisconnect(ctx context.Context,
	event wtxmgr.BlockMeta) (waddrmgr.BlockStamp, error) {

	var source waddrmgr.BlockStamp

	if !s.cfg.Chain.IsCurrent() {
		return source, errors.New("disconnect source is not current")
	}

	block, err := storeBlockFromBlockMeta(event)
	if err != nil {
		return source, fmt.Errorf("disconnect block: %w", err)
	}

	synced, err := s.syncedTo(ctx)
	if err != nil {
		return source, err
	}

	sourceHash, sourceHeight, err := s.cfg.Chain.GetBestBlock()
	if err != nil {
		return source, fmt.Errorf("disconnect source tip: %w", err)
	}

	if synced.Height != sourceHeight || synced.Hash != *sourceHash {
		s.state.Store(uint32(syncStateSyncing))
	}

	fork, err := s.findDisconnectFork(
		ctx, event.Height-1, sourceHeight, synced,
	)
	if err != nil {
		return source, err
	}

	source = waddrmgr.BlockStamp{Hash: *sourceHash, Height: sourceHeight}
	err = s.applyDisconnect(ctx, *block, synced.Height, fork, source)

	return source, err
}

// applyDisconnect verifies the collected fork against the captured source
// before a live notification or divergent startup changes Wallet history.
func (s *syncer) applyDisconnect(ctx context.Context, block db.Block,
	committedHeight int32, fork, source waddrmgr.BlockStamp) error {

	canonical, err := s.findCanonicalBlockHashes(
		ctx, block.Height, committedHeight, fork, source,
	)
	if err != nil {
		return err
	}

	if block.Hash.IsEqual(canonical[block.Height]) {
		return nil
	}

	err = s.store.DisconnectBlock(
		ctx, s.walletID, block, db.OptionalBlockFromBlockStamp(fork),
		canonical,
	)
	if err != nil {
		return fmt.Errorf("disconnect Wallet history: %w", err)
	}

	return nil
}
