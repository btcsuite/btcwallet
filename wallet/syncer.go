package wallet

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs"
	"github.com/btcsuite/btcd/btcutil/gcs/builder"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
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
)

// syncState represents the synchronization status of the wallet with the
// blockchain.
type syncState uint32

const (
	// syncStateBackendSyncing indicates the wallet is waiting for the
	// chain backend to finish syncing.
	syncStateBackendSyncing syncState = iota

	// syncStateSyncing indicates the wallet is running but catching up to
	// the chain tip (or rewinding).
	syncStateSyncing

	// syncStateSynced indicates the wallet is running and synced to the
	// chain tip.
	syncStateSynced

	// syncStateRescanning indicates the wallet is running a historical
	// scan for specific user-provided targets, such as accounts or
	// addresses, without rewinding the global synchronization state.
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

// scanResult holds the result of processing a single block during a batch
// scan.
type scanResult struct {
	// BlockProcessResult embeds the results of filtering the block.
	*BlockProcessResult

	// meta contains block metadata (hash, height, time).
	meta *wtxmgr.BlockMeta
}

// chainSyncer is a private interface that abstracts the chain synchronization
// logic, allowing it to be mocked for testing the wallet and controller.
type chainSyncer interface {
	// run executes the main synchronization loop.
	run(ctx context.Context) error

	// requestScan submits a rescan job to the syncer.
	requestScan(ctx context.Context, req *scanReq) error

	// syncState returns the current synchronization state.
	syncState() syncState
}

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

	// state tracks the chain synchronization status.
	state atomic.Uint32

	// scanReqChan is the internal mailbox used to receive scan requests
	// from the controller. It is buffered to ensure that submitting a
	// request does not unnecessarily block the calling goroutine.
	scanReqChan chan *scanReq

	// publisher is the component responsible for broadcasting transactions
	// to the network. It is primarily used during the maintenance phase to
	// ensure unmined transactions remain in the mempool.
	publisher TxPublisher
}

// newSyncer creates a new syncer instance.
func newSyncer(cfg Config, addrStore waddrmgr.AddrStore,
	txStore wtxmgr.TxStore, publisher TxPublisher) *syncer {

	return &syncer{
		cfg:         cfg,
		addrStore:   addrStore,
		txStore:     txStore,
		scanReqChan: make(chan *scanReq, 1),
		publisher:   publisher,
	}
}

// syncState returns the current synchronization state of the wallet.
func (s *syncer) syncState() syncState {
	return syncState(s.state.Load())
}

// isRecoveryMode returns true if the wallet is currently syncing or
// rescanning.
func (s *syncer) isRecoveryMode() bool {
	status := s.syncState()
	return status == syncStateSyncing || status == syncStateRescanning
}

// initChainSync performs the initial setup for the chain synchronization loop.
// This includes waiting for the backend to sync, checking for rollbacks, and
// enabling block notifications. It returns an error if any of these setup
// steps fail.
func (s *syncer) initChainSync(ctx context.Context) error {
	var err error

	// Inform the backend about our birthday for optimization. For backends
	// like Neutrino (SPV), this provides a starting point for the internal
	// synchronization of block headers and compact filters. Without this
	// hint, the backend might attempt to sync from genesis or its latest
	// checkpoint, leading to unnecessary network I/O and delayed wallet
	// readiness.
	if cc, ok := s.cfg.Chain.(*chain.NeutrinoClient); ok {
		cc.SetStartTime(s.addrStore.Birthday())
	}

	// Wait for the backend to be synced to the network. We require the
	// backend to be synced before we start scanning to ensure we have a
	// consistent view of the chain and can perform recovery correctly.
	s.state.Store(uint32(syncStateBackendSyncing))

	err = s.waitUntilBackendSynced(ctx)
	if err != nil {
		return fmt.Errorf("unable to wait for backend sync: %w", err)
	}

	// Check for any reorgs that happened while we were down.
	err = s.checkRollback(ctx)
	if err != nil {
		return fmt.Errorf("unable to check for rollback: %w", err)
	}

	// Enable block notifications from the chain backend.
	err = s.cfg.Chain.NotifyBlocks()
	if err != nil {
		return fmt.Errorf("unable to start block notifications: %w",
			err)
	}

	return nil
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
		select {
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
func (s *syncer) checkRollback(ctx context.Context) error {
	var err error

	// batchSize is the number of blocks to fetch from the chain backend in
	// a single batch when checking for a rollback. A value of 10 is chosen
	// as a conservative default that covers the vast majority of reorg
	// scenarios (typically 1-3 blocks) while keeping individual batch
	// requests lightweight.
	const batchSize = 10

	syncedTo := s.addrStore.SyncedTo()
	syncedHeight := syncedTo.Height

	var (
		localHashes  []*chainhash.Hash
		remoteHashes []chainhash.Hash
		header       *wire.BlockHeader
	)

	for syncedHeight > 0 {
		// Calculate the range for this batch. We scan backwards:
		// [startHeight, endHeight] where endHeight is syncedHeight.
		endHeight := syncedHeight
		startHeight := max(0, endHeight-batchSize+1)

		// Fetch Local Batch (from wallet's database).
		localHashes, err = s.DBGetSyncedBlocks(
			ctx, startHeight, endHeight,
		)
		if err != nil {
			return err
		}

		// Fetch Remote Batch - Fetch corresponding hashes from the
		// chain backend.
		remoteHashes, err = s.cfg.Chain.GetBlockHashes(
			int64(startHeight), int64(endHeight),
		)
		if err != nil {
			return fmt.Errorf("remote get block hashes: %w", err)
		}

		// Compare Batches. Iterate backwards to find the last matching
		// block (the fork point).
		matchIndex := s.findForkPoint(localHashes, remoteHashes)

		// Case A: Tip matches. No rollback needed (if we are at the
		// tip). If syncedHeight == syncedTo.Height and matchIndex is
		// the last element, then we are fully synced on the main
		// chain.
		if syncedHeight == syncedTo.Height &&
			matchIndex == len(localHashes)-1 {

			return nil
		}

		// Case B: Mismatch found within this batch. A fork point has
		// been detected. This indicates a blockchain reorganization
		// where the wallet's local chain history diverges from the
		// chain backend's view within the current batch of blocks.
		if matchIndex != -1 {
			//nolint:gosec // matchIndex < batchSize (10).
			forkHeight := startHeight + int32(matchIndex)
			forkHash := localHashes[matchIndex]

			log.Infof("Rollback detected! Rewinding to height %d "+
				"(%v)", forkHeight, forkHash)

			// Fetch the block header outside the DB transaction to
			// avoid holding the lock during an RPC call.
			header, err = s.cfg.Chain.GetBlockHeader(forkHash)
			if err != nil {
				return fmt.Errorf("get fork header: %w", err)
			}

			// Perform the rollback.
			return s.DBPutRewind(ctx, waddrmgr.BlockStamp{
				Height:    forkHeight,
				Hash:      *forkHash,
				Timestamp: header.Timestamp,
			})
		}

		// Case C: No match in this batch. The fork point is deeper.
		// Move syncedHeight back and continue loop.
		syncedHeight = startHeight - 1
	}

	return nil
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
// attempts to re-broadcast them to the network.
func (s *syncer) broadcastUnminedTxns(ctx context.Context) error {
	txs, err := s.DBGetUnminedTxns(ctx)
	if err != nil {
		log.Errorf("Unable to retrieve unconfirmed transactions to "+
			"resend: %v", err)

		return fmt.Errorf("failed to retrieve unconfirmed txs: %w", err)
	}

	for _, tx := range txs {
		err := s.publisher.Broadcast(ctx, tx, "")
		if err != nil {
			log.Warnf("Unable to rebroadcast tx %v: %v",
				tx.TxHash(), err)
		}
	}

	return nil
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

		// addition to startHeight won't overflow int32.
		height := startHeight + int32(i)

		meta := &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Hash: hash, Height: height},
			Time:  header.Timestamp,
		}

		results = append(results, scanResult{
			meta: meta,
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

	horizonData, initialAddrs, initialUnspent, err := s.loadWalletScanData(
		ctx,
	)
	if err != nil {
		return nil, err
	}

	// Initialize a fresh recovery state for this batch to ensure no stale
	// state leaks between batches.
	scanState := NewRecoveryState(
		s.cfg.RecoveryWindow, s.cfg.ChainParams, s.addrStore,
	)

	// Initialize Batch State (History + Lookahead)
	err = scanState.Initialize(horizonData, initialAddrs, initialUnspent)
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

		// addition to startHeight won't overflow int32.
		height := startHeight + int32(i)

		meta := &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Hash: hash, Height: height},
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
			meta: &wtxmgr.BlockMeta{
				Block: wtxmgr.Block{
					Hash: hashes[i],

					// size (2000), so addition to
					// startHeight won't overflow int32.
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
	// NOTE: For targeted rescans, the state will never be empty as it is
	// initialized with specific targets.
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
const defaultMaxCFilterItems = 100000

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

		if scanState.WatchListSize() > threshold {
			log.Infof("Auto sync: Watchlist size %d > %d, "+
				"switching to full blocks for performance",
				scanState.WatchListSize(), threshold)

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
	_, bestHeight, err := s.cfg.Chain.GetBestBlock()
	if err != nil {
		// An error getting best block height means we couldn't
		// determine sync status. We are NOT finished, and an error
		// occurred. Caller should retry.
		return false, fmt.Errorf("unable to get best block height: %w",
			err)
	}

	// Determine our current sync state.
	syncedTo := s.addrStore.SyncedTo()

	// If the wallet is caught up to the best known tip, log this and
	// return.
	if syncedTo.Height >= bestHeight {
		s.state.Store(uint32(syncStateSynced))
		log.Infof("Wallet is synced to chain tip: height=%d",
			syncedTo.Height)

		return true, nil
	}

	// Calculate the gap.
	gap := bestHeight - syncedTo.Height

	// If the gap is large (> 6 blocks), we treat it as a major event
	// requiring Syncing state protection. Smaller gaps are handled
	// silently to avoid disrupting user operations like CreateTx.
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

// scanBatch fetches and processes a batch of blocks from the chain backend. It
// handles fetching, CFilter matching, and DB updates.
func (s *syncer) scanBatch(ctx context.Context, syncedTo waddrmgr.BlockStamp,
	bestHeight int32) error {

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
	// Process Batch (Update). We do this in a single DB transaction.
	return s.DBPutSyncBatch(ctx, results)
}

// handleChainUpdate processes a notification immediately.
// It returns an error if processing fails or if the wallet is shutting down.
func (s *syncer) handleChainUpdate(ctx context.Context, n any) error {
	// For a single update, we process it and commit immediately.
	err := s.processChainUpdate(ctx, n)
	if err != nil {
		return fmt.Errorf("failed to process chain update: %w", err)
	}

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

	return nil
}

// processChainUpdate writes a single chain update to the database.
func (s *syncer) processChainUpdate(ctx context.Context, update any) error {
	switch n := update.(type) {
	case chain.BlockConnected:
		return s.DBPutSyncTip(ctx, wtxmgr.BlockMeta(n))

	// A block was disconnected. We use checkRollback to safely verify our
	// chain state against the backend and rewind if necessary. This
	// handles both single block disconnects and deeper reorgs robustly.
	case chain.BlockDisconnected:
		return s.checkRollback(ctx)

	// We only expect individual transaction notifications for unconfirmed
	// transactions as they enter the mempool. Confirmed transactions are
	// handled atomically via FilteredBlockConnected.
	case chain.RelevantTx:
		matches := s.prepareTxMatches([]*wtxmgr.TxRecord{n.TxRecord})
		return s.DBPutTxns(ctx, matches, n.Block)

	case chain.FilteredBlockConnected:
		matches := s.prepareTxMatches(n.RelevantTxs)
		return s.DBPutBlocks(ctx, matches, n.Block)
	}

	return nil
}

// prepareTxMatches extracts address entries from a batch of transactions and
// groups them by transaction hash.
func (s *syncer) prepareTxMatches(recs []*wtxmgr.TxRecord) TxEntries {
	matches := make(TxEntries, 0, len(recs))
	for _, rec := range recs {
		entries := s.extractAddrEntries(rec.MsgTx.TxOut)
		matches = append(matches, TxEntry{
			Rec:     rec,
			Entries: entries,
		})
	}

	return matches
}

// extractAddrEntries collects all addresses from transaction outputs and
// creates initial AddrEntry objects with output indices.
func (s *syncer) extractAddrEntries(txOuts []*wire.TxOut) []AddrEntry {
	var entries []AddrEntry
	for i, output := range txOuts {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, s.cfg.ChainParams,
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

					Index: uint32(i),
				},
			})
		}
	}

	return entries
}

// handleScanReq processes a user-initiated rescan request.
func (s *syncer) handleScanReq(ctx context.Context,
	req *scanReq) error {

	// If the wallet is already syncing or rescanning, we can't accept a
	// full resync request. This prevents conflicting rescan operations.
	if s.isRecoveryMode() {
		return fmt.Errorf("%w: wallet is currently %s",
			ErrStateForbidden, s.syncState())
	}

	if req.typ == scanTypeTargeted {
		return s.scanWithTargets(ctx, req)
	}

	return s.scanWithRewind(ctx, req)
}

// waitForEvent blocks until a notification, rescan job, or context
// cancellation occurs, processing the event accordingly.
func (s *syncer) waitForEvent(ctx context.Context) error {
	select {
	// Process asynchronous notifications from the chain backend, such as
	// new blocks or transactions.
	case n, ok := <-s.cfg.Chain.Notifications():
		if !ok {
			return ErrWalletShuttingDown
		}

		return s.handleChainUpdate(ctx, n)

	// Handle synchronous rescan or resync requests submitted via the
	// controller.
	case job := <-s.scanReqChan:
		return s.handleScanReq(ctx, job)

	// Exit gracefully if the context is canceled or the wallet is shutting
	// down.
	case <-ctx.Done():
		return ctx.Err()
	}
}

// scanWithRewind rewinds the wallet's sync status to the requested start
// block.
func (s *syncer) scanWithRewind(ctx context.Context, req *scanReq) error {
	current := s.addrStore.SyncedTo()

	if req.startBlock.Height >= current.Height {
		// Requested start is ahead of or equal to current sync.
		// Nothing to do (we are already synced past it).
		return nil
	}

	log.Infof("Rewinding sync status from %d to %d for rescan",
		current.Height, req.startBlock.Height)

	// Rewind the database status.
	err := s.DBPutRewind(ctx, req.startBlock)
	if err != nil {
		log.Errorf("Failed to rewind sync status: %v", err)

		return err
	}

	return nil
}

// scanWithTargets performs a targeted rescan for specific accounts without
// rewinding the global sync state.
func (s *syncer) scanWithTargets(ctx context.Context, req *scanReq) error {
	scanState, err := s.loadTargetedScanState(ctx, req.targets)
	if err != nil {
		return err
	}

	s.state.Store(uint32(syncStateRescanning))
	defer s.state.Store(uint32(syncStateSynced))

	startHeight := req.startBlock.Height

	_, bestHeight, err := s.cfg.Chain.GetBestBlock()
	if err != nil {
		return fmt.Errorf("get best block: %w", err)
	}

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
			return err
		}

		if len(results) == 0 {
			return fmt.Errorf("%w: fetchAndFilterBlocks returned "+
				"0 results", ErrScanBatchEmpty)
		}

		// Process results (update DB).
		err = s.DBPutTargetedBatch(ctx, results)
		if err != nil {
			return err
		}

		// Advance startHeight.
		//nolint:gosec // batch size is bounded.
		startHeight += int32(len(results))
	}

	log.Infof("Targeted rescan complete")

	return nil
}

// loadTargetedScanState initializes a recovery state for a targeted rescan of
// specific accounts.
func (s *syncer) loadTargetedScanState(ctx context.Context,
	targets []waddrmgr.AccountScope) (*RecoveryState, error) {

	horizonData, initialAddrs, initialUnspent, err :=
		s.loadTargetedScanData(ctx, targets)
	if err != nil {
		return nil, err
	}

	state := NewRecoveryState(
		s.cfg.RecoveryWindow, s.cfg.ChainParams, s.addrStore,
	)

	err = state.Initialize(horizonData, initialAddrs, initialUnspent)
	if err != nil {
		return nil, fmt.Errorf("init scan state: %w", err)
	}

	return state, nil
}

// loadTargetedScanData retrieves all necessary data from the database to
// initialize the recovery state for a targeted rescan.
func (s *syncer) loadTargetedScanData(ctx context.Context,
	targets []waddrmgr.AccountScope) ([]*waddrmgr.AccountProperties,
	[]btcutil.Address, []wtxmgr.Credit, error) {

	return s.DBGetScanData(ctx, targets)
}

// loadWalletScanData retrieves all necessary data from the database to
// initialize the recovery state. This includes account horizons, active
// addresses, and unspent outputs to watch.
func (s *syncer) loadWalletScanData(ctx context.Context) (
	[]*waddrmgr.AccountProperties, []btcutil.Address,
	[]wtxmgr.Credit, error) {

	var targets []waddrmgr.AccountScope
	for _, scopedMgr := range s.addrStore.ActiveScopedKeyManagers() {
		for _, accNum := range scopedMgr.ActiveAccounts() {
			targets = append(targets, waddrmgr.AccountScope{
				Scope:   scopedMgr.Scope(),
				Account: accNum,
			})
		}
	}

	return s.DBGetScanData(ctx, targets)
}
