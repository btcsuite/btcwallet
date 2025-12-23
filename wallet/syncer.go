//nolint:unused,revive // TODO(yy): remove it once implemented
package wallet

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
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
	return nil
}

// requestScan submits a rescan job to the syncer.
func (s *syncer) requestScan(ctx context.Context, req *scanReq) error {
	select {
	case s.scanReqChan <- req:
		return nil

	case <-ctx.Done():
		return fmt.Errorf("context done: %w", ctx.Err())
	}
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

		//nolint:gosec // i is bounded by batch size (2000), so
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

		//nolint:gosec // i is bounded by batch size (2000), so
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

// loadWalletScanData retrieves all necessary data from the database.
func (s *syncer) loadWalletScanData(ctx context.Context) (
	[]*waddrmgr.AccountProperties, []address.Address,
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
