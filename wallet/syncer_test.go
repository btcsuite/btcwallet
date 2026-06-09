package wallet

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs"
	"github.com/btcsuite/btcd/btcutil/gcs/builder"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestSyncerInitialization verifies that a new syncer is created with the
// correct default state.
func TestSyncerInitialization(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize mock dependencies for the syncer.
	mockAddrStore := &bwmock.AddrStore{}
	mockTxStore := &bwmock.TxStore{}
	mockPublisher := &mockTxPublisher{}

	// Act: Create a new syncer instance with a recovery window of 1.
	s := newSyncer(
		Config{RecoveryWindow: 1}, mockAddrStore, mockTxStore,
		mockPublisher,
		&walletmock.Store{}, 0,
	)

	// Assert: Verify that the syncer is correctly initialized in the
	// backend syncing state and is not in recovery mode.
	require.NotNil(t, s)
	require.Equal(t, syncStateBackendSyncing, s.syncState())
	require.False(t, s.isRecoveryMode())
}

// TestSyncerRequestScan verifies that scan requests are correctly accepted
// by the syncer's buffered channel.
func TestSyncerRequestScan(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer and a rewind scan request.
	mockAddrStore := &bwmock.AddrStore{}
	mockTxStore := &bwmock.TxStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{}, mockAddrStore, mockTxStore, mockPublisher,
		&walletmock.Store{}, 0,
	)

	req := &scanReq{
		typ: scanTypeRewind,
		startBlock: waddrmgr.BlockStamp{
			Height: 100,
		},
	}

	// Act: Submit the rewind request to the syncer.
	err := s.requestScan(t.Context(), req)

	// Assert: Ensure the request is accepted without error and is
	// correctly placed in the scan request channel.
	require.NoError(t, err)

	select {
	case received := <-s.scanReqChan:
		require.Equal(t, req, received)
	default:
		require.Fail(t, "request not received")
	}
}

// TestSyncerRequestScanBlocked verifies behavior when the channel is full.
func TestSyncerRequestScanBlocked(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and fill its scan request buffer.
	mockAddrStore := &bwmock.AddrStore{}
	mockTxStore := &bwmock.TxStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{}, mockAddrStore, mockTxStore, mockPublisher,
		&walletmock.Store{}, 0,
	)

	// Fill the buffer (size 1).
	s.scanReqChan <- &scanReq{}

	// Act: Attempt to submit another request with a context that is
	// already canceled.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := s.requestScan(ctx, &scanReq{})

	// Assert: Verify that the request fails as expected due to the
	// context cancellation.
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
}

// TestSyncerRun verifies the run implementation.
func TestSyncerRun(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and mock its chain and address store.
	mockChain := &bwmock.Chain{}
	mockAddrStore := &bwmock.AddrStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain}, mockAddrStore, nil, mockPublisher,
		&walletmock.Store{}, 0,
	)

	// context cancellation.
	mockAddrStore.On("Birthday").Return(time.Now()).Maybe()
	mockChain.On("IsCurrent").Return(false).Maybe()
	mockAddrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{}).Maybe()
	mockChain.On("NotifyBlocks").Return(nil).Maybe()

	// Act: Execute the syncer's run loop with a context that is canceled
	// immediately to stop the loop.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Assert: The run loop should exit without error.
	err := s.run(ctx)
	require.NoError(t, err)
}

// TestWaitUntilBackendSynced verifies polling logic.
func TestWaitUntilBackendSynced(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and mock its chain to simulate a
	// delayed synchronization.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	// Simulate the backend not being current on the first check, but
	// becoming current on the second check.
	mockChain.On("IsCurrent").Return(false).Once()
	mockChain.On("IsCurrent").Return(true).Once()

	// Act & Assert: Call waitUntilBackendSynced and verify it waits for
	// the backend to sync before returning successfully.
	err := s.waitUntilBackendSynced(t.Context())
	require.NoError(t, err)
	mockChain.AssertExpectations(t)
}

// TestCheckRollbackNoReorg verifies checkRollback when tips match.
func TestCheckRollbackNoReorg(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a store-backed syncer and mock chain.
	store := &walletmock.Store{}
	mockChain := &bwmock.Chain{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		store, uint32(0),
	)

	tip := waddrmgr.BlockStamp{Height: 100, Hash: chainhash.Hash{0x01}}
	expectSyncedTip(store, tip)

	// Mock retrieval of synced block hashes from the store for the last 10
	// blocks.
	localBlocks := make([]db.Block, 0, 10)
	for i := uint32(91); i <= 100; i++ {
		localBlocks = append(localBlocks, db.Block{
			Hash:   chainhash.Hash{byte(i)},
			Height: i,
		})
	}

	store.On("ListSyncedBlocks", mock.Anything, db.ListSyncedBlocksQuery{
		StartHeight: 91,
		EndHeight:   100,
	}).Return(localBlocks, nil).Once()

	// Mock retrieval of matching block hashes from the remote chain.
	remoteHashes := make([]chainhash.Hash, 10)
	for i := range 10 {
		remoteHashes[i] = chainhash.Hash{byte(91 + i)}
	}

	mockChain.On(
		"GetBlockHashes", int64(91), int64(100),
	).Return(remoteHashes, nil).Once()

	// Act & Assert: Verify that checkRollback completes without error
	// and no rollback is triggered when hashes match.
	err := s.checkRollback(t.Context())
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestCheckRollbackDetected verifies checkRollback when reorg is detected.
func TestCheckRollbackDetected(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a store-backed syncer and mocks to simulate a
	// chain reorganization.
	store := &walletmock.Store{}
	mockChain := &bwmock.Chain{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, mockPublisher,
		store, uint32(0),
	)

	tip := waddrmgr.BlockStamp{Height: 100, Hash: chainhash.Hash{0x01}}
	expectSyncedTip(store, tip)

	// Mock retrieval of synced block hashes from the store for blocks 91
	// to 100.
	localBlocks := make([]db.Block, 0, 10)
	for i := uint32(91); i <= 100; i++ {
		localBlocks = append(localBlocks, db.Block{
			Hash:   chainhash.Hash{byte(i)},
			Height: i,
		})
	}

	store.On("ListSyncedBlocks", mock.Anything, db.ListSyncedBlocksQuery{
		StartHeight: 91,
		EndHeight:   100,
	}).Return(localBlocks, nil).Once()

	// Mock retrieval of remote block hashes where a fork occurs at
	// height 95.
	remoteHashes := make([]chainhash.Hash, 10)
	for i := range 10 {
		h := 91 + i
		if h > 95 {
			remoteHashes[i] = chainhash.Hash{0xff} // Mismatch
		} else {
			remoteHashes[i] = chainhash.Hash{byte(h)} // Match
		}
	}

	mockChain.On(
		"GetBlockHashes", int64(91), int64(100),
	).Return(remoteHashes, nil).Once()

	// Mock header retrieval for the detected fork point at height 95.
	forkHash := chainhash.Hash{byte(95)}
	header := &wire.BlockHeader{Timestamp: time.Now()}
	mockChain.On("GetBlockHeader", &forkHash).Return(header, nil).Once()

	// Expect a single atomic rollback to the common ancestor: rewindToBlock
	// rolls transaction state back and rewinds the sync tip together via
	// RollbackToBlock for the rollback boundary (fork height 95 + 1).
	store.On(
		"RollbackToBlock", mock.Anything, uint32(96),
	).Return(nil).Once()

	// Act & Assert: Verify that checkRollback correctly identifies the
	// fork and performs the rollback.
	err := s.checkRollback(t.Context())
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestInitChainSync verifies the initial synchronization sequence.
func TestInitChainSync(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a store-backed syncer and mock its dependencies
	// for the initial synchronization sequence.
	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, mockPublisher,
		store, uint32(0),
	)

	// Mock backend synchronization check.
	mockChain.On("IsCurrent").Return(true).Once()

	// Mock block notification registration.
	mockChain.On("NotifyBlocks").Return(nil).Once()

	// Mock the synced tip read at the start of the rollback check. A height
	// of 0 means checkRollback reads the tip and returns without scanning
	// any block ranges.
	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 0})

	// Act & Assert: Verify that the initial chain synchronization
	// sequence completes successfully.
	err := s.initChainSync(t.Context())
	require.NoError(t, err)
}

// TestScanBatchHeadersOnly verifies header-only scan logic.
func TestScanBatchHeadersOnly(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and mock block and header retrieval.
	mockChain := &bwmock.Chain{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, mockPublisher,
		&walletmock.Store{}, 0,
	)

	hashes := []chainhash.Hash{{0x01}, {0x02}}
	mockChain.On(
		"GetBlockHashes", int64(10), int64(11),
	).Return(hashes, nil).Once()

	headers := []*wire.BlockHeader{
		{Timestamp: time.Unix(100, 0)},
		{Timestamp: time.Unix(200, 0)},
	}
	mockChain.On("GetBlockHeaders", hashes).Return(headers, nil).Once()

	// Act: Perform a header-only scan for blocks 10 and 11.
	results, err := s.scanBatchHeadersOnly(t.Context(), 10, 11)

	// Assert: Verify that the correct block results are returned with
	// expected heights.
	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Equal(t, int32(10), results[0].meta.Height)
	require.Equal(t, int32(11), results[1].meta.Height)
}

// TestSyncerLoadScanState verifies full scan state loading.
func TestSyncerLoadScanState(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a store-backed syncer and set up mock
	// expectations for loading wallet scan data. Scan-data loading reads
	// account horizons, addresses, and watch outputs through the store,
	// while the recovery state still derives the lookahead window through
	// the legacy address manager.
	const walletID uint32 = 21

	store := &walletmock.Store{}
	mockAddrStore := &bwmock.AddrStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{
			RecoveryWindow: 10,
			ChainParams:    &chainParams,
		},
		mockAddrStore, nil, mockPublisher,
		store, walletID,
	)

	// The store returns one derived BIP0084 account, used for both the
	// horizon and address loads.
	store.On("ListAccounts", mock.Anything, mock.MatchedBy(
		func(query db.ListAccountsQuery) bool {
			return query.WalletID == walletID && query.SkipBalance
		},
	)).Return([]db.AccountInfo{{
		AccountNumber: 0,
		KeyScope:      db.KeyScopeBIP0084,
	}}, nil).Twice()

	store.On("ListAddresses", mock.Anything, mock.Anything).Return(
		page.Result[db.AddressInfo, uint32]{}, nil,
	).Once()

	store.On(
		"ListOutputsToWatch", mock.Anything, walletID,
	).Return([]db.UtxoInfo(nil), nil).Once()

	// The recovery state derives the lookahead window for the account's
	// branches through the legacy address manager.
	scopedMgr := &bwmock.AccountStore{}
	mockAddrStore.On(
		"FetchScopedKeyManager", mock.Anything,
	).Return(scopedMgr, nil).Maybe()

	mockAddr := &bwmock.Address{}
	mockAddr.On("EncodeAddress").Return("addr")
	mockAddr.On("ScriptAddress").Return([]byte{0x00})
	scopedMgr.On(
		"DeriveAddr", mock.Anything, mock.Anything, mock.Anything,
	).Return(
		mockAddr, []byte{0x00}, nil,
	).Maybe()

	// Act: Load the full scan state.
	state, err := s.loadFullScanState(t.Context())

	// Assert: Verify that the scan state is correctly loaded and not nil.
	require.NoError(t, err)
	require.NotNil(t, state)
	store.AssertExpectations(t)
}

// TestScanBatchWithFullBlocks verifies fallback scan logic.
func TestScanBatchWithFullBlocks(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and a recovery state for scanning.
	mockChain := &bwmock.Chain{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, mockPublisher,
		&walletmock.Store{}, 0,
	)

	mockAddrStore := &bwmock.AddrStore{}
	scanState := NewRecoveryState(
		10, &chainParams, mockAddrStore,
	)

	hashes := []chainhash.Hash{{0x01}}

	// Create a mock block message for testing.
	msgBlock := wire.NewMsgBlock(wire.NewBlockHeader(
		1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))
	blocks := []*wire.MsgBlock{msgBlock}
	mockChain.On(
		"GetBlocks", hashes,
	).Return(blocks, nil).Once()

	// Act: Perform a batch scan using full blocks.
	results, err := s.scanBatchWithFullBlocks(
		t.Context(), scanState, 10, hashes,
	)

	// Assert: Verify that the scan returned the expected block result.
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, int32(10), results[0].meta.Height)
}

// TestScanBatchWithCFilters verifies CFilter-based scan logic.
func TestScanBatchWithCFilters(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and set up a recovery state.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &bwmock.Chain{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain, DB: db}, nil, nil, mockPublisher,
		&walletmock.Store{}, 0,
	)

	mockAddrStore := &bwmock.AddrStore{}
	scanState := NewRecoveryState(
		10, &chainParams, mockAddrStore,
	)

	hashes := []chainhash.Hash{{0x01}}

	// Mock retrieval of compact filters for the block batch.
	filter, err := gcs.BuildGCSFilter(
		builder.DefaultP, builder.DefaultM, [16]byte{}, nil,
	)
	require.NoError(t, err)
	mockChain.On(
		"GetCFilters", hashes, wire.GCSFilterRegular,
	).Return([]*gcs.Filter{filter}, nil).Once()

	// Mock retrieval of block headers for the batch.
	headers := []*wire.BlockHeader{{Timestamp: time.Unix(100, 0)}}
	mockChain.On("GetBlockHeaders", hashes).Return(headers, nil).Once()

	// Mock retrieval of full blocks for the batch (simulating a filter
	// match).
	msgBlock := wire.NewMsgBlock(wire.NewBlockHeader(
		1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))
	mockChain.On("GetBlocks", hashes).Return(
		[]*wire.MsgBlock{msgBlock}, nil,
	).Once()

	// Mock address store failures to simplify the test path and avoid
	// deep derivation logic.
	mockAddrStore.On(
		"Address", mock.Anything, mock.Anything,
	).Return(nil, waddrmgr.ErrAddressNotFound).Maybe()
	mockAddrStore.On(
		"FetchScopedKeyManager", mock.Anything,
	).Return(nil, waddrmgr.ErrAddressNotFound).Maybe()

	// Act: Perform a batch scan using CFilters.
	results, err := s.scanBatchWithCFilters(
		t.Context(), scanState, 10, hashes,
	)

	// Assert: Verify that the scan results are correct.
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, int32(10), results[0].meta.Height)
}

// TestDispatchScanStrategy verifies strategy selection.
func TestDispatchScanStrategy(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and mock dependencies.
	mockChain := &bwmock.Chain{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, mockPublisher,
		&walletmock.Store{}, 0,
	)

	scanState := NewRecoveryState(10, &chainParams, nil)
	hashes := []chainhash.Hash{{0x01}}

	// 1. Test the SyncMethodFullBlocks strategy.
	s.cfg.SyncMethod = SyncMethodFullBlocks
	msgBlock := wire.NewMsgBlock(wire.NewBlockHeader(
		1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))
	mockChain.On(
		"GetBlocks", hashes,
	).Return([]*wire.MsgBlock{msgBlock}, nil).Once()

	// Act: Dispatch the scan strategy for full blocks.
	results, err := s.dispatchScanStrategy(
		t.Context(), scanState, 10, hashes,
	)

	// Assert: Verify that full blocks strategy was used.
	require.NoError(t, err)
	require.Len(t, results, 1)

	// 2. Test the SyncMethodCFilters strategy.
	s.cfg.SyncMethod = SyncMethodCFilters
	filter, err := gcs.BuildGCSFilter(
		builder.DefaultP, builder.DefaultM, [16]byte{}, nil,
	)
	require.NoError(t, err)

	mockChain.On(
		"GetCFilters", hashes, wire.GCSFilterRegular,
	).Return([]*gcs.Filter{filter}, nil).Once()
	mockChain.On(
		"GetBlockHeaders", hashes,
	).Return([]*wire.BlockHeader{{}}, nil).Once()

	// Simulate a filter match (N=0) to force a full block download.
	mockChain.On(
		"GetBlocks", hashes,
	).Return([]*wire.MsgBlock{msgBlock}, nil).Once()

	// Act: Dispatch the scan strategy for CFilters.
	results, err = s.dispatchScanStrategy(
		t.Context(), scanState, 10, hashes,
	)

	// Assert: Verify that CFilters strategy was used.
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// TestScanBatch verifies the batch scanning entry point.
func TestScanBatch(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a store-backed syncer and set up mocks for the
	// batch scan. Scan data (one derived account, no addresses, no watch
	// outputs) is loaded through the store.
	mockAddrStore := &bwmock.AddrStore{}
	mockChain := &bwmock.Chain{}
	mockPublisher := &mockTxPublisher{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{Chain: mockChain}, mockAddrStore, nil, mockPublisher,
		store, uint32(0),
	)

	store.On("ListAccounts", mock.Anything, mock.Anything).Return(
		[]db.AccountInfo{{KeyScope: db.KeyScopeBIP0084}}, nil,
	).Twice()
	store.On("ListAddresses", mock.Anything, mock.Anything).Return(
		page.Result[db.AddressInfo, uint32]{}, nil,
	).Once()
	store.On("ListOutputsToWatch", mock.Anything, mock.Anything).Return(
		[]db.UtxoInfo(nil), nil,
	).Once()

	// The recovery state resolves the account's branches through the legacy
	// address manager.
	scopedMgr := &bwmock.AccountStore{}
	mockAddrStore.On(
		"FetchScopedKeyManager", mock.Anything,
	).Return(scopedMgr, nil).Maybe()

	// Mock expectations for header-only scanning when no targets are
	// present.
	hashes := []chainhash.Hash{{0x01}}
	mockChain.On(
		"GetBlockHashes", int64(11), int64(11),
	).Return(hashes, nil).Once()
	mockChain.On(
		"GetBlockHeaders", hashes,
	).Return([]*wire.BlockHeader{{}}, nil).Once()

	// Expect the scan batch to be written through the store, advancing the
	// synced tip.
	store.On("ApplyScanBatch", mock.Anything, mock.Anything).Return(
		nil).Once()

	// Act: Perform a batch scan from height 10 to 11.
	err := s.scanBatch(t.Context(), waddrmgr.BlockStamp{Height: 10}, 11)

	// Assert: Verify that the batch scan completed successfully.
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestFetchAndFilterBlocks verifies the block fetching and filtering helper.
func TestFetchAndFilterBlocks(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and mock chain for block fetching.
	mockChain := &bwmock.Chain{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, mockPublisher,
		&walletmock.Store{}, 0,
	)

	// Create an empty recovery state for testing.
	scanState := NewRecoveryState(10, &chainParams, nil)
	hashes := []chainhash.Hash{{0x01}}

	// Mock expectations for header-only scanning when the recovery state
	// is empty.
	mockChain.On(
		"GetBlockHashes", int64(10), int64(11),
	).Return(hashes, nil).Once()
	mockChain.On(
		"GetBlockHeaders", hashes,
	).Return([]*wire.BlockHeader{{}}, nil).Once()

	// Act: Fetch and filter blocks for heights 10 to 11.
	results, err := s.fetchAndFilterBlocks(t.Context(), scanState, 10, 11)

	// Assert: Verify that the block results are correct.
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// TestAdvanceChainSync verifies advancement logic.
func TestAdvanceChainSync(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a store-backed syncer and mocks to test the
	// chain synchronization advancement logic.
	const walletID uint32 = 22

	mockChain := &bwmock.Chain{}
	mockAddrStore := &bwmock.AddrStore{}
	mockPublisher := &mockTxPublisher{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{Chain: mockChain}, mockAddrStore, nil, mockPublisher,
		store, walletID,
	)

	// The synced tip is read from the store as height 100 for both the
	// already-synced case and the behind case.
	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})

	// Case 1: Test advancement when the wallet is already synced to the
	// best block.
	mockChain.On(
		"GetBestBlock",
	).Return(&chainhash.Hash{}, int32(100), nil).Once()

	// Act & Assert: Advance the chain sync and verify that it correctly
	// identifies the synced state.
	finished, err := s.advanceChainSync(t.Context())
	require.NoError(t, err)
	require.True(t, finished)
	require.Equal(t, syncStateSynced, s.syncState())

	// Case 2: Test advancement when the wallet is behind and needs to
	// trigger a scan.
	mockChain.On("GetBestBlock").Return(
		&chainhash.Hash{}, int32(105), nil,
	).Once()

	// Set up mocks for the batch scan triggered by advancement. Scan data
	// is loaded through the store: one derived BIP0084 account, no active
	// addresses, and no watch outputs.
	store.On("ListAccounts", mock.Anything, mock.Anything).Return(
		[]db.AccountInfo{{
			AccountNumber: 0,
			KeyScope:      db.KeyScopeBIP0084,
		}}, nil,
	).Twice()
	store.On("ListAddresses", mock.Anything, mock.Anything).Return(
		page.Result[db.AddressInfo, uint32]{}, nil,
	).Once()
	store.On("ListOutputsToWatch", mock.Anything, walletID).Return(
		[]db.UtxoInfo(nil), nil,
	).Once()

	// The recovery state resolves the account's branches through the legacy
	// address manager. With a zero recovery window no lookahead addresses
	// are derived, so DeriveAddr is optional.
	scopedMgr := &bwmock.AccountStore{}
	mockAddrStore.On(
		"FetchScopedKeyManager", mock.Anything,
	).Return(scopedMgr, nil).Maybe()
	scopedMgr.On(
		"DeriveAddr", mock.Anything, mock.Anything, mock.Anything,
	).Return(
		&bwmock.Address{}, []byte{}, nil,
	).Maybe()

	// Mock fetching and filtering of blocks for the missing height range.
	// Mock retrieval of block hashes when scan targets are present.
	hashes := []chainhash.Hash{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}}
	mockChain.On(
		"GetBlockHashes", int64(101), int64(105),
	).Return(hashes, nil).Once()

	// Mock the scan strategy dispatch for the block batch.
	filter, err := gcs.BuildGCSFilter(
		builder.DefaultP, builder.DefaultM, [16]byte{}, nil,
	)
	require.NoError(t, err)

	filters := make([]*gcs.Filter, 5)
	for i := range 5 {
		filters[i] = filter
	}

	mockChain.On(
		"GetCFilters", hashes, wire.GCSFilterRegular,
	).Return(filters, nil).Once()

	headers := make([]*wire.BlockHeader, 5)
	for i := range 5 {
		headers[i] = &wire.BlockHeader{}
	}

	mockChain.On("GetBlockHeaders", hashes).Return(headers, nil).Once()

	// Simulate filter matches for all blocks to force full block downloads.
	msgBlock := wire.NewMsgBlock(wire.NewBlockHeader(
		1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))

	blocks := make([]*wire.MsgBlock, 5)
	for i := range 5 {
		blocks[i] = msgBlock
	}

	mockChain.On("GetBlocks", hashes).Return(blocks, nil).Once()

	// Expect the batch scan results to be written through the store, which
	// advances the synced tip for the batch.
	store.On("ApplyScanBatch", mock.Anything, mock.Anything).Return(
		nil).Once()

	// Act & Assert: Advance the chain sync and verify that it triggers
	// the expected batch scan.
	finished, err = s.advanceChainSync(t.Context())
	require.NoError(t, err)
	require.False(t, finished)
	store.AssertExpectations(t)
}

// TestHandleChainUpdate verifies notification handling.
func TestHandleChainUpdate(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a store-backed syncer for handling chain
	// updates.
	const walletID uint32 = 23

	mockChain := &bwmock.Chain{}
	mockPublisher := &mockTxPublisher{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{Chain: mockChain, ChainParams: &chainParams}, nil, nil,
		mockPublisher,
		store, walletID,
	)

	// Case 1: Test handling of a BlockConnected notification, which
	// advances the synced tip through the store.
	meta := wtxmgr.BlockMeta{Block: wtxmgr.Block{Height: 100}}

	store.On("UpdateWallet", mock.Anything, mock.Anything).Return(
		nil).Once()

	// Act & Assert: Verify that a BlockConnected notification is
	// correctly processed.
	err := s.handleChainUpdate(t.Context(), chain.BlockConnected(meta))
	require.NoError(t, err)

	// Case 2: Test handling of a RelevantTx notification, which records the
	// transaction through the store batch path.
	tx := wire.NewMsgTx(1)
	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	require.NoError(t, err)
	store.On("ApplyTxBatch", mock.Anything, mock.Anything).Return(
		nil).Once()

	// Act & Assert: Verify that a RelevantTx notification is correctly
	// processed.
	err = s.handleChainUpdate(t.Context(), chain.RelevantTx{TxRecord: rec})
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// matchRelevantTxParams reports whether the single batched transaction carries
// the expected wallet, hash, receive time, credit address, and published
// status. Block confirmation is validated separately by the caller.
func matchRelevantTxParams(txParams db.CreateTxParams, walletID uint32,
	tx *wire.MsgTx, addr btcutil.Address, received time.Time) bool {

	creditAddr, ok := txParams.Credits[0]
	if !ok || creditAddr == nil || txParams.Tx == nil {
		return false
	}

	return txParams.WalletID == walletID &&
		txParams.Tx.TxHash() == tx.TxHash() &&
		txParams.Received.Equal(received) &&
		txParams.Status == db.TxStatusPublished &&
		creditAddr.EncodeAddress() == addr.EncodeAddress()
}

// matchUnminedTxBatch returns a matcher asserting an unmined relevant
// transaction is written as a single store batch with the expected credit and
// no confirming block.
func matchUnminedTxBatch(walletID uint32, tx *wire.MsgTx,
	addr btcutil.Address, received time.Time) any {

	return mock.MatchedBy(func(params db.TxBatchParams) bool {
		if params.WalletID != walletID ||
			len(params.Transactions) != 1 {

			return false
		}

		txParams := params.Transactions[0]
		if txParams.Block != nil {
			return false
		}

		return matchRelevantTxParams(
			txParams, walletID, tx, addr, received,
		)
	})
}

// expectAddressOwned registers Store.GetAddress expectations so
// applyStoreTxBatch treats the supplied addresses as wallet-owned. Each owned
// address is matched by its own PayToAddrScript (the script applyStoreTxBatch
// resolves with) and resolves to a minimal AddressInfo. Any other address query
// resolves to ErrAddressNotFound, modeling a third-party output that must be
// dropped.
func expectAddressOwned(t *testing.T, store *walletmock.Store, walletID uint32,
	owned ...btcutil.Address) {

	t.Helper()

	ownedScripts := make(map[string]struct{}, len(owned))
	for _, addr := range owned {
		script, err := txscript.PayToAddrScript(addr)
		require.NoError(t, err)

		ownedScripts[string(script)] = struct{}{}

		store.On("GetAddress", mock.Anything, db.GetAddressQuery{
			WalletID:     walletID,
			ScriptPubKey: script,
		}).Return(&db.AddressInfo{ScriptPubKey: script}, nil).Maybe()
	}

	// Every other script the syncer resolves is not wallet-owned, which the
	// Store reports as ErrAddressNotFound.
	store.On("GetAddress", mock.Anything, mock.MatchedBy(
		func(query db.GetAddressQuery) bool {
			if query.WalletID != walletID {
				return false
			}

			_, ok := ownedScripts[string(query.ScriptPubKey)]

			return !ok
		},
	)).Return(nil, db.ErrAddressNotFound).Maybe()
}

// expectSyncedTip mocks Store.GetWallet so syncedTip returns the given synced
// tip for any wallet name. A height of -1 is encoded as a nil SyncedTo,
// matching how an unsynced wallet is represented; any other height is encoded
// as a stored block.
func expectSyncedTip(store *walletmock.Store, tip waddrmgr.BlockStamp) {
	var info db.WalletInfo
	if tip.Height >= 0 {
		info.SyncedTo = &db.Block{
			Hash:      tip.Hash,
			Height:    uint32(tip.Height),
			Timestamp: tip.Timestamp,
		}
	}

	store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&info, nil).Maybe()
}

// serializeTx returns the wire encoding of tx, for stubbing TxInfo.SerializedTx
// in store-backed unmined-transaction reads.
func serializeTx(t *testing.T, tx *wire.MsgTx) []byte {
	t.Helper()

	var buf bytes.Buffer

	require.NoError(t, tx.Serialize(&buf))

	return buf.Bytes()
}

// TestProcessRelevantTxUsesStore verifies that relevant transaction
// notifications are routed through the store when store wiring is available.
func TestProcessRelevantTxUsesStore(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer with store wiring and a transaction paying to a
	// wallet-owned address.
	const walletID uint32 = 7

	store := &walletmock.Store{}
	publisher := &mockTxPublisher{}
	s := newSyncer(
		Config{ChainParams: &chainParams}, nil, nil, publisher,
		store, walletID,
	)

	addr, err := btcutil.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	tx := wire.NewMsgTx(1)
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: pkScript})

	received := time.Unix(123, 0).UTC()
	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, received)
	require.NoError(t, err)

	expectAddressOwned(t, store, walletID, addr)
	store.On("ApplyTxBatch", mock.Anything,
		matchUnminedTxBatch(walletID, tx, addr, received),
	).Return(nil).Once()

	// Act: Process an unconfirmed relevant transaction notification.
	err = s.processChainUpdate(t.Context(), chain.RelevantTx{TxRecord: rec})

	// Assert: The notification was written through the store batch API.
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// matchStoreBlockFields reports whether a store block matches the wtxmgr block
// metadata's hash, height, and timestamp.
func matchStoreBlockFields(b *db.Block, block *wtxmgr.BlockMeta) bool {
	return b.Hash == block.Hash &&
		b.Height == uint32(block.Height) &&
		b.Timestamp.Equal(block.Time)
}

// matchBlockTxBatch returns a matcher asserting a filtered block transaction is
// written as one store batch together with the matching sync-tip update.
func matchBlockTxBatch(walletID uint32, tx *wire.MsgTx, addr btcutil.Address,
	received time.Time, block *wtxmgr.BlockMeta) any {

	return mock.MatchedBy(func(params db.TxBatchParams) bool {
		if params.WalletID != walletID ||
			len(params.Transactions) != 1 ||
			params.SyncedTo == nil {

			return false
		}

		txParams := params.Transactions[0]
		if txParams.Block == nil ||
			!matchStoreBlockFields(txParams.Block, block) {

			return false
		}

		if !matchStoreBlockFields(params.SyncedTo, block) {
			return false
		}

		return matchRelevantTxParams(
			txParams, walletID, tx, addr, received,
		)
	})
}

// newBareMultisigScript builds a 1-of-2 bare-multisig output script and returns
// the two member pubkey addresses it pays to.
func newBareMultisigScript(t *testing.T) ([]btcutil.Address, []byte) {
	t.Helper()

	firstKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	secondKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	firstAddr, err := btcutil.NewAddressPubKey(
		firstKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	secondAddr, err := btcutil.NewAddressPubKey(
		secondKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	builder := txscript.NewScriptBuilder()
	builder.AddInt64(1)
	builder.AddData(firstKey.PubKey().SerializeCompressed())
	builder.AddData(secondKey.PubKey().SerializeCompressed())
	builder.AddInt64(2)
	builder.AddOp(txscript.OP_CHECKMULTISIG)

	script, err := builder.Script()
	require.NoError(t, err)

	return []btcutil.Address{firstAddr, secondAddr}, script
}

// matchMultisigCreditBatch returns a matcher asserting a filtered block
// transaction is written as one store batch whose index-0 credit carries one of
// the bare-multisig member addresses (rather than being dropped).
func matchMultisigCreditBatch(walletID uint32, tx *wire.MsgTx,
	members []btcutil.Address, block *wtxmgr.BlockMeta) any {

	want := make(map[string]struct{}, len(members))
	for _, member := range members {
		want[member.EncodeAddress()] = struct{}{}
	}

	return mock.MatchedBy(func(params db.TxBatchParams) bool {
		if params.WalletID != walletID ||
			len(params.Transactions) != 1 ||
			params.SyncedTo == nil {

			return false
		}

		return matchMultisigCreditTx(
			params.Transactions[0], tx, block, want,
		)
	})
}

// matchMultisigCreditTx reports whether the batched transaction params record
// the expected multisig transaction with a credit owned by one of the wanted
// member addresses.
func matchMultisigCreditTx(txParams db.CreateTxParams, tx *wire.MsgTx,
	block *wtxmgr.BlockMeta, want map[string]struct{}) bool {

	if txParams.Tx == nil ||
		txParams.Tx.TxHash() != tx.TxHash() ||
		txParams.Block == nil ||
		!matchStoreBlockFields(txParams.Block, block) {

		return false
	}

	credit, ok := txParams.Credits[0]
	if !ok || credit == nil {
		return false
	}

	_, found := want[credit.EncodeAddress()]

	return found
}

// TestProcessFilteredBlockBareMultisigCredit verifies that a bare-multisig
// output owned through a member pubkey survives the applyStoreTxBatch path.
// PayToAddrScript(member) does not equal the multisig output script, so the
// removed GetAddress(outputScript) lookup would have missed and dropped the
// credit; the credit must instead be carried from the matched member address.
func TestProcessFilteredBlockBareMultisigCredit(t *testing.T) {
	t.Parallel()

	// Arrange: Create a store-backed syncer and a filtered block containing a
	// bare-multisig output.
	const walletID uint32 = 11

	store := &walletmock.Store{}
	publisher := &mockTxPublisher{}
	s := newSyncer(
		Config{ChainParams: &chainParams}, nil, nil, publisher,
		store, walletID,
	)

	members, pkScript := newBareMultisigScript(t)

	tx := wire.NewMsgTx(1)
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: pkScript})

	received := time.Unix(456, 0).UTC()
	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, received)
	require.NoError(t, err)

	blockTime := time.Unix(789, 0).UTC()
	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   chainhash.Hash{0x0c},
			Height: 102,
		},
		Time: blockTime,
	}

	expectAddressOwned(t, store, walletID, members...)
	store.On("ApplyTxBatch", mock.Anything,
		matchMultisigCreditBatch(walletID, tx, members, block),
	).Return(nil).Once()

	// Act: Process a filtered block connected notification.
	err = s.processChainUpdate(t.Context(), chain.FilteredBlockConnected{
		Block:       block,
		RelevantTxs: []*wtxmgr.TxRecord{rec},
	})

	// Assert: The member-owned credit was written through the store batch API
	// instead of being dropped.
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// matchOwnedCreditOnlyBatch returns a matcher asserting a filtered block
// transaction is written as one store batch whose Credits hold exactly the
// single owned address at ownedIndex and omit every other output index, so a
// third-party output sharing the same transaction is never credited.
// matchOwnedCreditOnlyTxShape reports whether the batch carries exactly the one
// expected wallet transaction confirmed in the expected block, ignoring its
// credits. Pulling the transaction-shape checks out of the matcher keeps the
// matcher's cyclomatic complexity within bounds.
func matchOwnedCreditOnlyTxShape(params db.TxBatchParams, walletID uint32,
	tx *wire.MsgTx, block *wtxmgr.BlockMeta) bool {

	if params.WalletID != walletID ||
		len(params.Transactions) != 1 ||
		params.SyncedTo == nil {

		return false
	}

	txParams := params.Transactions[0]

	return txParams.Tx != nil &&
		txParams.Tx.TxHash() == tx.TxHash() &&
		txParams.Block != nil &&
		matchStoreBlockFields(txParams.Block, block)
}

func matchOwnedCreditOnlyBatch(walletID uint32, tx *wire.MsgTx,
	owned btcutil.Address, ownedIndex uint32, block *wtxmgr.BlockMeta) any {

	return mock.MatchedBy(func(params db.TxBatchParams) bool {
		if !matchOwnedCreditOnlyTxShape(params, walletID, tx, block) {
			return false
		}

		// Only the wallet-owned output is credited: exactly one credit,
		// at the owned index, carrying the owned address.
		if len(params.Transactions[0].Credits) != 1 {
			return false
		}

		credit, ok := params.Transactions[0].Credits[ownedIndex]

		return ok && credit != nil &&
			credit.EncodeAddress() == owned.EncodeAddress()
	})
}

// TestProcessFilteredBlockDropsThirdPartyCredit verifies that a relevant
// transaction carrying both a wallet-owned output and an unrelated third-party
// output credits only the owned output. extractAddrEntries pulls every output
// address, so without the ownership filter applyStoreTxBatch would also credit
// the third-party output and ApplyTxBatch would fail with ErrAddressNotFound.
func TestProcessFilteredBlockDropsThirdPartyCredit(t *testing.T) {
	t.Parallel()

	// Arrange: Create a store-backed syncer and a filtered block whose single
	// relevant transaction pays both a wallet-owned output (index 0) and a
	// third-party output (index 1).
	const walletID uint32 = 13

	store := &walletmock.Store{}
	publisher := &mockTxPublisher{}
	s := newSyncer(
		Config{ChainParams: &chainParams}, nil, nil, publisher,
		store, walletID,
	)

	ownedAddr, err := btcutil.NewAddressPubKeyHash(
		bytes.Repeat([]byte{0x01}, 20), &chainParams,
	)
	require.NoError(t, err)

	ownedScript, err := txscript.PayToAddrScript(ownedAddr)
	require.NoError(t, err)

	thirdPartyAddr, err := btcutil.NewAddressPubKeyHash(
		bytes.Repeat([]byte{0x02}, 20), &chainParams,
	)
	require.NoError(t, err)

	thirdPartyScript, err := txscript.PayToAddrScript(thirdPartyAddr)
	require.NoError(t, err)

	tx := wire.NewMsgTx(1)
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: ownedScript})
	tx.AddTxOut(&wire.TxOut{Value: 2000, PkScript: thirdPartyScript})

	received := time.Unix(456, 0).UTC()
	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, received)
	require.NoError(t, err)

	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   chainhash.Hash{0x0d},
			Height: 103,
		},
		Time: time.Unix(789, 0).UTC(),
	}

	// Only the owned address resolves; the third-party address is reported as
	// ErrAddressNotFound and must be dropped before crediting.
	expectAddressOwned(t, store, walletID, ownedAddr)
	store.On("ApplyTxBatch", mock.Anything,
		matchOwnedCreditOnlyBatch(walletID, tx, ownedAddr, 0, block),
	).Return(nil).Once()

	// Act: Process a filtered block connected notification.
	err = s.processChainUpdate(t.Context(), chain.FilteredBlockConnected{
		Block:       block,
		RelevantTxs: []*wtxmgr.TxRecord{rec},
	})

	// Assert: Only the wallet-owned output was credited and the batch applied
	// successfully without an ErrAddressNotFound failure.
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestProcessFilteredBlockUsesStore verifies that filtered block notifications
// are routed through the store as one transaction batch with a sync-tip update.
func TestProcessFilteredBlockUsesStore(t *testing.T) {
	t.Parallel()

	// Arrange: Create a store-backed syncer and a filtered block containing a
	// wallet-owned transaction output.
	const walletID uint32 = 9

	store := &walletmock.Store{}
	publisher := &mockTxPublisher{}
	s := newSyncer(
		Config{ChainParams: &chainParams}, nil, nil, publisher,
		store, walletID,
	)

	addr, err := btcutil.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	tx := wire.NewMsgTx(1)
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: pkScript})

	received := time.Unix(456, 0).UTC()
	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, received)
	require.NoError(t, err)

	blockTime := time.Unix(789, 0).UTC()
	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   chainhash.Hash{0x09},
			Height: 101,
		},
		Time: blockTime,
	}

	expectAddressOwned(t, store, walletID, addr)
	store.On("ApplyTxBatch", mock.Anything,
		matchBlockTxBatch(walletID, tx, addr, received, block),
	).Return(nil).Once()

	// Act: Process a filtered block connected notification.
	err = s.processChainUpdate(t.Context(), chain.FilteredBlockConnected{
		Block:       block,
		RelevantTxs: []*wtxmgr.TxRecord{rec},
	})

	// Assert: The block transaction and sync tip were written together.
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// storeScanBatchFixture contains expected values for store scan batch tests.
type storeScanBatchFixture struct {
	result      scanResult
	tx          *wire.MsgTx
	addr        btcutil.Address
	scope       waddrmgr.BranchScope
	accountName string
	block       *wtxmgr.BlockMeta
	received    time.Time
}

// newStoreScanBatchFixture builds one scan result with a horizon and wallet
// transaction output.
func newStoreScanBatchFixture(t *testing.T) storeScanBatchFixture {
	t.Helper()

	addr, err := btcutil.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	tx := wire.NewMsgTx(1)
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: pkScript})

	rec, err := wtxmgr.NewTxRecordFromMsgTx(
		tx, time.Unix(1, 0).UTC(),
	)
	require.NoError(t, err)

	scope := waddrmgr.BranchScope{
		Scope:   waddrmgr.KeyScopeBIP0084,
		Account: 2,
		Branch:  waddrmgr.InternalBranch,
	}

	blockTime := time.Unix(789, 0).UTC()
	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   chainhash.Hash{0x0b},
			Height: 111,
		},
		Time: blockTime,
	}

	const accountName = "watch-only-xpub"

	return storeScanBatchFixture{
		accountName: accountName,
		result: scanResult{
			BlockProcessResult: &BlockProcessResult{
				FoundHorizons: map[waddrmgr.BranchScope]uint32{
					scope: 12,
				},
				RelevantOutputs: TxEntries{{
					Rec: rec,
					Entries: []AddrEntry{{
						Address: addr,
						Credit: wtxmgr.CreditEntry{
							Index: 0,
						},
					}},
				}},
			},
			meta: block,
		},
		tx:       tx,
		addr:     addr,
		scope:    scope,
		block:    block,
		received: blockTime,
	}
}

// newStoreScanBatchScanState builds a recovery state whose account-name lookup
// resolves the fixture's branch-scope account to its durable name. This is the
// identity the syncer stamps onto every emitted horizon.
func newStoreScanBatchScanState(
	fixture storeScanBatchFixture) *RecoveryState {

	scanState := NewRecoveryState(0, &chainParams, nil)
	scanState.accountNames[waddrmgr.AccountScope{
		Scope:   fixture.scope.Scope,
		Account: fixture.scope.Account,
	}] = fixture.accountName

	return scanState
}

// matchStoreScanHorizon reports whether a scan horizon matches the fixture's
// branch scope at the expected discovered index.
func matchStoreScanHorizon(horizon db.ScanHorizon,
	fixture storeScanBatchFixture) bool {

	return horizon.Scope == db.KeyScope(fixture.scope.Scope) &&
		horizon.Account == fixture.scope.Account &&
		horizon.AccountName == fixture.accountName &&
		horizon.Branch == fixture.scope.Branch &&
		horizon.Index == 12
}

// matchStoreScanSyncedBlocks reports whether the batch's synced blocks match
// the expectation implied by wantSynced: exactly one fixture block when
// syncing, or none otherwise.
func matchStoreScanSyncedBlocks(params db.ScanBatchParams, wantSynced bool,
	fixture storeScanBatchFixture) bool {

	if !wantSynced {
		return len(params.SyncedBlocks) == 0
	}

	return len(params.SyncedBlocks) == 1 &&
		matchStoreScanBlock(&params.SyncedBlocks[0], fixture)
}

// matchStoreScanTx reports whether the batched scan transaction carries the
// fixture's wallet, hash, receive time, credit, status, and confirming block.
func matchStoreScanTx(txParams db.CreateTxParams, walletID uint32,
	fixture storeScanBatchFixture) bool {

	creditAddr, ok := txParams.Credits[0]
	if !ok || creditAddr == nil || txParams.Tx == nil ||
		txParams.Block == nil {

		return false
	}

	if !matchStoreScanBlock(txParams.Block, fixture) {
		return false
	}

	return txParams.WalletID == walletID &&
		txParams.Tx.TxHash() == fixture.tx.TxHash() &&
		txParams.Received.Equal(fixture.received) &&
		txParams.Status == db.TxStatusPublished &&
		creditAddr.EncodeAddress() == fixture.addr.EncodeAddress()
}

// matchStoreScanBatch matches the store scan batch produced by scan routing.
func matchStoreScanBatch(walletID uint32, fixture storeScanBatchFixture,
	wantSynced bool) any {

	return mock.MatchedBy(func(params db.ScanBatchParams) bool {
		if params.WalletID != walletID || len(params.Horizons) != 1 ||
			len(params.Transactions) != 1 {

			return false
		}

		if !matchStoreScanSyncedBlocks(params, wantSynced, fixture) {
			return false
		}

		if !matchStoreScanHorizon(params.Horizons[0], fixture) {
			return false
		}

		return matchStoreScanTx(
			params.Transactions[0], walletID, fixture,
		)
	})
}

// matchStoreScanBlock reports whether a store block matches the scan fixture.
func matchStoreScanBlock(block *db.Block,
	fixture storeScanBatchFixture) bool {

	return block.Hash == fixture.block.Hash &&
		block.Height == uint32(fixture.block.Height) &&
		block.Timestamp.Equal(fixture.block.Time)
}

// TestPutSyncBatchStore verifies sync scan writes use the store batch API.
func TestPutSyncBatchStore(t *testing.T) {
	t.Parallel()

	// Arrange: Create a store-backed syncer and one scan result.
	const walletID uint32 = 11

	store := &walletmock.Store{}
	s := newSyncer(
		Config{}, nil, nil, &mockTxPublisher{},
		store, walletID,
	)
	fixture := newStoreScanBatchFixture(t)
	scanState := newStoreScanBatchScanState(fixture)

	store.On(
		"ApplyScanBatch", mock.Anything,
		matchStoreScanBatch(walletID, fixture, true),
	).Return(nil).Once()

	// Act: Apply a normal sync scan batch.
	err := s.putSyncBatch(
		t.Context(), scanState, []scanResult{fixture.result},
	)

	// Assert: The store saw transactions, horizons, and synced blocks.
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestPutTargetedBatchStore verifies targeted scan writes use the store batch
// API without advancing synced blocks.
func TestPutTargetedBatchStore(t *testing.T) {
	t.Parallel()

	// Arrange: Create a store-backed syncer and one targeted scan result.
	const walletID uint32 = 12

	store := &walletmock.Store{}
	s := newSyncer(
		Config{}, nil, nil, &mockTxPublisher{},
		store, walletID,
	)
	fixture := newStoreScanBatchFixture(t)
	scanState := newStoreScanBatchScanState(fixture)

	store.On(
		"ApplyScanBatch", mock.Anything,
		matchStoreScanBatch(walletID, fixture, false),
	).Return(nil).Once()

	// Act: Apply a targeted scan batch.
	err := s.putTargetedBatch(
		t.Context(), scanState, []scanResult{fixture.result},
	)

	// Assert: The store saw transactions and horizons, but no synced blocks.
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestScanHorizonParamsStampsAccountName verifies that scanHorizonParams, a
// pure flattening function, stamps every horizon it emits with the account
// name resolved from the recovery state, and leaves the name empty on a miss
// so a backend can fall back to its number-based behavior. It exercises the
// stamping directly with two derived accounts plus an unknown account; the
// production scan path only ever feeds derived accounts into the recovery
// state, since imported accounts are withheld from the scan horizons (see
// withholdFromRecoveryHorizons), so this test does not assert anything about
// imported accounts reaching emission.
func TestScanHorizonParamsStampsAccountName(t *testing.T) {
	t.Parallel()

	// Arrange: A recovery state that knows two derived accounts in the same
	// scope (0 and 3), plus a horizon for an account the state does not know
	// (9) to exercise the fail-safe.
	scope := waddrmgr.KeyScopeBIP0084

	scanState := NewRecoveryState(0, &chainParams, nil)
	scanState.accountNames[waddrmgr.AccountScope{
		Scope:   scope,
		Account: 0,
	}] = "default"
	scanState.accountNames[waddrmgr.AccountScope{
		Scope:   scope,
		Account: 3,
	}] = "savings"

	externalBS := waddrmgr.BranchScope{
		Scope:   scope,
		Account: 0,
		Branch:  waddrmgr.ExternalBranch,
	}
	internalBS := waddrmgr.BranchScope{
		Scope:   scope,
		Account: 3,
		Branch:  waddrmgr.InternalBranch,
	}
	unknownBS := waddrmgr.BranchScope{
		Scope:   scope,
		Account: 9,
		Branch:  waddrmgr.ExternalBranch,
	}

	horizons := map[waddrmgr.BranchScope]uint32{
		externalBS: 4,
		internalBS: 7,
		unknownBS:  1,
	}

	// Act: Flatten the horizon map into store params.
	params := scanHorizonParams(scanState, horizons)

	// Assert: Each known horizon carries its resolved name, while the
	// unknown one is left with an empty name for number fallback.
	require.Len(t, params, 3)

	byAccount := make(map[uint32]db.ScanHorizon, len(params))
	for _, h := range params {
		byAccount[h.Account] = h
	}

	require.Equal(t, "default", byAccount[0].AccountName)
	require.Equal(t, "savings", byAccount[3].AccountName)
	require.Empty(t, byAccount[9].AccountName)
}

// TestStoreScanHorizonsListAccounts verifies full scan horizon reads use the
// store account list.
func TestStoreScanHorizonsListAccounts(t *testing.T) {
	t.Parallel()

	// Arrange: Create a store-backed syncer with two scan accounts.
	const walletID uint32 = 13

	store := &walletmock.Store{}
	s := newSyncer(
		Config{}, nil, nil, &mockTxPublisher{},
		store, walletID,
	)

	accounts := []db.AccountInfo{{
		AccountNumber:        2,
		AccountName:          "default",
		ExternalKeyCount:     5,
		InternalKeyCount:     3,
		ImportedKeyCount:     1,
		MasterKeyFingerprint: 9,
		KeyScope:             db.KeyScopeBIP0084,
		IsWatchOnly:          true,
	}}

	store.On("ListAccounts", mock.Anything, mock.MatchedBy(
		func(query db.ListAccountsQuery) bool {
			return query.WalletID == walletID && query.SkipBalance
		},
	)).Return(accounts, nil).Once()

	// Act: Load all scan horizons from the store.
	props, err := s.storeScanHorizons(t.Context(), nil)

	// Assert: The store account row was converted for RecoveryState.
	require.NoError(t, err)
	require.Len(t, props, 1)
	require.Equal(t, accounts[0].AccountNumber, props[0].AccountNumber)
	require.Equal(t, accounts[0].ExternalKeyCount, props[0].ExternalKeyCount)
	require.Equal(t, accounts[0].InternalKeyCount, props[0].InternalKeyCount)
	require.Equal(t, waddrmgr.KeyScopeBIP0084, props[0].KeyScope)
	require.True(t, props[0].IsWatchOnly)
	store.AssertExpectations(t)
}

// TestStoreScanHorizonsGetAccount verifies targeted scan horizon reads resolve
// the account by its durable AccountName, mirroring the ScanHorizon contract:
// the resolved scanTarget carries a name, so storeScanHorizons must query the
// store by name and never by the maskable account number.
func TestStoreScanHorizonsGetAccount(t *testing.T) {
	t.Parallel()

	// Arrange: Create a store-backed syncer and one resolved scanTarget that
	// carries the durable account name.
	const walletID uint32 = 14

	store := &walletmock.Store{}
	s := newSyncer(
		Config{}, nil, nil, &mockTxPublisher{},
		store, walletID,
	)

	target := scanTarget{
		Scope:       waddrmgr.KeyScopeBIP0084,
		Account:     7,
		AccountName: "savings",
	}
	account := db.AccountInfo{
		AccountNumber:    target.Account,
		AccountName:      target.AccountName,
		ExternalKeyCount: 8,
		InternalKeyCount: 4,
		KeyScope:         db.KeyScope(target.Scope),
	}

	// The lookup must key on the durable name, not the account number.
	store.On("GetAccount", mock.Anything, mock.MatchedBy(
		func(query db.GetAccountQuery) bool {
			return query.WalletID == walletID &&
				query.Scope == db.KeyScope(target.Scope) &&
				query.AccountNumber == nil &&
				query.Name != nil &&
				*query.Name == target.AccountName &&
				query.SkipBalance
		},
	)).Return(&account, nil).Once()

	// Act: Load targeted scan horizons from the store.
	props, err := s.storeScanHorizons(
		t.Context(), []scanTarget{target},
	)

	// Assert: The targeted account row was converted for RecoveryState.
	require.NoError(t, err)
	require.Len(t, props, 1)
	require.Equal(t, target.Account, props[0].AccountNumber)
	require.Equal(t, account.ExternalKeyCount, props[0].ExternalKeyCount)
	require.Equal(t, account.InternalKeyCount, props[0].InternalKeyCount)
	require.Equal(t, target.Scope, props[0].KeyScope)
	store.AssertExpectations(t)
}

// TestStoreScanHorizonsListAccountsSkipsImported verifies that untargeted scan
// horizon reads skip every imported account -- both the keyless
// imported-address bucket and a true imported xpub account. Crucially the
// imported xpub account surfaces with the masked AccountNumber 0 that the store
// contract guarantees for imported rows, in the same scope as a default derived
// account that legitimately owns number 0. Emitting exactly one horizon proves
// the masked imported account does not collide with or clobber the default
// account at (scope, 0).
func TestStoreScanHorizonsListAccountsSkipsImported(t *testing.T) {
	t.Parallel()

	// Arrange: a store-backed syncer whose ListAccounts returns a default
	// derived account at number 0, the keyless imported-address bucket, and
	// a true imported xpub account that the store surfaces with the masked
	// number 0 -- the same (scope, number) as the default account.
	const walletID uint32 = 23

	store := &walletmock.Store{}
	s := newSyncer(
		Config{}, nil, nil, &mockTxPublisher{},
		store, walletID,
	)

	accounts := []db.AccountInfo{{
		// The default derived account legitimately owns number 0.
		AccountNumber:    0,
		AccountName:      "default",
		ExternalKeyCount: 8,
		InternalKeyCount: 4,
		KeyScope:         db.KeyScopeBIP0084,
		Origin:           db.DerivedAccount,
	}, {
		// The keyless bucket is an imported account, so it must be
		// skipped.
		AccountNumber: waddrmgr.ImportedAddrAccount,
		AccountName:   db.DefaultImportedAccountName,
		KeyScope:      db.KeyScopeBIP0084,
		Origin:        db.ImportedAccount,
	}, {
		// The true imported xpub account carries an account public key
		// and HD key counts, but the store masks its number to 0. It is
		// still an imported account, so it must be skipped rather than
		// collide with the default account at (scope, 0).
		AccountNumber:    0,
		AccountName:      "imported-xpub",
		ExternalKeyCount: 6,
		InternalKeyCount: 2,
		KeyScope:         db.KeyScopeBIP0084,
		Origin:           db.ImportedAccount,
		PublicKey:        []byte("account-xpub"),
	}}

	store.On("ListAccounts", mock.Anything, mock.MatchedBy(
		func(query db.ListAccountsQuery) bool {
			return query.WalletID == walletID && query.SkipBalance
		},
	)).Return(accounts, nil).Once()

	// Act: load all scan horizons from the store.
	props, err := s.storeScanHorizons(t.Context(), nil)

	// Assert: exactly one horizon is emitted -- the default derived account
	// -- proving both imported accounts (including the masked-0 xpub) were
	// withheld and did not clobber the default account at (scope, 0).
	require.NoError(t, err)
	require.Len(t, props, 1)
	require.Equal(t, "default", props[0].AccountName)
	require.Equal(t, uint32(0), props[0].AccountNumber)
	require.Equal(t, uint32(8), props[0].ExternalKeyCount)
	require.Equal(t, uint32(4), props[0].InternalKeyCount)

	store.AssertExpectations(t)
}

// newStoreScanSyncer builds a store-backed syncer over a real, freshly created
// and unlocked waddrmgr-backed wallet. It returns the syncer and the open
// *waddrmgr.Manager so tests can resolve internal (non-masked) account numbers
// the same way production identity resolution does. The legacy manager is the
// identity-aware backend the Store path consults before its own masked
// lookups, so a real one is required to exercise resolveScanTargets.
func newStoreScanSyncer(t *testing.T) (*syncer, *waddrmgr.Manager) {
	t.Helper()

	dbConn, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)

	const (
		pubPass  = "pub"
		privPass = "priv"
	)

	seed := bytes.Repeat([]byte{0x5A}, hdkeychain.RecommendedSeedLen)
	rootKey, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)

	var mgr *waddrmgr.Manager

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := waddrmgr.Create(
			ns, rootKey, []byte(pubPass), []byte(privPass),
			&chaincfg.SimNetParams, &waddrmgr.FastScryptOptions,
			time.Time{},
		)
		if err != nil {
			return err
		}

		mgr, err = waddrmgr.Open(
			ns, []byte(pubPass), &chaincfg.SimNetParams,
		)

		return err
	})
	require.NoError(t, err)

	// Unlock the manager so scoped key managers can derive new accounts.
	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		return mgr.Unlock(ns, []byte(privPass))
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = mgr.Lock()
		mgr.Close()
	})

	// Create and open a real transaction store so the full targeted-scan
	// flow (active addresses and watched outputs) can read through the
	// Store rather than relying on mocks.
	var txStore *wtxmgr.Store

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		err := wtxmgr.Create(ns)
		if err != nil {
			return err
		}

		txStore, err = wtxmgr.Open(ns, &chaincfg.SimNetParams)

		return err
	})
	require.NoError(t, err)

	store := kvdb.NewStore(dbConn, txStore, mgr)
	s := newSyncer(
		Config{DB: dbConn, ChainParams: &chaincfg.SimNetParams}, mgr,
		txStore, &mockTxPublisher{}, store, 0,
	)

	return s, mgr
}

// createImportedXpubAccount imports a watch-only xpub account into the real
// manager-backed store and returns its non-masked internal waddrmgr account
// number. The Store masks an imported account's public AccountNumber to 0, so
// tests need the internal number to address the imported account distinctly
// from the default derived account that also owns number 0.
func createImportedXpubAccount(t *testing.T, s *syncer, mgr *waddrmgr.Manager,
	scope waddrmgr.KeyScope, name string) uint32 {

	t.Helper()

	seed := bytes.Repeat([]byte{0xC1}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)

	masterPub, err := master.Neuter()
	require.NoError(t, err)

	_, err = s.store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			Scope:     db.KeyScope(scope),
			Name:      name,
			PublicKey: []byte(masterPub.String()),
		},
	)
	require.NoError(t, err)

	scopedMgr, err := mgr.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	var internalNumber uint32

	err = walletdb.View(s.cfg.DB, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		internalNumber, err = scopedMgr.LookupAccount(ns, name)

		return err
	})
	require.NoError(t, err)

	return internalNumber
}

// TestStoreScanHorizonsTargetedImportedBucketSkipped verifies that a targeted
// rescan for the keyless legacy imported-address bucket never issues a Store
// number lookup and produces no horizon for the bucket. The real kvdb backend
// rejects a by-number lookup of waddrmgr.ImportedAddrAccount with
// ErrAccountNotFound, so a passing run (no error, no horizon) proves the bucket
// was skipped before any lookup rather than mis-resolved.
func TestStoreScanHorizonsTargetedImportedBucketSkipped(t *testing.T) {
	t.Parallel()

	// Arrange: a store-backed syncer over a real manager and a single target
	// for the keyless imported-address bucket.
	s, _ := newStoreScanSyncer(t)

	targets := []waddrmgr.AccountScope{{
		Scope:   waddrmgr.KeyScopeBIP0084,
		Account: waddrmgr.ImportedAddrAccount,
	}}

	// Act: resolve the targets and load their horizons through the Store.
	resolved, err := s.resolveScanTargets(t.Context(), targets)
	require.NoError(t, err)

	props, err := s.storeScanHorizons(t.Context(), resolved)

	// Assert: the bucket was skipped before any Store lookup -- a number
	// lookup would have surfaced ErrAccountNotFound -- so no horizon is
	// emitted and no error is returned.
	require.NoError(t, err)
	require.Empty(t, props)
}

// TestStoreScanHorizonsTargetedImportedNotResolvedAsDerived verifies the core
// fix: a targeted rescan setup containing both the default derived account
// (number 0) and an imported-xpub account whose public number is masked to 0
// does not resolve the imported target as the default derived account. The
// imported target is addressed by its non-masked internal number; the Store
// path resolves it by its durable name, classifies it as imported, and
// withholds it, so the only horizon emitted is the default derived account.
func TestStoreScanHorizonsTargetedImportedNotResolvedAsDerived(t *testing.T) {
	t.Parallel()

	// Arrange: a real-backend syncer with the auto-created default derived
	// account at number 0 and an imported-xpub account masked to number 0.
	s, mgr := newStoreScanSyncer(t)

	scope := waddrmgr.KeyScopeBIP0084
	importedNumber := createImportedXpubAccount(
		t, s, mgr, scope, "imported-xpub",
	)

	// The imported account's internal number must differ from the default
	// derived account's number 0, yet the Store masks it back to 0.
	require.NotEqual(t, uint32(waddrmgr.DefaultAccountNum), importedNumber)

	// Target both the default derived account (by its real number 0) and the
	// imported-xpub account (by its non-masked internal number).
	targets := []waddrmgr.AccountScope{
		{Scope: scope, Account: waddrmgr.DefaultAccountNum},
		{Scope: scope, Account: importedNumber},
	}

	// Act: resolve the targets and load their horizons through the Store.
	resolved, err := s.resolveScanTargets(t.Context(), targets)
	require.NoError(t, err)

	// The imported target must resolve to its durable name through the
	// identity-aware manager, the identity Store horizon loading keys on
	// instead of the maskable number.
	require.Len(t, resolved, 2)
	require.Equal(t, waddrmgr.DefaultAccountName, resolved[0].AccountName)
	require.Equal(t, "imported-xpub", resolved[1].AccountName)

	props, err := s.storeScanHorizons(t.Context(), resolved)
	require.NoError(t, err)

	// Assert: exactly one horizon is emitted -- the default derived account
	// -- proving the imported target was resolved by name, classified as
	// imported, and withheld rather than mis-resolved as the default derived
	// account at the shared masked number 0.
	require.Len(t, props, 1)
	require.Equal(t, waddrmgr.DefaultAccountName, props[0].AccountName)
	require.Equal(t, uint32(waddrmgr.DefaultAccountNum),
		props[0].AccountNumber)
	require.False(t, props[0].IsWatchOnly)
}

// TestStoreScanAddresses verifies scan address reads use paginated store
// address queries.
func TestStoreScanAddresses(t *testing.T) {
	t.Parallel()

	// Arrange: Create a store-backed syncer and one stored address script.
	const walletID uint32 = 15

	store := &walletmock.Store{}
	s := newSyncer(
		Config{ChainParams: &chainParams}, nil, nil, &mockTxPublisher{},
		store, walletID,
	)

	addr, err := btcutil.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	store.On("ListAccounts", mock.Anything, mock.MatchedBy(
		func(query db.ListAccountsQuery) bool {
			return query.WalletID == walletID && query.SkipBalance
		},
	)).Return([]db.AccountInfo{{
		AccountName: "default",
		KeyScope:    db.KeyScopeBIP0084,
	}}, nil).Once()

	store.On("ListAddresses", mock.Anything, mock.MatchedBy(
		func(query db.ListAddressesQuery) bool {
			return query.WalletID == walletID &&
				query.AccountName == "default" &&
				query.Scope == db.KeyScopeBIP0084 &&
				query.Page.Limit() == scanAddressPageLimit
		},
	)).Return(page.Result[db.AddressInfo, uint32]{
		Items: []db.AddressInfo{{ScriptPubKey: pkScript}},
	}, nil).Once()

	// Act: Load scan addresses from the store.
	addrs, err := s.storeScanAddresses(t.Context())

	// Assert: The stored script was converted into a scan address.
	require.NoError(t, err)
	require.Len(t, addrs, 1)
	require.Equal(t, addr.EncodeAddress(), addrs[0].EncodeAddress())
	store.AssertExpectations(t)
}

// TestStoreScanAddressesNonDefaultScope verifies that, for non-default key
// scopes, only internal-branch (change) addresses are watched, matching the
// legacy ForEachRelevantActiveAddress filtering.
func TestStoreScanAddressesNonDefaultScope(t *testing.T) {
	t.Parallel()

	// Arrange: a store-backed syncer with one non-default-scope account
	// holding one external and one internal address.
	const walletID uint32 = 23

	store := &walletmock.Store{}
	s := newSyncer(
		Config{ChainParams: &chainParams}, nil, nil, &mockTxPublisher{},
		store, walletID,
	)

	// A purpose outside waddrmgr.DefaultKeyScopes is a non-default scope.
	nonDefault := db.KeyScope{Purpose: 1017, Coin: 0}

	externalAddr, err := btcutil.NewAddressPubKeyHash(
		bytes.Repeat([]byte{0x01}, 20), &chainParams,
	)
	require.NoError(t, err)
	externalScript, err := txscript.PayToAddrScript(externalAddr)
	require.NoError(t, err)

	internalAddr, err := btcutil.NewAddressPubKeyHash(
		bytes.Repeat([]byte{0x02}, 20), &chainParams,
	)
	require.NoError(t, err)
	internalScript, err := txscript.PayToAddrScript(internalAddr)
	require.NoError(t, err)

	store.On("ListAccounts", mock.Anything, mock.MatchedBy(
		func(query db.ListAccountsQuery) bool {
			return query.WalletID == walletID && query.SkipBalance
		},
	)).Return([]db.AccountInfo{{
		AccountName: "custom",
		KeyScope:    nonDefault,
	}}, nil).Once()

	store.On("ListAddresses", mock.Anything, mock.MatchedBy(
		func(query db.ListAddressesQuery) bool {
			return query.WalletID == walletID &&
				query.AccountName == "custom" &&
				query.Scope == nonDefault
		},
	)).Return(page.Result[db.AddressInfo, uint32]{
		Items: []db.AddressInfo{
			{
				ScriptPubKey: externalScript,
				Branch:       waddrmgr.ExternalBranch,
			},
			{
				ScriptPubKey: internalScript,
				Branch:       waddrmgr.InternalBranch,
			},
		},
	}, nil).Once()

	// Act: load scan addresses from the store.
	addrs, err := s.storeScanAddresses(t.Context())

	// Assert: only the internal-branch address survived the filter.
	require.NoError(t, err)
	require.Len(t, addrs, 1)
	require.Equal(t, internalAddr.EncodeAddress(), addrs[0].EncodeAddress())
	store.AssertExpectations(t)
}

// TestStoreScanUnspent verifies scan UTXO reads use the store watch-output API.
func TestStoreScanUnspent(t *testing.T) {
	t.Parallel()

	// Arrange: Create a store-backed syncer and one watch output.
	const walletID uint32 = 16

	store := &walletmock.Store{}
	s := newSyncer(
		Config{}, nil, nil, &mockTxPublisher{},
		store, walletID,
	)

	outpoint := wire.OutPoint{Hash: chainhash.Hash{0x16}, Index: 2}
	received := time.Unix(987, 0).UTC()
	utxos := []db.UtxoInfo{{
		OutPoint:     outpoint,
		Amount:       btcutil.Amount(1234),
		PkScript:     []byte{0x51},
		Received:     received,
		FromCoinBase: true,
		Height:       42,
	}}

	store.On(
		"ListOutputsToWatch", mock.Anything, walletID,
	).Return(utxos, nil).Once()

	// Act: Load scan UTXOs from the store.
	credits, err := s.storeScanUnspent(t.Context())

	// Assert: The store UTXO row was converted into a recovery credit.
	require.NoError(t, err)
	require.Len(t, credits, 1)
	require.Equal(t, outpoint, credits[0].OutPoint)
	require.Equal(t, utxos[0].Amount, credits[0].Amount)
	require.Equal(t, utxos[0].PkScript, credits[0].PkScript)
	require.Equal(t, received, credits[0].Received)
	require.Equal(t, int32(42), credits[0].Height)
	require.True(t, credits[0].FromCoinBase)
	store.AssertExpectations(t)
}

// TestLoadWalletScanDataStore verifies wallet scan-data loading uses the store
// when store wiring is available.
func TestLoadWalletScanDataStore(t *testing.T) {
	t.Parallel()

	// Arrange: Create a store-backed syncer with one account, address, and
	// watch output.
	const walletID uint32 = 17

	store := &walletmock.Store{}
	s := newSyncer(
		Config{ChainParams: &chainParams}, nil, nil, &mockTxPublisher{},
		store, walletID,
	)

	addr, err := btcutil.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	store.On("ListAccounts", mock.Anything, mock.MatchedBy(
		func(query db.ListAccountsQuery) bool {
			return query.WalletID == walletID && query.SkipBalance
		},
	)).Return([]db.AccountInfo{{
		AccountNumber:    3,
		ExternalKeyCount: 4,
		InternalKeyCount: 5,
		KeyScope:         db.KeyScopeBIP0084,
	}}, nil).Twice()

	store.On("ListAddresses", mock.Anything, mock.Anything).Return(
		page.Result[db.AddressInfo, uint32]{
			Items: []db.AddressInfo{{ScriptPubKey: pkScript}},
		}, nil,
	).Once()

	store.On(
		"ListOutputsToWatch", mock.Anything, walletID,
	).Return([]db.UtxoInfo{{
		OutPoint: wire.OutPoint{Hash: chainhash.Hash{0x17}, Index: 1},
		PkScript: pkScript,
		Height:   db.UnminedHeight,
	}}, nil).Once()

	// Act: Load wallet scan data through the store-backed path.
	horizons, addrs, unspent, err := s.loadWalletScanData(t.Context())

	// Assert: All scan initialization groups came from the store.
	require.NoError(t, err)
	require.Len(t, horizons, 1)
	require.Equal(t, uint32(3), horizons[0].AccountNumber)
	require.Len(t, addrs, 1)
	require.Equal(t, addr.EncodeAddress(), addrs[0].EncodeAddress())
	require.Len(t, unspent, 1)
	require.Equal(t, int32(-1), unspent[0].Height)
	store.AssertExpectations(t)
}

// TestExtractAddrEntries verifies address extraction from outputs.
func TestExtractAddrEntries(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and create a P2PKH output for address
	// extraction.
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(
		Config{ChainParams: &chainParams}, nil, nil,
		mockPublisher,
		&walletmock.Store{}, 0,
	)

	addr, err := btcutil.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	txOut := &wire.TxOut{Value: 1000, PkScript: pkScript}

	// Act: Extract address entries from the output.
	entries := s.extractAddrEntries([]*wire.TxOut{txOut})

	// Assert: Verify that the correct address was extracted.
	require.Len(t, entries, 1)
	require.Equal(t, addr.String(), entries[0].Address.String())
	require.Equal(t, uint32(0), entries[0].Credit.Index)
}

// TestHandleScanReq verifies scan request handling.
func TestHandleScanReq(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a store-backed syncer and mocks to test handling
	// of different scan request types.
	mockAddrStore := &bwmock.AddrStore{}
	mockPublisher := &mockTxPublisher{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{}, mockAddrStore, nil, mockPublisher,
		store, uint32(0),
	)

	// Case 1: Test handling of a rewind scan request. The current tip is at
	// height 100, so rewinding to height 50 issues an atomic store rollback
	// for the rollback boundary (51).
	req := &scanReq{
		typ:        scanTypeRewind,
		startBlock: waddrmgr.BlockStamp{Height: 50},
	}
	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})
	store.On("RollbackToBlock", mock.Anything, uint32(51)).Return(
		nil).Once()

	// Act & Assert: Verify that a rewind scan request is correctly handled.
	err := s.handleScanReq(t.Context(), req)
	require.NoError(t, err)

	// Case 2: Test handling of a targeted scan request. A real-backend
	// syncer is used so resolveScanTargets resolves the target to its
	// durable name through the manager and the targeted scan reads and
	// writes through the real Store.
	sTargeted, _ := newStoreScanSyncer(t)

	mockChain := &bwmock.Chain{}
	sTargeted.cfg.Chain = mockChain
	sTargeted.cfg.RecoveryWindow = MinRecoveryWindow

	// Target the auto-created default derived account at number 0.
	req = &scanReq{
		typ:        scanTypeTargeted,
		startBlock: waddrmgr.BlockStamp{Height: 100},
		targets: []waddrmgr.AccountScope{{
			Scope:   waddrmgr.KeyScopeBIP0084,
			Account: waddrmgr.DefaultAccountNum,
		}},
	}

	mockChain.On("GetBestBlock").Return(
		&chainhash.Hash{}, int32(101), nil,
	).Once()

	// Mock block hash retrieval for the targeted scan range.
	mockChain.On(
		"GetBlockHashes", int64(100), int64(101),
	).Return([]chainhash.Hash{{0x01}, {0x02}}, nil).Once()

	// Mock CFilter-based scanning for the targeted scan.
	mockChain.On(
		"GetCFilters", mock.Anything, mock.Anything,
	).Return([]*gcs.Filter{nil, nil}, nil).Once()
	mockChain.On(
		"GetBlockHeaders", mock.Anything,
	).Return([]*wire.BlockHeader{{}, {}}, nil).Once()

	msgBlock := wire.NewMsgBlock(wire.NewBlockHeader(
		1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))

	blocks := make([]*wire.MsgBlock, 2)
	for i := range 2 {
		blocks[i] = msgBlock
	}

	mockChain.On("GetBlocks", mock.Anything).Return(blocks, nil).Once()

	// Act & Assert: Verify that a targeted scan request is correctly
	// handled.
	err = sTargeted.handleScanReq(t.Context(), req)
	require.NoError(t, err)
}

// TestWaitForEvent verifies event loop idling and dispatch.
func TestWaitForEvent(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a store-backed syncer for testing the event loop.
	mockChain := &bwmock.Chain{}
	mockPublisher := &mockTxPublisher{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, mockPublisher,
		store, uint32(0),
	)

	// Mock chain notifications channel.
	notificationChan := make(chan any, 1)
	mockChain.On("Notifications").Return((<-chan any)(notificationChan))

	// Case 1: Test event handling when a chain notification arrives, which
	// advances the synced tip through the store.
	notificationChan <- chain.BlockConnected{}

	store.On("UpdateWallet", mock.Anything, mock.Anything).Return(
		nil).Once()

	// Act & Assert: Call waitForEvent and verify it correctly processes
	// the arriving notification.
	err := s.waitForEvent(t.Context())
	require.NoError(t, err)

	// Case 2: Test event handling when a scan request arrives. The
	// requested rewind start is at or beyond the current synced tip, so the
	// rewind is a no-op.
	s.scanReqChan <- &scanReq{typ: scanTypeRewind}

	expectSyncedTip(store, waddrmgr.BlockStamp{})

	// Act & Assert: Call waitForEvent and verify it correctly processes
	// the arriving scan request.
	err = s.waitForEvent(t.Context())
	require.NoError(t, err)
}

// TestSyncerFullRun verifies the full run loop coordination.
func TestSyncerFullRun(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a store-backed syncer and set up extensive mocks
	// to simulate a full run loop execution. The synced tip and unmined
	// transactions are read through the store; the legacy address manager
	// only supplies the backend birthday.
	mockChain := &bwmock.Chain{}
	mockAddrStore := &bwmock.AddrStore{}
	mockPublisher := &mockTxPublisher{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{Chain: mockChain}, mockAddrStore, nil, mockPublisher,
		store, uint32(0),
	)

	// Mock initial chain sync sequence.
	mockAddrStore.On("Birthday").Return(time.Now()).Once()
	mockChain.On("IsCurrent").Return(true).Once()
	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})

	// Mock rollback check dependencies. The store and the remote chain
	// agree, so no rollback occurs.
	localBlocks := make([]db.Block, 0, 10)
	for i := uint32(91); i <= 100; i++ {
		localBlocks = append(localBlocks, db.Block{Height: i})
	}

	store.On("ListSyncedBlocks", mock.Anything, mock.Anything).Return(
		localBlocks, nil).Maybe()

	// Mock remote hashes for rollback check (batch size 10).
	remoteHashes := make([]chainhash.Hash, 10)
	mockChain.On(
		"GetBlockHashes", mock.Anything, mock.Anything,
	).Return(remoteHashes, nil).Maybe()
	mockChain.On("NotifyBlocks").Return(nil).Once()

	// Mock advancement to the current best block.
	mockChain.On(
		"GetBestBlock",
	).Return(&chainhash.Hash{}, int32(100), nil).Once()

	// Mock retrieval of unmined transactions through the store.
	store.On("ListTxns", mock.Anything, mock.Anything).Return(
		[]db.TxInfo(nil), nil,
	).Once()

	// Set up for the event waiting phase of the run loop.
	ctx, cancel := context.WithCancel(t.Context())

	// Use a goroutine to cancel the context after a delay to allow the
	// syncer to enter its event loop.
	go func() {
		time.Sleep(1500 * time.Millisecond)
		cancel()
	}()

	notificationChan := make(chan any)
	mockChain.On("Notifications").Return((<-chan any)(notificationChan))

	// Act & Assert: Execute the syncer's run loop and verify that it
	// completes all initial sync steps and enters the idle loop.
	err := s.run(ctx)
	require.NoError(t, err)
}

var (
	errDBMockSync = errors.New("db error")
	errCFilter    = errors.New("not supported")
)

// TestProcessChainUpdate_Disconnect verifies rollback on block disconnect.
func TestProcessChainUpdate_Disconnect(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a store-backed syncer for handling a block
	// disconnect.
	mockChain := &bwmock.Chain{}
	mockPublisher := &mockTxPublisher{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, mockPublisher,
		store, uint32(0),
	)

	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})

	// The store and the remote chain agree (all-zero hashes), so the
	// rollback check finds no reorg.
	localBlocks := make([]db.Block, 0, 10)
	for i := uint32(91); i <= 100; i++ {
		localBlocks = append(localBlocks, db.Block{Height: i})
	}

	store.On("ListSyncedBlocks", mock.Anything, mock.Anything).Return(
		localBlocks, nil).Once()

	remoteHashes := make([]chainhash.Hash, 10)
	mockChain.On("GetBlockHashes", mock.Anything, mock.Anything).Return(
		remoteHashes, nil,
	).Once()

	// Act & Assert: Process a BlockDisconnected notification and verify
	// that it triggers a rollback check.
	err := s.processChainUpdate(t.Context(), chain.BlockDisconnected{})
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestBroadcastUnminedTxns_Error verifies error handling.
func TestBroadcastUnminedTxns_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a store-backed syncer and mock an error during
	// unmined transaction retrieval.
	store := &walletmock.Store{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{}, nil, nil, mockPublisher,
		store, uint32(0),
	)

	store.On("ListTxns", mock.Anything, mock.Anything).Return(
		([]db.TxInfo)(nil), errDBMockSync,
	).Once()

	// Act & Assert: Verify that broadcasting unmined transactions
	// returns the expected database error.
	err := s.broadcastUnminedTxns(t.Context())
	require.Error(t, err)
}

// TestInitChainSync_BackendNotSynced verifies it waits/errors.
func TestInitChainSync_BackendNotSynced(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and mock the backend as not being
	// current to test initialization timeout.
	mockChain := &bwmock.Chain{}
	mockAddrStore := &bwmock.AddrStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain}, mockAddrStore, nil, mockPublisher,
		&walletmock.Store{}, 0,
	)

	mockAddrStore.On("Birthday").Return(time.Now()).Once()
	mockChain.On("IsCurrent").Return(false)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	// Act & Assert: Verify that initialization fails due to timeout
	// when the backend never becomes current.
	err := s.initChainSync(ctx)
	require.Error(t, err)
}

// TestDispatchScanStrategy_CFilterFail verifies fallback.
func TestDispatchScanStrategy_CFilterFail(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and mock a CFilter retrieval failure
	// to test fallback to full block scanning.
	mockChain := &bwmock.Chain{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(
		Config{Chain: mockChain, SyncMethod: SyncMethodAuto}, nil, nil,
		mockPublisher,
		&walletmock.Store{}, 0,
	)
	mockAddrStore := &bwmock.AddrStore{}
	scanState := NewRecoveryState(
		10, &chainParams, mockAddrStore,
	)
	hashes := []chainhash.Hash{{0x01}}

	mockChain.On(
		"GetCFilters", hashes, wire.GCSFilterRegular,
	).Return(([]*gcs.Filter)(nil), errCFilter).Once()

	msgBlock := wire.NewMsgBlock(wire.NewBlockHeader(
		1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))
	mockChain.On(
		"GetBlocks", hashes,
	).Return([]*wire.MsgBlock{msgBlock}, nil).Once()

	// Act: Dispatch the scan strategy when CFilters are not supported.
	results, err := s.dispatchScanStrategy(
		t.Context(), scanState, 10, hashes,
	)

	// Assert: Verify that the scan fell back to full blocks successfully.
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// TestFilterBatch_MatchFound verifies logic when CFilter matches.
func TestFilterBatch_MatchFound(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer configured for CFilter scanning.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain, SyncMethod: SyncMethodCFilters},
		nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	// Create a filter that matches "data".
	data := []byte("match_me")
	filter, err := gcs.BuildGCSFilter(
		builder.DefaultP, builder.DefaultM, [16]byte{}, [][]byte{data},
	)
	require.NoError(t, err)

	// Setup scan state watching the data.
	scanState := NewRecoveryState(10, &chainParams, nil)

	mockAddr := &bwmock.Address{}
	mockAddr.On("ScriptAddress").Return(data)
	mockAddr.On("String").Return("addr")

	scopeState := scanState.StateForScope(waddrmgr.KeyScopeBIP0084)
	scopeState.ExternalBranch.AddAddr(0, mockAddr)

	hashes := []chainhash.Hash{{0x01}}
	mockChain.On(
		"GetCFilters", hashes, wire.GCSFilterRegular,
	).Return([]*gcs.Filter{filter}, nil).Once()

	// Expect full block fetch due to filter match.
	msgBlock := wire.NewMsgBlock(wire.NewBlockHeader(
		1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))
	mockChain.On("GetBlocks", hashes).Return(
		[]*wire.MsgBlock{msgBlock}, nil,
	).Once()

	mockChain.On("GetBlockHeaders", hashes).Return(
		[]*wire.BlockHeader{{}}, nil,
	).Once()

	// Act: Perform the scan.
	results, err := s.scanBatchWithCFilters(
		t.Context(), scanState, 10, hashes,
	)

	// Assert: Verify results.
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// TestScanBatchWithCFilters_GetHeadersFail verifies error handling.
func TestScanBatchWithCFilters_GetHeadersFail(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer and mock CFilter success but header retrieval
	// failure.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)
	scanState := NewRecoveryState(10, &chainParams, nil)
	hashes := []chainhash.Hash{{0x01}}

	filter, err := gcs.BuildGCSFilter(
		builder.DefaultP, builder.DefaultM, [16]byte{}, nil,
	)
	require.NoError(t, err)

	mockChain.On(
		"GetCFilters", hashes, wire.GCSFilterRegular,
	).Return([]*gcs.Filter{filter}, nil).Once()

	mockChain.On(
		"GetBlockHeaders", hashes,
	).Return(([]*wire.BlockHeader)(nil), errHeaders).Once()

	// Act: Attempt to scan the batch.
	results, err := s.scanBatchWithCFilters(
		t.Context(), scanState, 10, hashes,
	)

	// Assert: Verify error propagation.
	require.Nil(t, results)
	require.ErrorContains(t, err, "headers fail")
}

// TestFetchAndFilterBlocks_NonEmpty verifies block fetching and filtering
// when the scan state is NOT empty.
func TestFetchAndFilterBlocks_NonEmpty(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer with a non-empty scan state.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	scanState := NewRecoveryState(10, &chainParams, nil)
	scanState.AddWatchedOutPoint(&wire.OutPoint{Index: 0}, nil)

	hashes := []chainhash.Hash{{0x01}}
	mockChain.On(
		"GetBlockHashes", int64(10), int64(11),
	).Return(hashes, nil).Once()

	filter, err := gcs.BuildGCSFilter(
		builder.DefaultP, builder.DefaultM, [16]byte{}, nil,
	)
	require.NoError(t, err)
	mockChain.On(
		"GetCFilters", hashes, wire.GCSFilterRegular,
	).Return([]*gcs.Filter{filter}, nil).Once()
	mockChain.On("GetBlockHeaders", hashes).Return(
		[]*wire.BlockHeader{{}}, nil).Once()

	// Act: Fetch and filter blocks.
	results, err := s.fetchAndFilterBlocks(
		t.Context(), scanState, 10, 11,
	)

	// Assert: Verify results.
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// TestFetchAndFilterBlocks_Errors verifies error paths.
func TestFetchAndFilterBlocks_Errors(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer with a non-empty scan state and mock a hash
	// fetch failure.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)
	scanState := NewRecoveryState(10, &chainParams, nil)
	scanState.AddWatchedOutPoint(&wire.OutPoint{Index: 0}, nil)

	mockChain.On(
		"GetBlockHashes", int64(10), int64(11),
	).Return([]chainhash.Hash(nil), errChainMock).Once()

	// Act: Attempt to fetch and filter blocks.
	results, err := s.fetchAndFilterBlocks(
		t.Context(), scanState, 10, 11,
	)

	// Assert: Verify error propagation.
	require.Nil(t, results)
	require.ErrorContains(t, err, "chain error")
}

// TestScanBatch_Empty verifies error when fetchAndFilterBlocks returns 0.
func TestScanBatch_Empty(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer that returns empty blocks during
	// a batch scan.
	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		store, uint32(0),
	)

	store.On("ListAccounts", mock.Anything, mock.Anything).Return(
		([]db.AccountInfo)(nil), nil).Twice()
	store.On("ListOutputsToWatch", mock.Anything, mock.Anything).Return(
		([]db.UtxoInfo)(nil), nil).Once()

	mockChain.On("GetBlockHashes", mock.Anything, mock.Anything).Return(
		[]chainhash.Hash{}, nil).Once()
	mockChain.On("GetBlockHeaders", []chainhash.Hash{}).Return(
		[]*wire.BlockHeader{}, nil).Once()

	// Act: Attempt to scan the batch.
	err := s.scanBatch(
		t.Context(), waddrmgr.BlockStamp{Height: 10}, 11,
	)

	// Assert: Verify that the empty batch error is returned.
	require.ErrorIs(t, err, ErrScanBatchEmpty)
}

// TestInitChainSync_Errors verifies initChainSync error paths.
func TestInitChainSync_Errors(t *testing.T) {
	t.Parallel()

	t.Run("CheckRollback_Failure", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup a store-backed syncer where the synced-block
		// read fails during the rollback check.
		mockChain := &bwmock.Chain{}
		store := &walletmock.Store{}

		s := newSyncer(
			Config{Chain: mockChain}, nil, nil, nil,
			store, uint32(0),
		)

		mockChain.On("IsCurrent").Return(true).Maybe()
		expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})
		store.On(
			"ListSyncedBlocks", mock.Anything, mock.Anything,
		).Return(([]db.Block)(nil), errDBMock).Once()

		// Act: Attempt initialization.
		err := s.initChainSync(t.Context())

		// Assert: Verify error.
		require.ErrorContains(t, err, "db error")
	})

	t.Run("NotifyBlocks_Failure", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup a store-backed syncer where block notifications
		// fail.
		mockChain := &bwmock.Chain{}
		store := &walletmock.Store{}
		s := newSyncer(
			Config{Chain: mockChain}, nil, nil, nil,
			store, uint32(0),
		)

		mockChain.On("IsCurrent").Return(true).Maybe()
		expectSyncedTip(store, waddrmgr.BlockStamp{Height: 0})
		mockChain.On("NotifyBlocks").Return(errNotify).Once()

		// Act: Attempt initialization.
		err := s.initChainSync(t.Context())

		// Assert: Verify error.
		require.ErrorContains(t, err, "notify fail")
	})
}

// TestHandleScanReq_Errors verifies handleScanReq error paths.
func TestHandleScanReq_Errors(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer already in syncing state.
	s := newSyncer(Config{}, nil, nil, nil, &walletmock.Store{}, 0)
	s.state.Store(uint32(syncStateSyncing))

	// Act: Attempt to handle a scan request.
	err := s.handleScanReq(t.Context(), &scanReq{})

	// Assert: Verify state forbidden error.
	require.ErrorIs(t, err, ErrStateForbidden)
}

// TestSyncerRun_InitError verifies run failure when initChainSync fails.
func TestSyncerRun_InitError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer where initialization fails
	// because the synced-block read errors during the rollback check.
	mockChain := &bwmock.Chain{}
	addrStore := &bwmock.AddrStore{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{Chain: mockChain}, addrStore, nil, nil,
		store, uint32(0),
	)

	addrStore.On("Birthday").Return(time.Now()).Once()
	mockChain.On("IsCurrent").Return(true).Once()

	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})
	store.On("ListSyncedBlocks", mock.Anything, mock.Anything).Return(
		([]db.Block)(nil), errDBMock).Once()

	// Act: Run the syncer.
	err := s.run(t.Context())

	// Assert: Verify error propagation.
	require.ErrorContains(t, err, "db error")
}

// TestHandleChainUpdate_BlockDisconnected verifies handleChainUpdate for
// BlockDisconnected.
func TestHandleChainUpdate_BlockDisconnected(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer for handling updates.
	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}
	s := newSyncer(
		Config{
			Chain:       mockChain,
			ChainParams: &chainParams,
		},
		nil, nil, nil,
		store, uint32(0),
	)

	// 1. BlockDisconnected. The store and the remote chain agree on blocks
	// 91..100, so the rollback check finds no reorg.
	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})

	localBlocks := make([]db.Block, 0, 10)
	for i := uint32(91); i <= 100; i++ {
		localBlocks = append(localBlocks, db.Block{
			Hash:   chainhash.Hash{byte(i)},
			Height: i,
		})
	}

	store.On("ListSyncedBlocks", mock.Anything, db.ListSyncedBlocksQuery{
		StartHeight: 91,
		EndHeight:   100,
	}).Return(localBlocks, nil).Once()

	remoteHashes := make([]chainhash.Hash, 10)
	for i := range 10 {
		remoteHashes[i] = chainhash.Hash{byte(91 + i)}
	}

	mockChain.On("GetBlockHashes", int64(91), int64(100)).Return(
		remoteHashes, nil).Once()

	// Act: Handle BlockDisconnected.
	err := s.handleChainUpdate(
		t.Context(), chain.BlockDisconnected{
			Block: wtxmgr.Block{Height: 100},
		},
	)

	// Assert: Verify success.
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestDispatchScanStrategy_AutoFallback verifies fallback to full blocks
// when watchlist is too large.
func TestDispatchScanStrategy_AutoFallback(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer with a low filter item threshold to force
	// fallback.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{
			Chain:           mockChain,
			SyncMethod:      SyncMethodAuto,
			MaxCFilterItems: 1,
		}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)
	scanState := NewRecoveryState(10, &chainParams, nil)

	// Add 2 items (threshold 1).
	credits := make([]wtxmgr.Credit, 2)
	for i := range credits {
		credits[i] = wtxmgr.Credit{
			OutPoint: wire.OutPoint{Index: uint32(i)},
			PkScript: []byte{0x00},
		}
	}

	err := scanState.Initialize(nil, nil, credits)
	require.NoError(t, err)

	hashes := []chainhash.Hash{{0x01}}
	msgBlock := wire.NewMsgBlock(wire.NewBlockHeader(
		1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))
	mockChain.On(
		"GetBlocks", hashes,
	).Return([]*wire.MsgBlock{msgBlock}, nil).Once()

	// Act: Dispatch the scan strategy.
	results, err := s.dispatchScanStrategy(
		t.Context(), scanState, 10, hashes,
	)

	// Assert: Verify results.
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// TestBroadcastUnminedTxns_Success verifies successful broadcast.
func TestBroadcastUnminedTxns_Success(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer and mock successful unmined
	// transaction retrieval and broadcast.
	store := &walletmock.Store{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{}, nil, nil, mockPublisher,
		store, uint32(0),
	)

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{0x10},
	}})
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})
	store.On("ListTxns", mock.Anything, mock.Anything).Return(
		[]db.TxInfo{{
			Status:       db.TxStatusPublished,
			SerializedTx: serializeTx(t, tx),
		}}, nil,
	).Once()
	mockPublisher.On(
		"Broadcast", mock.Anything, mock.Anything, "",
	).Return(nil).Once()

	// Act: Broadcast unmined transactions.
	err := s.broadcastUnminedTxns(t.Context())

	// Assert: Verify success.
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestFilterBatch_EmptyFilter verifies that empty filters force download.
func TestFilterBatch_EmptyFilter(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer and mock an empty filter response.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain, SyncMethod: SyncMethodCFilters},
		nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	emptyFilter, err := gcs.BuildGCSFilter(
		builder.DefaultP, builder.DefaultM, [16]byte{}, nil,
	)
	require.NoError(t, err)

	scanState := NewRecoveryState(10, &chainParams, nil)
	hashes := []chainhash.Hash{{0x01}}
	mockChain.On(
		"GetCFilters", hashes, wire.GCSFilterRegular,
	).Return([]*gcs.Filter{emptyFilter}, nil).Once()

	msgBlock := wire.NewMsgBlock(wire.NewBlockHeader(
		1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))
	mockChain.On("GetBlocks", hashes).Return(
		[]*wire.MsgBlock{msgBlock}, nil,
	).Once()
	mockChain.On("GetBlockHeaders", hashes).Return(
		[]*wire.BlockHeader{{}}, nil,
	).Once()

	// Act: Scan the batch with CFilters.
	results, err := s.scanBatchWithCFilters(
		t.Context(), scanState, 10, hashes,
	)

	// Assert: Verify that the block was fetched.
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// TestWaitForEvent_NotificationsClosed verifies that the loop exits when the
// notifications channel is closed.
func TestWaitForEvent_NotificationsClosed(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer with a closed notification channel.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	closedChan := make(chan any)
	close(closedChan)

	mockChain.On("Notifications").Return((<-chan any)(closedChan)).Once()

	// Act: Start waiting for events.
	err := s.waitForEvent(t.Context())

	// Assert: Verify that the loop exits with the expected error.
	require.ErrorIs(t, err, ErrWalletShuttingDown)
}

// TestWaitForEvent_ContextCancelled verifies exit on context cancellation.
func TestWaitForEvent_ContextCancelled(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer with a blocking notification channel and a
	// cancelled context.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	blockChan := make(chan any)
	mockChain.On("Notifications").Return((<-chan any)(blockChan)).Once()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Attempt to wait for events.
	err := s.waitForEvent(ctx)

	// Assert: Verify cancellation error.
	require.ErrorIs(t, err, context.Canceled)
}

// TestMatchAndFetchBatch_GetBlocksError verifies error propagation.
func TestMatchAndFetchBatch_GetBlocksError(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer and setup a recovery state.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	state := NewRecoveryState(1, nil, nil)

	// Setup results and mock filters such that a match is forced, then
	// mock a block fetch failure.
	results := []scanResult{
		{meta: &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Hash: chainhash.Hash{0x01}},
		}},
	}

	filters := []*gcs.Filter{nil}

	blockMap := make(map[chainhash.Hash]*wire.MsgBlock)
	mockChain.On("GetBlocks", mock.Anything).Return(
		([]*wire.MsgBlock)(nil), errGetBlocks).Once()

	// Act: Attempt to match and fetch the batch.
	err := s.matchAndFetchBatch(
		t.Context(), state, results, filters, blockMap,
	)

	// Assert: Verify error propagation.
	require.ErrorIs(t, err, errGetBlocks)
}

// TestFilterBatch_ContextCancelled verifies early exit.
func TestFilterBatch_ContextCancelled(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer and a cancelled context.
	s := newSyncer(Config{}, nil, nil, nil, &walletmock.Store{}, 0)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Attempt to filter a batch.
	results := []scanResult{{}}
	matched, err := s.filterBatch(ctx, results, nil, nil, nil)

	// Assert: Verify failure.
	require.Nil(t, matched)
	require.ErrorIs(t, err, context.Canceled)
}

// TestFilterBatch_BlockAlreadyFetched verifies skipping.
func TestFilterBatch_BlockAlreadyFetched(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer where the target block has already been
	// fetched.
	s := newSyncer(Config{}, nil, nil, nil, &walletmock.Store{}, 0)

	hash := chainhash.Hash{0x01}
	results := []scanResult{
		{meta: &wtxmgr.BlockMeta{Block: wtxmgr.Block{Hash: hash}}},
	}
	blockMap := map[chainhash.Hash]*wire.MsgBlock{
		hash: {},
	}

	// Act: Filter the batch.
	matched, err := s.filterBatch(t.Context(), results, nil, blockMap, nil)

	// Assert: Verify that the block was skipped.
	require.NoError(t, err)
	require.Empty(t, matched)
}

// TestInitChainSync_WaitUntilSyncedError verifies error propagation.
func TestInitChainSync_WaitUntilSyncedError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where the backend is not current,
	// then cancel the context.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	mockChain.On("IsCurrent").Return(false).Maybe()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Attempt chain sync initialization.
	err := s.initChainSync(ctx)

	// Assert: Verify failure.
	require.ErrorContains(t, err, "unable to wait for backend sync")
}

// TestScanBatchHeadersOnly_ContextCancelled verifies early exit.
func TestScanBatchHeadersOnly_ContextCancelled(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations and a cancelled context.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	mockChain.On("GetBlockHashes", mock.Anything, mock.Anything).Return(
		[]chainhash.Hash{}, context.Canceled).Maybe()

	// Act: Attempt header-only scan.
	results, err := s.scanBatchHeadersOnly(ctx, 0, 0)

	// Assert: Verify failure.
	require.Nil(t, results)
	require.ErrorIs(t, err, context.Canceled)
}

// TestBroadcastUnminedTxns_BroadcastError verifies warning log (no error
// returned).
func TestBroadcastUnminedTxns_BroadcastError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer where a transaction broadcast
	// fails.
	mockPublisher := &mockTxPublisher{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{}, nil, nil, mockPublisher,
		store, uint32(0),
	)

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{0x10},
	}})
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})
	store.On("ListTxns", mock.Anything, mock.Anything).Return(
		[]db.TxInfo{{
			Status:       db.TxStatusPublished,
			SerializedTx: serializeTx(t, tx),
		}}, nil).Once()
	mockPublisher.On(
		"Broadcast", mock.Anything, mock.Anything, "",
	).Return(errBroadcast).Once()

	// Act: Broadcast unmined transactions.
	err := s.broadcastUnminedTxns(t.Context())

	// Assert: Verify that the error is not propagated (it's only logged).
	require.NoError(t, err)
}

// TestCheckRollback_DBError verifies error propagation.
func TestCheckRollback_DBError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer where the synced-block read
	// fails during a rollback check.
	store := &walletmock.Store{}
	s := newSyncer(
		Config{}, nil, nil, nil, store, uint32(0),
	)

	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})
	store.On("ListSyncedBlocks", mock.Anything, mock.Anything).Return(
		([]db.Block)(nil), errBlockHash).Once()

	// Act: Perform a rollback check.
	err := s.checkRollback(t.Context())

	// Assert: Verify failure.
	require.ErrorIs(t, err, errBlockHash)
}

// TestCheckRollback_RemoteError verifies error propagation from
// GetBlockHashes.
func TestCheckRollback_RemoteError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer where the remote hash lookup
	// fails during a rollback check.
	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		store, uint32(0),
	)

	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})
	store.On("ListSyncedBlocks", mock.Anything, mock.Anything).Return(
		[]db.Block{}, nil).Maybe()
	mockChain.On("GetBlockHashes", mock.Anything, mock.Anything).Return(
		([]chainhash.Hash)(nil), errRemote).Once()

	// Act: Perform a rollback check.
	err := s.checkRollback(t.Context())

	// Assert: Verify failure.
	require.ErrorIs(t, err, errRemote)
}

// TestFilterBatch_NilFilter verifies logging and forcing download.
func TestFilterBatch_NilFilter(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a batch with a nil filter.
	s := newSyncer(Config{}, nil, nil, nil, &walletmock.Store{}, 0)

	hash := chainhash.Hash{0x01}
	results := []scanResult{
		{meta: &wtxmgr.BlockMeta{Block: wtxmgr.Block{Hash: hash}}},
	}
	filters := []*gcs.Filter{nil}
	blockMap := make(map[chainhash.Hash]*wire.MsgBlock)

	// Act: Filter the batch.
	matched, err := s.filterBatch(
		t.Context(), results, filters, blockMap, nil,
	)

	// Assert: Verify that the block is matched to force download.
	require.NoError(t, err)
	require.Len(t, matched, 1)
	require.Equal(t, hash, matched[0])
}

// TestInitChainSync_NotifyBlocksError verifies error propagation.
func TestInitChainSync_NotifyBlocksError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer where block notification fails.
	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		store, uint32(0),
	)

	mockChain.On("IsCurrent").Return(true).Once()
	mockChain.On("NotifyBlocks").Return(errNotify).Once()

	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 0})

	// Act: Attempt chain sync initialization.
	err := s.initChainSync(t.Context())

	// Assert: Verify failure.
	require.ErrorContains(t, err, "unable to start block notifications")
}

// TestScanBatchHeadersOnly_Errors verifies error paths.
func TestScanBatchHeadersOnly_Errors(t *testing.T) {
	t.Parallel()

	t.Run("GetBlockHashes_Failure", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup mock expectations where GetBlockHashes fails.
		mockChain := &bwmock.Chain{}
		s := newSyncer(
			Config{Chain: mockChain}, nil, nil, nil,
			&walletmock.Store{}, 0,
		)

		mockChain.On("GetBlockHashes", mock.Anything,
			mock.Anything).Return(([]chainhash.Hash)(nil),
			errHashes).Once()

		// Act: Perform header-only scan.
		results, err := s.scanBatchHeadersOnly(t.Context(), 0, 0)

		// Assert: Verify failure.
		require.Nil(t, results)
		require.ErrorIs(t, err, errHashes)
	})

	t.Run("GetBlockHeaders_Failure", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup mock expectations where GetBlockHeaders fails.
		mockChain := &bwmock.Chain{}
		s := newSyncer(
			Config{Chain: mockChain}, nil, nil, nil,
			&walletmock.Store{}, 0,
		)

		mockChain.On("GetBlockHashes", mock.Anything,
			mock.Anything).Return([]chainhash.Hash{{}}, nil).Once()
		mockChain.On("GetBlockHeaders", mock.Anything).Return(
			([]*wire.BlockHeader)(nil), errHeaders).Once()

		// Act: Perform header-only scan again.
		results, err := s.scanBatchHeadersOnly(t.Context(), 0, 0)

		// Assert: Verify failure.
		require.Nil(t, results)
		require.ErrorIs(t, err, errHeaders)
	})
}

// TestCheckRollback_HeaderError verifies error when fetching fork header.
func TestCheckRollback_HeaderError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer for a rollback check where a
	// header fetch failure occurs at the fork point.
	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		store, uint32(0),
	)

	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 101})

	hashA := chainhash.Hash{0x0A}
	hashB := chainhash.Hash{0x0B}
	hashC := chainhash.Hash{0x0C}

	// The store returns the local synced blocks for the range [92, 101]
	// ascending: heights 92..99 are unique fillers, height 100 is hashA and
	// height 101 is hashB.
	localBlocks := make([]db.Block, 0, 10)
	for h := uint32(92); h <= 101; h++ {
		block := db.Block{Hash: chainhash.Hash{byte(h)}, Height: h}
		switch h {
		case 100:
			block.Hash = hashA
		case 101:
			block.Hash = hashB
		}

		localBlocks = append(localBlocks, block)
	}

	store.On("ListSyncedBlocks", mock.Anything, db.ListSyncedBlocksQuery{
		StartHeight: 92,
		EndHeight:   101,
	}).Return(localBlocks, nil).Once()

	// The remote chain agrees up to height 100 (hashA at index 8) but
	// diverges at the tip (hashC at index 9), so the fork point is height
	// 100 and the syncer fetches that block's header.
	remoteHashes := make([]chainhash.Hash, 10)
	remoteHashes[8] = hashA
	remoteHashes[9] = hashC
	mockChain.On("GetBlockHashes", int64(92), int64(101)).Return(
		remoteHashes, nil).Once()
	mockChain.On("GetBlockHeader", &hashA).Return(
		(*wire.BlockHeader)(nil), errHeader).Once()

	// Act: Perform the rollback check.
	err := s.checkRollback(t.Context())

	// Assert: Verify failure.
	require.ErrorIs(t, err, errHeader)
}

// TestFilterBatch_Match verifies positive match logic.
func TestFilterBatch_Match(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a batch with a matching filter.
	s := newSyncer(Config{}, nil, nil, nil, &walletmock.Store{}, 0)

	hash := chainhash.Hash{0x01}
	results := []scanResult{
		{meta: &wtxmgr.BlockMeta{Block: wtxmgr.Block{Hash: hash}}},
	}
	blockMap := make(map[chainhash.Hash]*wire.MsgBlock)

	key := builder.DeriveKey(&hash)
	filter, err := gcs.BuildGCSFilter(
		builder.DefaultP, builder.DefaultM, key, [][]byte{{0x01}},
	)
	require.NoError(t, err)

	filters := []*gcs.Filter{filter}
	watchList := [][]byte{{0x01}}

	// Act: Filter the batch.
	matched, err := s.filterBatch(
		t.Context(), results, filters, blockMap, watchList,
	)

	// Assert: Verify the match.
	require.NoError(t, err)
	require.Len(t, matched, 1)
	require.Equal(t, hash, matched[0])
}

// TestScanWithTargets_Empty verifies handling of empty batch results.
func TestScanWithTargets_Empty(t *testing.T) {
	t.Parallel()

	// Arrange: a real-backend syncer so resolveScanTargets resolves the
	// targeted default account to its durable name through the manager, and
	// storeScanHorizons loads its horizon by that name. The targeted scan
	// then returns an empty block batch.
	s, _ := newStoreScanSyncer(t)

	mockChain := &bwmock.Chain{}
	defer mockChain.AssertExpectations(t)

	s.cfg.Chain = mockChain
	s.cfg.SyncMethod = SyncMethodAuto
	s.cfg.MaxCFilterItems = 100
	s.cfg.RecoveryWindow = MinRecoveryWindow

	// Target the auto-created default derived account at number 0. It
	// resolves to its durable name and seeds the recovery state with a
	// lookahead window, so the scan exercises the filter path rather than
	// the header-only shortcut for an empty watchlist.
	req := &scanReq{
		startBlock: waddrmgr.BlockStamp{Height: 100},
		targets: []waddrmgr.AccountScope{{
			Scope:   waddrmgr.KeyScopeBIP0084,
			Account: waddrmgr.DefaultAccountNum,
		}},
	}

	mockChain.On("GetBestBlock").Return(&chainhash.Hash{}, int32(100),
		nil).Once()
	mockChain.On("GetBlockHashes", int64(100), int64(100)).Return(
		[]chainhash.Hash{}, nil).Once()
	mockChain.On("GetCFilters", []chainhash.Hash{},
		wire.GCSFilterRegular).Return([]*gcs.Filter{}, nil).Once()
	mockChain.On("GetBlockHeaders", []chainhash.Hash{}).Return(
		[]*wire.BlockHeader{}, nil).Once()

	// Act: Perform the scan.
	err := s.scanWithTargets(t.Context(), req)

	// Assert: Verify that an empty batch error is returned.
	require.ErrorIs(t, err, ErrScanBatchEmpty)
}

// TestInitChainSync_Neutrino verifies the type switch case for NeutrinoClient.
func TestInitChainSync_Neutrino(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock neutrino chain service and a syncer with a
	// NeutrinoClient.
	mockCS := &bwmock.NeutrinoChain{}
	// IsCurrent called by waitUntilBackendSynced.
	// Return false to keep polling until context cancel.
	mockCS.On("IsCurrent").Return(false).Maybe()

	nc := &chain.NeutrinoClient{
		CS: mockCS,
	}
	mockAddrStore := &bwmock.AddrStore{}
	// Birthday called by SetStartTime.
	mockAddrStore.On("Birthday").Return(time.Time{}).Once()

	s := newSyncer(
		Config{Chain: nc}, mockAddrStore, nil, nil,
		&walletmock.Store{}, 0,
	)

	// Cancel context immediately to abort waitUntilBackendSynced.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Attempt chain sync initialization.
	err := s.initChainSync(ctx)

	// Assert: Verify cancellation error and that Birthday was accessed.
	require.Error(t, err)
	mockAddrStore.AssertExpectations(t)
}

// TestFetchAndFilterBlocks_HeaderScan verifies the optimization for empty scan
// state.
func TestFetchAndFilterBlocks_HeaderScan(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer with an empty scan state.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	scanState := NewRecoveryState(10, nil, nil)

	// Expect hash and header fetching for the empty scan state.
	mockChain.On("GetBlockHashes", int64(100), int64(100)).Return(
		[]chainhash.Hash{{0x01}}, nil,
	).Once()
	mockChain.On("GetBlockHeaders", mock.Anything).Return(
		[]*wire.BlockHeader{{Timestamp: time.Unix(12345, 0)}}, nil,
	).Once()

	// Act: Perform the fetch and filter operation.
	results, err := s.fetchAndFilterBlocks(
		t.Context(), scanState, 100, 100,
	)

	// Assert: Verify results.
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, int32(100), results[0].meta.Height)
}

// TestScanBatchWithFullBlocks_ProcessError verifies error from ProcessBlock.
func TestScanBatchWithFullBlocks_ProcessError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations to simulate an expansion failure
	// during full block scanning.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain, DB: db}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	addrStore := &bwmock.AccountStore{}
	rs := NewRecoveryState(10, &chainParams, nil)
	rs.addrFilters = make(map[string]AddrEntry)
	rs.outpoints = make(map[wire.OutPoint][]byte)
	rs.branchStates[waddrmgr.BranchScope{}] = NewBranchRecoveryState(
		10, addrStore,
	)

	// Force expansion by finding an address.
	addr, err := btcutil.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)

	rs.addrFilters[addr.EncodeAddress()] = AddrEntry{
		Address:     addr,
		IsLookahead: true,
		addrScope:   waddrmgr.AddrScope{Index: 0},
	}
	block := wire.NewMsgBlock(&wire.BlockHeader{})
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	tx := wire.NewMsgTx(1)
	tx.AddTxOut(wire.NewTxOut(100, pkScript))
	require.NoError(t, block.AddTransaction(tx))

	hashes := []chainhash.Hash{{0x01}}
	mockChain.On("GetBlocks", hashes).Return([]*wire.MsgBlock{block},
		nil).Once()
	addrStore.On("DeriveAddr", mock.Anything, mock.Anything,
		mock.Anything).Return(nil, nil, errDeriveFail).Once()

	// Act: Execute the scan.
	results, err := s.scanBatchWithFullBlocks(
		t.Context(), rs, 100, hashes,
	)

	// Assert: Verify derivation failure.
	require.Nil(t, results)
	require.ErrorContains(t, err, "derive fail")
}

// TestDispatchScanStrategy_Auto verifies heuristics.
func TestDispatchScanStrategy_Auto(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations for the auto dispatch strategy.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{
			Chain:           mockChain,
			SyncMethod:      SyncMethodAuto,
			MaxCFilterItems: 1,
		}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)
	scanState := NewRecoveryState(10, nil, nil)

	scanState.outpoints = make(map[wire.OutPoint][]byte)
	for i := range 5 {
		scanState.outpoints[wire.OutPoint{Index: uint32(i)}] = []byte{}
	}

	hashes := []chainhash.Hash{{0x01}}
	mockChain.On("GetBlocks", hashes).Return(
		[]*wire.MsgBlock{wire.NewMsgBlock(&wire.BlockHeader{})}, nil,
	).Once()

	// Act: Dispatch the scan strategy.
	results, err := s.dispatchScanStrategy(
		t.Context(), scanState, 100, hashes,
	)

	// Assert: Verify successful dispatch.
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// TestDispatchScanStrategy_AutoFallback_Final verifies fallback on
// ErrCFiltersUnavailable.
func TestDispatchScanStrategy_AutoFallback_Final(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where CFilters are unavailable,
	// triggering a fallback to full blocks.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{
			Chain:      mockChain,
			SyncMethod: SyncMethodAuto,
		}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	scanState := NewRecoveryState(10, nil, nil)
	scanState.outpoints = make(map[wire.OutPoint][]byte)
	scanState.outpoints[wire.OutPoint{}] = []byte{}
	hashes := []chainhash.Hash{{0x01}}

	mockChain.On("GetCFilters", hashes, mock.Anything).Return(
		[]*gcs.Filter(nil), ErrCFiltersUnavailable).Once()
	mockChain.On("GetBlocks", hashes).Return(
		[]*wire.MsgBlock{wire.NewMsgBlock(&wire.BlockHeader{})}, nil,
	).Once()

	// Act: Dispatch the strategy.
	results, err := s.dispatchScanStrategy(
		t.Context(), scanState, 100, hashes,
	)

	// Assert: Verify successful fallback.
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// TestProcessChainUpdate_Disconnected verifies rollback on disconnect.
func TestProcessChainUpdate_Disconnected(t *testing.T) {
	t.Parallel()

	// Arrange: Create a store-backed syncer reporting an unsynced tip, so
	// the rollback check returns without scanning any block ranges.
	store := &walletmock.Store{}
	s := newSyncer(
		Config{}, nil, nil, nil, store, uint32(0),
	)

	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 0})

	// Act: Process a BlockDisconnected update.
	err := s.processChainUpdate(
		t.Context(), chain.BlockDisconnected{},
	)

	// Assert: Verify success.
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestScanWithTargets_Errors verifies error paths in scanWithTargets.
func TestScanWithTargets_Errors(t *testing.T) {
	t.Parallel()

	t.Run("GetBestBlock_Failure", func(t *testing.T) {
		t.Parallel()

		// Arrange: a real-backend syncer where GetBestBlock fails after
		// the targeted scan state has loaded through the Store.
		s, _ := newStoreScanSyncer(t)

		mockChain := &bwmock.Chain{}
		s.cfg.Chain = mockChain
		s.cfg.RecoveryWindow = MinRecoveryWindow

		req := &scanReq{
			startBlock: waddrmgr.BlockStamp{Height: 100},
			targets: []waddrmgr.AccountScope{{
				Scope:   waddrmgr.KeyScopeBIP0084,
				Account: waddrmgr.DefaultAccountNum,
			}},
		}

		mockChain.On("GetBestBlock").Return(nil, int32(0),
			errBestBlock).Once()

		// Act: Attempt targeted scan.
		err := s.scanWithTargets(t.Context(), req)

		// Assert: Verify failure.
		require.ErrorContains(t, err, "best block fail")
	})

	t.Run("GetBlockHashes_Failure", func(t *testing.T) {
		t.Parallel()

		// Arrange: a real-backend syncer where GetBlockHashes fails after
		// the targeted scan state has loaded through the Store.
		s, _ := newStoreScanSyncer(t)

		mockChain := &bwmock.Chain{}
		s.cfg.Chain = mockChain
		s.cfg.RecoveryWindow = MinRecoveryWindow

		req := &scanReq{
			startBlock: waddrmgr.BlockStamp{Height: 100},
			targets: []waddrmgr.AccountScope{{
				Scope:   waddrmgr.KeyScopeBIP0084,
				Account: waddrmgr.DefaultAccountNum,
			}},
		}

		mockChain.On("GetBestBlock").Return(&chainhash.Hash{},
			int32(200), nil).Once()
		mockChain.On("GetBlockHashes", mock.Anything,
			mock.Anything).Return([]chainhash.Hash(nil),
			errHashes).Once()

		// Act: Attempt targeted scan.
		err := s.scanWithTargets(t.Context(), req)

		// Assert: Verify failure.
		require.ErrorContains(t, err, "hashes fail")
	})

	t.Run("FetchScopedKeyManager_Failure", func(t *testing.T) {
		t.Parallel()

		// Arrange: a real-backend syncer targeting a scope with no
		// registered scoped key manager. resolveScanTargets resolves
		// every non-imported target's durable name up front through the
		// manager, so the unknown scope fails there -- before any Store
		// horizon lookup.
		s, _ := newStoreScanSyncer(t)

		targets := []waddrmgr.AccountScope{{
			Scope:   waddrmgr.KeyScope{Purpose: 99, Coin: 0},
			Account: waddrmgr.DefaultAccountNum,
		}}

		// Act: Attempt a targeted scan.
		err := s.scanWithTargets(
			t.Context(), &scanReq{
				targets:    targets,
				startBlock: waddrmgr.BlockStamp{Height: 100},
			},
		)

		// Assert: the failure surfaces from resolving the scan target's
		// scoped manager, not from a later Store lookup.
		var mgrErr waddrmgr.ManagerError
		require.ErrorAs(t, err, &mgrErr)
		require.Equal(t, waddrmgr.ErrScopeNotFound, mgrErr.ErrorCode)
		require.ErrorContains(t, err, "fetch scoped manager")
	})
}

// TestScanBatchWithCFilters_InitResultsError verifies error propagation.
func TestScanBatchWithCFilters_InitResultsError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where header retrieval fails during
	// initialization for a CFilter scan.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{
			Chain:      mockChain,
			SyncMethod: SyncMethodCFilters,
		}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	hashes := []chainhash.Hash{{0x01}}
	mockChain.On("GetCFilters", hashes, mock.Anything).Return(
		[]*gcs.Filter{{}}, nil).Once()
	mockChain.On("GetBlockHeaders", hashes).Return(
		[]*wire.BlockHeader(nil), errHeaders).Once()

	// Act: Attempt batch scan with CFilters.
	results, err := s.scanBatchWithCFilters(
		t.Context(), nil, 100, hashes,
	)

	// Assert: Verify failure.
	require.Nil(t, results)
	require.ErrorContains(t, err, "headers fail")
}

// TestProcessChainUpdate verifies processChainUpdate for all update types.
func TestProcessChainUpdate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		update interface{}
		setup  func(*walletmock.Store, *bwmock.Chain)
	}{
		{
			name: "BlockConnected",
			update: chain.BlockConnected{
				Block: wtxmgr.Block{Height: 100},
			},
			setup: func(store *walletmock.Store, c *bwmock.Chain) {
				store.On("UpdateWallet", mock.Anything, mock.MatchedBy(
					func(params db.UpdateWalletParams) bool {
						return params.SyncedTo != nil &&
							params.SyncedTo.Height == 100
					})).Return(nil).Once()
			},
		},
		{
			name: "RelevantTx",
			update: chain.RelevantTx{
				TxRecord: &wtxmgr.TxRecord{MsgTx: *wire.NewMsgTx(1)},
			},
			setup: func(store *walletmock.Store, c *bwmock.Chain) {
				store.On("ApplyTxBatch", mock.Anything,
					mock.Anything).Return(nil).Once()
			},
		},
		{
			name: "FilteredBlockConnected",
			update: chain.FilteredBlockConnected{
				Block: &wtxmgr.BlockMeta{
					Block: wtxmgr.Block{Height: 102},
				},
			},
			setup: func(store *walletmock.Store, c *bwmock.Chain) {
				store.On("ApplyTxBatch", mock.Anything, mock.MatchedBy(
					func(params db.TxBatchParams) bool {
						return params.SyncedTo != nil &&
							params.SyncedTo.Height == 102
					})).Return(nil).Once()
			},
		},
		{
			name: "BlockDisconnected",
			update: chain.BlockDisconnected{
				Block: wtxmgr.Block{Height: 100, Hash: chainhash.Hash{0x01}},
			},
			setup: func(store *walletmock.Store, c *bwmock.Chain) {
				expectSyncedTip(
					store, waddrmgr.BlockStamp{Height: 100},
				)

				localBlocks := make([]db.Block, 0, 10)
				for i := uint32(91); i <= 100; i++ {
					localBlocks = append(localBlocks, db.Block{
						Height: i,
					})
				}
				store.On(
					"ListSyncedBlocks", mock.Anything, mock.Anything,
				).Return(localBlocks, nil).Once()

				remoteHashes := make([]chainhash.Hash, 10)
				c.On(
					"GetBlockHashes", mock.Anything, mock.Anything,
				).Return(remoteHashes, nil).Once()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			store := &walletmock.Store{}
			mockChain := &bwmock.Chain{}
			s := newSyncer(
				Config{
					Chain:       mockChain,
					ChainParams: &chainParams,
				},
				nil, nil, nil,
				store, uint32(0),
			)

			tc.setup(store, mockChain)

			// Act
			err := s.processChainUpdate(t.Context(), tc.update)

			// Assert
			require.NoError(t, err)
		})
	}
}

// TestProcessChainUpdateRoutesSyncTip verifies connected block notifications
// update the runtime store sync tip when the store is available.
func TestProcessChainUpdateRoutesSyncTip(t *testing.T) {
	t.Parallel()

	store := &walletmock.Store{}
	s := newSyncer(Config{}, nil, nil, nil, &walletmock.Store{}, 0)
	s.store = store
	s.walletID = 77

	block := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   chainhash.Hash{77},
			Height: 144,
		},
		Time: time.Unix(1710003800, 0),
	}
	store.On("UpdateWallet", mock.Anything, mock.MatchedBy(
		func(params db.UpdateWalletParams) bool {
			return params.WalletID == s.walletID &&
				params.SyncedTo != nil &&
				params.SyncedTo.Hash == block.Hash &&
				params.SyncedTo.Height == uint32(block.Height) &&
				params.SyncedTo.Timestamp.Equal(block.Time)
		},
	)).Return(nil).Once()

	err := s.processChainUpdate(t.Context(), chain.BlockConnected(block))
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestBroadcastUnminedTxnsRoutesStore verifies rebroadcast reads active unmined
// transactions from the runtime store and publishes the decoded transaction.
func TestBroadcastUnminedTxnsRoutesStore(t *testing.T) {
	t.Parallel()

	store := &walletmock.Store{}
	publisher := &mockTxPublisher{}
	s := newSyncer(Config{}, nil, nil, publisher, &walletmock.Store{}, 0)
	s.store = store
	s.walletID = 66

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{66},
	}})
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})

	var txBytes bytes.Buffer

	err := tx.Serialize(&txBytes)
	require.NoError(t, err)

	store.On("ListTxns", mock.Anything, db.ListTxnsQuery{
		WalletID:    s.walletID,
		UnminedOnly: true,
	}).Return([]db.TxInfo{{
		Hash:         tx.TxHash(),
		Status:       db.TxStatusPublished,
		SerializedTx: txBytes.Bytes(),
	}}, nil).Once()
	publisher.On("Broadcast", mock.Anything, mock.MatchedBy(
		func(got *wire.MsgTx) bool {
			return got.TxHash() == tx.TxHash()
		},
	), "").Return(nil).Once()

	err = s.broadcastUnminedTxns(t.Context())
	require.NoError(t, err)
	store.AssertExpectations(t)
	publisher.AssertExpectations(t)
}

// TestSyncedBlockHashesRoutesStore verifies rollback reads consult the runtime
// store when it is available.
func TestSyncedBlockHashesRoutesStore(t *testing.T) {
	t.Parallel()

	store := &walletmock.Store{}
	s := newSyncer(Config{}, nil, nil, nil, &walletmock.Store{}, 0)
	s.store = store
	s.walletID = 88

	blocks := []db.Block{{Hash: chainhash.Hash{88}, Height: 100}, {
		Hash:   chainhash.Hash{89},
		Height: 101,
	}}
	store.On("ListSyncedBlocks", mock.Anything, db.ListSyncedBlocksQuery{
		StartHeight: 100,
		EndHeight:   101,
	}).Return(blocks, nil).Once()

	hashes, err := s.syncedBlockHashes(t.Context(), 100, 101)
	require.NoError(t, err)
	require.Len(t, hashes, 2)
	require.Equal(t, blocks[0].Hash, *hashes[0])
	require.Equal(t, blocks[1].Hash, *hashes[1])
	store.AssertExpectations(t)
}

// TestRewindToBlockRoutesStore verifies the store rewind path issues a single
// atomic RollbackToBlock for the rollback boundary, which rewinds the wallet
// sync tip and rolls transaction state back together, rather than two
// independent sync-tip and rollback writes.
func TestRewindToBlockRoutesStore(t *testing.T) {
	t.Parallel()

	store := &walletmock.Store{}
	s := newSyncer(Config{}, nil, nil, nil, &walletmock.Store{}, 0)
	s.store = store
	s.walletID = 99

	fork := waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{99},
		Height:    100,
		Timestamp: time.Unix(1710003900, 0),
	}

	store.On(
		"RollbackToBlock", mock.Anything, uint32(101),
	).Return(nil).Once()

	err := s.rewindToBlock(t.Context(), fork)
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestHandleChainUpdate_SpecialNotifs verifies RescanProgress and
// RescanFinished.
func TestHandleChainUpdate_SpecialNotifs(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer for special notification handling.
	mockAddrStore := &bwmock.AddrStore{}
	s := newSyncer(Config{}, mockAddrStore, nil, nil, &walletmock.Store{}, 0)

	// 1. RescanProgress
	// Act: Handle RescanProgress.
	err := s.handleChainUpdate(
		t.Context(), &chain.RescanProgress{
			Height: 100, Hash: chainhash.Hash{0x01},
		},
	)
	require.NoError(t, err)

	// 2. RescanFinished
	// Act: Handle RescanFinished.
	err = s.handleChainUpdate(
		t.Context(), &chain.RescanFinished{
			Height: 100, Hash: &chainhash.Hash{0x01},
		},
	)
	require.NoError(t, err)
}

// TestSyncStateString verifies String representations.
func TestSyncStateString(t *testing.T) {
	t.Parallel()

	// Arrange: Define test cases for syncState string conversion.
	tests := []struct {
		state syncState
		want  string
	}{
		{syncStateBackendSyncing, "backend-syncing"},
		{syncStateSyncing, "syncing"},
		{syncStateSynced, "synced"},
		{syncStateRescanning, "rescanning"},
		{syncState(99), "unknown sync state"},
	}

	// Act & Assert: Execute test cases.
	for _, tt := range tests {
		require.Equal(t, tt.want, tt.state.String())
	}
}

// TestFetchAndFilterBlocks_BatchCapping verifies endHeight calculation.
func TestFetchAndFilterBlocks_BatchCapping(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer with expectations for batch capping.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)
	scanState := NewRecoveryState(10, nil, nil)

	// Expect GetBlockHashes with a capped range based on recoveryBatchSize.
	mockChain.On("GetBlockHashes", int64(100), int64(2099)).Return(
		[]chainhash.Hash{{0x01}}, nil,
	).Once()
	mockChain.On("GetBlockHeaders", mock.Anything).Return(
		[]*wire.BlockHeader{{}}, nil,
	).Once()

	// Act: Perform the fetch.
	results, err := s.fetchAndFilterBlocks(
		t.Context(), scanState, 100, 5000,
	)

	// Assert: Verify success.
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// TestRunSyncStep_Unfinished verifies the early return if sync not finished.
func TestRunSyncStep_Unfinished(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer with an incomplete sync state.
	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		store, uint32(0),
	)

	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 90})
	mockChain.On("GetBestBlock").Return(&chainhash.Hash{}, int32(100),
		nil).Once()

	// The scan over the gap reads empty scan data through the store and
	// advances the synced tip through the store batch.
	store.On("ListAccounts", mock.Anything, mock.Anything).Return(
		([]db.AccountInfo)(nil), nil).Maybe()
	store.On("ListOutputsToWatch", mock.Anything, mock.Anything).Return(
		([]db.UtxoInfo)(nil), nil).Maybe()
	mockChain.On("GetBlockHashes", int64(91), int64(100)).Return(
		[]chainhash.Hash{{0x01}}, nil).Once()
	mockChain.On("GetBlockHeaders", mock.Anything).Return(
		[]*wire.BlockHeader{{}}, nil).Once()
	store.On("ApplyScanBatch", mock.Anything, mock.Anything).Return(
		nil).Maybe()

	// Act: Execute a sync step.
	err := s.runSyncStep(t.Context())

	// Assert: Verify success.
	require.NoError(t, err)
}

// TestDispatchScanStrategy_OtherMethods verifies FullBlocks, CFilters and
// Default.
func TestDispatchScanStrategy_OtherMethods(t *testing.T) {
	t.Parallel()

	hashes := []chainhash.Hash{{0x01}}
	scanState := NewRecoveryState(10, nil, nil)

	t.Run("FullBlocks", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup a syncer for FullBlocks strategy.
		mockChain := &bwmock.Chain{}
		s := newSyncer(
			Config{
				Chain:      mockChain,
				SyncMethod: SyncMethodFullBlocks,
			}, nil, nil, nil,
			&walletmock.Store{}, 0,
		)
		mockChain.On("GetBlocks", hashes).Return([]*wire.MsgBlock{
			wire.NewMsgBlock(&wire.BlockHeader{})}, nil).Once()

		// Act: Dispatch the strategy.
		results, err := s.dispatchScanStrategy(
			t.Context(), scanState, 100, hashes,
		)

		// Assert: Verify success.
		require.NoError(t, err)
		require.Len(t, results, 1)
	})

	t.Run("CFilters", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup a syncer for CFilters strategy.
		mockChain := &bwmock.Chain{}
		s := newSyncer(
			Config{
				Chain:      mockChain,
				SyncMethod: SyncMethodCFilters,
			}, nil, nil, nil,
			&walletmock.Store{}, 0,
		)
		mockChain.On("GetCFilters", hashes, mock.Anything).Return(
			[]*gcs.Filter{{}}, nil).Once()
		mockChain.On("GetBlockHeaders", hashes).Return(
			[]*wire.BlockHeader{{}}, nil).Once()
		mockChain.On("GetBlocks", mock.Anything).Return(
			[]*wire.MsgBlock{wire.NewMsgBlock(&wire.BlockHeader{})},
			nil).Once()

		// Act: Dispatch the strategy.
		results, err := s.dispatchScanStrategy(
			t.Context(), scanState, 100, hashes,
		)

		// Assert: Verify success.
		require.NoError(t, err)
		require.Len(t, results, 1)
	})

	t.Run("Default_Unknown", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup a syncer with an unknown method.
		mockChain := &bwmock.Chain{}
		s := newSyncer(
			Config{
				Chain:      mockChain,
				SyncMethod: 99,
			}, nil, nil, nil,
			&walletmock.Store{}, 0,
		)

		// Act: Dispatch the strategy.
		results, err := s.dispatchScanStrategy(
			t.Context(), scanState, 100, hashes,
		)

		// Assert: Verify failure for unknown method.
		require.Nil(t, results)
		require.ErrorContains(t, err, "unknown sync method")
	})
}

// TestHandleChainUpdate_Error verifies that handleChainUpdate returns error if
// processChainUpdate fails.
func TestHandleChainUpdate_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer where chain update processing
	// fails because the synced-block read errors.
	store := &walletmock.Store{}
	s := newSyncer(
		Config{}, nil, nil, nil, store, uint32(0),
	)

	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})
	store.On("ListSyncedBlocks", mock.Anything, mock.Anything).Return(
		([]db.Block)(nil), errDBFail).Once()

	// Act: Attempt to handle a BlockDisconnected update.
	err := s.handleChainUpdate(
		t.Context(), chain.BlockDisconnected{},
	)

	// Assert: Verify failure.
	require.ErrorContains(t, err, "failed to process chain update")
}

// TestRunSyncStep_Success verifies the idle path in runSyncStep.
func TestRunSyncStep_Success(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer and mock a notification arrival
	// to trigger the idle processing path.
	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		store, uint32(0),
	)

	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})
	mockChain.On("GetBestBlock").Return(&chainhash.Hash{}, int32(100),
		nil).Once()
	store.On("ListTxns", mock.Anything, mock.Anything).Return(
		[]db.TxInfo{}, nil).Once()

	notifChan := make(chan any, 1)
	mockChain.On("Notifications").Return((<-chan any)(notifChan)).Maybe()

	notifChan <- chain.BlockConnected{Block: wtxmgr.Block{Height: 101}}

	// The queued BlockConnected notification advances the synced tip
	// through the store.
	store.On("UpdateWallet", mock.Anything, mock.Anything).Return(
		nil).Once()

	// Act: Execute a sync step.
	err := s.runSyncStep(t.Context())

	// Assert: Verify success.
	require.NoError(t, err)
}

// TestScanBatchWithCFilters_HorizonExpansion verifies the re-matching logic
// when a horizon is expanded.
func TestScanBatchWithCFilters_HorizonExpansion(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a complex mock scenario where finding an address
	// triggers a horizon expansion, requiring a re-match of the block
	// batch.
	mockChain := &bwmock.Chain{}
	addrStore := &bwmock.AddrStore{}
	accountStore := &bwmock.AccountStore{}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	s := newSyncer(
		Config{Chain: mockChain, DB: db}, addrStore, nil, nil,
		&walletmock.Store{}, 0,
	)

	hashes := []chainhash.Hash{{0x01}, {0x02}}

	mockChain.On("GetCFilters", hashes, wire.GCSFilterRegular).Return(
		[]*gcs.Filter{nil, nil}, nil).Once()
	mockChain.On("GetBlockHeaders", hashes).Return(
		[]*wire.BlockHeader{{}, {}}, nil).Once()

	block1 := wire.NewMsgBlock(&wire.BlockHeader{})
	block2 := wire.NewMsgBlock(&wire.BlockHeader{})
	mockChain.On("GetBlocks", mock.MatchedBy(func(h []chainhash.Hash) bool {
		return len(h) == 2
	})).Return([]*wire.MsgBlock{block1, block2}, nil).Once()

	scanState := NewRecoveryState(1, &chainParams, addrStore)

	scanState.addrFilters = make(map[string]AddrEntry)
	scanState.outpoints = make(map[wire.OutPoint][]byte)

	bs := waddrmgr.BranchScope{}
	scanState.branchStates[bs] = NewBranchRecoveryState(1, accountStore)

	// Found address in block 1.
	addr, err := btcutil.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)

	scanState.addrFilters[addr.EncodeAddress()] = AddrEntry{
		Address:     addr,
		IsLookahead: true,
		addrScope:   waddrmgr.AddrScope{Index: 0},
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	tx1 := wire.NewMsgTx(1)
	tx1.AddTxOut(wire.NewTxOut(100, pkScript))
	require.NoError(t, block1.AddTransaction(tx1))

	// Mock DeriveAddr and ExtendAddresses for expansion.
	expAddr, err := btcutil.NewAddressPubKeyHash(
		append([]byte{1}, make([]byte, 19)...), &chainParams,
	)
	require.NoError(t, err)

	accountStore.On("DeriveAddr", mock.Anything, mock.Anything,
		mock.Anything).Return(expAddr, []byte{}, nil).Maybe()
	accountStore.On("ExtendAddresses", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Return(
		[]btcutil.Address{expAddr}, [][]byte{make([]byte, 20)}, nil,
	).Once()

	// Act: Perform a batch scan with CFilters.
	results, err := s.scanBatchWithCFilters(
		t.Context(), scanState, 100, hashes,
	)

	// Assert: Verify that both blocks were returned after expansion.
	require.NoError(t, err)
	require.Len(t, results, 2)
}

// TestRunSyncStep_AdvanceError verifies that runSyncStep returns errors
// from advanceChainSync.
func TestRunSyncStep_AdvanceError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer where loading the scan state
	// fails within runSyncStep.
	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		store, uint32(0),
	)

	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})

	mockChain.On("GetBestBlock").Return(
		&chainhash.Hash{}, int32(101), nil).Once()

	store.On("ListAccounts", mock.Anything, mock.Anything).Return(
		([]db.AccountInfo)(nil), errLoadStateFail).Once()

	// Act: Execute a single sync step.
	err := s.runSyncStep(t.Context())

	// Assert: Verify error propagation.
	require.ErrorContains(t, err, "load state fail")
}

// TestLoadFullScanState_Error verifies error propagation.
func TestLoadFullScanState_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer where loading scan data fails.
	store := &walletmock.Store{}
	s := newSyncer(
		Config{}, nil, nil, nil, store, uint32(0),
	)

	store.On("ListAccounts", mock.Anything, mock.Anything).Return(
		([]db.AccountInfo)(nil), errDBMock).Once()

	// Act: Attempt to load the full scan state.
	state, err := s.loadFullScanState(t.Context())

	// Assert: Verify failure.
	require.Nil(t, state)
	require.ErrorContains(t, err, "db error")
}

// TestScanWithRewind_Error verifies error propagation from scanWithRewind.
func TestScanWithRewind_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer for a rewind scan where the
	// store rollback fails.
	store := &walletmock.Store{}
	s := newSyncer(
		Config{}, nil, nil, nil, store, uint32(0),
	)

	// The current tip is at height 100, so a rewind to height 90 issues an
	// atomic store rollback for the rollback boundary (91), which fails.
	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})
	store.On("RollbackToBlock", mock.Anything, uint32(91)).Return(
		errRollbackFail).Once()

	// Act: Attempt to perform a scan with rewind.
	err := s.scanWithRewind(
		t.Context(), &scanReq{
			startBlock: waddrmgr.BlockStamp{Height: 90},
		},
	)

	// Assert: Verify rollback failure is propagated.
	require.ErrorContains(t, err, "rollback fail")
}

// TestMatchAndFetchBatch_GetBlockHeadersError verifies error handling.
func TestMatchAndFetchBatch_GetBlockHeadersError(t *testing.T) {
	t.Parallel()

	// Arrange: Create a nil filter to force a match, bypassing complex
	// filter logic, then mock a block fetch failure.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	filters := []*gcs.Filter{nil}
	results := []scanResult{{
		meta: &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Hash: chainhash.Hash{0x01}},
		},
	}}

	blockMap := make(map[chainhash.Hash]*wire.MsgBlock)

	state := NewRecoveryState(10, nil, nil)

	mockChain.On("GetBlocks", mock.Anything).Return(
		[]*wire.MsgBlock(nil), errGetBlocks).Once()

	// Act: Attempt to match and fetch a batch.
	err := s.matchAndFetchBatch(
		t.Context(), state, results, filters, blockMap,
	)

	// Assert: Verify failure.
	require.ErrorContains(t, err, "get blocks fail")
}

// TestScanBatchWithCFilters_FilterBatchError verifies error propagation.
func TestScanBatchWithCFilters_FilterBatchError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where CFilter retrieval fails.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	hashes := []chainhash.Hash{{0x01}}

	mockChain.On("GetCFilters", hashes, wire.GCSFilterRegular).Return(
		[]*gcs.Filter(nil), errCFilterFail).Once()

	// Act: Attempt a batch scan using CFilters.
	results, err := s.scanBatchWithCFilters(
		t.Context(), nil, 100, hashes,
	)

	// Assert: Verify failure.
	require.Nil(t, results)
	require.ErrorContains(t, err, "cfilter fail")
}

// TestScanBatch_GetScanDataError verifies scanBatch failure.
func TestScanBatch_GetScanDataError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer where scan data loading fails
	// during a batch scan.
	store := &walletmock.Store{}
	s := newSyncer(
		Config{}, nil, nil, nil, store, uint32(0),
	)

	store.On("ListAccounts", mock.Anything, mock.Anything).Return(
		([]db.AccountInfo)(nil), errActiveMgrsFail).Once()

	// Act: Attempt to execute scanBatch.
	err := s.scanBatch(
		t.Context(), waddrmgr.BlockStamp{Height: 100}, 105,
	)

	// Assert: Verify error propagation.
	require.ErrorContains(t, err, "active managers fail")
}

// TestInitResultsForCFilterScan_Error verifies basic error propagation (e.g.
// GetBlockHeader).
func TestInitResultsForCFilterScan_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where header retrieval fails during
	// initialization for a CFilter scan.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	hashes := []chainhash.Hash{{0x01}}

	mockChain.On("GetBlockHeaders", hashes).Return(
		[]*wire.BlockHeader(nil), errHeaders).Once()

	// Act: Initialize results for a CFilter scan.
	results, err := s.initResultsForCFilterScan(t.Context(), 100, hashes)

	// Assert: Verify failure.
	require.Nil(t, results)
	require.ErrorContains(t, err, "headers fail")
}

// TestDispatchScanStrategy_AutoError verifies error return in Auto mode.
func TestDispatchScanStrategy_AutoError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where header retrieval fails during
	// an auto-dispatch scan.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain, SyncMethod: SyncMethodAuto},
		nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	hashes := []chainhash.Hash{{0x01}}
	scanState := NewRecoveryState(1, nil, nil)

	mockChain.On("GetCFilters", hashes, mock.Anything).Return(
		[]*gcs.Filter{{}}, nil).Once()
	mockChain.On("GetBlockHeaders", hashes).Return(
		([]*wire.BlockHeader)(nil), errOther).Once()

	// Act: Dispatch the scan strategy.
	results, err := s.dispatchScanStrategy(
		t.Context(), scanState, 100, hashes,
	)

	// Assert: Verify failure.
	require.Nil(t, results)
	require.ErrorIs(t, err, errOther)
}

// TestAdvanceChainSync_SmallGap verifies the silent sync path.
func TestAdvanceChainSync_SmallGap(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer for a small gap where silent
	// sync is preferred. The wallet has no accounts to scan, so the scan
	// batch only advances the synced tip.
	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		store, uint32(0),
	)

	mockChain.On("GetBestBlock").Return(&chainhash.Hash{}, int32(105),
		nil).Once()
	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})
	store.On("ListAccounts", mock.Anything, mock.Anything).Return(
		([]db.AccountInfo)(nil), nil).Twice()
	store.On("ListOutputsToWatch", mock.Anything, mock.Anything).Return(
		([]db.UtxoInfo)(nil), nil).Once()
	mockChain.On("GetBlockHashes", int64(101), int64(105)).Return(
		[]chainhash.Hash{{0x01}}, nil).Once()
	mockChain.On("GetBlockHeaders", mock.Anything).Return(
		[]*wire.BlockHeader{{}}, nil).Once()
	store.On("ApplyScanBatch", mock.Anything, mock.Anything).Return(
		nil).Once()

	// Act: Advance chain sync.
	finished, err := s.advanceChainSync(t.Context())

	// Assert: Verify state transition to backend-syncing.
	require.NoError(t, err)
	require.False(t, finished)
	require.Equal(t, uint32(syncStateBackendSyncing), s.state.Load())
	store.AssertExpectations(t)
}

// TestRunSyncStep_BroadcastError verifies error propagation.
func TestRunSyncStep_BroadcastError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer where the unmined-transaction
	// read fails during a sync step.
	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		store, uint32(0),
	)

	mockChain.On("GetBestBlock").Return(&chainhash.Hash{}, int32(100),
		nil).Once()
	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})
	store.On("ListTxns", mock.Anything, mock.Anything).Return(
		([]db.TxInfo)(nil), errBroadcast).Once()

	// Act: Execute a sync step.
	err := s.runSyncStep(t.Context())

	// Assert: Verify failure.
	require.ErrorIs(t, err, errBroadcast)
}

// TestFetchAndFilterBlocks_DispatchError verifies error from
// dispatchScanStrategy.
func TestFetchAndFilterBlocks_DispatchError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where an invalid sync method is
	// encountered during block filtering.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain, SyncMethod: 99}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	hashes := []chainhash.Hash{{0x01}}
	mockChain.On("GetBlockHashes", mock.Anything, mock.Anything).Return(
		hashes, nil).Once()

	scanState := NewRecoveryState(1, nil, nil)
	scanState.outpoints = make(map[wire.OutPoint][]byte)
	scanState.outpoints[wire.OutPoint{}] = []byte{}

	// Act: Attempt to fetch and filter blocks.
	results, err := s.fetchAndFilterBlocks(t.Context(), scanState, 100, 100)

	// Assert: Verify unknown sync method error.
	require.Nil(t, results)
	require.ErrorContains(t, err, "unknown sync method")
}

// TestAdvanceChainSync_ScanBatchError verifies error propagation.
func TestAdvanceChainSync_ScanBatchError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where address iteration fails
	// during chain sync advancement.
	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		store, uint32(0),
	)

	mockChain.On("GetBestBlock").Return(&chainhash.Hash{}, int32(105),
		nil).Once()
	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})
	store.On("ListAccounts", mock.Anything, mock.Anything).Return(
		([]db.AccountInfo)(nil), errScan).Once()

	// Act: Advance chain sync.
	finished, err := s.advanceChainSync(t.Context())

	// Assert: Verify failure.
	require.False(t, finished)
	require.ErrorIs(t, err, errScan)
}

// TestDispatchScanStrategy_FullBlocksError verifies error propagation.
func TestDispatchScanStrategy_FullBlocksError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where block retrieval fails during
	// a full-block scan.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain, SyncMethod: SyncMethodFullBlocks},
		nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	hashes := []chainhash.Hash{{0x01}}
	scanState := NewRecoveryState(1, nil, nil)

	mockChain.On("GetBlocks", hashes).Return([]*wire.MsgBlock(nil),
		errBlocks).Once()

	// Act: Dispatch the strategy.
	results, err := s.dispatchScanStrategy(
		t.Context(), scanState, 100, hashes,
	)

	// Assert: Verify failure.
	require.Nil(t, results)
	require.ErrorIs(t, err, errBlocks)
}

// TestExtractAddrEntries_NonStd verifies non-standard script handling.
func TestExtractAddrEntries_NonStd(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and create various output scripts,
	// including non-standard and OP_RETURN scripts.
	s := newSyncer(
		Config{ChainParams: &chainParams},
		nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	pkh, err := btcutil.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(pkh)
	require.NoError(t, err)

	txOuts := []*wire.TxOut{
		{
			// OP_DATA_1 but no data byte follows. (Error path)
			PkScript: []byte{0x01},
		},
		{
			// OP_RETURN (Empty addrs, no error)
			PkScript: []byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			// Standard P2PKH (Success path)
			PkScript: pkScript,
		},
	}

	// Act: Extract address entries.
	entries := s.extractAddrEntries(txOuts)

	// Assert: Verify that only the standard P2PKH output was extracted.
	require.Len(t, entries, 1)
}

// TestAdvanceChainSync_GetBestBlockError verifies error propagation.
func TestAdvanceChainSync_GetBestBlockError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where GetBestBlock fails during
	// chain sync advancement.
	mockChain := &bwmock.Chain{}
	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		&walletmock.Store{}, 0,
	)

	mockChain.On("GetBestBlock").Return((*chainhash.Hash)(nil), int32(0),
		errBestBlock).Once()

	// Act: Advance chain sync.
	finished, err := s.advanceChainSync(t.Context())

	// Assert: Verify failure.
	require.False(t, finished)
	require.ErrorIs(t, err, errBestBlock)
}

// TestAdvanceChainSyncStoreSyncedTip verifies that store-backed advancement
// reads the synced tip from the Store rather than the legacy addrStore. A nil
// addrStore is passed so any accidental addrStore.SyncedTo() call would panic.
func TestAdvanceChainSyncStoreSyncedTip(t *testing.T) {
	t.Parallel()

	// Arrange: a store-backed syncer whose Store reports a synced tip at
	// the chain's best height.
	const walletID uint32 = 21

	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}
	s := newSyncer(
		Config{Chain: mockChain, Name: "store-sync"}, nil, nil,
		&mockTxPublisher{},
		store, walletID,
	)

	mockChain.On("GetBestBlock").Return(
		&chainhash.Hash{}, int32(100), nil,
	).Once()
	store.On("GetWallet", mock.Anything, "store-sync").Return(
		&db.WalletInfo{
			SyncedTo: &db.Block{
				Hash:   chainhash.Hash{0x01},
				Height: 100,
			},
		}, nil,
	).Once()

	// Act: advance the chain sync.
	finished, err := s.advanceChainSync(t.Context())

	// Assert: the store tip matched the chain tip, so we are synced and
	// the addrStore was never consulted.
	require.NoError(t, err)
	require.True(t, finished)
	require.Equal(t, syncStateSynced, s.syncState())
	store.AssertExpectations(t)
	mockChain.AssertExpectations(t)
}

// TestDispatchScanStrategy_AutoDefaultThreshold verifies threshold=0 branch.
func TestDispatchScanStrategy_AutoDefaultThreshold(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations for auto strategy with a zero
	// threshold for compact filters.
	mockChain := &bwmock.Chain{}
	s := newSyncer(Config{
		Chain:           mockChain,
		SyncMethod:      SyncMethodAuto,
		MaxCFilterItems: 0,
	}, nil, nil, nil, &walletmock.Store{}, 0)

	hashes := []chainhash.Hash{{0x01}}
	scanState := NewRecoveryState(1, nil, nil)

	mockChain.On("GetCFilters", hashes, mock.Anything).Return(
		[]*gcs.Filter{{}}, nil).Once()
	mockChain.On("GetBlockHeaders", hashes).Return(
		[]*wire.BlockHeader{{}}, nil).Once()
	mockChain.On("GetBlocks", mock.Anything).Return(
		[]*wire.MsgBlock{
			wire.NewMsgBlock(&wire.BlockHeader{})}, nil).Once()

	// Act: Dispatch the strategy.
	results, err := s.dispatchScanStrategy(
		t.Context(), scanState, 100, hashes,
	)

	// Assert: Verify success.
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// TestAdvanceChainSync_LargeGap verifies the explicit syncing state.
func TestAdvanceChainSync_LargeGap(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a store-backed syncer for a large sync gap where the
	// syncing state is set before the scan runs.
	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}

	s := newSyncer(
		Config{Chain: mockChain}, nil, nil, nil,
		store, uint32(0),
	)

	mockChain.On("GetBestBlock").Return(&chainhash.Hash{}, int32(110),
		nil).Once()
	expectSyncedTip(store, waddrmgr.BlockStamp{Height: 100})

	// The scan over the gap reads empty scan data and advances the synced
	// tip through the store batch. These use Maybe() because the assertion
	// only cares that the syncing state is set, which happens before the
	// scan.
	store.On("ListAccounts", mock.Anything, mock.Anything).Return(
		([]db.AccountInfo)(nil), nil).Maybe()
	store.On("ListOutputsToWatch", mock.Anything, mock.Anything).Return(
		([]db.UtxoInfo)(nil), nil).Maybe()
	mockChain.On("GetBlockHashes", mock.Anything, mock.Anything).Return(
		[]chainhash.Hash{{0x01}}, nil).Maybe()
	mockChain.On("GetBlockHeaders", mock.Anything).Return(
		[]*wire.BlockHeader{{}}, nil).Maybe()
	store.On("ApplyScanBatch", mock.Anything, mock.Anything).Return(
		nil).Maybe()

	// Act: Advance chain sync.
	finished, err := s.advanceChainSync(t.Context())

	// Assert: Verify state transition to syncing.
	require.NoError(t, err)
	require.False(t, finished)
	require.Equal(t, uint32(syncStateSyncing), s.state.Load())
}

// TestCheckRollbackStoreSyncedTip verifies that checkRollback reads the synced
// tip from the Store rather than the legacy addrStore. The Store reports a
// current tip while the legacy addrStore is nil, so any read of the legacy tip
// would panic; checkRollback must still scan from the Store tip and detect the
// reorg. This guards a Store-backed backend that does not mirror its tip into
// the legacy manager, where a stale legacy height could skip a needed rollback.
func TestCheckRollbackStoreSyncedTip(t *testing.T) {
	t.Parallel()

	// Arrange: a store-backed syncer whose Store reports a current tip at
	// height 100. The legacy addrStore is nil so any SyncedTo() read panics.
	const walletID uint32 = 31

	mockChain := &bwmock.Chain{}
	store := &walletmock.Store{}
	s := newSyncer(
		Config{Chain: mockChain, Name: "rollback-store"}, nil, nil,
		&mockTxPublisher{},
		store, walletID,
	)

	// syncedTip reads the current tip (height 100) from the Store.
	store.On("GetWallet", mock.Anything, "rollback-store").Return(
		&db.WalletInfo{
			SyncedTo: &db.Block{
				Hash:   chainhash.Hash{0x01},
				Height: 100,
			},
		}, nil,
	).Once()

	// Local hashes for heights 91..100 come from the Store, ascending.
	localBlocks := make([]db.Block, 0, 10)
	for i := uint32(91); i <= 100; i++ {
		localBlocks = append(localBlocks, db.Block{
			Hash:   chainhash.Hash{byte(i)},
			Height: i,
		})
	}

	store.On("ListSyncedBlocks", mock.Anything, db.ListSyncedBlocksQuery{
		StartHeight: 91,
		EndHeight:   100,
	}).Return(localBlocks, nil).Once()

	// Remote hashes fork at height 95: 91..95 match, 96..100 differ.
	remoteHashes := make([]chainhash.Hash, 10)
	for i := range 10 {
		h := 91 + i
		if h > 95 {
			remoteHashes[i] = chainhash.Hash{0xff}
		} else {
			remoteHashes[i] = chainhash.Hash{byte(h)}
		}
	}

	mockChain.On(
		"GetBlockHashes", int64(91), int64(100),
	).Return(remoteHashes, nil).Once()

	forkHash := chainhash.Hash{byte(95)}
	header := &wire.BlockHeader{Timestamp: time.Unix(95, 0).UTC()}
	mockChain.On("GetBlockHeader", &forkHash).Return(header, nil).Once()

	// The rollback is written atomically through the Store to the fork
	// height plus one (96). RollbackToBlock derives the new sync tip from
	// the stored fork-point block, so the caller only supplies the rollback
	// boundary.
	store.On(
		"RollbackToBlock", mock.Anything, uint32(96),
	).Return(nil).Once()

	// Act: run the rollback check.
	err := s.checkRollback(t.Context())

	// Assert: the reorg was detected from the Store tip and rolled back
	// without ever consulting the legacy addrStore.
	require.NoError(t, err)
	store.AssertExpectations(t)
	mockChain.AssertExpectations(t)
}

// TestScanWithRewindStoreSyncedTip verifies that scanWithRewind decides whether
// to rewind using the Store tip rather than the legacy addrStore. The legacy
// addrStore is nil so any SyncedTo() read panics; the rewind decision must come
// from the Store's current tip. This guards a Store-backed backend whose stale
// legacy tip could otherwise make a needed full rescan wrongly conclude there
// is nothing to rewind.
func TestScanWithRewindStoreSyncedTip(t *testing.T) {
	t.Parallel()

	t.Run("rewinds when start is below store tip", func(t *testing.T) {
		t.Parallel()

		// Arrange: a store-backed syncer whose Store tip is current at
		// height 100 and a rescan requesting a start at height 50.
		const walletID uint32 = 32

		store := &walletmock.Store{}
		s := newSyncer(
			Config{Name: "rewind-store"}, nil, nil,
			&mockTxPublisher{},
			store, walletID,
		)

		store.On("GetWallet", mock.Anything, "rewind-store").Return(
			&db.WalletInfo{
				SyncedTo: &db.Block{
					Hash:   chainhash.Hash{0x01},
					Height: 100,
				},
			}, nil,
		).Once()

		start := waddrmgr.BlockStamp{
			Height:    50,
			Hash:      chainhash.Hash{byte(50)},
			Timestamp: time.Unix(50, 0).UTC(),
		}

		// Because the Store tip (100) is above the requested start
		// (50), the rewind proceeds and writes through the Store to the
		// fork height plus one (51). RollbackToBlock derives the new sync
		// tip from the stored fork-point block, so the caller only
		// supplies the rollback boundary.
		store.On(
			"RollbackToBlock", mock.Anything, uint32(51),
		).Return(nil).Once()

		// Act: request a rewind rescan.
		err := s.scanWithRewind(
			t.Context(), &scanReq{
				typ:        scanTypeRewind,
				startBlock: start,
			},
		)

		// Assert: the rewind was performed using the Store tip without
		// reading the legacy addrStore.
		require.NoError(t, err)
		store.AssertExpectations(t)
	})

	t.Run("no rewind when start is at store tip", func(t *testing.T) {
		t.Parallel()

		// Arrange: a store-backed syncer whose Store tip is at height 50
		// and a rescan requesting a start at the same height.
		const walletID uint32 = 33

		store := &walletmock.Store{}
		s := newSyncer(
			Config{Name: "rewind-noop"}, nil, nil,
			&mockTxPublisher{},
			store, walletID,
		)

		store.On("GetWallet", mock.Anything, "rewind-noop").Return(
			&db.WalletInfo{
				SyncedTo: &db.Block{
					Hash:   chainhash.Hash{0x01},
					Height: 50,
				},
			}, nil,
		).Once()

		start := waddrmgr.BlockStamp{
			Height: 50,
			Hash:   chainhash.Hash{byte(50)},
		}

		// Act: request a rewind rescan whose start is not below the
		// Store tip.
		err := s.scanWithRewind(
			t.Context(), &scanReq{
				typ:        scanTypeRewind,
				startBlock: start,
			},
		)

		// Assert: the decision came from the Store tip, so no rewind was
		// issued (RollbackToBlock is never called) and the legacy
		// addrStore was never read.
		require.NoError(t, err)
		store.AssertExpectations(t)
		store.AssertNotCalled(
			t, "RollbackToBlock", mock.Anything, mock.Anything,
		)
	})
}
