package wallet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/btcsuite/btcd/btcutil/v2/gcs/builder"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestSyncerInitialization verifies that a new syncer is created with the
// correct default state.
func TestSyncerInitialization(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize mock dependencies for the syncer.
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}

	// Act: Create a new syncer instance with a recovery window of 1.
	s := newSyncer(
		Config{RecoveryWindow: 1}, mockAddrStore, mockTxStore,
		mockPublisher,
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
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(Config{}, mockAddrStore, mockTxStore, mockPublisher)

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
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(Config{}, mockAddrStore, mockTxStore, mockPublisher)

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
	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain}, mockAddrStore, nil, mockPublisher,
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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

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

	// Arrange: Initialize a syncer with a test database and mock chain.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	mockChain := &mockChain{}

	s := newSyncer(
		Config{Chain: mockChain, DB: db}, mockAddrStore, nil, nil,
	)

	tip := waddrmgr.BlockStamp{Height: 100, Hash: chainhash.Hash{0x01}}
	mockAddrStore.On("SyncedTo").Return(tip)

	// Mock retrieval of synced block hashes from the database for the
	// last 10 blocks.
	for i := int32(91); i <= 100; i++ {
		hash := chainhash.Hash{byte(i)}
		mockAddrStore.On(
			"BlockHash", mock.Anything, i,
		).Return(&hash, nil)
	}

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
}

// TestCheckRollbackDetected verifies checkRollback when reorg is detected.
func TestCheckRollbackDetected(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer with a test database and mocks to
	// simulate a chain reorganization.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	mockChain := &mockChain{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain, DB: db}, mockAddrStore, mockTxStore,
		mockPublisher,
	)

	tip := waddrmgr.BlockStamp{Height: 100, Hash: chainhash.Hash{0x01}}
	mockAddrStore.On("SyncedTo").Return(tip)

	// Mock retrieval of synced block hashes from the database for blocks
	// 91 to 100.
	for i := int32(91); i <= 100; i++ {
		hash := chainhash.Hash{byte(i)}
		mockAddrStore.On(
			"BlockHash", mock.Anything, i,
		).Return(&hash, nil)
	}

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

	// Expect a rollback to the common ancestor at height 95 and a
	// corresponding transaction store rollback.
	mockAddrStore.On(
		"SetSyncedTo", mock.Anything, mock.Anything,
	).Return(nil).Once()
	mockTxStore.On("Rollback", mock.Anything, int32(96)).Return(nil).Once()

	// Act & Assert: Verify that checkRollback correctly identifies the
	// fork and performs the rollback.
	err := s.checkRollback(t.Context())
	require.NoError(t, err)
}

// TestInitChainSync verifies the initial synchronization sequence.
func TestInitChainSync(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and mock its dependencies for the
	// initial synchronization sequence.
	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain}, mockAddrStore, nil, mockPublisher,
	)

	// Mock backend synchronization check.
	mockChain.On("IsCurrent").Return(true).Once()

	// Mock block notification registration.
	mockChain.On("NotifyBlocks").Return(nil).Once()

	// Mock rollback check at the start of synchronization.
	tip := waddrmgr.BlockStamp{Height: 0}
	mockAddrStore.On("SyncedTo").Return(tip)

	// Act & Assert: Verify that the initial chain synchronization
	// sequence completes successfully.
	err := s.initChainSync(t.Context())
	require.NoError(t, err)
}

// TestScanBatchHeadersOnly verifies header-only scan logic.
func TestScanBatchHeadersOnly(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and mock block and header retrieval.
	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(Config{Chain: mockChain}, nil, nil, mockPublisher)

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

	// Arrange: Initialize a syncer with a test database and set up complex
	// mock expectations for loading wallet scan data.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{
			DB:             db,
			RecoveryWindow: 10,
			ChainParams:    &chainParams,
		},
		mockAddrStore, mockTxStore, mockPublisher,
	)

	// Mock active scoped key managers.
	scopedMgr := &mockAccountStore{}
	mockAddrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore{scopedMgr}).Once()

	// Mock active accounts for the key manager scope.
	scopedMgr.On("ActiveAccounts").Return([]uint32{0}).Once()
	scopedMgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Once()

	// Mock database operations to fetch scan data, including key managers,
	// account properties, active addresses, and outputs to watch.
	mockAddrStore.On(
		"FetchScopedKeyManager", mock.Anything,
	).Return(scopedMgr, nil).Times(3)

	props := &waddrmgr.AccountProperties{
		AccountNumber: 0,
		KeyScope:      waddrmgr.KeyScopeBIP0084,
	}
	scopedMgr.On(
		"AccountProperties", mock.Anything, uint32(0),
	).Return(props, nil).Twice()

	mockAddrStore.On(
		"ForEachRelevantActiveAddress", mock.Anything, mock.Anything,
	).Return(nil).Once()

	mockTxStore.On(
		"OutputsToWatch", mock.Anything,
	).Return([]wtxmgr.Credit(nil), nil).Once()

	// Mock address derivation for the lookahead window (10 addresses for
	// each branch).
	mockAddr := &mockAddress{}
	mockAddr.On("EncodeAddress").Return("addr")
	mockAddr.On("ScriptAddress").Return([]byte{0x00})
	scopedMgr.On(
		"DeriveAddr", mock.Anything, mock.Anything, mock.Anything,
	).Return(
		mockAddr, []byte{0x00}, nil,
	).Maybe()

	// Act: Load the full scan state from the database.
	state, err := s.loadFullScanState(t.Context())

	// Assert: Verify that the scan state is correctly loaded and not nil.
	require.NoError(t, err)
	require.NotNil(t, state)
}

// TestScanBatchWithFullBlocks verifies fallback scan logic.
func TestScanBatchWithFullBlocks(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and a recovery state for scanning.
	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(Config{Chain: mockChain}, nil, nil, mockPublisher)

	mockAddrStore := &mockAddrStore{}
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

	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain, DB: db}, nil, nil, mockPublisher,
	)

	mockAddrStore := &mockAddrStore{}
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
	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(Config{Chain: mockChain}, nil, nil, mockPublisher)

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

	// Arrange: Initialize a syncer with a test database and set up mocks
	// for the batch scan.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain, DB: db}, mockAddrStore, nil,
		mockPublisher,
	)

	// Mock loading of the full scan state required by the batch scan.
	scopedMgr := &mockAccountStore{}
	scopedMgr.On("ActiveAccounts").Return([]uint32{0}).Once()
	scopedMgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Once()
	scopedMgr.On(
		"AccountProperties", mock.Anything, uint32(0),
	).Return(&waddrmgr.AccountProperties{}, nil).Twice()
	mockAddrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore{scopedMgr}).Once()
	mockAddrStore.On(
		"FetchScopedKeyManager", mock.Anything,
	).Return(scopedMgr, nil).Times(3)
	mockAddrStore.On(
		"ForEachRelevantActiveAddress", mock.Anything, mock.Anything,
	).Return(nil).Once()

	mockTxStore := &mockTxStore{}
	s.txStore = mockTxStore
	mockTxStore.On(
		"OutputsToWatch", mock.Anything,
	).Return([]wtxmgr.Credit(nil), nil).Once()

	// Mock expectations for header-only scanning when no targets are
	// present.
	hashes := []chainhash.Hash{{0x01}}
	mockChain.On(
		"GetBlockHashes", int64(11), int64(11),
	).Return(hashes, nil).Once()
	mockChain.On(
		"GetBlockHeaders", hashes,
	).Return([]*wire.BlockHeader{{}}, nil).Once()

	// Expect the sync progress to be updated in the database.
	mockAddrStore.On(
		"SetSyncedTo", mock.Anything, mock.Anything,
	).Return(nil).Once()

	// Act: Perform a batch scan from height 10 to 11.
	err := s.scanBatch(t.Context(), waddrmgr.BlockStamp{Height: 10}, 11)

	// Assert: Verify that the batch scan completed successfully.
	require.NoError(t, err)
}

// TestFetchAndFilterBlocks verifies the block fetching and filtering helper.
func TestFetchAndFilterBlocks(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and mock chain for block fetching.
	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(Config{Chain: mockChain}, nil, nil, mockPublisher)

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

	// Arrange: Initialize a syncer with a test database and mocks to
	// test the chain synchronization advancement logic.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain, DB: db}, mockAddrStore, mockTxStore,
		mockPublisher,
	)

	// Case 1: Test advancement when the wallet is already synced to the
	// best block.
	mockChain.On(
		"GetBestBlock",
	).Return(&chainhash.Hash{}, int32(100), nil).Once()
	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100},
	).Once()

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
	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100},
	).Once()

	// Set up mocks for the batch scan triggered by advancement.
	// Mock loading of the full scan state.
	scopedMgr := &mockAccountStore{}
	mockAddrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore{scopedMgr}).Once()
	scopedMgr.On("ActiveAccounts").Return([]uint32{0}).Once()
	scopedMgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Once()
	mockAddrStore.On(
		"FetchScopedKeyManager", mock.Anything,
	).Return(scopedMgr, nil).Times(3)

	props := &waddrmgr.AccountProperties{
		AccountNumber: 0,
		KeyScope:      waddrmgr.KeyScopeBIP0084,
	}
	scopedMgr.On(
		"AccountProperties", mock.Anything, uint32(0),
	).Return(props, nil).Twice()
	mockAddrStore.On(
		"ForEachRelevantActiveAddress", mock.Anything, mock.Anything,
	).Return(nil).Once()

	mockTxStore.On(
		"OutputsToWatch", mock.Anything,
	).Return([]wtxmgr.Credit(nil), nil).Once()

	scopedMgr.On(
		"DeriveAddr", mock.Anything, mock.Anything, mock.Anything,
	).Return(
		&mockAddress{}, []byte{}, nil,
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

	// Expect the sync progress to be updated for each block in the batch.
	mockAddrStore.On(
		"SetSyncedTo", mock.Anything, mock.Anything,
	).Return(nil).Times(5)

	// Act & Assert: Advance the chain sync and verify that it triggers
	// the expected batch scan.
	finished, err = s.advanceChainSync(t.Context())
	require.NoError(t, err)
	require.False(t, finished)
}

// TestHandleChainUpdate verifies notification handling.
func TestHandleChainUpdate(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and mock its dependencies for
	// handling chain updates.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain, DB: db}, mockAddrStore, mockTxStore,
		mockPublisher,
	)

	// Case 1: Test handling of a BlockConnected notification.
	meta := wtxmgr.BlockMeta{Block: wtxmgr.Block{Height: 100}}

	mockAddrStore.On(
		"SetSyncedTo", mock.Anything, mock.Anything,
	).Return(nil).Once()

	// Act & Assert: Verify that a BlockConnected notification is
	// correctly processed.
	err := s.handleChainUpdate(t.Context(), chain.BlockConnected(meta))
	require.NoError(t, err)

	// Case 2: Test handling of a RelevantTx notification.
	tx := wire.NewMsgTx(1)
	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	require.NoError(t, err)
	mockTxStore.On(
		"InsertUnconfirmedTx", mock.Anything, mock.Anything,
		mock.Anything,
	).Return(nil).Once()

	// Act & Assert: Verify that a RelevantTx notification is correctly
	// processed.
	err = s.handleChainUpdate(t.Context(), chain.RelevantTx{TxRecord: rec})
	require.NoError(t, err)
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
	)

	addr, err := address.NewAddressPubKeyHash(
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

	// Arrange: Initialize a syncer with a test database and mocks to
	// test handling of different scan request types.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{DB: db}, mockAddrStore, nil, mockPublisher,
	)

	// Case 1: Test handling of a rewind scan request.
	req := &scanReq{
		typ:        scanTypeRewind,
		startBlock: waddrmgr.BlockStamp{Height: 50},
	}
	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100},
	).Once()

	// Expect sync state update and transaction rollback for the rewind.
	mockAddrStore.On(
		"SetSyncedTo", mock.Anything, mock.Anything,
	).Return(nil).Once()

	mockTxStore := &mockTxStore{}
	s.txStore = mockTxStore
	mockTxStore.On("Rollback", mock.Anything, int32(51)).Return(nil).Once()

	// Act & Assert: Verify that a rewind scan request is correctly handled.
	err := s.handleScanReq(t.Context(), req)
	require.NoError(t, err)

	// Case 2: Test handling of a targeted scan request.
	req = &scanReq{
		typ:        scanTypeTargeted,
		startBlock: waddrmgr.BlockStamp{Height: 100},
		targets:    []waddrmgr.AccountScope{{Account: 1}},
	}
	mockChain := &mockChain{}
	s.cfg.Chain = mockChain
	mockChain.On("GetBestBlock").Return(
		&chainhash.Hash{}, int32(101), nil,
	).Once()

	// Mock loading of targeted scan data.
	scopedMgr := &mockAccountStore{}
	mockAddrStore.On(
		"FetchScopedKeyManager", mock.Anything,
	).Return(scopedMgr, nil).Times(3)

	// Set up mocks for initializing targeted scan state.
	props := &waddrmgr.AccountProperties{
		AccountNumber: 1,
		KeyScope:      waddrmgr.KeyScopeBIP0084,
	}
	scopedMgr.On(
		"AccountProperties", mock.Anything, uint32(1),
	).Return(props, nil).Twice()
	// ActiveAccounts might not be called in targeted scan flow.
	scopedMgr.On("ActiveAccounts").Return([]uint32{1}).Maybe()
	mockAddrStore.On(
		"ForEachRelevantActiveAddress", mock.Anything, mock.Anything,
	).Return(nil).Once()
	mockTxStore.On(
		"OutputsToWatch", mock.Anything,
	).Return([]wtxmgr.Credit(nil), nil).Once()

	// DeriveAddr is called multiple times during state initialization.
	// Use Maybe() to avoid assertions on specific iteration counts.
	scopedMgr.On(
		"DeriveAddr", mock.Anything, mock.Anything, mock.Anything,
	).Return(&mockAddress{}, []byte{}, nil).Maybe()

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
	err = s.handleScanReq(t.Context(), req)
	require.NoError(t, err)
}

// TestWaitForEvent verifies event loop idling and dispatch.
func TestWaitForEvent(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and mock its dependencies for testing
	// the event loop.
	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}
	mockAddrStore := &mockAddrStore{}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	s := newSyncer(
		Config{
			Chain: mockChain,
			DB:    db,
		},
		mockAddrStore, nil, mockPublisher,
	)

	// Mock chain notifications channel.
	notificationChan := make(chan any, 1)
	mockChain.On("Notifications").Return((<-chan any)(notificationChan))

	// Case 1: Test event handling when a chain notification arrives.
	notificationChan <- chain.BlockConnected{}

	// Mock sync progress update resulting from the chain notification.
	mockAddrStore.On(
		"SetSyncedTo", mock.Anything, mock.Anything,
	).Return(nil).Once()

	// Act & Assert: Call waitForEvent and verify it correctly processes
	// the arriving notification.
	err := s.waitForEvent(t.Context())
	require.NoError(t, err)

	// Case 2: Test event handling when a scan request arrives.
	s.scanReqChan <- &scanReq{typ: scanTypeRewind}

	mockAddrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{}).Once()

	// Act & Assert: Call waitForEvent and verify it correctly processes
	// the arriving scan request.
	err = s.waitForEvent(t.Context())
	require.NoError(t, err)
}

// TestSyncerFullRun verifies the full run loop coordination.
func TestSyncerFullRun(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer with a test database and set up
	// extensive mocks to simulate a full run loop execution.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain, DB: db}, mockAddrStore, nil,
		mockPublisher,
	)

	// Mock initial chain sync sequence.
	mockAddrStore.On("Birthday").Return(time.Now()).Once()
	mockChain.On("IsCurrent").Return(true).Once()
	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100},
	).Once()

	// Mock rollback check dependencies.
	mockAddrStore.On(
		"BlockHash", mock.Anything, mock.Anything,
	).Return(&chainhash.Hash{}, nil).Maybe()

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

	// Mock synced state retrieval.
	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100},
	).Once()

	// Mock retrieval of unmined transactions from the store.
	mockTxStore := &mockTxStore{}
	s.txStore = mockTxStore
	mockTxStore.On("UnminedTxs", mock.Anything).Return(
		[]*wire.MsgTx(nil), nil,
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

	// Arrange: Initialize a syncer and mock its dependencies for handling
	// a block disconnect.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain, DB: db}, mockAddrStore, mockTxStore,
		mockPublisher,
	)

	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100},
	).Once()

	mockAddrStore.On(
		"BlockHash", mock.Anything, mock.Anything,
	).Return(&chainhash.Hash{}, nil).Maybe()

	remoteHashes := make([]chainhash.Hash, 10)
	mockChain.On("GetBlockHashes", mock.Anything, mock.Anything).Return(
		remoteHashes, nil,
	).Once()

	// Act & Assert: Process a BlockDisconnected notification and verify
	// that it triggers a rollback check.
	err := s.processChainUpdate(t.Context(), chain.BlockDisconnected{})
	require.NoError(t, err)
}

// TestBroadcastUnminedTxns_Error verifies error handling.
func TestBroadcastUnminedTxns_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize a syncer and mock an error during unmined
	// transactions retrieval.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(Config{DB: db}, nil, mockTxStore, mockPublisher)

	mockTxStore.On("UnminedTxs", mock.Anything).Return(
		([]*wire.MsgTx)(nil), errDBMockSync,
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
	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(
		Config{Chain: mockChain}, mockAddrStore, nil, mockPublisher,
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
	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(
		Config{Chain: mockChain, SyncMethod: SyncMethodAuto}, nil, nil,
		mockPublisher,
	)
	mockAddrStore := &mockAddrStore{}
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
	mockChain := &mockChain{}
	s := newSyncer(
		Config{Chain: mockChain, SyncMethod: SyncMethodCFilters},
		nil, nil, nil,
	)

	// Create a filter that matches "data".
	data := []byte("match_me")
	filter, err := gcs.BuildGCSFilter(
		builder.DefaultP, builder.DefaultM, [16]byte{}, [][]byte{data},
	)
	require.NoError(t, err)

	// Setup scan state watching the data.
	scanState := NewRecoveryState(10, &chainParams, nil)

	mockAddr := &mockAddress{}
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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)
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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)
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

	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Arrange: Setup a syncer that returns empty blocks during a batch
	// scan.
	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}

	s := newSyncer(
		Config{Chain: mockChain, DB: db},
		mockAddrStore, mockTxStore, nil,
	)

	mockAddrStore.On("ActiveScopedKeyManagers").Return(
		[]waddrmgr.AccountStore{}).Once()

	mockTxStore.On("OutputsToWatch", mock.Anything).Return(
		[]wtxmgr.Credit(nil), nil).Once()
	mockAddrStore.On("ForEachRelevantActiveAddress", mock.Anything,
		mock.Anything).Return(nil).Once()

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

		db, cleanup := setupTestDB(t)
		defer cleanup()

		// Arrange: Setup a syncer where DB operations fail during
		// rollback check.
		mockChain := &mockChain{}
		addrStore := &mockAddrStore{}

		s := newSyncer(
			Config{Chain: mockChain, DB: db}, addrStore, nil, nil,
		)

		mockChain.On("IsCurrent").Return(true).Maybe()
		addrStore.On("Birthday").Return(time.Now()).Maybe()
		addrStore.On("SyncedTo").Return(
			waddrmgr.BlockStamp{Height: 100},
		)
		addrStore.On("BlockHash", mock.Anything, mock.Anything).Return(
			&chainhash.Hash{}, errDBMock).Once()

		// Act: Attempt initialization.
		err := s.initChainSync(t.Context())

		// Assert: Verify error.
		require.ErrorContains(t, err, "db error")
	})

	t.Run("NotifyBlocks_Failure", func(t *testing.T) {
		t.Parallel()

		db, cleanup := setupTestDB(t)
		defer cleanup()

		// Arrange: Setup a syncer where block notifications fail.
		mockChain := &mockChain{}
		addrStore := &mockAddrStore{}
		s := newSyncer(
			Config{Chain: mockChain, DB: db}, addrStore, nil, nil,
		)

		mockChain.On("IsCurrent").Return(true).Maybe()
		addrStore.On("Birthday").Return(time.Now()).Maybe()
		addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{Height: 0})
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
	s := newSyncer(Config{}, nil, nil, nil)
	s.state.Store(uint32(syncStateSyncing))

	// Act: Attempt to handle a scan request.
	err := s.handleScanReq(t.Context(), &scanReq{})

	// Assert: Verify state forbidden error.
	require.ErrorIs(t, err, ErrStateForbidden)
}

// TestSyncerRun_InitError verifies run failure when initChainSync fails.
func TestSyncerRun_InitError(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Arrange: Setup a syncer where initialization fails.
	mockChain := &mockChain{}
	addrStore := &mockAddrStore{}

	s := newSyncer(Config{Chain: mockChain, DB: db}, addrStore, nil, nil)

	addrStore.On("Birthday").Return(time.Now()).Once()
	mockChain.On("IsCurrent").Return(true).Once()

	addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{Height: 100})
	addrStore.On("BlockHash", mock.Anything, mock.Anything).Return(
		&chainhash.Hash{}, errDBMock).Once()

	// Act: Run the syncer.
	err := s.run(t.Context())

	// Assert: Verify error propagation.
	require.ErrorContains(t, err, "db error")
}

// TestHandleChainUpdate_BlockDisconnected verifies handleChainUpdate for
// BlockDisconnected.
func TestHandleChainUpdate_BlockDisconnected(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer and dependencies for handling updates.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockChain := &mockChain{}
	s := newSyncer(
		Config{
			Chain:       mockChain,
			ChainParams: &chainParams,
			DB:          db,
		},
		mockAddrStore, mockTxStore, nil,
	)

	// 1. BlockDisconnected.
	mockTxStore.On("Rollback", mock.Anything, int32(100)).Return(nil).Once()
	mockAddrStore.On("SetSyncedTo", mock.Anything, mock.Anything).Return(
		nil).Once()
	mockAddrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{Height: 100})

	for i := int32(91); i <= 100; i++ {
		hash := chainhash.Hash{byte(i)}
		mockAddrStore.On("BlockHash", mock.Anything, i).Return(
			&hash, nil).Maybe()
	}

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
}

// TestDispatchScanStrategy_AutoFallback verifies fallback to full blocks
// when watchlist is too large.
func TestDispatchScanStrategy_AutoFallback(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer with a low filter item threshold to force
	// fallback.
	mockChain := &mockChain{}
	s := newSyncer(
		Config{
			Chain:           mockChain,
			SyncMethod:      SyncMethodAuto,
			MaxCFilterItems: 1,
		}, nil, nil, nil,
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

	// Arrange: Setup a syncer and mock successful transaction retrieval
	// and broadcast.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}

	s := newSyncer(Config{DB: db}, nil, mockTxStore, mockPublisher)

	tx := wire.NewMsgTx(1)
	mockTxStore.On("UnminedTxs", mock.Anything).Return(
		[]*wire.MsgTx{tx}, nil,
	).Once()
	mockPublisher.On("Broadcast", mock.Anything, tx, "").Return(nil).Once()

	// Act: Broadcast unmined transactions.
	err := s.broadcastUnminedTxns(t.Context())

	// Assert: Verify success.
	require.NoError(t, err)
}

// TestFilterBatch_EmptyFilter verifies that empty filters force download.
func TestFilterBatch_EmptyFilter(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer and mock an empty filter response.
	mockChain := &mockChain{}
	s := newSyncer(
		Config{Chain: mockChain, SyncMethod: SyncMethodCFilters},
		nil, nil, nil,
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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

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
	s := newSyncer(Config{}, nil, nil, nil)

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
	s := newSyncer(Config{}, nil, nil, nil)

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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

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

	// Arrange: Setup mock expectations where a transaction broadcast fails.
	mockPublisher := &mockTxPublisher{}
	mockTxStore := &mockTxStore{}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	s := newSyncer(Config{DB: db}, nil, mockTxStore, mockPublisher)

	tx := wire.NewMsgTx(1)
	mockTxStore.On("UnminedTxs", mock.Anything).Return(
		[]*wire.MsgTx{tx}, nil).Once()
	mockPublisher.On("Broadcast", mock.Anything, tx, "").Return(
		errBroadcast).Once()

	// Act: Broadcast unmined transactions.
	err := s.broadcastUnminedTxns(t.Context())

	// Assert: Verify that the error is not propagated (it's only logged).
	require.NoError(t, err)
}

// TestCheckRollback_DBError verifies error propagation.
func TestCheckRollback_DBError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where local block hash lookup fails
	// during a rollback check.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	s := newSyncer(Config{DB: db}, mockAddrStore, nil, nil)

	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100}).Once()
	mockAddrStore.On("BlockHash", mock.Anything, mock.Anything).Return(
		(*chainhash.Hash)(nil), errBlockHash).Once()

	// Act: Perform a rollback check.
	err := s.checkRollback(t.Context())

	// Assert: Verify failure.
	require.ErrorIs(t, err, errBlockHash)
}

// TestCheckRollback_RemoteError verifies error propagation from
// GetBlockHashes.
func TestCheckRollback_RemoteError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where remote hash lookup fails
	// during a rollback check.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	s := newSyncer(
		Config{Chain: mockChain, DB: db},
		mockAddrStore, nil, nil,
	)

	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100}).Once()
	mockAddrStore.On("BlockHash", mock.Anything, mock.Anything).Return(
		&chainhash.Hash{}, nil).Maybe()
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
	s := newSyncer(Config{}, nil, nil, nil)

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

	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Arrange: Setup mock expectations where block notification fails.
	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	s := newSyncer(
		Config{Chain: mockChain, DB: db},
		mockAddrStore, nil, nil,
	)

	mockChain.On("IsCurrent").Return(true).Once()
	mockChain.On("GetBlockHashes", mock.Anything, mock.Anything).Return(
		[]chainhash.Hash{}, nil).Once()
	mockChain.On("NotifyBlocks").Return(errNotify).Once()

	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 0}).Once()
	mockAddrStore.On("Birthday").Return(time.Time{}).Maybe()

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
		mockChain := &mockChain{}
		s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

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
		mockChain := &mockChain{}
		s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

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

	// Arrange: Setup mock expectations for a rollback check where a
	// header fetch failure occurs at the fork point.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	s := newSyncer(
		Config{Chain: mockChain, DB: db},
		mockAddrStore, nil, nil,
	)

	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 101}).Once()

	hashA := &chainhash.Hash{0x0A}
	hashB := &chainhash.Hash{0x0B}
	hashC := chainhash.Hash{0x0C}

	mockAddrStore.On("BlockHash", mock.Anything, int32(101)).Return(hashB,
		nil).Once()
	mockAddrStore.On("BlockHash", mock.Anything, int32(100)).Return(hashA,
		nil).Once()
	mockAddrStore.On("BlockHash", mock.Anything, mock.Anything).Return(
		&chainhash.Hash{}, nil).Maybe()

	remoteHashes := make([]chainhash.Hash, 10)
	remoteHashes[8] = *hashA
	remoteHashes[9] = hashC
	mockChain.On("GetBlockHashes", int64(92), int64(101)).Return(
		remoteHashes, nil).Once()
	mockChain.On("GetBlockHeader", hashA).Return(
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
	s := newSyncer(Config{}, nil, nil, nil)

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

	// Arrange: Setup a targeted scan where the resulting block batch is
	// empty.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}

	defer mockChain.AssertExpectations(t)
	defer mockAddrStore.AssertExpectations(t)
	defer mockTxStore.AssertExpectations(t)

	s := newSyncer(Config{
		DB:              db,
		Chain:           mockChain,
		SyncMethod:      SyncMethodAuto,
		MaxCFilterItems: 100,
	}, mockAddrStore, mockTxStore, nil)

	req := &scanReq{
		startBlock: waddrmgr.BlockStamp{Height: 100},
		targets: []waddrmgr.AccountScope{
			{Scope: waddrmgr.KeyScopeBIP0084, Account: 0}},
	}

	mockTxStore.On("OutputsToWatch", mock.Anything).Return(
		[]wtxmgr.Credit{{PkScript: []byte{0x01}}}, nil).Once()

	mgr := &mockAccountStore{}
	mockAddrStore.On("FetchScopedKeyManager", mock.Anything).Return(mgr,
		nil).Times(3)
	mgr.On("AccountProperties", mock.Anything, mock.Anything).Return(
		&waddrmgr.AccountProperties{}, nil).Once()
	mockAddrStore.On("ForEachRelevantActiveAddress", mock.Anything,
		mock.AnythingOfType("func(address.Address) error")).Return(
		nil).Once()
	// SyncedTo is not called in the targeted scan path.
	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100}).Maybe()

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
	mockCS := &mockNeutrinoChain{}
	// IsCurrent called by waitUntilBackendSynced.
	// Return false to keep polling until context cancel.
	mockCS.On("IsCurrent").Return(false).Maybe()

	nc := &chain.NeutrinoClient{
		CS: mockCS,
	}
	mockAddrStore := &mockAddrStore{}
	// Birthday called by SetStartTime.
	mockAddrStore.On("Birthday").Return(time.Time{}).Once()

	s := newSyncer(Config{Chain: nc}, mockAddrStore, nil, nil)

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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

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

	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain, DB: db}, nil, nil, nil)

	addrStore := &mockAccountStore{}
	rs := NewRecoveryState(10, &chainParams, nil)
	rs.addrFilters = make(map[string]AddrEntry)
	rs.outpoints = make(map[wire.OutPoint][]byte)
	rs.branchStates[waddrmgr.BranchScope{}] = NewBranchRecoveryState(
		10, addrStore,
	)

	// Force expansion by finding an address.
	addr, err := address.NewAddressPubKeyHash(
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
	mockChain := &mockChain{}
	s := newSyncer(
		Config{
			Chain:           mockChain,
			SyncMethod:      SyncMethodAuto,
			MaxCFilterItems: 1,
		}, nil, nil, nil,
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
	mockChain := &mockChain{}
	s := newSyncer(
		Config{
			Chain:      mockChain,
			SyncMethod: SyncMethodAuto,
		}, nil, nil, nil,
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

	// Arrange: Create a syncer with a database and verify initial sync
	// state.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	s := newSyncer(Config{DB: db}, mockAddrStore, nil, nil)

	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 0}).Once()

	// Act: Process a BlockDisconnected update.
	err := s.processChainUpdate(
		t.Context(), chain.BlockDisconnected{},
	)

	// Assert: Verify success.
	require.NoError(t, err)
}

// TestScanWithTargets_Errors verifies error paths in scanWithTargets.
func TestScanWithTargets_Errors(t *testing.T) {
	t.Parallel()

	t.Run("GetBestBlock_Failure", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup mock expectations where GetBestBlock fails
		// during targeted scan initialization.
		db, cleanup := setupTestDB(t)
		defer cleanup()

		mockChain := &mockChain{}
		mockAddrStore := &mockAddrStore{}
		mockTxStore := &mockTxStore{}

		s := newSyncer(
			Config{
				Chain: mockChain,
				DB:    db,
			}, mockAddrStore, mockTxStore, nil,
		)

		req := &scanReq{
			startBlock: waddrmgr.BlockStamp{Height: 100},
			targets: []waddrmgr.AccountScope{{
				Scope: waddrmgr.KeyScopeBIP0084, Account: 0,
			}},
		}

		mgr := &mockAccountStore{}
		mockAddrStore.On("FetchScopedKeyManager",
			mock.Anything).Return(mgr, nil)
		mgr.On("AccountProperties", mock.Anything, mock.Anything).Return(
			&waddrmgr.AccountProperties{}, nil)
		mockAddrStore.On("ForEachRelevantActiveAddress", mock.Anything,
			mock.Anything).Return(nil)
		mockTxStore.On("OutputsToWatch", mock.Anything).Return(
			[]wtxmgr.Credit(nil), nil)
		mockChain.On("GetBestBlock").Return(nil, int32(0),
			errBestBlock).Once()

		// Act: Attempt targeted scan.
		err := s.scanWithTargets(t.Context(), req)

		// Assert: Verify failure.
		require.ErrorContains(t, err, "best block fail")
	})

	t.Run("GetBlockHashes_Failure", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup mock expectations where GetBlockHashes fails.
		db, cleanup := setupTestDB(t)
		defer cleanup()

		mockChain := &mockChain{}
		mockAddrStore := &mockAddrStore{}
		mockTxStore := &mockTxStore{}

		s := newSyncer(
			Config{
				Chain: mockChain,
				DB:    db,
			}, mockAddrStore, mockTxStore, nil,
		)

		req := &scanReq{
			startBlock: waddrmgr.BlockStamp{Height: 100},
			targets: []waddrmgr.AccountScope{{
				Scope: waddrmgr.KeyScopeBIP0084, Account: 0,
			}},
		}

		mgr := &mockAccountStore{}
		mockAddrStore.On("FetchScopedKeyManager",
			mock.Anything).Return(mgr, nil)
		mgr.On("AccountProperties", mock.Anything, mock.Anything).Return(
			&waddrmgr.AccountProperties{}, nil).Once()
		mockAddrStore.On("ForEachRelevantActiveAddress", mock.Anything,
			mock.Anything).Return(nil).Once()
		mockTxStore.On("OutputsToWatch", mock.Anything).Return(
			[]wtxmgr.Credit(nil), nil).Once()
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

		// Arrange: Setup mock expectations to simulate a fetch failure during
		// targeted scan initialization.
		db, cleanup := setupTestDB(t)
		defer cleanup()

		mockAddrStore := &mockAddrStore{}
		s := newSyncer(Config{DB: db}, mockAddrStore, nil, nil)

		mockAddrStore.On("FetchScopedKeyManager", mock.Anything).Return(
			nil, errFetchFail).Once()

		targets := []waddrmgr.AccountScope{{
			Scope: waddrmgr.KeyScopeBIP0084, Account: 0,
		}}

		// Act: Attempt a targeted scan.
		err := s.scanWithTargets(
			t.Context(), &scanReq{
				targets:    targets,
				startBlock: waddrmgr.BlockStamp{Height: 100},
			},
		)

		// Assert: Verify propagation.
		require.ErrorContains(t, err, "fetch fail")
	})
}

// TestScanBatchWithCFilters_InitResultsError verifies error propagation.
func TestScanBatchWithCFilters_InitResultsError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where header retrieval fails during
	// initialization for a CFilter scan.
	mockChain := &mockChain{}
	s := newSyncer(
		Config{
			Chain:      mockChain,
			SyncMethod: SyncMethodCFilters,
		}, nil, nil, nil,
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

	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)

	tests := []struct {
		name   string
		update interface{}
		setup  func(*mockAddrStore, *mockTxStore, *mockChain)
	}{
		{
			name: "BlockConnected",
			update: chain.BlockConnected{
				Block: wtxmgr.Block{Height: 100},
			},
			setup: func(as *mockAddrStore, ts *mockTxStore, c *mockChain) {
				as.On("SetSyncedTo", mock.Anything, mock.MatchedBy(
					func(bs *waddrmgr.BlockStamp) bool {
						return bs.Height == 100
					})).Return(nil).Once()
			},
		},
		{
			name: "RelevantTx",
			update: chain.RelevantTx{
				TxRecord: &wtxmgr.TxRecord{MsgTx: *wire.NewMsgTx(1)},
			},
			setup: func(as *mockAddrStore, ts *mockTxStore, c *mockChain) {
				ts.On("InsertUnconfirmedTx", mock.Anything, mock.Anything,
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
			setup: func(as *mockAddrStore, ts *mockTxStore, c *mockChain) {
				as.On("SetSyncedTo", mock.Anything, mock.MatchedBy(
					func(bs *waddrmgr.BlockStamp) bool {
						return bs.Height == 102
					})).Return(nil).Once()
			},
		},
		{
			name: "BlockDisconnected",
			update: chain.BlockDisconnected{
				Block: wtxmgr.Block{Height: 100, Hash: chainhash.Hash{0x01}},
			},
			setup: func(as *mockAddrStore, ts *mockTxStore, c *mockChain) {
				as.On("SyncedTo").Return(
					waddrmgr.BlockStamp{Height: 100},
				).Once()
				as.On(
					"BlockHash", mock.Anything, mock.Anything,
				).Return(&chainhash.Hash{}, nil).Maybe()

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
			mockAddrStore := &mockAddrStore{}
			mockTxStore := &mockTxStore{}
			mockChain := &mockChain{}
			s := newSyncer(
				Config{
					Chain:       mockChain,
					ChainParams: &chainParams,
					DB:          db,
				},
				mockAddrStore, mockTxStore, nil,
			)

			tc.setup(mockAddrStore, mockTxStore, mockChain)

			// Act
			err := s.processChainUpdate(t.Context(), tc.update)

			// Assert
			require.NoError(t, err)
		})
	}
}

// TestHandleChainUpdate_SpecialNotifs verifies RescanProgress and
// RescanFinished.
func TestHandleChainUpdate_SpecialNotifs(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a syncer for special notification handling.
	mockAddrStore := &mockAddrStore{}
	s := newSyncer(Config{}, mockAddrStore, nil, nil)

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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)
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

	// Arrange: Setup a syncer and mock an incomplete sync state.
	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	s := newSyncer(
		Config{
			Chain: mockChain,
			DB:    db,
		}, mockAddrStore, mockTxStore, nil,
	)

	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 90}).Maybe()
	mockChain.On("GetBestBlock").Return(&chainhash.Hash{}, int32(100),
		nil).Once()

	mockAddrStore.On("ActiveScopedKeyManagers").Return(
		[]waddrmgr.AccountStore(nil)).Maybe()
	mockAddrStore.On("ForEachRelevantActiveAddress", mock.Anything,
		mock.Anything).Return(nil).Maybe()

	mockTxStore.On("OutputsToWatch", mock.Anything).Return(
		[]wtxmgr.Credit(nil), nil).Maybe()
	mockChain.On("GetBlockHashes", int64(91), int64(100)).Return(
		[]chainhash.Hash{{0x01}}, nil).Once()
	mockChain.On("GetBlockHeaders", mock.Anything).Return(
		[]*wire.BlockHeader{{}}, nil).Once()
	mockAddrStore.On("SetSyncedTo", mock.Anything,
		mock.Anything).Return(nil).Maybe()

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
		mockChain := &mockChain{}
		s := newSyncer(
			Config{
				Chain:      mockChain,
				SyncMethod: SyncMethodFullBlocks,
			}, nil, nil, nil,
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
		mockChain := &mockChain{}
		s := newSyncer(
			Config{
				Chain:      mockChain,
				SyncMethod: SyncMethodCFilters,
			}, nil, nil, nil,
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
		mockChain := &mockChain{}
		s := newSyncer(
			Config{
				Chain:      mockChain,
				SyncMethod: 99,
			}, nil, nil, nil,
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

	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Arrange: Setup a syncer where chain update processing will fail due
	// to a database error.
	mockAddrStore := &mockAddrStore{}
	s := newSyncer(Config{DB: db}, mockAddrStore, nil, nil)

	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100}).Maybe()
	mockAddrStore.On("BlockHash", mock.Anything, mock.Anything).Return(
		(*chainhash.Hash)(nil), errDBFail).Once()

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

	// Arrange: Setup a syncer and mock a notification arrival to trigger
	// the idle processing path.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	s := newSyncer(
		Config{
			Chain: mockChain,
			DB:    db,
		}, mockAddrStore, mockTxStore, nil,
	)

	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100}).Maybe()
	mockChain.On("GetBestBlock").Return(&chainhash.Hash{}, int32(100),
		nil).Once()
	mockTxStore.On("UnminedTxs", mock.Anything).Return([]*wire.MsgTx{},
		nil).Once()

	notifChan := make(chan any, 1)
	mockChain.On("Notifications").Return((<-chan any)(notifChan)).Maybe()

	notifChan <- chain.BlockConnected{Block: wtxmgr.Block{Height: 101}}

	mockAddrStore.On("SetSyncedTo", mock.Anything,
		mock.Anything).Return(nil).Once()

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
	mockChain := &mockChain{}
	addrStore := &mockAddrStore{}
	accountStore := &mockAccountStore{}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	s := newSyncer(Config{Chain: mockChain, DB: db}, addrStore, nil, nil)

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
	addr, err := address.NewAddressPubKeyHash(
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
	expAddr, err := address.NewAddressPubKeyHash(
		append([]byte{1}, make([]byte, 19)...), &chainParams,
	)
	require.NoError(t, err)

	accountStore.On("DeriveAddr", mock.Anything, mock.Anything,
		mock.Anything).Return(expAddr, []byte{}, nil).Maybe()
	accountStore.On("ExtendAddresses", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Return(
		[]address.Address{expAddr}, [][]byte{make([]byte, 20)}, nil,
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

	// Arrange: Setup mock expectations to simulate a failure during
	// loadFullScanState within runSyncStep.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	s := newSyncer(
		Config{Chain: mockChain, DB: db},
		mockAddrStore, nil, nil,
	)

	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100}).Maybe()

	mockChain.On("GetBestBlock").Return(
		&chainhash.Hash{}, int32(101), nil).Once()

	mgr := &mockAccountStore{}
	mockAddrStore.On("ActiveScopedKeyManagers").Return(
		[]waddrmgr.AccountStore{mgr}).Once()
	mgr.On("ActiveAccounts").Return([]uint32{0}).Once()
	mgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Once()

	mockAddrStore.On("FetchScopedKeyManager",
		waddrmgr.KeyScopeBIP0084).Return(nil, errLoadStateFail).Once()

	// Act: Execute a single sync step.
	err := s.runSyncStep(t.Context())

	// Assert: Verify error propagation.
	require.ErrorContains(t, err, "load state fail")
}

// TestLoadFullScanState_Error verifies error propagation.
func TestLoadFullScanState_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations to simulate a database failure
	// when loading scan state.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	s := newSyncer(Config{DB: db}, mockAddrStore, nil, nil)

	mgr := &mockAccountStore{}
	mgr.On("ActiveAccounts").Return([]uint32{0}).Once()
	mgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Once()

	mockAddrStore.On("ActiveScopedKeyManagers").Return(
		[]waddrmgr.AccountStore{mgr}).Once()
	mockAddrStore.On("FetchScopedKeyManager",
		waddrmgr.KeyScopeBIP0084).Return(nil, errDBMock).Once()

	// Act: Attempt to load the full scan state.
	state, err := s.loadFullScanState(t.Context())

	// Assert: Verify failure.
	require.Nil(t, state)
	require.ErrorContains(t, err, "db error")
}

// TestScanWithRewind_Error verifies error propagation from DBPutRewind.
func TestScanWithRewind_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations for a rewind scan where a database
	// rollback failure occurs.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockTxStore := &mockTxStore{}
	mockAddrStore := &mockAddrStore{}
	s := newSyncer(Config{DB: db}, mockAddrStore, mockTxStore, nil)
	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100}).Maybe()

	mockAddrStore.On("SetSyncedTo", mock.Anything,
		mock.Anything).Return(nil).Maybe()
	mockTxStore.On("Rollback", mock.Anything, mock.Anything).Return(
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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

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

	// Arrange: Setup mock expectations where scan data loading fails
	// during a batch scan.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	s := newSyncer(Config{DB: db}, mockAddrStore, nil, nil)

	mgr := &mockAccountStore{}
	mockAddrStore.On("ActiveScopedKeyManagers").Return(
		[]waddrmgr.AccountStore{mgr}).Once()
	mgr.On("ActiveAccounts").Return([]uint32{0}).Once()
	mgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Once()
	mockAddrStore.On("FetchScopedKeyManager",
		waddrmgr.KeyScopeBIP0084).Return(nil, errActiveMgrsFail).Once()

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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

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
	mockChain := &mockChain{}
	s := newSyncer(
		Config{Chain: mockChain, SyncMethod: SyncMethodAuto},
		nil, nil, nil,
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

	// Arrange: Setup mock expectations for a small gap where silent sync
	// is preferred.
	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	s := newSyncer(
		Config{Chain: mockChain, DB: db},
		mockAddrStore, mockTxStore, nil,
	)

	mockChain.On("GetBestBlock").Return(&chainhash.Hash{}, int32(105),
		nil).Once()
	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100}).Once()
	mockAddrStore.On("ActiveScopedKeyManagers").Return(
		[]waddrmgr.AccountStore(nil)).Once()
	mockAddrStore.On("ForEachRelevantActiveAddress", mock.Anything,
		mock.Anything).Return(nil).Once()

	mockTxStore.On("OutputsToWatch", mock.Anything).Return(
		[]wtxmgr.Credit(nil), nil).Once()
	mockChain.On("GetBlockHashes", int64(101), int64(105)).Return(
		[]chainhash.Hash{{0x01}}, nil).Once()
	mockChain.On("GetBlockHeaders", mock.Anything).Return(
		[]*wire.BlockHeader{{}}, nil).Once()
	mockAddrStore.On("SetSyncedTo", mock.Anything,
		mock.Anything).Return(nil).Once()

	// Act: Advance chain sync.
	finished, err := s.advanceChainSync(t.Context())

	// Assert: Verify state transition to backend-syncing.
	require.NoError(t, err)
	require.False(t, finished)
	require.Equal(t, uint32(syncStateBackendSyncing), s.state.Load())
}

// TestRunSyncStep_BroadcastError verifies error propagation.
func TestRunSyncStep_BroadcastError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where a broadcast-related failure
	// occurs during a sync step.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}

	s := newSyncer(
		Config{Chain: mockChain, DB: db},
		mockAddrStore, mockTxStore, nil,
	)

	mockChain.On("GetBestBlock").Return(&chainhash.Hash{}, int32(100),
		nil).Once()
	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100}).Maybe()
	mockTxStore.On("UnminedTxs", mock.Anything).Return([]*wire.MsgTx(nil),
		errBroadcast).Once()

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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain, SyncMethod: 99}, nil, nil, nil)

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
	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	s := newSyncer(
		Config{Chain: mockChain, DB: db},
		mockAddrStore, nil, nil,
	)

	mockChain.On("GetBestBlock").Return(&chainhash.Hash{}, int32(105),
		nil).Once()
	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100}).Once()
	mockAddrStore.On("ActiveScopedKeyManagers").Return(
		[]waddrmgr.AccountStore(nil)).Once()
	mockAddrStore.On("ForEachRelevantActiveAddress", mock.Anything,
		mock.Anything).Return(errScan).Once()

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
	mockChain := &mockChain{}
	s := newSyncer(
		Config{Chain: mockChain, SyncMethod: SyncMethodFullBlocks},
		nil, nil, nil,
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
	)

	pkh, err := address.NewAddressPubKeyHash(
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
	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

	mockChain.On("GetBestBlock").Return((*chainhash.Hash)(nil), int32(0),
		errBestBlock).Once()

	// Act: Advance chain sync.
	finished, err := s.advanceChainSync(t.Context())

	// Assert: Verify failure.
	require.False(t, finished)
	require.ErrorIs(t, err, errBestBlock)
}

// TestDispatchScanStrategy_AutoDefaultThreshold verifies threshold=0 branch.
func TestDispatchScanStrategy_AutoDefaultThreshold(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations for auto strategy with a zero
	// threshold for compact filters.
	mockChain := &mockChain{}
	s := newSyncer(Config{
		Chain:           mockChain,
		SyncMethod:      SyncMethodAuto,
		MaxCFilterItems: 0,
	}, nil, nil, nil)

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

	// Arrange: Setup mock expectations for a large sync gap where explicit
	// scanning is triggered.
	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	s := newSyncer(
		Config{Chain: mockChain, DB: db},
		mockAddrStore, mockTxStore, nil,
	)

	mockChain.On("GetBestBlock").Return(&chainhash.Hash{}, int32(110),
		nil).Once()
	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100}).Once()

	// The following mocks use Maybe() because for a large gap, the syncer
	// transitions to SyncStateSyncing and returns early, skipping these
	// calls.
	mockAddrStore.On("ActiveScopedKeyManagers").Return(
		[]waddrmgr.AccountStore(nil)).Maybe()
	mockAddrStore.On("ForEachRelevantActiveAddress", mock.Anything,
		mock.Anything).Return(nil).Maybe()

	mockTxStore.On("OutputsToWatch", mock.Anything).Return(
		[]wtxmgr.Credit(nil), nil).Maybe()
	mockChain.On("GetBlockHashes", mock.Anything, mock.Anything).Return(
		[]chainhash.Hash{{0x01}}, nil).Maybe()
	mockChain.On("GetBlockHeaders", mock.Anything).Return(
		[]*wire.BlockHeader{{}}, nil).Maybe()
	mockAddrStore.On("SetSyncedTo", mock.Anything,
		mock.Anything).Return(nil).Maybe()

	// Act: Advance chain sync.
	finished, err := s.advanceChainSync(t.Context())

	// Assert: Verify state transition to syncing.
	require.NoError(t, err)
	require.False(t, finished)
	require.Equal(t, uint32(syncStateSyncing), s.state.Load())
}
