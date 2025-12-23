package wallet

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/btcsuite/btcd/btcutil/v2/gcs/builder"
	"github.com/btcsuite/btcd/chaincfg/v2"
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

	// Act: Submit request.
	err := s.requestScan(context.Background(), req)

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

	// Act: Submit another request with a canceled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

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

	// Mock expectations for the initial chain sync sequence.
	// Use Maybe() because the run loop might exit immediately due to
	// context cancellation.
	mockAddrStore.On("Birthday").Return(time.Now()).Maybe()
	mockChain.On("IsCurrent").Return(true).Maybe()
	mockAddrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{}).Maybe()
	mockChain.On("NotifyBlocks").Return(nil).Maybe()

	// Act: Run with canceled context to stop loop immediately.
	ctx, cancel := context.WithCancel(context.Background())
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
			ChainParams:    &chaincfg.MainNetParams,
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
		10, &chaincfg.MainNetParams, mockAddrStore,
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
		10, &chaincfg.MainNetParams, mockAddrStore,
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

	scanState := NewRecoveryState(10, &chaincfg.MainNetParams, nil)
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
	scanState := NewRecoveryState(10, &chaincfg.MainNetParams, nil)
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
		Config{ChainParams: &chaincfg.MainNetParams}, nil, nil,
		mockPublisher,
	)

	addr, err := address.NewAddressPubKeyHash(
		make([]byte, 20), &chaincfg.MainNetParams,
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
