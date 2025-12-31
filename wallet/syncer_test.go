package wallet

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
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
