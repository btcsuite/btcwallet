package chain

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/neutrino/headerfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// maxDur is the max duration a test has to execute successfully.
var maxDur = 5 * time.Second

// TestNeutrinoClientBatchFetch verifies that the batch fetching methods
// correctly loop over the range/list and call the underlying service.
func TestNeutrinoClientBatchFetch(t *testing.T) {
	t.Parallel()

	nc := newMockNeutrinoClient()
	mockCS, ok := nc.CS.(*mockChainService)
	require.True(t, ok)

	// Clear default expectations set in newMockNeutrinoClient so we can
	// set strict expectations for this test.

	// Test GetBlockHashes
	startHeight := int64(100)
	endHeight := int64(102)
	hash1 := chainhash.Hash{1}
	hash2 := chainhash.Hash{2}
	hash3 := chainhash.Hash{3}

	mockCS.On("GetBlockHash", int64(100)).Return(&hash1, nil).Once()
	mockCS.On("GetBlockHash", int64(101)).Return(&hash2, nil).Once()
	mockCS.On("GetBlockHash", int64(102)).Return(&hash3, nil).Once()

	hashes, err := nc.GetBlockHashes(startHeight, endHeight)
	require.NoError(t, err)
	require.Len(t, hashes, 3)
	require.Equal(t, hash1, hashes[0])
	require.Equal(t, hash2, hashes[1])
	require.Equal(t, hash3, hashes[2])

	// Test GetCFilters
	filterType := wire.GCSFilterRegular
	filter1 := &gcs.Filter{} // Empty filter
	mockCS.On("GetCFilter", hash1, filterType, mock.Anything).
		Return(filter1, nil).Once()
	mockCS.On("GetCFilter", hash2, filterType, mock.Anything).
		Return(filter1, nil).Once()
	mockCS.On("GetCFilter", hash3, filterType, mock.Anything).
		Return(filter1, nil).Once()

	filters, err := nc.GetCFilters(hashes, filterType)
	require.NoError(t, err)
	require.Len(t, filters, 3)

	// Test GetBlocks
	block1 := btcutil.NewBlock(&wire.MsgBlock{})
	mockCS.On("GetBlock", hash1, mock.Anything).Return(block1, nil).Once()
	mockCS.On("GetBlock", hash2, mock.Anything).Return(block1, nil).Once()
	mockCS.On("GetBlock", hash3, mock.Anything).Return(block1, nil).Once()

	blocks, err := nc.GetBlocks(hashes)
	require.NoError(t, err)
	require.Len(t, blocks, 3)

	// Test GetBlockHeaders
	header1 := &wire.BlockHeader{}
	mockCS.On("GetBlockHeader", &hash1).Return(header1, nil).Once()
	mockCS.On("GetBlockHeader", &hash2).Return(header1, nil).Once()
	mockCS.On("GetBlockHeader", &hash3).Return(header1, nil).Once()

	headers, err := nc.GetBlockHeaders(hashes)
	require.NoError(t, err)
	require.Len(t, headers, 3)

	mockCS.AssertExpectations(t)
}

// TestNeutrinoClientSequentialStartStop ensures that the client
// can sequentially Start and Stop without errors or races.
func TestNeutrinoClientSequentialStartStop(t *testing.T) {
	var (
		nc           = newMockNeutrinoClient()
		wantRestarts = 50
	)

	mockCS, ok := nc.CS.(*mockChainService)
	require.True(t, ok)

	testBestBlock := &headerfs.BlockStamp{
		Hash:   chainhash.Hash(make([]byte, 32)),
		Height: 1,
	}

	mockCS.On("Start").Return(nil).Times(wantRestarts)
	mockCS.On("Stop").Return(nil).Times(wantRestarts)
	mockCS.On("BestBlock").Return(testBestBlock, nil).Maybe()

	// callStartStop starts the neutrino client, requires no error on
	// startup, immediately stops the client and waits for shutdown.
	// The returned channel is closed once shutdown is complete.
	callStartStop := func() <-chan struct{} {
		done := make(chan struct{})

		go func() {
			defer close(done)

			err := nc.Start(t.Context())
			require.NoError(t, err)
			nc.Stop()
			nc.WaitForShutdown()
		}()

		return done
	}

	// For each wanted restart, execute callStartStop and wait until the
	// call is done before continuing to the next execution.  Waiting for
	// a read from done forces all executions of callStartStop to be done
	// sequentially.
	//
	// The test fails if all of the wanted restarts cannot be completed
	// sequentially before the timeout is reached.
	timeout := time.After(maxDur)
	for i := 0; i < wantRestarts; i++ {
		select {
		case <-timeout:
			t.Fatal("timed out")
		case <-callStartStop():
		}
	}
}

// TestNeutrinoClientNotifyReceived verifies that a call to NotifyReceived sets
// the client into the scanning state and that subsequent calls while scanning
// will call Update on the client's Rescanner.
func TestNeutrinoClientNotifyReceived(t *testing.T) {
	var (
		nc                      = newMockNeutrinoClient()
		wantNotifyReceivedCalls = 50
		wantUpdateCalls         = wantNotifyReceivedCalls - 1
	)

	// executeCalls calls NotifyReceived() synchronously n times without
	// blocking the test and requires no error after each call.
	executeCalls := func(n int) <-chan struct{} {
		done := make(chan struct{})

		go func() {
			defer close(done)

			var addrs []address.Address
			for i := 0; i < n; i++ {
				err := nc.NotifyReceived(addrs)
				require.NoError(t, err)
			}
		}()

		return done
	}

	// Wait for all calls to complete or test to time out.
	timeout := time.After(maxDur)
	select {
	case <-timeout:
		t.Fatal("timed out")
	case <-executeCalls(wantNotifyReceivedCalls):
		// Require that the expected number of calls to Update were made
		// once done sending all NotifyReceived calls.
		mockRescan := nc.rescan.(*mockRescanner)
		gotUpdateCalls := mockRescan.updateArgs.Len()
		require.Equal(t, wantUpdateCalls, gotUpdateCalls)
	}
}

// TestNeutrinoClientNotifyReceivedRescan verifies concurrent calls to
// NotifyBlocks, NotifyReceived and Rescan do not result in a data race
// and that there is no panic on replacing the rescan goroutine single instance.
//
// Each successful method call writes a success message to a buffered channel.
// The channel is buffered so that no concurrent reader is needed.  The buffer
// size is exactly the number of goroutines launched because each goroutine
// must finish successfully or else this test will fail.  Each message is read
// out of the channel to verify the number of messages received is the number
// expected (i.e., wantMsgs == gotMsgs).
func TestNeutrinoClientNotifyReceivedRescan(t *testing.T) {
	var (
		addrs     []address.Address
		nc        = newMockNeutrinoClient()
		wantMsgs  = 100
		gotMsgs   = 0
		msgCh     = make(chan string, wantMsgs)
		msgPrefix = "successfully called"
	)

	mockCS, ok := nc.CS.(*mockChainService)
	require.True(t, ok)

	testBestBlock := &headerfs.BlockStamp{
		Hash:   chainhash.Hash(make([]byte, 32)),
		Height: 1,
	}

	testBlockHeader := &wire.BlockHeader{Timestamp: time.Unix(1, 0)}

	mockCS.On("Start").Return(nil).Once()
	mockCS.On("Stop").Return(nil).Once()
	mockCS.On("BestBlock").Return(testBestBlock, nil).Maybe()
	mockCS.On("GetBlockHeader", mock.Anything).
		Return(testBlockHeader, nil).Maybe()

	// sendMsg writes a message to the buffered message channel.
	sendMsg := func(s string) {
		msgCh <- fmt.Sprintf("%s %s", msgPrefix, s)
	}

	// Define closures to wrap desired neutrino client method calls.

	// cleanup is the shared cleanup function for a closure executing
	// a neutrino client method call.  It sends a message and then
	// decrements the wait group counter.
	cleanup := func(wg *sync.WaitGroup, s string) {
		defer wg.Done()
		sendMsg(s)
	}

	// callRescan calls the Rescan() method and asserts it completes
	// with no errors. Rescan() is called with the hash of an empty header
	// on each call.
	startHash := new(wire.BlockHeader).BlockHash()
	callRescan := func(wg *sync.WaitGroup) {
		defer cleanup(wg, "rescan")

		err := nc.Rescan(&startHash, addrs, nil)
		require.NoError(t, err)
	}

	// callNotifyReceived calls the NotifyReceived() method and asserts it
	// completes with no errors.
	callNotifyReceived := func(wg *sync.WaitGroup) {
		defer cleanup(wg, "notify received")

		err := nc.NotifyReceived(addrs)
		require.NoError(t, err)
	}

	// callNotifyBlocks calls the NotifyBlocks() method and asserts it
	// completes with no errors.
	callNotifyBlocks := func(wg *sync.WaitGroup) {
		defer cleanup(wg, "notify blocks")

		err := nc.NotifyBlocks()
		require.NoError(t, err)
	}

	// executeCalls launches the wanted number of goroutines, waits
	// for them to finish and signals all done by closing the returned
	// channel.
	executeCalls := func(n int) <-chan struct{} {
		done := make(chan struct{})

		go func() {
			defer close(done)

			var wg sync.WaitGroup
			defer wg.Wait()

			wg.Add(n)
			for i := 0; i < n; i++ {
				if i%3 == 0 {
					go callRescan(&wg)
					continue
				}

				if i%10 == 0 {
					go callNotifyBlocks(&wg)
					continue
				}

				go callNotifyReceived(&wg)
			}
		}()

		return done
	}

	// Start the client.
	err := nc.Start(t.Context())
	require.NoError(t, err)

	// Wait for all calls to complete or test to time out.
	timeout := time.After(maxDur)
	select {
	case <-timeout:
		t.Fatal("timed out")
	case <-executeCalls(wantMsgs):
		// Ensure that exactly wantRoutines number of calls were made
		// by counting the results on the message channel.
		close(msgCh)
		for str := range msgCh {
			assert.Contains(t, str, msgPrefix)
			gotMsgs++
		}

		require.Equal(t, wantMsgs, gotMsgs)
	}
}
