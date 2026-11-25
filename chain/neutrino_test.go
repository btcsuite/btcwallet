package chain

import (
	"container/list"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/neutrino"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maxDur is the max duration a test has to execute successfully.
var maxDur = 5 * time.Second

// TestNeutrinoClientSequentialStartStop ensures that the client
// can sequentially Start and Stop without errors or races.
func TestNeutrinoClientSequentialStartStop(t *testing.T) {
	var (
		nc           = newMockNeutrinoClient()
		wantRestarts = 50
	)

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

		// sendMsg writes a message to the buffered message channel.
		sendMsg = func(s string) {
			msgCh <- fmt.Sprintf("%s %s", msgPrefix, s)
		}
	)

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

// TestNeutrinoClientRescanErrorNotMissed asserts that when Rescan() is called
// and the rescanner's Start() returns an error channel that produces an error
// immediately, notificationHandler does not miss the error while waiting in
// select, and s.scanning is reset to false once the error is handled.
func TestNeutrinoClientRescanErrorNotMissed(t *testing.T) {
	nc := newMockNeutrinoClient()
	nc.rescanMinBackoff = 100 * time.Millisecond

	errCh := make(chan error, 1)
	expectedErr := errors.New("peer disconnected: batch 0 timed out")
	errCh <- expectedErr

	nc.newRescan = func(ro ...neutrino.RescanOption) rescanner {
		return &mockRescanner{
			updateArgs: list.New(),
			startChan:  errCh,
		}
	}

	require.NoError(t, nc.Start(t.Context()))
	defer nc.Stop()

	startHash := new(wire.BlockHeader).BlockHash()
	require.NoError(t, nc.Rescan(&startHash, nil, nil))

	// The error channel should be drained by notificationHandler.
	require.Eventually(t, func() bool {
		return len(errCh) == 0
	}, maxDur, 10*time.Millisecond)

	// Scanning state should be reset to false after the error is processed.
	require.Eventually(t, func() bool {
		nc.clientMtx.Lock()
		defer nc.clientMtx.Unlock()
		return !nc.scanning
	}, maxDur, 10*time.Millisecond)
}

// TestNeutrinoClientRescanRetriesOnError asserts that a rescan that fails with
// an error retries with backoff and finishes once the retry succeeds.
func TestNeutrinoClientRescanRetriesOnError(t *testing.T) {
	nc := newMockNeutrinoClient()
	nc.rescanMinBackoff = 10 * time.Millisecond

	var attempts atomic.Int32
	errCh := make(chan error, 1)

	nc.newRescan = func(ro ...neutrino.RescanOption) rescanner {
		attempt := attempts.Add(1)
		if attempt == 1 {
			return &mockRescanner{
				updateArgs: list.New(),
				startChan:  errCh,
			}
		}

		return &mockRescanner{
			updateArgs: list.New(),
		}
	}

	require.NoError(t, nc.Start(t.Context()))
	defer nc.Stop()

	// Start from a block hash different from best block so attempt 1
	// does not immediately complete.
	startHash := chainhash.Hash{1}
	require.NoError(t, nc.Rescan(&startHash, nil, nil))

	// Simulate that attempt 1 delivered a block before failing.
	nc.onFilteredBlockConnected(1, &wire.BlockHeader{}, nil)

	// Now fail attempt 1.
	errCh <- errors.New("temporary peer timeout")

	// Attempt 1 should fail, then attempt 2 should be started on retry
	// resuming from the delivered block header which matches best block.
	require.Eventually(t, func() bool {
		return attempts.Load() >= 2
	}, maxDur, 10*time.Millisecond)

	// RescanFinished notification should eventually arrive.
	timeout := time.After(maxDur)
	var gotFinished bool
	for !gotFinished {
		select {
		case n := <-nc.Notifications():
			if _, ok := n.(*RescanFinished); ok {
				gotFinished = true
			}
		case <-timeout:
			t.Fatal("timed out waiting for RescanFinished")
		}
	}

	require.True(t, gotFinished)
}

// TestNeutrinoClientRescanRetryStopsOnShutdown asserts that a rescan that is
// waiting to retry does not block client shutdown.
func TestNeutrinoClientRescanRetryStopsOnShutdown(t *testing.T) {
	nc := newMockNeutrinoClient()
	// Use a long backoff to verify quit unblocks immediately.
	nc.rescanMinBackoff = 1 * time.Hour

	errCh := make(chan error, 1)
	errCh <- errors.New("persistent error")

	nc.newRescan = func(ro ...neutrino.RescanOption) rescanner {
		return &mockRescanner{
			updateArgs: list.New(),
			startChan:  errCh,
		}
	}

	require.NoError(t, nc.Start(t.Context()))

	startHash := new(wire.BlockHeader).BlockHash()
	require.NoError(t, nc.Rescan(&startHash, nil, nil))

	// Wait until error channel is drained and retry sleep has started.
	require.Eventually(t, func() bool {
		return len(errCh) == 0
	}, maxDur, 10*time.Millisecond)

	// Stop client and verify shutdown completes without waiting
	// out backoff.
	done := make(chan struct{})
	go func() {
		nc.Stop()
		nc.WaitForShutdown()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(maxDur):
		t.Fatal("client did not shut down while rescan was retrying")
	}
}
