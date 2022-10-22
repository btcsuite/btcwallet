package chain

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/stretchr/testify/require"
)

// TestNeutrinoClientSequentialStartStop ensures that the client
// can sequentially Start and Stop without errors or races.
func TestNeutrinoClientSequentialStartStop(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(),
			1*time.Second)
		nc            = newMockNeutrinoClient(t)
		callStartStop = func() <-chan struct{} {
			done := make(chan struct{})
			go func() {
				defer close(done)
				err := nc.Start()
				require.NoError(t, err)
				nc.Stop()
				nc.WaitForShutdown()
			}()
			return done
		}
		numRestarts = 5
	)

	t.Cleanup(cancel)

	for i := 0; i < numRestarts; i++ {
		done := callStartStop()
		select {
		case <-ctx.Done():
			t.Fatal("timed out")
		case <-done:
		}
	}
}

// TestNeutrinoClientNotifyReceived verifies that a call to NotifyReceived sets
// the client into the scanning state and that subsequent calls while scanning
// will call Update on the client's Rescanner.
func TestNeutrinoClientNotifyReceived(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(),
			1*time.Second)
		addrs                   []btcutil.Address
		done                    = make(chan struct{})
		nc                      = newMockNeutrinoClient(t)
		wantNotifyReceivedCalls = 4
		wantUpdateCalls         = wantNotifyReceivedCalls - 1
	)
	t.Cleanup(cancel)

	go func() {
		defer close(done)
		for i := 0; i < wantNotifyReceivedCalls; i++ {
			err := nc.NotifyReceived(addrs)
			require.NoError(t, err)
		}
	}()

	// Wait for all calls to complete or test to time out.
	select {
	case <-ctx.Done():
		t.Fatal("timed out")
	case <-done:
		// Require that the expected number of calls to Update were made
		// once done sending all NotifyReceived calls.
		maybeRescan := <-nc.rescanCh
		mockRescan := maybeRescan.(*mockRescanner)
		gotUpdateCalls := mockRescan.updateArgs.Len()
		require.Equal(t, wantUpdateCalls, gotUpdateCalls)
	}
}

// TestNeutrinoClientNotifyReceivedRescan verifies concurrent calls to
// NotifyReceived and Rescan do not result in a data race and that there is no
// panic on replacing the Rescanner.
func TestNeutrinoClientNotifyReceivedRescan(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(),
			1*time.Second)
		wg        sync.WaitGroup
		addrs     []btcutil.Address
		startHash = testBestBlock.Hash
		done      = make(chan struct{})
		nc        = newMockNeutrinoClient(t)

		callRescan = func() {
			defer wg.Done()
			rerr := nc.Rescan(&startHash, addrs, nil)
			require.NoError(t, rerr)
		}

		callNotifyReceived = func() {
			defer wg.Done()
			err := nc.NotifyReceived(addrs)
			require.NoError(t, err)
		}

		callNotifyBlocks = func() {
			defer wg.Done()
			err := nc.NotifyBlocks()
			require.NoError(t, err)
		}

		wantRoutines = 100
	)

	t.Cleanup(cancel)

	// Start the client.
	err := nc.Start()
	require.NoError(t, err)

	// Launch the wanted number of goroutines, wait for them to finish and
	// signal all done.
	wg.Add(wantRoutines)
	go func() {
		defer close(done)
		defer wg.Wait()
		for i := 0; i < wantRoutines; i++ {
			if i%3 == 0 {
				go callRescan()
				continue
			}

			if i%10 == 0 {
				go callNotifyBlocks()
				continue
			}

			go callNotifyReceived()
		}
	}()

	// Wait for all calls to complete or test to time out.
	select {
	case <-ctx.Done():
		t.Fatal("timed out")
	case <-done:
	}
}
