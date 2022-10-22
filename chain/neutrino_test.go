package chain

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/stretchr/testify/require"
)

// TestNeutrinoClientSequentialStartStop ensures that the client
// can sequentially Start and Stop without errors or races.
func TestNeutrinoClientSequentialStartStop(t *testing.T) {
	var (
		ctx, cancel   = context.WithTimeout(context.Background(), 1*time.Second)
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
		mockRescan := nc.rescan.(*mockRescanner)
		gotUpdateCalls := mockRescan.updateArgs.Len()
		require.Equal(t, wantUpdateCalls, gotUpdateCalls)
	}
}
