package chain

import (
	"context"
	"testing"
	"time"

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
