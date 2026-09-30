package bwtest

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/btcsuite/btcwallet/bwtest/wait"
)

// waitForTCPListener polls until addr accepts TCP connections.
//
// The integration harness uses this before starting external backends that
// immediately dial the miner. Without the extra readiness check, a backend's
// first outbound peer attempt can race the rpctest miner listener on slower CI
// runners and leave the backend stuck at height 0 until its next reconnect.
func waitForTCPListener(addr string, timeout time.Duration) error {
	err := wait.NoError(func() error {
		ctx, cancel := context.WithTimeout(
			context.Background(), wait.PollInterval,
		)
		defer cancel()

		dialer := &net.Dialer{}

		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("dial %s: %w", addr, err)
		}

		_ = conn.Close()

		return nil
	}, timeout)
	if err != nil {
		return fmt.Errorf("wait for tcp listener %s: %w", addr, err)
	}

	return nil
}
