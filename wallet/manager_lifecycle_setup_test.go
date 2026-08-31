package wallet

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// requireLifecyclePending verifies a lifecycle result has not published.
func requireLifecyclePending(t *testing.T, result <-chan error) {
	t.Helper()

	select {
	case err := <-result:
		require.Failf(t, "lifecycle call completed early",
			"unexpected result: %v", err)

	default:
	}
}

// TestManagerWalletLifecycleSetup verifies that Stop and cancellation join a
// blocked setup helper before startup publishes its winning result.
func TestManagerWalletLifecycleSetup(t *testing.T) {
	t.Parallel()

	t.Run("stop wins startup", func(t *testing.T) {
		t.Parallel()

		// Arrange: Block setup until its context is canceled and cleanup is
		// explicitly released.
		m, w, deps := newLifecycleTestManager(t)
		setup := expectBlockedLifecycleSetup(deps)
		deps.vault.On("Lock").Return().Once()

		startResult := make(chan error, 1)

		// Act: Begin Start, verify duplicate admission, then submit Stop.
		go func() {
			startResult <- m.StartWallet(t.Context(), w)
		}()

		<-setup.entered
		require.ErrorIs(
			t, m.StartWallet(t.Context(), w),
			ErrWalletAlreadyStarted,
		)

		stopResult := make(chan error, 1)
		go func() {
			stopResult <- m.StopWallet(t.Context(), w)
		}()

		// Assert: Stop cancels setup but neither result publishes before the
		// setup helper joins.
		<-setup.canceled
		requireLifecyclePending(t, startResult)
		requireLifecyclePending(t, stopResult)

		close(setup.release)

		// Assert: Stop wins the Start result and terminal teardown completes.
		require.ErrorIs(t, <-startResult, ErrWalletStopped)
		require.NoError(t, <-stopResult)
		require.Equal(t, lifecycleStopped,
			lifecycle(w.state.lifecycle.Load()))
	})

	t.Run("cancellation wins startup", func(t *testing.T) {
		t.Parallel()

		// Arrange: Block setup so caller cancellation must join its cleanup.
		m, w, deps := newLifecycleTestManager(t)
		setup := expectBlockedLifecycleSetup(deps)
		deps.vault.On("Lock").Return().Once()

		startCtx, cancelStart := context.WithCancel(t.Context())
		startResult := make(chan error, 1)

		// Act: Start the runtime, cancel its accepted caller, and hold setup
		// cleanup after cancellation is observed.
		go func() {
			startResult <- m.StartWallet(startCtx, w)
		}()

		<-setup.entered
		cancelStart()
		<-setup.canceled

		// Assert: The result remains pending until setup joins.
		requireLifecyclePending(t, startResult)

		// Act: Release the setup helper and join terminal teardown.
		close(setup.release)

		startErr := <-startResult
		stopErr := m.StopWallet(t.Context(), w)

		// Assert: Caller cancellation wins and publishes no runtime workers.
		require.ErrorIs(t, startErr, context.Canceled)
		require.NoError(t, stopErr)
		require.Equal(t, lifecycleStopped,
			lifecycle(w.state.lifecycle.Load()))
	})
}
