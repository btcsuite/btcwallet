package wallet

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestManagerWalletLifecycleCutoff verifies the final serialized decision
// between Stop, caller cancellation, and complete worker publication.
func TestManagerWalletLifecycleCutoff(t *testing.T) {
	t.Parallel()

	t.Run("stop wins", func(t *testing.T) {
		t.Parallel()

		// Arrange: Complete setup, then hold the coordinator at the final
		// publication seam until a public Stop request arrives.
		m, w, deps := newLifecycleTestManager(t)
		cutoffReached := make(chan struct{})
		stopAdmitted := make(chan struct{})
		releaseCutoff := make(chan struct{})
		m.lifecycleTestHooks = &managerLifecycleTestHooks{
			beforeStartPublication: func(
				c *walletLifecycleCoordinator) {

				close(cutoffReached)
				<-c.requests
				close(stopAdmitted)
				<-releaseCutoff
			},
		}

		expectLifecycleSetup(deps)
		deps.vault.On("Lock").Return().Once()

		startResult := make(chan error, 1)
		stopResult := make(chan error, 1)

		// Act: Start through setup, then admit Stop before final worker
		// publication is allowed to continue.
		go func() {
			startResult <- m.StartWallet(t.Context(), w)
		}()

		<-cutoffReached

		go func() {
			stopResult <- m.StopWallet(t.Context(), w)
		}()

		<-stopAdmitted

		// Assert: Stop admission is already terminal for public Start even
		// while the coordinator remains paused in Starting.
		require.Equal(t, lifecycleStarting,
			lifecycle(w.state.lifecycle.Load()))
		require.ErrorIs(
			t, m.StartWallet(t.Context(), w), ErrWalletStopped,
		)

		close(releaseCutoff)

		// Assert: The delivered Stop wins the serialized cutoff, publishes no
		// workers, and completes terminal teardown.
		require.ErrorIs(t, <-startResult, ErrWalletStopped)
		require.NoError(t, <-stopResult)
		require.Equal(t, lifecycleStopped,
			lifecycle(w.state.lifecycle.Load()))
	})

	t.Run("cancellation wins", func(t *testing.T) {
		t.Parallel()

		// Arrange: Complete setup and pause immediately before final
		// publication so caller cancellation is already observable.
		m, w, deps := newLifecycleTestManager(t)
		cutoffReached := make(chan struct{})
		releaseCutoff := make(chan struct{})
		m.lifecycleTestHooks = &managerLifecycleTestHooks{
			beforeStartPublication: func(
				*walletLifecycleCoordinator) {

				close(cutoffReached)
				<-releaseCutoff
			},
		}

		expectLifecycleSetup(deps)
		deps.vault.On("Lock").Return().Once()

		startCtx, cancelStart := context.WithCancel(t.Context())
		startResult := make(chan error, 1)

		// Act: Reach the cutoff, cancel the accepted Start caller, then let
		// the coordinator make its final decision.
		go func() {
			startResult <- m.StartWallet(startCtx, w)
		}()

		<-cutoffReached
		cancelStart()
		close(releaseCutoff)

		startErr := <-startResult
		stopErr := m.StopWallet(t.Context(), w)

		// Assert: Observed cancellation wins, publishes no workers, and
		// leaves a terminal result for later Stop callers.
		require.ErrorIs(t, startErr, context.Canceled)
		require.NoError(t, stopErr)
		require.Equal(t, lifecycleStopped,
			lifecycle(w.state.lifecycle.Load()))
	})

	t.Run("publication wins", func(t *testing.T) {
		t.Parallel()

		// Arrange: Pause at the cutoff with no winning contender so releasing
		// it publishes the complete runtime.
		m, w, deps := newLifecycleTestManager(t)
		cutoffReached := make(chan struct{})
		releaseCutoff := make(chan struct{})
		m.lifecycleTestHooks = &managerLifecycleTestHooks{
			beforeStartPublication: func(
				*walletLifecycleCoordinator) {

				close(cutoffReached)
				<-releaseCutoff
			},
		}

		expectLifecycleSetup(deps)
		deps.syncer.On("run", mock.Anything).Return(nil).Once()
		deps.vault.On("Lock").Return().Once()

		startCtx, cancelStart := context.WithCancel(t.Context())
		startResult := make(chan error, 1)

		// Act: Release publication, observe its latched success, then cancel
		// that caller and stop the published runtime.
		go func() {
			startResult <- m.StartWallet(startCtx, w)
		}()

		<-cutoffReached
		close(releaseCutoff)

		startErr := <-startResult
		repeatedStartErr := m.StartWallet(t.Context(), w)

		// Assert: Publication latches success and makes the complete worker
		// generation visible; a repeated Start sees it active.
		require.NoError(t, startErr)
		require.ErrorIs(
			t, repeatedStartErr, ErrWalletAlreadyStarted,
		)
		require.Equal(t, lifecycleStarted,
			lifecycle(w.state.lifecycle.Load()))

		// Act: Cancel the completed Start caller and stop the already
		// published runtime.
		cancelStart()

		stopErr := m.StopWallet(t.Context(), w)

		// Assert: Post-publication cancellation cannot replace the successful
		// Start result, and Stop joins both workers.
		require.NoError(t, stopErr)
		require.Equal(t, lifecycleStopped,
			lifecycle(w.state.lifecycle.Load()))
	})
}
