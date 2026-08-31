package wallet

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestManagerWalletLifecycleTeardown verifies one canceled Stop caller cannot
// abandon shared teardown or change the result seen by later callers.
func TestManagerWalletLifecycleTeardown(t *testing.T) {
	t.Parallel()

	// Arrange: Hold worker exit and Vault locking at separate teardown
	// barriers.
	m, w, deps := newLifecycleTestManager(t)
	workerStarted := make(chan struct{})
	workerCanceled := make(chan struct{})
	releaseWorker := make(chan struct{})
	vaultEntered := make(chan struct{})
	releaseVault := make(chan struct{})

	expectLifecycleSetup(deps)
	deps.syncer.On("run", mock.Anything).Run(
		func(args mock.Arguments) {
			ctx, ok := args.Get(0).(context.Context)
			if !ok {
				return
			}

			close(workerStarted)
			<-ctx.Done()
			close(workerCanceled)
			<-releaseWorker
		},
	).Return(nil).Once()
	deps.vault.On("Lock").Run(func(mock.Arguments) {
		close(vaultEntered)
		<-releaseVault
	}).Return().Once()

	startCtx, cancelStart := context.WithCancel(t.Context())

	// Act: Start the runtime and cancel only its now-latched Start caller.
	startErr := m.StartWallet(startCtx, w)

	cancelStart()
	<-workerStarted

	// Assert: Post-publication Start cancellation leaves workers active.
	require.NoError(t, startErr)
	require.Equal(t, lifecycleStarted,
		lifecycle(w.state.lifecycle.Load()))

	stopCtx, cancelStop := context.WithCancel(t.Context())
	firstStop := make(chan error, 1)

	// Act: Begin teardown, then cancel only the first Stop caller.
	go func() {
		firstStop <- m.StopWallet(stopCtx, w)
	}()

	<-workerCanceled
	require.ErrorIs(
		t, m.StartWallet(t.Context(), w), ErrWalletStopped,
	)

	cancelStop()

	// Assert: The first caller exits without abandoning shared teardown.
	require.ErrorIs(t, <-firstStop, context.Canceled)

	// Act: Join teardown from a later caller while the worker is held.
	laterStop := make(chan error, 1)
	go func() {
		laterStop <- m.StopWallet(t.Context(), w)
	}()

	requireLifecyclePending(t, laterStop)

	select {
	case <-vaultEntered:
		require.Fail(t, "Vault locked before worker exit")
	default:
	}

	// Act: Release worker exit, then hold teardown inside Vault locking.
	close(releaseWorker)
	<-vaultEntered

	// Assert: Stop remains pending until Vault locking finishes.
	requireLifecyclePending(t, laterStop)
	close(releaseVault)

	// Act: Join the completed teardown again with the canceled context.
	laterErr := <-laterStop
	repeatedErr := m.StopWallet(stopCtx, w)

	// Assert: All later Stops observe the recorded terminal result.
	require.NoError(t, laterErr)
	require.NoError(t, repeatedErr)
	require.Equal(t, lifecycleStopped,
		lifecycle(w.state.lifecycle.Load()))
}
