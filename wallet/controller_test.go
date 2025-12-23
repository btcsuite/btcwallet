package wallet

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestHandleUnlockReq verifies that the handleUnlockReq method correctly
// processes an unlock request by invoking the address manager's Unlock method
// and updating the wallet state.
func TestHandleUnlockReq(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and mock its dependencies.
	w, deps := createTestWalletWithMocks(t)

	// Simulate the wallet being in the 'Started' state, which is a
	// prerequisite for unlocking.
	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	pass := []byte("password")
	req := newUnlockReq(UnlockRequest{Passphrase: pass})

	// Setup the expected call to the address manager's Unlock method.
	deps.addrStore.On("Unlock", mock.Anything, pass).Return(nil).Once()

	// Act: Dispatch the unlock request to the handler.
	w.handleUnlockReq(req)

	// Assert: Verify that the response indicates success and the wallet
	// state has transitioned to 'Unlocked'.
	resp := <-req.resp
	require.NoError(t, resp)
	require.True(t, w.state.isUnlocked())
}

// TestHandleUnlockReq_Errors verifies that handleUnlockReq correctly handles
// error conditions, such as attempting to unlock a stopped wallet or a failure
// from the underlying storage.
func TestHandleUnlockReq_Errors(t *testing.T) {
	t.Parallel()

	// 1. ErrStateForbidden (Wallet Locked).
	//
	// Arrange: Create a test wallet. By default, it is in the 'Stopped'
	// state.
	w, deps := createTestWalletWithMocks(t)

	pass := []byte("password")
	req := newUnlockReq(UnlockRequest{Passphrase: pass})

	// Act: Attempt to unlock the wallet while it is stopped.
	w.handleUnlockReq(req)

	// Assert: Verify that the request fails with ErrStateForbidden.
	err := <-req.resp
	require.ErrorIs(t, err, ErrStateForbidden)

	// 2. DBUnlock failure.
	//
	// Arrange: Transition the wallet to 'Started' so the state check
	// passes, but setup the address manager to return an error.
	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	req = newUnlockReq(UnlockRequest{Passphrase: pass})
	deps.addrStore.On("Unlock", mock.Anything, pass).Return(
		errDBMock,
	).Once()

	// Act: Attempt to unlock the wallet again.
	w.handleUnlockReq(req)

	// Assert: Verify that the database error is propagated.
	err = <-req.resp
	require.ErrorContains(t, err, "db error")
}

// TestHandleLockReq verifies that the handleLockReq method correctly processes
// a lock request by invoking the address manager's Lock method and updating
// the wallet state.
func TestHandleLockReq(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and transition it to 'Started' and
	// then 'Unlocked'.
	w, deps := createTestWalletWithMocks(t)
	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())
	w.state.toUnlocked()

	req := newLockReq()

	// Setup the expected call to the address manager's Lock method.
	deps.addrStore.On("Lock").Return(nil).Once()

	// Act: Dispatch the lock request to the handler.
	w.handleLockReq(req)

	// Assert: Verify that the response indicates success and the wallet
	// state is no longer 'Unlocked'.
	resp := <-req.resp
	require.NoError(t, resp)
	require.False(t, w.state.isUnlocked())
}

// TestHandleLockReq_Errors verifies that handleLockReq correctly handles error
// conditions, such as attempting to lock a stopped wallet.
func TestHandleLockReq_Errors(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet in the default 'Stopped' state.
	w, _ := createTestWalletWithMocks(t)

	req := newLockReq()

	// Act: Attempt to lock the wallet.
	w.handleLockReq(req)

	// Assert: Verify that the request fails with ErrStateForbidden.
	err := <-req.resp
	require.ErrorIs(t, err, ErrStateForbidden)
}

// TestMainLoop verifies that the wallet's main event loop can start and stop
// correctly in response to context cancellation.
func TestMainLoop(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and setup a cancellable context to
	// control the main loop's lifecycle.
	w, _ := createTestWalletWithMocks(t)
	ctx, cancel := context.WithCancel(t.Context())
	w.lifetimeCtx = ctx
	w.cancel = cancel

	var testWg sync.WaitGroup
	testWg.Add(1)
	w.wg.Add(1)

	// Act: Start the main loop in a background goroutine.
	go func() {
		defer testWg.Done()

		w.mainLoop()
	}()

	// Act: Cancel the context to signal the main loop to exit.
	cancel()

	// Assert: Wait for the main loop to exit, ensuring it respects the
	// context cancellation.
	testWg.Wait()
}

// TestHandleChangePassphraseReq verifies the change passphrase request handler.
func TestHandleChangePassphraseReq(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and a dummy change passphrase request.
	w, deps := createTestWalletWithMocks(t)

	// Transition the wallet to 'Started' so the state check passes.
	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	reqStruct := ChangePassphraseRequest{
		ChangePrivate: true,
		PrivateOld:    []byte("old"),
		PrivateNew:    []byte("new"),
	}
	req := newChangePassphraseReq(reqStruct)

	// Setup the expected call to the address manager's ChangePassphrase
	// method.
	deps.addrStore.On(
		"ChangePassphrase", mock.Anything, []byte("old"),
		[]byte("new"), true, mock.Anything,
	).Return(nil).Once()

	// Act: Call the handler.
	w.handleChangePassphraseReq(req)

	// Assert: Verify that the response indicates success.
	resp := <-req.resp
	require.NoError(t, resp)
}
