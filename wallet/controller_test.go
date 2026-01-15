package wallet

import (
	"context"
	"sync"
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
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

// TestHandleLockReq_Idempotency verifies that if the wallet is already locked
// (indicated by waddrmgr.ErrLocked), the lock request treats it as a success
// and ensures the state is consistent.
func TestHandleLockReq_Idempotency(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and transition it to 'Started'.
	w, deps := createTestWalletWithMocks(t)
	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	// Transition the wallet to the 'Unlocked' state for testing.
	w.state.toUnlocked()

	req := newLockReq()

	// Setup the expected call to the address manager's Lock method
	// returning ErrLocked.
	errLocked := waddrmgr.ManagerError{
		ErrorCode:   waddrmgr.ErrLocked,
		Description: "address manager is locked",
	}
	deps.addrStore.On("Lock").Return(errLocked).Once()

	// Act: Dispatch the lock request to the handler.
	w.handleLockReq(req)

	// Assert: Verify that the response indicates success and the wallet
	// state is 'Locked'.
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

// TestControllerStart verifies that the Start method correctly initializes the
// wallet, verifying the birthday block, loading accounts, cleaning up locks,
// and starting the syncer.
func TestControllerStart(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and mock all dependencies required for
	// startup.
	w, deps := createTestWalletWithMocks(t)

	// 1. Mock verifyBirthday: Expect a call to retrieve the birthday
	//    block.
	bs := waddrmgr.BlockStamp{Height: 100}
	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(bs, true, nil).Once()

	// 2. Mock DBGetAllAccounts: Expect a call to load active account
	//    managers.
	deps.addrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore(nil)).Once()

	// 3. Mock deleteExpiredLockedOutputs: Expect a call to cleanup expired
	//    locks in the transaction store.
	deps.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()

	// 4. Mock syncer.run: Expect the syncer to be started.
	deps.syncer.On(
		"run", mock.Anything,
	).Return(nil).Once()

	// Act: Start the wallet.
	err := w.Start(t.Context())

	// Assert: Verify that Start returned no error and the wallet state is
	// 'Started'.
	require.NoError(t, err)
	require.True(t, w.state.isStarted())

	// Cleanup: Stop the wallet to release resources.
	err = w.Stop(t.Context())
	require.NoError(t, err)
	w.wg.Wait()
}

// TestControllerStop verifies that the Stop method correctly shuts down the
// wallet, waiting for the syncer and other background processes to exit.
func TestControllerStop(t *testing.T) {
	t.Parallel()

	// Arrange: Create and start a test wallet.
	w, deps := createTestWalletWithMocks(t)

	// Setup mocks for the startup sequence.
	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(waddrmgr.BlockStamp{}, true, nil).Once()
	deps.addrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore(nil)).Once()
	deps.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()

	// Mock syncer.run to simulate a long-running process that exits when
	// the context is cancelled.
	deps.syncer.On("run", mock.Anything).Run(func(args mock.Arguments) {
		ctx, ok := args.Get(0).(context.Context)
		if !ok {
			return
		}
		<-ctx.Done()
	}).Return(nil).Once()

	require.NoError(t, w.Start(t.Context()))
	require.True(t, w.state.isStarted())

	// Act: Stop the wallet.
	err := w.Stop(t.Context())

	// Assert: Verify that Stop returned no error and the wallet state is
	// no longer 'Started'.
	require.NoError(t, err)
	require.False(t, w.state.isStarted())

	// Act: Call Stop again to verify idempotency.
	err = w.Stop(t.Context())

	// Assert: Verify that subsequent Stop calls are safe and return no
	// error.
	require.NoError(t, err)
}

// TestControllerLock verifies the Lock method. It ensures that the wallet
// can only be locked when it is started and currently unlocked.
func TestControllerLock(t *testing.T) {
	t.Parallel()

	// Arrange: Create and start a test wallet.
	w, deps := createTestWalletWithMocks(t)

	// Setup mocks for startup.
	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(waddrmgr.BlockStamp{}, true, nil).Once()
	deps.addrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore(nil)).Once()
	deps.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()
	deps.syncer.On("run", mock.Anything).Return(nil).Once()

	require.NoError(t, w.Start(t.Context()))

	// Transition the wallet to the 'Unlocked' state for testing.
	w.state.toUnlocked()
	require.True(t, w.state.isUnlocked())

	// Expect a call to the address manager's Lock method.
	deps.addrStore.On("Lock").Return(nil).Once()

	// Act: Call the Lock method.
	err := w.Lock(t.Context())

	// Assert: Verify success and that the wallet state is locked.
	require.NoError(t, err)
	require.False(t, w.state.isUnlocked())

	// Cleanup: Stop the wallet to release resources.
	err = w.Stop(t.Context())
	require.NoError(t, err)
	w.wg.Wait()
}

// TestControllerUnlock verifies the Unlock method. It ensures that the wallet
// can be unlocked by providing the correct passphrase.
func TestControllerUnlock(t *testing.T) {
	t.Parallel()

	// Arrange: Create and start a test wallet.
	w, deps := createTestWalletWithMocks(t)

	// Setup mocks for startup.
	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(waddrmgr.BlockStamp{}, true, nil).Once()
	deps.addrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore(nil)).Once()
	deps.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()
	deps.syncer.On("run", mock.Anything).Return(nil).Once()

	require.NoError(t, w.Start(t.Context()))
	require.False(t, w.state.isUnlocked())

	pass := []byte("password")

	// Expect a call to the address manager's Unlock method.
	deps.addrStore.On("Unlock", mock.Anything, pass).Return(nil).Once()

	// Act: Call the Unlock method.
	err := w.Unlock(t.Context(), UnlockRequest{Passphrase: pass})

	// Assert: Verify success and that the wallet state is unlocked.
	require.NoError(t, err)
	require.True(t, w.state.isUnlocked())

	// Cleanup: Stop the wallet to release resources.
	err = w.Stop(t.Context())
	require.NoError(t, err)
	w.wg.Wait()
}

// TestControllerChangePassphrase verifies the ChangePassphrase method. It
// ensures that the wallet forwards the request to the address manager to
// update the passphrases.
func TestControllerChangePassphrase(t *testing.T) {
	t.Parallel()

	// Arrange: Create and start a test wallet.
	w, deps := createTestWalletWithMocks(t)

	// Setup mocks for startup.
	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(waddrmgr.BlockStamp{}, true, nil).Once()
	deps.addrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore(nil)).Once()
	deps.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()
	deps.syncer.On("run", mock.Anything).Return(nil).Once()

	require.NoError(t, w.Start(t.Context()))

	req := ChangePassphraseRequest{
		ChangePrivate: true,
		PrivateOld:    []byte("old"),
		PrivateNew:    []byte("new"),
	}

	// Expect a call to ChangePassphrase in the address store.
	deps.addrStore.On(
		"ChangePassphrase", mock.Anything, []byte("old"), []byte("new"),
		true, mock.Anything,
	).Return(nil).Once()

	// Act: Call ChangePassphrase.
	err := w.ChangePassphrase(t.Context(), req)

	// Assert: Verify that the operation completed without error.
	require.NoError(t, err)

	// Cleanup: Stop the wallet to release resources.
	err = w.Stop(t.Context())
	require.NoError(t, err)
	w.wg.Wait()
}

// TestHandleChangePassphraseReq_Errors verifies error handling for the
// internal change passphrase request handler.
func TestHandleChangePassphraseReq_Errors(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet in the default 'Stopped' state.
	w, _ := createTestWalletWithMocks(t)

	req := changePassphraseReq{
		req:  ChangePassphraseRequest{},
		resp: make(chan error, 1),
	}

	// Act: Call the internal handler while the wallet is stopped.
	w.handleChangePassphraseReq(req)

	// Assert: Verify that the request fails with ErrStateForbidden.
	err := <-req.resp
	require.ErrorIs(t, err, ErrStateForbidden)
}

// TestControllerInfo verifies the Info method. It checks that the wallet
// correctly aggregates information from its subsystems (chain backend,
// address manager, and syncer).
func TestControllerInfo(t *testing.T) {
	t.Parallel()

	// Arrange: Create and start a test wallet with mocked subsystems.
	w, deps := createTestWalletWithMocks(t)

	bs := waddrmgr.BlockStamp{Height: 100}
	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(bs, true, nil).Once()
	deps.addrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore(nil)).Once()
	deps.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()
	deps.syncer.On("run", mock.Anything).Return(nil).Once()

	// Mock the chain backend to return a specific name.
	deps.chain.On("BackEnd").Return("mock")

	// Mock SyncedTo to return a known block stamp.
	deps.addrStore.On("SyncedTo").Return(bs)

	// Mock syncState to indicate the wallet is fully synced.
	deps.syncer.On("syncState").Return(syncStateSynced)

	require.NoError(t, w.Start(t.Context()))

	// Act: Call the Info method.
	info, err := w.Info(t.Context())

	// Assert: Verify that the returned information matches the mocked
	// values and current wallet state.
	require.NoError(t, err)
	require.Equal(t, "mock", info.Backend)
	require.Equal(t, int32(100), info.BirthdayBlock.Height)
	require.True(t, info.Synced)
	require.True(t, info.Locked)

	// Cleanup: Stop the wallet to release resources.
	err = w.Stop(t.Context())
	require.NoError(t, err)
	w.wg.Wait()
}
