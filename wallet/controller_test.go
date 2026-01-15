package wallet

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
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

// TestControllerUnlock_Interrupted_SendCancelled verifies Unlock when the
// request send is interrupted by context cancellation.
func TestControllerUnlock_Interrupted_SendCancelled(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a wallet and a cancelled context during Unlock.
	w1, _ := createTestWalletWithMocks(t)
	require.NoError(t, w1.state.toStarting())
	require.NoError(t, w1.state.toStarted())

	w1.requestChan = make(chan any) // Unbuffered to block send.
	ctx1, cancel1 := context.WithCancel(t.Context())

	errChan1 := make(chan error, 1)
	go func() {
		errChan1 <- w1.Unlock(ctx1,
			UnlockRequest{Passphrase: []byte("pw")})
	}()

	// Act: Cancel context to interrupt send.
	cancel1()

	// Assert: Verify cancellation error.
	select {
	case err := <-errChan1:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}
}

// TestControllerUnlock_Interrupted_SendShutdown verifies Unlock when the
// request send is interrupted by wallet shutdown.
func TestControllerUnlock_Interrupted_SendShutdown(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a wallet and trigger shutdown during Unlock.
	w2, _ := createTestWalletWithMocks(t)
	require.NoError(t, w2.state.toStarting())
	require.NoError(t, w2.state.toStarted())

	w2.requestChan = make(chan any)

	errChan2 := make(chan error, 1)
	go func() {
		errChan2 <- w2.Unlock(t.Context(),
			UnlockRequest{Passphrase: []byte("pw")})
	}()

	// Act: Stop wallet.
	w2.cancel()

	// Assert: Verify shutdown error.
	select {
	case err := <-errChan2:
		require.ErrorIs(t, err, ErrWalletShuttingDown)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}
}

// TestControllerUnlock_Interrupted_WaitCancelled verifies Unlock when the
// response wait is interrupted by context cancellation.
func TestControllerUnlock_Interrupted_WaitCancelled(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a wallet with a buffered channel to allow send but
	// block on response.
	w3, _ := createTestWalletWithMocks(t)
	require.NoError(t, w3.state.toStarting())
	require.NoError(t, w3.state.toStarted())

	ctx3, cancel3 := context.WithCancel(t.Context())

	errChan3 := make(chan error, 1)
	go func() {
		errChan3 <- w3.Unlock(ctx3,
			UnlockRequest{Passphrase: []byte("pw")})
	}()

	// Wait for request to be sent.
	select {
	case <-w3.requestChan:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for request")
	}

	// Act: Cancel context during response wait.
	cancel3()

	// Assert: Verify cancellation error.
	select {
	case err := <-errChan3:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}
}

// TestControllerUnlock_Interrupted_WaitShutdown verifies Unlock when the
// response wait is interrupted by wallet shutdown.
func TestControllerUnlock_Interrupted_WaitShutdown(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a wallet and trigger shutdown during response wait.
	w4, _ := createTestWalletWithMocks(t)
	require.NoError(t, w4.state.toStarting())
	require.NoError(t, w4.state.toStarted())

	errChan4 := make(chan error, 1)
	go func() {
		errChan4 <- w4.Unlock(t.Context(),
			UnlockRequest{Passphrase: []byte("pw")})
	}()

	select {
	case <-w4.requestChan:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for request")
	}

	// Act: Stop wallet.
	w4.cancel()

	// Assert: Verify shutdown error.
	select {
	case err := <-errChan4:
		require.ErrorIs(t, err, ErrWalletShuttingDown)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}
}

// TestControllerVerifyBirthday_Verified verifies that verifyBirthday
// returns early if the birthday block is already verified.
func TestControllerVerifyBirthday_Verified(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a wallet where the birthday block is already verified.
	w, deps := createTestWalletWithMocks(t)
	bs := waddrmgr.BlockStamp{Height: 123, Hash: chainhash.Hash{0x01}}
	deps.addrStore.On("BirthdayBlock", mock.Anything).Return(
		bs, true, nil).Once()

	// Act: Verify birthday.
	err := w.verifyBirthday(t.Context())

	// Assert: Verify success.
	require.NoError(t, err)
	require.Equal(t, bs, w.birthdayBlock)
}

// TestControllerVerifyBirthday_LocateFail verifies verifyBirthday failure
// when locateBirthdayBlock fails.
func TestControllerVerifyBirthday_LocateFail(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where the birthday block is not set
	// and chain lookup fails.
	w, deps := createTestWalletWithMocks(t)

	deps.addrStore.On("BirthdayBlock", mock.Anything).Return(
		waddrmgr.BlockStamp{}, false, waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrBirthdayBlockNotSet,
		}).Once()
	deps.addrStore.On("Birthday").Return(time.Now()).Once()
	deps.chain.On("GetBestBlock").Return(nil, int32(0), errChainMock).Once()

	// Act: Attempt to verify birthday.
	err := w.verifyBirthday(t.Context())

	// Assert: Verify failure.
	require.ErrorContains(t, err, "chain error")
}

// TestControllerVerifyBirthday_PutFail verifies verifyBirthday failure
// when DBPutBirthdayBlock fails.
func TestControllerVerifyBirthday_PutFail(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where block location succeeds but
	// persisting the birthday block fails.
	w, deps := createTestWalletWithMocks(t)

	deps.addrStore.On("BirthdayBlock", mock.Anything).Return(
		waddrmgr.BlockStamp{}, false, waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrBirthdayBlockNotSet,
		}).Once()
	deps.addrStore.On("Birthday").Return(time.Now()).Once()
	deps.chain.On("GetBestBlock").Return(
		&chainhash.Hash{}, int32(100), nil).Once()
	deps.chain.On("GetBlockHash", mock.Anything).Return(
		&chainhash.Hash{}, nil).Maybe()
	deps.chain.On("GetBlockHeader", mock.Anything).Return(
		&wire.BlockHeader{}, nil).Maybe()
	deps.addrStore.On("SetBirthdayBlock", mock.Anything, mock.Anything,
		true).Return(errPutMock).Once()

	// Act: Attempt to verify birthday.
	err := w.verifyBirthday(t.Context())

	// Assert: Verify failure.
	require.ErrorContains(t, err, "put error")
}

// TestSubmitRescanRequest_Errors verifies submitRescanRequest error paths.
func TestSubmitRescanRequest_Errors(t *testing.T) {
	t.Parallel()

	t.Run("ErrStateForbidden", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup a stopped wallet.
		w, _ := createTestWalletWithMocks(t)

		// Act: Attempt to submit rescan.
		err := w.submitRescanRequest(t.Context(), scanTypeRewind, 0, nil)

		// Assert: Verify failure.
		require.ErrorIs(t, err, ErrStateForbidden)
	})

	t.Run("GetBestBlock_Failure", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup a started wallet where best block lookup fails.
		w, deps := createTestWalletWithMocks(t)
		require.NoError(t, w.state.toStarting())
		require.NoError(t, w.state.toStarted())

		deps.syncer.On("syncState").Return(syncStateSynced)
		deps.chain.On("GetBestBlock").Return(
			nil, int32(0), errBestBlock).Once()

		// Act: Attempt to submit rescan.
		err := w.submitRescanRequest(t.Context(), scanTypeRewind,
			0, nil)

		// Assert: Verify failure.
		require.ErrorContains(t, err, "best block fail")
	})
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

// TestControllerLock_Errors verifies Lock failures.
func TestControllerLock_Errors(t *testing.T) {
	t.Parallel()

	t.Run("ContextCanceled", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup a started wallet with an unbuffered request
		// channel and a cancelled context.
		w, _ := createTestWalletWithMocks(t)
		require.NoError(t, w.state.toStarting())
		require.NoError(t, w.state.toStarted())

		w.requestChan = make(chan any) // Unbuffered to block send.
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		// Act: Attempt to lock.
		err := w.Lock(ctx)

		// Assert: Verify cancellation error.
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("WalletStopped", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup a stopped wallet.
		w, _ := createTestWalletWithMocks(t)
		ctx, cancel := context.WithCancel(t.Context())
		w.lifetimeCtx = ctx
		w.cancel = cancel
		w.cancel() // Stop wallet.

		// Act: Attempt to lock.
		err := w.Lock(t.Context())

		// Assert: Verify forbidden error.
		require.ErrorIs(t, err, ErrStateForbidden)
	})
}

// TestControllerChangePassphrase_Errors verifies ChangePassphrase failures.
func TestControllerChangePassphrase_Errors(t *testing.T) {
	t.Parallel()

	t.Run("ContextCanceled", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup a started wallet and a cancelled context.
		w, _ := createTestWalletWithMocks(t)
		require.NoError(t, w.state.toStarting())
		require.NoError(t, w.state.toStarted())

		w.requestChan = make(chan any)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		// Act: Attempt to change passphrase.
		err := w.ChangePassphrase(ctx, ChangePassphraseRequest{})

		// Assert: Verify cancellation error.
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("WalletStopped", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup a stopped wallet.
		w, _ := createTestWalletWithMocks(t)
		ctx, cancel := context.WithCancel(t.Context())
		w.lifetimeCtx = ctx
		w.cancel = cancel
		w.cancel()

		// Act: Attempt to change passphrase.
		err := w.ChangePassphrase(
			t.Context(), ChangePassphraseRequest{},
		)

		// Assert: Verify forbidden error.
		require.ErrorIs(t, err, ErrStateForbidden)
	})
}

// TestControllerStart_WithAccounts verifies Start with existing accounts.
func TestControllerStart_WithAccounts(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a wallet with existing accounts in the address store.
	w, deps := createTestWalletWithMocks(t)

	bs := waddrmgr.BlockStamp{Height: 100}
	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(bs, true, nil).Once()

	scopedMgr := &mockAccountStore{}
	deps.addrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore{scopedMgr}).Once()

	scopedMgr.On("LastAccount", mock.Anything).Return(uint32(1), nil).Once()
	scopedMgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Maybe()
	scopedMgr.On(
		"AccountProperties", mock.Anything, uint32(0),
	).Return(&waddrmgr.AccountProperties{AccountNumber: 0}, nil).Once()
	scopedMgr.On(
		"AccountProperties", mock.Anything, uint32(1),
	).Return(&waddrmgr.AccountProperties{AccountNumber: 1}, nil).Once()

	deps.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()
	deps.syncer.On("run", mock.Anything).Return(nil).Once()

	// Act: Start the wallet.
	err := w.Start(t.Context())

	// Assert: Verify success.
	require.NoError(t, err)
	require.True(t, w.state.isStarted())

	// Cleanup.
	require.NoError(t, w.Stop(t.Context()))
	w.wg.Wait()
}

// TestMainLoop_AutoLock verifies that the main loop handles auto-lock
// timeouts.
func TestMainLoop_AutoLock(t *testing.T) {
	t.Parallel()

	// Arrange: Setup an unlocked wallet with a short lock timer.
	w, deps := createTestWalletWithMocks(t)
	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	w.state.toUnlocked()

	ctx, cancel := context.WithCancel(t.Context())
	w.lifetimeCtx = ctx
	w.cancel = cancel
	w.lockTimer = time.NewTimer(time.Millisecond * 10)

	lockCalled := make(chan struct{})
	deps.addrStore.On("Lock").Run(func(args mock.Arguments) {
		close(lockCalled)
	}).Return(nil).Once()

	// Act: Start main loop.
	w.wg.Add(1)

	go w.mainLoop()

	// Assert: Verify that the auto-lock was triggered.
	select {
	case <-lockCalled:
	case <-time.After(time.Second):
		t.Fatal("Auto-lock not triggered")
	}

	// Clean up.
	cancel()
	w.wg.Wait()
}

// TestMainLoop_UnknownRequest verifies main loop handles unknown requests
// gracefully.
func TestMainLoop_UnknownRequest(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a wallet and start the main loop.
	w, _ := createTestWalletWithMocks(t)

	ctx, cancel := context.WithCancel(t.Context())
	w.lifetimeCtx = ctx
	w.cancel = cancel

	w.wg.Add(1)

	go w.mainLoop()

	// Act: Send an unknown request type.
	w.requestChan <- "unknown"

	// Assert: Ensure it doesn't crash and can be stopped cleanly.
	cancel()
	w.wg.Wait()
}

// TestControllerLock_Interrupted_SendShutdown verifies Lock when request
// send is interrupted by wallet shutdown.
func TestControllerLock_Interrupted_SendShutdown(t *testing.T) {
	t.Parallel()

	// Arrange: Trigger shutdown during Lock.
	w, _ := createTestWalletWithMocks(t)

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	w.requestChan = make(chan any)
	w.cancel() // Stop wallet.

	// Act: Attempt to lock.
	err := w.Lock(t.Context())

	// Assert: Verify error.
	require.ErrorIs(t, err, ErrWalletShuttingDown)
}

// TestControllerLock_Interrupted_WaitCancelled verifies Lock when response
// wait is interrupted by context cancellation.
func TestControllerLock_Interrupted_WaitCancelled(t *testing.T) {
	t.Parallel()

	// Arrange: Block during response wait and cancel context.
	w, _ := createTestWalletWithMocks(t)

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	ctx, cancel := context.WithCancel(t.Context())

	errChan := make(chan error, 1)
	go func() {
		errChan <- w.Lock(ctx)
	}()

	// Wait for request.
	select {
	case <-w.requestChan:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for request")
	}

	// Act: Cancel context.
	cancel()

	// Assert: Verify error.
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}
}

// TestControllerLock_Interrupted_WaitShutdown verifies Lock when response
// wait is interrupted by wallet shutdown.
func TestControllerLock_Interrupted_WaitShutdown(t *testing.T) {
	t.Parallel()

	// Arrange: Block during response wait and trigger shutdown.
	w, _ := createTestWalletWithMocks(t)

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	errChan := make(chan error, 1)
	go func() {
		errChan <- w.Lock(t.Context())
	}()

	select {
	case <-w.requestChan:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for request")
	}

	// Act: Stop wallet.
	w.cancel()

	// Assert: Verify error.
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, ErrWalletShuttingDown)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}
}

// TestControllerLock_Interrupted_WaitTimeout verifies Lock when response
// wait times out.
func TestControllerLock_Interrupted_WaitTimeout(t *testing.T) {
	t.Parallel()

	// Arrange: Block during response wait and allow timeout to occur.
	w, _ := createTestWalletWithMocks(t)

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	ctx, cancel := context.WithTimeout(
		t.Context(), 10*time.Millisecond,
	)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- w.Lock(ctx)
	}()

	select {
	case <-w.requestChan:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// Assert: Verify timeout error.
	select {
	case err := <-errChan:
		require.ErrorContains(t, err,
			"context deadline exceeded")
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}
}

// TestControllerChangePassphrase_Interrupted_SendShutdown verifies
// ChangePassphrase when request send is interrupted by wallet shutdown.
func TestControllerChangePassphrase_Interrupted_SendShutdown(t *testing.T) {
	t.Parallel()

	// Arrange: Trigger shutdown during send.
	w, _ := createTestWalletWithMocks(t)

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	w.requestChan = make(chan any)
	w.cancel() // Stop wallet.

	// Act: Attempt change.
	err := w.ChangePassphrase(t.Context(),
		ChangePassphraseRequest{})

	// Assert: Verify error.
	require.ErrorIs(t, err, ErrWalletShuttingDown)
}

// TestControllerChangePassphrase_Interrupted_WaitCancelled verifies
// ChangePassphrase when response wait is interrupted by context cancellation.
func TestControllerChangePassphrase_Interrupted_WaitCancelled(t *testing.T) {
	t.Parallel()

	// Arrange: Block during response wait and cancel context.
	w, _ := createTestWalletWithMocks(t)

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	ctx, cancel := context.WithCancel(t.Context())

	errChan := make(chan error, 1)
	go func() {
		errChan <- w.ChangePassphrase(ctx,
			ChangePassphraseRequest{})
	}()

	select {
	case <-w.requestChan:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for request")
	}

	// Act: Cancel context.
	cancel()

	// Assert: Verify error.
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}
}

// TestControllerChangePassphrase_Interrupted_WaitShutdown verifies
// ChangePassphrase when response wait is interrupted by wallet shutdown.
func TestControllerChangePassphrase_Interrupted_WaitShutdown(t *testing.T) {
	t.Parallel()

	// Arrange: Block during response wait and trigger shutdown.
	w, _ := createTestWalletWithMocks(t)

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	errChan := make(chan error, 1)
	go func() {
		errChan <- w.ChangePassphrase(t.Context(),
			ChangePassphraseRequest{})
	}()

	select {
	case <-w.requestChan:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for request")
	}

	// Act: Stop wallet.
	w.cancel()

	// Assert: Verify error.
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, ErrWalletShuttingDown)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}
}

// TestControllerChangePassphrase_Interrupted_WaitTimeout verifies
// ChangePassphrase when response wait times out.
func TestControllerChangePassphrase_Interrupted_WaitTimeout(t *testing.T) {
	t.Parallel()

	// Arrange: Block during response wait and allow timeout.
	w, _ := createTestWalletWithMocks(t)

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	ctx, cancel := context.WithTimeout(t.Context(),
		10*time.Millisecond)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- w.ChangePassphrase(ctx,
			ChangePassphraseRequest{})
	}()

	select {
	case <-w.requestChan:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// Assert: Verify timeout.
	select {
	case err := <-errChan:
		require.ErrorContains(t, err,
			"context deadline exceeded")
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}
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

// TestControllerResync verifies the Resync method.
func TestControllerResync(t *testing.T) {
	t.Parallel()

	t.Run("StartHeightTooHigh", func(t *testing.T) {
		t.Parallel()

		w, deps := createTestWalletWithMocks(t)
		require.NoError(t, w.state.toStarting())
		require.NoError(t, w.state.toStarted())

		deps.syncer.On("syncState").Return(syncStateSynced)
		deps.chain.On("GetBestBlock").Return(
			&chainhash.Hash{}, int32(100), nil,
		).Once()

		err := w.Resync(t.Context(), 101)
		require.ErrorIs(t, err, ErrStartHeightTooHigh)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		w, deps := createTestWalletWithMocks(t)
		require.NoError(t, w.state.toStarting())
		require.NoError(t, w.state.toStarted())

		deps.syncer.On("syncState").Return(syncStateSynced)
		deps.chain.On("GetBestBlock").Return(
			&chainhash.Hash{}, int32(100), nil,
		).Once()
		deps.syncer.On("requestScan", mock.Anything, mock.MatchedBy(
			func(req *scanReq) bool {
				return req.typ == scanTypeRewind &&
					req.startBlock.Height == 50
			},
		)).Return(nil).Once()

		err := w.Resync(t.Context(), 50)
		require.NoError(t, err)
	})
}

// TestControllerRescan verifies the Rescan method.
func TestControllerRescan(t *testing.T) {
	t.Parallel()

	t.Run("NoTargets", func(t *testing.T) {
		t.Parallel()

		w, _ := createTestWalletWithMocks(t)
		require.NoError(t, w.state.toStarting())
		require.NoError(t, w.state.toStarted())

		err := w.Rescan(t.Context(), 50, nil)
		require.ErrorIs(t, err, ErrNoScanTargets)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		w, deps := createTestWalletWithMocks(t)
		require.NoError(t, w.state.toStarting())
		require.NoError(t, w.state.toStarted())

		deps.syncer.On("syncState").Return(syncStateSynced)

		targets := []waddrmgr.AccountScope{{Account: 1}}

		deps.chain.On("GetBestBlock").Return(
			&chainhash.Hash{}, int32(100), nil,
		).Once()
		deps.syncer.On("requestScan", mock.Anything, mock.MatchedBy(
			func(req *scanReq) bool {
				return req.typ == scanTypeTargeted &&
					req.startBlock.Height == 50 &&
					len(req.targets) == 1
			},
		)).Return(nil).Once()

		err := w.Rescan(t.Context(), 50, targets)
		require.NoError(t, err)
	})
}

// TestControllerStart_VerifyBirthdayFail verifies Start fails when
// verifyBirthday fails.
func TestControllerStart_VerifyBirthdayFail(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where birthday block lookup fails.
	w, deps := createTestWalletWithMocks(t)

	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(waddrmgr.BlockStamp{}, false, errDBMock).Once()

	// Act: Attempt to start the wallet.
	err := w.Start(t.Context())

	// Assert: Verify failure.
	require.ErrorIs(t, err, errDBMock)
	require.False(t, w.state.isStarted())
}

// TestControllerStart_DBGetAllAccountsFail verifies Start fails when
// DBGetAllAccounts fails.
func TestControllerStart_DBGetAllAccountsFail(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where account lookup fails during
	// startup.
	w, deps := createTestWalletWithMocks(t)

	bs := waddrmgr.BlockStamp{Height: 100}
	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(bs, true, nil).Once()

	mockScopedMgr := &mockAccountStore{}
	deps.addrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore{mockScopedMgr}).Once()

	mockScopedMgr.On(
		"LastAccount", mock.Anything,
	).Return(uint32(0), errDBMock).Once()

	// Act: Attempt to start the wallet.
	err := w.Start(t.Context())

	// Assert: Verify failure.
	require.ErrorIs(t, err, errDBMock)
	require.False(t, w.state.isStarted())
}

// TestControllerStart_BirthdayNotSet verifies the flow when birthday block is
// not set in DB.
func TestControllerStart_BirthdayNotSet(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where the birthday block is not set
	// and must be located from the chain.
	w, deps := createTestWalletWithMocks(t)

	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(waddrmgr.BlockStamp{}, false, waddrmgr.ManagerError{
		ErrorCode: waddrmgr.ErrBirthdayBlockNotSet,
	}).Once()

	birthday := time.Now()
	deps.addrStore.On("Birthday").Return(birthday).Once()

	deps.chain.On(
		"GetBestBlock",
	).Return(&chainhash.Hash{}, int32(100), nil).Once()
	deps.chain.On(
		"GetBlockHash", int64(50),
	).Return(&chainhash.Hash{}, nil).Once()

	header := &wire.BlockHeader{Timestamp: birthday}
	deps.chain.On(
		"GetBlockHeader", mock.Anything,
	).Return(header, nil).Once()

	deps.addrStore.On(
		"SetBirthdayBlock", mock.Anything,
		mock.MatchedBy(func(bs waddrmgr.BlockStamp) bool {
			return bs.Height == 50
		}), true,
	).Return(nil).Once()
	deps.addrStore.On(
		"SetSyncedTo", mock.Anything, mock.Anything,
	).Return(nil).Once()

	deps.addrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore(nil)).Once()
	deps.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()
	deps.syncer.On("run", mock.Anything).Return(nil).Once()

	// Act: Start the wallet.
	err := w.Start(t.Context())

	// Assert: Verify success.
	require.NoError(t, err)
	require.True(t, w.state.isStarted())

	// Clean up.
	require.NoError(t, w.Stop(t.Context()))
	w.wg.Wait()
}

// TestControllerUnlock_DefaultTimeout verifies default timeout usage.
func TestControllerUnlock_DefaultTimeout(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a wallet with an auto-lock duration and start the
	// main loop.
	w, deps := createTestWalletWithMocks(t)

	w.cfg.AutoLockDuration = time.Minute

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	w.wg.Add(1)

	go w.mainLoop()

	pass := []byte("pass")
	req := UnlockRequest{Passphrase: pass}
	deps.addrStore.On("Unlock", mock.Anything, pass).Return(nil).Once()
	// Auto-lock might trigger if the test runs slowly, but it's not
	// guaranteed.
	deps.addrStore.On("Lock").Return(nil).Maybe()

	// Act: Perform Unlock with default timeout.
	err := w.Unlock(t.Context(), req)

	// Assert: Verify success.
	require.NoError(t, err)

	// Clean up.
	w.cancel()
	w.wg.Wait()
}

// TestControllerStart_DeleteExpiredFail verifies Start fails when
// deleteExpiredLockedOutputs fails.
func TestControllerStart_DeleteExpiredFail(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where cleanup of expired locks
	// fails.
	w, deps := createTestWalletWithMocks(t)

	bs := waddrmgr.BlockStamp{Height: 100}
	deps.addrStore.On("BirthdayBlock", mock.Anything).Return(
		bs, true, nil).Once()
	deps.addrStore.On("ActiveScopedKeyManagers").Return(
		[]waddrmgr.AccountStore(nil)).Once()

	deps.txStore.On("DeleteExpiredLockedOutputs", mock.Anything).Return(
		errDBMock).Once()

	// Act: Attempt to start.
	err := w.Start(t.Context())

	// Assert: Verify failure.
	require.ErrorIs(t, err, errDBMock)
	require.False(t, w.state.isStarted())
}

// TestControllerUnlock_NegativeTimeout verifies Unlock with negative
// timeout.
func TestControllerUnlock_NegativeTimeout(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a wallet and start the main loop.
	w, deps := createTestWalletWithMocks(t)

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	w.wg.Add(1)

	go w.mainLoop()

	pass := []byte("pass")
	req := UnlockRequest{Passphrase: pass, Timeout: -1}
	deps.addrStore.On("Unlock", mock.Anything, pass).Return(nil).Once()

	// Act: Perform Unlock with negative timeout (no auto-lock).
	err := w.Unlock(t.Context(), req)

	// Assert: Verify success.
	require.NoError(t, err)

	// Clean up.
	w.cancel()
	w.wg.Wait()
}

// TestControllerUnlock_DBUnlockFail verifies Unlock failure when
// DBUnlock fails.
func TestControllerUnlock_DBUnlockFail(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a wallet and mock an unlock failure.
	w, deps := createTestWalletWithMocks(t)

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	w.wg.Add(1)

	go w.mainLoop()

	pass := []byte("pass")
	deps.addrStore.On("Unlock", mock.Anything, pass).Return(
		errDBMock).Once()

	// Act: Attempt Unlock.
	err := w.Unlock(t.Context(), UnlockRequest{Passphrase: pass})

	// Assert: Verify failure.
	require.ErrorIs(t, err, errDBMock)

	// Clean up.
	w.cancel()
	w.wg.Wait()
}

// TestHandleLockReq_LockError verifies error handling when Lock fails.
func TestHandleLockReq_LockError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where internal lock fails.
	w, deps := createTestWalletWithMocks(t)

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	req := lockReq{resp: make(chan error, 1)}

	deps.addrStore.On("Lock").Return(errLockMock).Once()

	// Act: Handle lock request.
	w.handleLockReq(req)
	err := <-req.resp

	// Assert: Verify error.
	require.ErrorContains(t, err, "lock fail")
}

// TestSubmitRescanRequest_HeightOverflow verifies large start height rejection.
func TestSubmitRescanRequest_HeightOverflow(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a wallet and attempt a rescan with an invalid height.
	w, deps := createTestWalletWithMocks(t)

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	deps.syncer.On("syncState").Return(syncStateSynced).Maybe()

	height := uint32(math.MaxInt32 + 1)

	// Act: Attempt to submit rescan request.
	err := w.submitRescanRequest(t.Context(), scanTypeTargeted,
		height, nil)

	// Assert: Verify error.
	require.ErrorIs(t, err, ErrStartHeightTooLarge)
}

// TestChangePassphrase_StateError verifies early failure when state forbids
// change.
func TestChangePassphrase_StateError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a stopped wallet.
	w, _ := createTestWalletWithMocks(t)

	// Act: Attempt change.
	err := w.ChangePassphrase(t.Context(),
		ChangePassphraseRequest{})

	// Assert: Verify forbidden error.
	require.ErrorIs(t, err, ErrStateForbidden)
}

// TestControllerStart_AlreadyStarted verifies Start fails if already started.
func TestControllerStart_AlreadyStarted(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a started wallet.
	w, _ := createTestWalletWithMocks(t)

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	// Act: Attempt to start again.
	err := w.Start(t.Context())

	// Assert: Verify error.
	require.ErrorIs(t, err, ErrWalletAlreadyStarted)
}

// TestControllerUnlock_StateError verifies Unlock fails if not started.
func TestControllerUnlock_StateError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a stopped wallet.
	w, _ := createTestWalletWithMocks(t)

	// Act: Attempt Unlock.
	err := w.Unlock(t.Context(), UnlockRequest{})

	// Assert: Verify error.
	require.ErrorIs(t, err, ErrStateForbidden)
}

// TestControllerLock_StateError verifies Lock fails if not started.
func TestControllerLock_StateError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup a stopped wallet.
	w, _ := createTestWalletWithMocks(t)

	// Act: Attempt Lock.
	err := w.Lock(t.Context())

	// Assert: Verify error.
	require.ErrorIs(t, err, ErrStateForbidden)
}
