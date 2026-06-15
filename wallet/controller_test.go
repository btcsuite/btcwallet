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
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestPerformRuntimeSetupRoutesStoreStartup verifies that startup setup uses
// the runtime store paths for account loading and lease cleanup.
func TestPerformRuntimeSetupRoutesStoreStartup(t *testing.T) {
	t.Parallel()

	w, deps := createTestWalletWithMocks(t)
	w.id = 51
	birthdayBlock := &db.Block{
		Hash:      chainhash.Hash{51},
		Height:    100,
		Timestamp: time.Unix(1710003700, 0),
	}

	deps.store.On("GetWallet", mock.Anything, "").Return(&db.WalletInfo{
		Name:          "",
		BirthdayBlock: birthdayBlock,
	}, nil).Once()
	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: w.id,
	}).Return([]db.AccountInfo{{AccountNumber: testUint32Ptr(0)}}, nil).Once()
	deps.store.On("DeleteExpiredLeases", mock.Anything, w.id).Return(nil).
		Once()

	err := w.performRuntimeSetup(t.Context())
	require.NoError(t, err)
}

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

	// Setup the expected call to the key vault's Unlock method.
	deps.vault.On(
		"Unlock", mock.Anything, pass, mock.Anything,
	).Return(nil).Once()

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

	t.Run("ErrStateForbidden", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create a test wallet. By default, it is in the 'Stopped'
		// state.
		w, _ := createTestWalletWithMocks(t)

		pass := []byte("password")
		req := newUnlockReq(UnlockRequest{Passphrase: pass})

		// Act: Attempt to unlock the wallet while it is stopped.
		w.handleUnlockReq(req)

		// Assert: Verify that the request fails with ErrStateForbidden.
		err := <-req.resp
		require.ErrorIs(t, err, ErrStateForbidden)
	})

	t.Run("DBUnlock_Failure", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create a test wallet and transition to 'Started'.
		w, deps := createTestWalletWithMocks(t)
		require.NoError(t, w.state.toStarting())
		require.NoError(t, w.state.toStarted())

		pass := []byte("password")
		req := newUnlockReq(UnlockRequest{Passphrase: pass})
		deps.vault.On(
			"Unlock", mock.Anything, pass, mock.Anything,
		).Return(
			errDBMock,
		).Once()

		// Act: Attempt to unlock the wallet.
		w.handleUnlockReq(req)

		// Assert: Verify that the database error is propagated.
		err := <-req.resp
		require.ErrorContains(t, err, "db error")
	})
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

	// Setup the expected call to the key vault's Lock method.
	deps.vault.On("Lock").Return().Once()

	// Act: Dispatch the lock request to the handler.
	w.handleLockReq(req)

	// Assert: Verify that the response indicates success and the wallet
	// state is no longer 'Unlocked'.
	resp := <-req.resp
	require.NoError(t, resp)
	require.False(t, w.state.isUnlocked())
}

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

	// DBPutPassphrase drives the legacy address manager for the private
	// rotation, then the controller refreshes the vault's runtime state.
	deps.addrStore.On(
		"ChangePassphrase", mock.Anything, []byte("old"),
		[]byte("new"), true, mock.Anything,
	).Return(nil).Once()
	deps.vault.On(
		"RefreshPrivatePassphrase", []byte("new"),
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
	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{BirthdayBlock: &db.Block{Height: 100}}, nil,
	).Once()

	// 2. Mock ListAccounts: Expect a call to load active account
	//    managers.
	deps.store.On("ListAccounts", mock.Anything,
		mock.AnythingOfType("db.ListAccountsQuery")).
		Return([]db.AccountInfo(nil), nil).Once()

	// 3. Mock deleteExpiredLeases: Expect a call to cleanup expired
	//    leases through the store.
	deps.store.On("DeleteExpiredLeases", mock.Anything,
		mock.Anything).Return(nil).Once()

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
	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{
			BirthdayBlock: &db.Block{
				Height: 123,
				Hash:   chainhash.Hash{0x01},
			},
		}, nil).Once()

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

	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{Birthday: time.Now()}, nil).Once()
	deps.chain.On("GetBestBlock").Return(nil, int32(0), errChainMock).Once()

	// Act: Attempt to verify birthday.
	err := w.verifyBirthday(t.Context())

	// Assert: Verify failure.
	require.ErrorContains(t, err, "chain error")
}

// TestControllerVerifyBirthday_PutFail verifies verifyBirthday failure
// when UpdateWallet fails.
func TestControllerVerifyBirthday_PutFail(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where block location succeeds but
	// persisting the birthday block fails.
	w, deps := createTestWalletWithMocks(t)

	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{Birthday: time.Now()}, nil).Once()
	deps.chain.On("GetBestBlock").Return(
		&chainhash.Hash{}, int32(100), nil).Once()
	deps.chain.On("GetBlockHash", mock.Anything).Return(
		&chainhash.Hash{}, nil).Maybe()
	deps.chain.On("GetBlockHeader", mock.Anything).Return(
		&wire.BlockHeader{}, nil).Maybe()
	deps.store.On("UpdateWallet", mock.Anything, mock.Anything).Return(
		errPutMock).Once()

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
	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil).Once()
	deps.store.On("ListAccounts", mock.Anything,
		mock.AnythingOfType("db.ListAccountsQuery")).
		Return([]db.AccountInfo(nil), nil).Once()
	deps.store.On("DeleteExpiredLeases", mock.Anything,
		mock.Anything).Return(nil).Once()

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

// TestControllerStartAfterStop verifies that restarting the same wallet
// pointer after Stop fails cleanly. Stop closes the instance's runtime,
// legacy, and cache stores, so a second Start must return ErrWalletStopped
// instead of running setup against closed stores. The mock expectations for
// the startup sequence are registered Once(); their satisfaction after the
// first Start (and the absence of any second round of calls) confirms the
// second Start never touched the stores.
func TestControllerStartAfterStop(t *testing.T) {
	t.Parallel()

	// Arrange: create and start a test wallet whose syncer blocks until
	// the lifetime context is cancelled, mirroring a real run loop.
	w, deps := createTestWalletWithMocks(t)

	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil).Once()
	deps.store.On("ListAccounts", mock.Anything,
		mock.AnythingOfType("db.ListAccountsQuery")).
		Return([]db.AccountInfo(nil), nil).Once()
	deps.store.On("DeleteExpiredLeases", mock.Anything,
		mock.Anything).Return(nil).Once()
	deps.syncer.On("run", mock.Anything).Run(func(args mock.Arguments) {
		ctx, ok := args.Get(0).(context.Context)
		if !ok {
			return
		}
		<-ctx.Done()
	}).Return(nil).Once()

	require.NoError(t, w.Start(t.Context()))
	require.True(t, w.state.isStarted())

	// Stop the wallet, which closes its stores and marks it terminal.
	require.NoError(t, w.Stop(t.Context()))
	require.False(t, w.state.isStarted())

	// Act: attempt to restart the same pointer.
	err := w.Start(t.Context())

	// Assert: the restart is refused with a typed error and the wallet
	// stays stopped. No panic, and no second round of store calls (the
	// Once() expectations above remain satisfied).
	require.ErrorIs(t, err, ErrWalletStopped)
	require.False(t, w.state.isStarted())
	require.False(t, w.state.isRunning())
}

// TestControllerLock verifies the Lock method. It ensures that the wallet
// can only be locked when it is started and currently unlocked.
func TestControllerLock(t *testing.T) {
	t.Parallel()

	// Arrange: Create and start a test wallet.
	w, deps := createTestWalletWithMocks(t)

	// Setup mocks for startup.
	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil).Once()
	deps.store.On("ListAccounts", mock.Anything,
		mock.AnythingOfType("db.ListAccountsQuery")).
		Return([]db.AccountInfo(nil), nil).Once()
	deps.store.On("DeleteExpiredLeases", mock.Anything,
		mock.Anything).Return(nil).Once()
	deps.syncer.On("run", mock.Anything).Return(nil).Once()

	require.NoError(t, w.Start(t.Context()))

	// Transition the wallet to the 'Unlocked' state for testing.
	w.state.toUnlocked()
	require.True(t, w.state.isUnlocked())

	// Expect a call to the key vault's Lock method.
	deps.vault.On("Lock").Return().Once()

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
	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil).Once()
	deps.store.On("ListAccounts", mock.Anything,
		mock.AnythingOfType("db.ListAccountsQuery")).
		Return([]db.AccountInfo(nil), nil).Once()
	deps.store.On("DeleteExpiredLeases", mock.Anything,
		mock.Anything).Return(nil).Once()
	deps.syncer.On("run", mock.Anything).Return(nil).Once()

	require.NoError(t, w.Start(t.Context()))
	require.False(t, w.state.isUnlocked())

	pass := []byte("password")

	// Expect a call to the key vault's Unlock method.
	deps.vault.On(
		"Unlock", mock.Anything, pass, mock.Anything,
	).Return(nil).Once()

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
	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil).Once()
	deps.store.On("ListAccounts", mock.Anything,
		mock.AnythingOfType("db.ListAccountsQuery")).
		Return([]db.AccountInfo(nil), nil).Once()
	deps.store.On("DeleteExpiredLeases", mock.Anything,
		mock.Anything).Return(nil).Once()
	deps.syncer.On("run", mock.Anything).Return(nil).Once()

	require.NoError(t, w.Start(t.Context()))

	req := ChangePassphraseRequest{
		ChangePrivate: true,
		PrivateOld:    []byte("old"),
		PrivateNew:    []byte("new"),
	}

	// DBPutPassphrase drives the legacy address manager for the private
	// rotation, then the controller refreshes the vault's runtime state.
	deps.addrStore.On(
		"ChangePassphrase", mock.Anything, []byte("old"),
		[]byte("new"), true, mock.Anything,
	).Return(nil).Once()
	deps.vault.On(
		"RefreshPrivatePassphrase", []byte("new"),
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

	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{BirthdayBlock: &db.Block{Height: 100}}, nil,
	).Once()

	deps.store.On("ListAccounts", mock.Anything,
		mock.AnythingOfType("db.ListAccountsQuery")).
		Return([]db.AccountInfo{
			{AccountNumber: testUint32Ptr(0)},
			{AccountNumber: testUint32Ptr(1)},
		}, nil).Once()

	deps.store.On("DeleteExpiredLeases", mock.Anything,
		mock.Anything).Return(nil).Once()
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
	deps.vault.On("Lock").Run(func(args mock.Arguments) {
		close(lockCalled)
	}).Return().Once()

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
	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{
			BirthdayBlock: &db.Block{Height: 100},
		}, nil).Once()
	deps.store.On("ListAccounts", mock.Anything,
		mock.AnythingOfType("db.ListAccountsQuery")).
		Return([]db.AccountInfo(nil), nil).Once()
	deps.store.On("DeleteExpiredLeases", mock.Anything,
		mock.Anything).Return(nil).Once()
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

	// Arrange: Setup mock expectations where GetWallet fails.
	w, deps := createTestWalletWithMocks(t)

	deps.store.On(
		"GetWallet", mock.Anything, mock.Anything,
	).Return(nil, errDBMock).Once()

	// Act: Attempt to start the wallet.
	err := w.Start(t.Context())

	// Assert: Verify failure.
	require.ErrorIs(t, err, errDBMock)
	require.False(t, w.state.isStarted())
}

// TestControllerStart_ListAccountsFail verifies Start fails when
// ListAccounts fails.
func TestControllerStart_ListAccountsFail(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where account lookup fails during
	// startup.
	w, deps := createTestWalletWithMocks(t)

	deps.store.On(
		"GetWallet", mock.Anything, mock.Anything,
	).Return(&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil).Once()

	deps.store.On("ListAccounts", mock.Anything,
		mock.AnythingOfType("db.ListAccountsQuery")).
		Return([]db.AccountInfo(nil), errDBMock).Once()

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

	birthday := time.Now()
	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{Birthday: birthday}, nil).Once()

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

	deps.store.On(
		"UpdateWallet", mock.Anything,
		mock.MatchedBy(func(p db.UpdateWalletParams) bool {
			return p.BirthdayBlock != nil &&
				p.BirthdayBlock.Height == 50
		}),
	).Return(nil).Once()

	deps.store.On("ListAccounts", mock.Anything,
		mock.AnythingOfType("db.ListAccountsQuery")).
		Return([]db.AccountInfo(nil), nil).Once()
	deps.store.On("DeleteExpiredLeases", mock.Anything,
		mock.Anything).Return(nil).Once()
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
	deps.vault.On(
		"Unlock", mock.Anything, pass, mock.Anything,
	).Return(nil).Once()
	// Auto-lock might trigger if the test runs slowly, but it's not
	// guaranteed.
	deps.vault.On("Lock").Return().Maybe()

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

	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil).Once()

	deps.store.On("ListAccounts", mock.Anything,
		mock.AnythingOfType("db.ListAccountsQuery")).Return(
		[]db.AccountInfo(nil), nil).Once()

	deps.store.On("DeleteExpiredLeases", mock.Anything, mock.Anything).
		Return(errDBMock).Once()

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
	deps.vault.On(
		"Unlock", mock.Anything, pass, mock.Anything,
	).Return(nil).Once()

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
	deps.vault.On("Unlock", mock.Anything, pass, mock.Anything).Return(
		errDBMock).Once()

	// Act: Attempt Unlock.
	err := w.Unlock(t.Context(), UnlockRequest{Passphrase: pass})

	// Assert: Verify failure.
	require.ErrorIs(t, err, errDBMock)

	// Clean up.
	w.cancel()
	w.wg.Wait()
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

// TestWaitForBackoff_StableRun verifies that the backoff is reset to the
// initial value if the syncer has been running for a stable amount of time.
func TestWaitForBackoff_StableRun(t *testing.T) {
	t.Parallel()

	// Arrange: Create a wallet with a canceled context to avoid waiting.
	w := &Wallet{
		lifetimeCtx: context.Background(),
	}

	// Mock a start time that exceeds the stable run time.
	startTime := time.Now().Add(-stableRunTime - time.Minute)
	currentBackoff := maxBackoff

	// Mock the timer function to fire immediately.
	timerFn := func(d time.Duration) <-chan time.Time {
		// Verify that the backoff was reset to initial before waiting.
		require.Equal(t, initialBackoff, d)

		c := make(chan time.Time, 1)
		c <- time.Now()

		return c
	}

	// Act: Wait for backoff.
	nextBackoff, ok := w.waitForBackoff(startTime, currentBackoff, timerFn)

	// Assert: Verify that the operation continued and backoff doubled.
	require.True(t, ok)
	require.Equal(t, initialBackoff*2, nextBackoff)
}

// TestWaitForBackoff_UnstableRun verifies that the backoff duration doubles
// when the syncer fails quickly (unstable run).
func TestWaitForBackoff_UnstableRun(t *testing.T) {
	t.Parallel()

	// Arrange: Create a wallet.
	w := &Wallet{
		lifetimeCtx: context.Background(),
	}

	// Mock a start time that is recent (unstable).
	startTime := time.Now()
	currentBackoff := time.Second

	// Mock the timer function.
	timerFn := func(d time.Duration) <-chan time.Time {
		// Verify that the backoff was NOT reset.
		require.Equal(t, currentBackoff, d)

		c := make(chan time.Time, 1)
		c <- time.Now()

		return c
	}

	// Act: Wait for backoff.
	nextBackoff, ok := w.waitForBackoff(startTime, currentBackoff, timerFn)

	// Assert: Verify that the operation continued and backoff doubled.
	require.True(t, ok)
	require.Equal(t, currentBackoff*2, nextBackoff)
}

// TestWaitForBackoff_MaxBackoffCap verifies that the backoff duration is
// capped at maxBackoff.
func TestWaitForBackoff_MaxBackoffCap(t *testing.T) {
	t.Parallel()

	// Arrange: Create a wallet.
	w := &Wallet{
		lifetimeCtx: context.Background(),
	}

	startTime := time.Now()
	// Current backoff is already high enough that doubling it would exceed
	// maxBackoff.
	currentBackoff := maxBackoff

	timerFn := func(d time.Duration) <-chan time.Time {
		require.Equal(t, currentBackoff, d)

		c := make(chan time.Time, 1)
		c <- time.Now()

		return c
	}

	// Act: Wait for backoff.
	nextBackoff, ok := w.waitForBackoff(startTime, currentBackoff, timerFn)

	// Assert: Verify that the backoff is capped.
	require.True(t, ok)
	require.Equal(t, maxBackoff, nextBackoff)
}

// TestWaitForBackoff_Shutdown verifies that waitForBackoff returns early if
// the wallet is shutting down.
func TestWaitForBackoff_Shutdown(t *testing.T) {
	t.Parallel()

	// Arrange: Create a wallet with a canceled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	w := &Wallet{
		lifetimeCtx: ctx,
	}

	startTime := time.Now()
	currentBackoff := time.Second

	// Mock a timer that never fires, ensuring we select on the context.
	timerFn := func(d time.Duration) <-chan time.Time {
		return make(chan time.Time)
	}

	// Act: Wait for backoff.
	nextBackoff, ok := w.waitForBackoff(startTime, currentBackoff, timerFn)

	// Assert: Verify that the operation was aborted.
	require.False(t, ok)
	require.Equal(t, time.Duration(0), nextBackoff)
}
