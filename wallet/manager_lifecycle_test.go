package wallet

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newLifecycleTestManager registers a mock-backed Wallet as the exact current
// runtime for a lightweight Manager.
func newLifecycleTestManager(t *testing.T) (*Manager, *Wallet,
	*mockWalletDeps) {

	t.Helper()

	w, deps := createTestWalletWithMocks(t)
	w.cfg.Name = t.Name()
	w.cfg.RecoveryWindow = 1
	m := testManagerForWallet(w)

	return m, w, deps
}

// lifecycleSetupBarrier holds startup cleanup after cancellation so tests can
// prove that lifecycle results do not publish before the setup helper joins.
type lifecycleSetupBarrier struct {
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
}

// expectBlockedLifecycleSetup programs setup to acknowledge entry and
// cancellation, then remain blocked until the test releases cleanup.
func expectBlockedLifecycleSetup(deps *mockWalletDeps) *lifecycleSetupBarrier {
	barrier := &lifecycleSetupBarrier{
		entered:  make(chan struct{}),
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
	}

	deps.store.On("GetWallet", mock.Anything, mock.Anything).Return(
		&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil,
	).Once()
	deps.store.On("ListAccounts", mock.Anything,
		mock.AnythingOfType("db.ListAccountsQuery")).Run(
		func(args mock.Arguments) {
			ctx, ok := args.Get(0).(context.Context)
			if !ok {
				return
			}

			close(barrier.entered)
			<-ctx.Done()
			close(barrier.canceled)
			<-barrier.release
		},
	).Return([]db.AccountInfo(nil), context.Canceled).Once()

	return barrier
}

// TestManagerWalletLifecycle verifies Manager lifecycle admission, terminal
// state results, exact pointer identity, and failed startup teardown.
func TestManagerWalletLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("preaccept cancellation", func(t *testing.T) {
		t.Parallel()

		// Arrange: Prepare one Created runtime and a Start context canceled
		// before Manager can accept the lifecycle request.
		m, w, _ := newLifecycleTestManager(t)
		entry := m.wallets[w.cfg.Name]
		canceledCtx, cancel := context.WithCancel(t.Context())
		cancel()

		// Act: Attempt Start before acceptance with the canceled caller.
		err := m.StartWallet(canceledCtx, w)

		// Assert: Cancellation leaves the runtime Created and uncoordinated.
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, lifecycleCreated,
			lifecycle(w.state.lifecycle.Load()))
		require.Nil(t, entry.coordinator)
	})

	t.Run("stop created", func(t *testing.T) {
		t.Parallel()

		// Arrange: Prepare a runtime whose coordinator has never started.
		m, w, deps := newLifecycleTestManager(t)
		deps.vault.On("Lock").Return().Once()

		// Act: Stop the Created runtime and attempt to start it afterward.
		stopErr := m.StopWallet(t.Context(), w)
		startErr := m.StartWallet(t.Context(), w)

		// Assert: Stop completes terminal teardown without publishing workers.
		require.NoError(t, stopErr)
		require.Equal(t, lifecycleStopped,
			lifecycle(w.state.lifecycle.Load()))
		require.ErrorIs(t, startErr, ErrWalletStopped)
	})

	t.Run("foreign pointer", func(t *testing.T) {
		t.Parallel()

		// Arrange: Give a foreign runtime the current wallet's name but not
		// its exact Manager-published identity.
		m, w, _ := newLifecycleTestManager(t)
		foreign, _ := createTestWalletWithMocks(t)
		foreign.cfg.Name = w.cfg.Name

		// Act: Submit both lifecycle operations with the foreign pointer.
		startErr := m.StartWallet(t.Context(), foreign)
		stopErr := m.StopWallet(t.Context(), foreign)

		// Assert: Exact identity validation rejects both without admission.
		require.ErrorIs(t, startErr, ErrWalletNotManaged)
		require.ErrorIs(t, stopErr, ErrWalletNotManaged)
		require.Equal(t, lifecycleCreated,
			lifecycle(w.state.lifecycle.Load()))
		require.Nil(t, m.wallets[w.cfg.Name].coordinator)
	})

	t.Run("startup failure terminal", func(t *testing.T) {
		t.Parallel()

		// Arrange: Fail setup before any runtime worker can publish.
		m, w, deps := newLifecycleTestManager(t)
		setupErr := errors.New("setup failed")
		deps.store.On("GetWallet", mock.Anything, mock.Anything).
			Return(nil, setupErr).Once()
		deps.vault.On("Lock").Return().Once()

		// Act: Start the runtime, then join its recorded terminal teardown.
		startErr := m.StartWallet(t.Context(), w)
		stopErr := m.StopWallet(t.Context(), w)
		terminalStartErr := m.StartWallet(t.Context(), w)

		// Assert: The setup error wins Start and leaves the pointer terminal.
		require.ErrorIs(t, startErr, setupErr)
		require.NoError(t, stopErr)
		require.Equal(t, lifecycleStopped,
			lifecycle(w.state.lifecycle.Load()))
		require.ErrorIs(t, terminalStartErr, ErrWalletStopped)
	})
}
