package wallet

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestStateSecureByDefault verifies that the zero-value of walletState
// represents a safe, locked condition that has not started yet.
func TestStateSecureByDefault(t *testing.T) {
	t.Parallel()

	// Arrange: Create a new state in Initialized (default) mode.
	syncer := &mockChainSyncer{}
	s := newWalletState(syncer)

	// Act & Assert: Verify initial state.
	require.False(t, s.isStarted())
	require.False(t, s.isRunning())

	// Act: Transition to Starting.
	err := s.toStarting()
	require.NoError(t, err)

	// Act: Transition to Started.
	err = s.toStarted()
	require.NoError(t, err)
	require.True(t, s.isStarted())
	require.True(t, s.isRunning())

	// Act: Transition to Stopping.
	err = s.toStopping()
	require.NoError(t, err)
	require.False(t, s.isStarted())

	// Stopping is NOT running.
	require.False(t, s.isRunning())

	// Act: Transition to Stopped.
	err = s.toStopped()
	require.NoError(t, err)
	require.False(t, s.isRunning())

	// Assert: Invalid transition (Stop when already Stopped).
	err = s.toStopping()
	require.ErrorIs(t, err, ErrStateForbidden)
}

// TestStateAuthentication verifies locking and unlocking logic.
func TestStateAuthentication(t *testing.T) {
	t.Parallel()

	syncer := &mockChainSyncer{}
	s := newWalletState(syncer)

	// Arrange: Start the wallet (must be started to be useful).
	require.NoError(t, s.toStarting())
	err := s.toStarted()
	require.NoError(t, err)

	// Assert: Default is Locked.
	require.False(t, s.isUnlocked())

	// Act: Unlock.
	s.toUnlocked()
	require.NoError(t, err)
	require.True(t, s.isUnlocked())

	// Act: Lock.
	s.toLocked()
	require.NoError(t, err)
	require.False(t, s.isUnlocked())

	// Act: Verify canSign checks.
	// Case 1: Locked -> Error.
	err = s.canSign()
	require.ErrorIs(t, err, ErrStateForbidden)
	require.ErrorContains(t, err, "wallet locked")

	// Case 2: Unlocked -> Success.
	s.toUnlocked()
	err = s.canSign()
	require.NoError(t, err)

	// Case 3: Stopped -> Error (even if unlocked, though stopped forces
	// lock).
	require.NoError(t, s.toStopping())
	err = s.toStopped()
	require.NoError(t, err)
	// Note: toStopped forces lock, so we must check that logic too.
	require.False(t, s.isUnlocked())

	// Manually unlock while stopped to test canSign check.
	s.toUnlocked()
	err = s.canSign()
	require.ErrorIs(t, err, ErrWalletStopped)
	require.ErrorContains(t, err, "wallet stopped")
}

// TestStateCanSignLifecycle verifies signing preserves the lifecycle error
// that distinguishes a Wallet which has not started from one that is terminal.
func TestStateCanSignLifecycle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		lifecycle lifecycle
		expected  error
	}{
		{
			name:      "rejects initialized",
			lifecycle: lifecycleInitialized,
			expected:  ErrStateForbidden,
		},
		{
			name:      "rejects stopping",
			lifecycle: lifecycleStopping,
			expected:  ErrWalletStopped,
		},
		{
			name:      "rejects stopped",
			lifecycle: lifecycleStopped,
			expected:  ErrWalletStopped,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Force the lifecycle under test and unlock the
			// state so only lifecycle admission can reject signing.
			state := newWalletState(nil)
			state.lifecycle.Store(uint32(test.lifecycle))
			state.toUnlocked()

			// Act: Ask the state boundary whether signing is allowed.
			err := state.canSign()

			// Assert: The guard preserves the sentinel assigned to the
			// selected non-running lifecycle.
			require.ErrorIs(t, err, test.expected)
		})
	}
}

// TestStateSynchronization verifies that the wallet state correctly reflects
// the syncer's status.
func TestStateSynchronization(t *testing.T) {
	t.Parallel()

	syncer := &mockChainSyncer{}
	s := newWalletState(syncer)
	require.NoError(t, s.toStarting())
	require.NoError(t, s.toStarted())

	// Arrange: Mock syncer to return Synced.
	syncer.On("syncState").Return(syncStateSynced)

	// Act & Assert.
	require.Equal(t, syncStateSynced, s.syncState())
	require.True(t, s.isSynced())
	require.False(t, s.isRecoveryMode())

	// Arrange: Mock syncer to return Syncing.
	// Note: We need to reset expectations or use a new mock/state if rigid.
	// testify/mock allows updating expectations usually.
	syncer.ExpectedCalls = nil
	syncer.On("syncState").Return(syncStateSyncing)

	// Act & Assert.
	require.Equal(t, syncStateSyncing, s.syncState())
	require.False(t, s.isSynced())
	require.True(t, s.isRecoveryMode())
}

// TestStateNilSyncer verifies behavior when syncer is nil (defensive check).
func TestStateNilSyncer(t *testing.T) {
	t.Parallel()

	s := newWalletState(nil)

	// Act & Assert: Should default to BackendSyncing safely.
	require.Equal(t, syncStateBackendSyncing, s.syncState())
}

// TestStateThreadSafety verifies that state transitions are safe under
// concurrent access.
func TestStateThreadSafety(t *testing.T) {
	t.Parallel()

	syncer := &mockChainSyncer{}
	s := newWalletState(syncer)

	// Arrange: Hammer the start/stop transitions.
	var wg sync.WaitGroup

	start := make(chan struct{})

	for range 100 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			// NOTE: We ignore errors here because we are
			// purposefully hammering the state machine from
			// multiple goroutines. Many of these transitions will
			// fail (e.g., trying to start an already starting
			// wallet), which is expected behavior. We are
			// primarily verifying that no data races or panics
			// occur.
			//
			// Try to start.
			_ = s.toStarting()

			// Try to stop.
			_ = s.toStopping()
		}()
	}

	close(start)
	wg.Wait()

	// Assert: State should be valid (either stopped, starting, or
	// stopping).
	// Just ensure no panics occurred.
}

// TestValidateSynced verifies the validation logic for operations requiring
// synchronization.
func TestValidateSynced(t *testing.T) {
	t.Parallel()

	syncer := &mockChainSyncer{}
	s := newWalletState(syncer)

	// Case 1: Not started.
	err := s.validateSynced()
	require.ErrorIs(t, err, ErrStateForbidden)

	// Case 2: Started but not synced.
	require.NoError(t, s.toStarting())
	require.NoError(t, s.toStarted())
	syncer.On("syncState").Return(syncStateSyncing)

	err = s.validateSynced()
	require.ErrorIs(t, err, ErrStateForbidden)

	// Case 3: Started and synced.
	syncer.ExpectedCalls = nil
	syncer.On("syncState").Return(syncStateSynced)

	err = s.validateSynced()
	require.NoError(t, err)
}

// TestStateValidateSyncedLifecycle verifies synchronization checks preserve
// the lifecycle error before consulting the chain synchronization state.
func TestStateValidateSyncedLifecycle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		lifecycle lifecycle
		expected  error
	}{
		{
			name:      "rejects initialized",
			lifecycle: lifecycleInitialized,
			expected:  ErrStateForbidden,
		},
		{
			name:      "rejects stopping",
			lifecycle: lifecycleStopping,
			expected:  ErrWalletStopped,
		},
		{
			name:      "rejects stopped",
			lifecycle: lifecycleStopped,
			expected:  ErrWalletStopped,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Build a state with no syncer and force the
			// lifecycle under test. A syncer access would therefore
			// expose a failure to reject at the lifecycle boundary.
			state := newWalletState(nil)
			state.lifecycle.Store(uint32(test.lifecycle))

			// Act: Validate an operation that requires synchronization.
			err := state.validateSynced()

			// Assert: Lifecycle rejection returns the expected sentinel
			// without attempting to inspect synchronization state.
			require.ErrorIs(t, err, test.expected)
		})
	}
}

// TestStateLifecycleTransitions verifies valid and invalid lifecycle
// state transitions.
func TestStateLifecycleTransitions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		lifecycle lifecycle
		running   bool
	}{
		{
			name:      "initialized is not running",
			lifecycle: lifecycleInitialized,
			running:   false,
		},
		{
			name:      "started is running",
			lifecycle: lifecycleStarted,
			running:   true,
		},
		{
			name:      "stopped is not running",
			lifecycle: lifecycleStopped,
			running:   false,
		},
		{
			name:      "stopping is not running",
			lifecycle: lifecycleStopping,
			running:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Setup state.
			state := newWalletState(nil)
			state.lifecycle.Store(uint32(tc.lifecycle))

			// Act & Assert: Verify isRunning result.
			require.Equal(t, tc.running, state.isRunning())
		})
	}
}

// TestStateString verifies the summary string format.
func TestStateString(t *testing.T) {
	t.Parallel()

	// Arrange: Create a specific state.
	ms := &mockChainSyncer{}
	ms.On("syncState").Return(syncStateSyncing)

	state := newWalletState(ms)
	state.lifecycle.Store(uint32(lifecycleStarted))
	state.unlocked.Store(true)

	// Act: Get the summary string.
	got := state.String()

	// Assert: Verify exact format and values.
	// Note: String uses !unlocked for "locked" boolean value.
	expected := "status=started, sync=syncing, locked=false"
	require.Equal(t, expected, got)
}

// TestStateStartStop verifies the transition logic for start and stop.
func TestStateStartStop(t *testing.T) {
	t.Parallel()

	t.Run("start success", func(t *testing.T) {
		t.Parallel()

		state := newWalletState(nil)

		// Set initial random state to verify reset.
		state.unlocked.Store(true)

		err := state.toStarting()
		require.NoError(t, err)
		require.Equal(t, uint32(lifecycleStarting),
			state.lifecycle.Load())
		require.False(t, state.unlocked.Load())

		// Now mark as started.
		err = state.toStarted()
		require.NoError(t, err)
		require.Equal(t, uint32(lifecycleStarted),
			state.lifecycle.Load())
	})

	t.Run("start fail already started", func(t *testing.T) {
		t.Parallel()

		state := newWalletState(nil)
		state.lifecycle.Store(uint32(lifecycleStarted))

		err := state.toStarting()
		require.ErrorIs(t, err, ErrWalletAlreadyStarted)
	})

	t.Run("start fail terminally stopped", func(t *testing.T) {
		t.Parallel()

		// Arrange: Set the lifecycle to its terminal Stopped state to
		// model a Wallet whose only runtime has already ended.
		state := newWalletState(nil)
		state.lifecycle.Store(uint32(lifecycleStopped))

		// Act: Attempt to start the same state instance again.
		err := state.toStarting()

		// Assert: A terminal Wallet reports only the specific stopped
		// sentinel so callers can distinguish final shutdown from other
		// state-based rejections.
		require.ErrorIs(t, err, ErrWalletStopped)
		require.NotErrorIs(t, err, ErrStateForbidden)
	})

	t.Run("stop success", func(t *testing.T) {
		t.Parallel()

		state := newWalletState(nil)
		state.lifecycle.Store(uint32(lifecycleStarted))
		state.unlocked.Store(true)

		err := state.toStopping()
		require.NoError(t, err)

		require.Equal(t, uint32(lifecycleStopping),
			state.lifecycle.Load())
		require.False(t, state.unlocked.Load())
	})

	t.Run("stop fail not started", func(t *testing.T) {
		t.Parallel()

		state := newWalletState(nil)
		state.lifecycle.Store(uint32(lifecycleStopped))

		err := state.toStopping()
		require.ErrorIs(t, err, ErrStateForbidden)
	})

	t.Run("stop initialized", func(t *testing.T) {
		t.Parallel()

		// Arrange: Use a fresh state to represent Stop arriving before
		// the Wallet's first Start.
		state := newWalletState(nil)

		// Act: Transition directly from Initialized to terminal Stopped.
		err := state.toStopped()

		// Assert: The direct transition succeeds and prevents a later
		// Start on the retained state instance.
		require.NoError(t, err)
		require.Equal(t, uint32(lifecycleStopped),
			state.lifecycle.Load())
		require.ErrorIs(t, state.toStarting(), ErrWalletStopped)
	})
}

// TestStateValidateStarted verifies the validateStarted check.
func TestStateValidateStarted(t *testing.T) {
	t.Parallel()

	t.Run("success started", func(t *testing.T) {
		t.Parallel()

		state := newWalletState(nil)
		state.lifecycle.Store(uint32(lifecycleStarted))
		require.NoError(t, state.validateStarted())
	})

	t.Run("fail stopped", func(t *testing.T) {
		t.Parallel()

		// Arrange: Put the state in its terminal Stopped condition.
		state := newWalletState(nil)
		state.lifecycle.Store(uint32(lifecycleStopped))

		// Act: Validate an operation that requires a running Wallet.
		err := state.validateStarted()

		// Assert: The specific stopped sentinel distinguishes terminal
		// shutdown from a non-terminal state rejection.
		require.ErrorIs(t, err, ErrWalletStopped)
	})

	t.Run("fail initialized", func(t *testing.T) {
		t.Parallel()

		// Arrange: Leave a fresh state in Initialized to distinguish a
		// Wallet that has never run from one that has stopped.
		state := newWalletState(nil)

		// Act: Validate an operation before the first Start.
		err := state.validateStarted()

		// Assert: Pre-start access retains the original broad state
		// error and does not claim that the Wallet has stopped.
		require.ErrorIs(t, err, ErrStateForbidden)
	})
}

// TestStateAuthChecks verifies the semantic auth check methods.
func TestStateAuthChecks(t *testing.T) {
	t.Parallel()

	// Helper to set state
	setState := func(s *walletState, lc lifecycle) {
		s.lifecycle.Store(uint32(lc))
	}

	t.Run("started allowed", func(t *testing.T) {
		t.Parallel()

		state := newWalletState(nil)

		setState(&state, lifecycleStarted)
		require.NoError(t, state.canUnlock())
		require.NoError(t, state.canLock())
		require.NoError(t, state.canChangePassphrase())
	})

	t.Run("stopped forbidden", func(t *testing.T) {
		t.Parallel()

		// Arrange: Put the state in its terminal Stopped condition so
		// every authentication check reaches lifecycle validation first.
		state := newWalletState(nil)
		setState(&state, lifecycleStopped)

		// Act: Exercise each authentication transition after terminal
		// shutdown has made the Wallet permanently unavailable.
		unlockErr := state.canUnlock()
		lockErr := state.canLock()
		changeErr := state.canChangePassphrase()

		// Assert: All three operations report the specific terminal
		// sentinel without also matching the generic state rejection.
		require.ErrorIs(t, unlockErr, ErrWalletStopped)
		require.NotErrorIs(t, unlockErr, ErrStateForbidden)
		require.ErrorIs(t, lockErr, ErrWalletStopped)
		require.NotErrorIs(t, lockErr, ErrStateForbidden)
		require.ErrorIs(t, changeErr, ErrWalletStopped)
		require.NotErrorIs(t, changeErr, ErrStateForbidden)
	})
}

// TestStateIsRecoveryMode verifies the recovery mode check.
func TestStateIsRecoveryMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		sync       syncState
		isRecovery bool
	}{
		{"backend syncing", syncStateBackendSyncing, false},
		{"syncing", syncStateSyncing, true},
		{"synced", syncStateSynced, false},
		{"rescanning", syncStateRescanning, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ms := &mockChainSyncer{}
			ms.On("syncState").Return(tc.sync)

			state := newWalletState(ms)
			require.Equal(t, tc.isRecovery, state.isRecoveryMode())
		})
	}
}

// TestStateAuxiliaryMethods verifies helper methods like canUnlock, canLock,
// and canChangePassphrase.
func TestStateAuxiliaryMethods(t *testing.T) {
	t.Parallel()

	syncer := &mockChainSyncer{}
	s := newWalletState(syncer)

	// Case 1: Initialized -> All forbidden.
	require.ErrorIs(t, s.canUnlock(), ErrStateForbidden)
	require.ErrorIs(t, s.canLock(), ErrStateForbidden)
	require.ErrorIs(t, s.canChangePassphrase(), ErrStateForbidden)

	// Case 2: Started -> All allowed.
	require.NoError(t, s.toStarting())
	require.NoError(t, s.toStarted())
	require.NoError(t, s.canUnlock())
	require.NoError(t, s.canLock())
	require.NoError(t, s.canChangePassphrase())
}
