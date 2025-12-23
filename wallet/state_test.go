package wallet

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestStateSecureByDefault verifies that the zero-value of walletState
// represents a safe, locked condition.
func TestStateSecureByDefault(t *testing.T) {
	t.Parallel()

	// Arrange: Create a new state in Stopped (default) mode.
	syncer := &mockChainSyncer{}
	s := newWalletState(syncer)

	// Act & Assert: Verify initial state.
	require.False(t, s.isStarted())
	require.False(t, s.isRunning())

	// Act: Transition to Starting.
	err := s.toStarting()
	require.NoError(t, err)

	// Act: Transition to Started.
	s.toStarted()
	require.True(t, s.isStarted())
	require.True(t, s.isRunning())

	// Act: Transition to Stopping.
	err = s.toStopping()
	require.NoError(t, err)
	require.False(t, s.isStarted())

	// Stopping is NOT running.
	require.False(t, s.isRunning())

	// Act: Transition to Stopped.
	s.toStopped()
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
	s.toStarted()

	// Assert: Default is Locked.
	require.False(t, s.isUnlocked())

	// Act: Unlock.
	s.toUnlocked()
	require.True(t, s.isUnlocked())

	// Act: Lock.
	s.toLocked()
	require.False(t, s.isUnlocked())

	// Act: Verify canSign checks.
	// Case 1: Locked -> Error.
	err := s.canSign()
	require.ErrorIs(t, err, ErrStateForbidden)
	require.ErrorContains(t, err, "wallet locked")

	// Case 2: Unlocked -> Success.
	s.toUnlocked()
	err = s.canSign()
	require.NoError(t, err)

	// Case 3: Stopped -> Error (even if unlocked, though stopped forces
	// lock).
	s.toStopped()
	// Note: toStopped forces lock, so we must check that logic too.
	require.False(t, s.isUnlocked())

	// Manually unlock while stopped to test canSign check.
	s.toUnlocked()
	err = s.canSign()
	require.ErrorIs(t, err, ErrStateForbidden)
	require.ErrorContains(t, err, "wallet not started")
}

// TestStateSynchronization verifies that the wallet state correctly reflects
// the syncer's status.
func TestStateSynchronization(t *testing.T) {
	t.Parallel()

	syncer := &mockChainSyncer{}
	s := newWalletState(syncer)
	s.toStarted()

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
	s.toStarted()
	syncer.On("syncState").Return(syncStateSyncing)

	err = s.validateSynced()
	require.ErrorIs(t, err, ErrStateForbidden)

	// Case 3: Started and synced.
	syncer.ExpectedCalls = nil
	syncer.On("syncState").Return(syncStateSynced)

	err = s.validateSynced()
	require.NoError(t, err)
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
		state.toStarted()
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

		state := newWalletState(nil)
		state.lifecycle.Store(uint32(lifecycleStopped))
		require.ErrorIs(t, state.validateStarted(), ErrStateForbidden)
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

		state := newWalletState(nil)

		setState(&state, lifecycleStopped)
		require.ErrorIs(t, state.canUnlock(), ErrStateForbidden)
		require.ErrorIs(t, state.canLock(), ErrStateForbidden)
		require.ErrorIs(t, state.canChangePassphrase(),
			ErrStateForbidden)
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

	// Case 1: Stopped -> All forbidden.
	require.ErrorIs(t, s.canUnlock(), ErrStateForbidden)
	require.ErrorIs(t, s.canLock(), ErrStateForbidden)
	require.ErrorIs(t, s.canChangePassphrase(), ErrStateForbidden)

	// Case 2: Started -> All allowed.
	s.toStarted()
	require.NoError(t, s.canUnlock())
	require.NoError(t, s.canLock())
	require.NoError(t, s.canChangePassphrase())
}
