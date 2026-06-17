package keyvault

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// trackedMutex wraps a mutex and reports whenever are attempts to acquire it.
type trackedMutex struct {
	// Mutex is the lock shared by the test and the autoLockTimer callback.
	sync.Mutex

	// attempted receives a signal when Lock is called.
	attempted chan struct{}
}

// Lock reports the lock attempt before blocking on the underlying mutex.
func (l *trackedMutex) Lock() {
	select {
	case l.attempted <- struct{}{}:
	default:
	}

	l.Mutex.Lock()
}

// Unlock releases the underlying mutex.
func (l *trackedMutex) Unlock() {
	l.Mutex.Unlock()
}

// TestAutoLockerStaleGenerationDoesNotExpireReplacement verifies that a stale
// timer callback cannot clear state after a newer generation is scheduled.
func TestAutoLockerStaleGenerationDoesNotExpireReplacement(t *testing.T) {
	t.Parallel()

	// timer is the autoLocker under test.
	var timer autoLockTimer

	// mtx lets the test hold the mutex while observing that the stale timer
	// callback has reached the lock path.
	mtx := &trackedMutex{
		attempted: make(chan struct{}, 2),
	}

	// staleRan is closed if the stale timer incorrectly runs its lock callback.
	staleRan := make(chan struct{})

	// replacementRan is closed when the replacement timer correctly runs its
	// lock callback.
	replacementRan := make(chan struct{})

	// Hold the mutex so the first timer callback can start, report its lock
	// attempt, and then block before checking the generation.
	mtx.Lock()

	// Schedule a timer that should become stale before it can acquire the
	// mutex.
	timer.schedule(
		time.Nanosecond, mtx, func() {
			close(staleRan)
		},
	)

	// Wait until the stale callback has started and is blocked on the mutex.
	require.Eventually(
		t, func() bool {
			select {
			case <-mtx.attempted:
				return true
			default:
				return false
			}
		}, time.Second, time.Millisecond,
		"timer callback did not attempt to acquire the lock",
	)

	// Cancel the first schedule while still holding the mutex. This increments
	// the generation, so the blocked callback must become stale.
	timer.cancelScheduled()

	// Schedule a replacement timer. This is the generation that should be
	// allowed to run.
	timer.schedule(
		time.Millisecond, mtx, func() {
			close(replacementRan)
		},
	)

	// Release the mutex so the stale callback can acquire it, observe the
	// generation mismatch, and return without calling staleExpired.
	mtx.Unlock()

	// The stale callback must never run.
	require.Never(
		t, func() bool {
			select {
			case <-staleRan:
				return true
			default:
				return false
			}
		}, time.Second, time.Millisecond,
		"stale timer callback ran after generation was replaced",
	)

	// The replacement callback must still run.
	require.Eventually(
		t, func() bool {
			select {
			case <-replacementRan:
				return true
			default:
				return false
			}
		}, time.Second, time.Millisecond,
		"replacement timer callback did not run",
	)
}

// TestAutoLockerCancelScheduledStopsActiveTimer verifies that cancelScheduled
// prevents the currently scheduled timer from firing.
func TestAutoLockerCancelScheduledStopsActiveTimer(t *testing.T) {
	t.Parallel()

	// timer is the autoLocker under test.
	var timer autoLockTimer

	// mtx is the mutex passed to the timer callback.
	var mtx sync.Mutex

	// expired is closed if the canceled callback incorrectly runs.
	expired := make(chan struct{})

	// Hold the mutex required by autoLocker callers while scheduling and
	// canceling the timer.
	mtx.Lock()
	timer.schedule(
		time.Millisecond, &mtx, func() {
			close(expired)
		},
	)
	timer.cancelScheduled()
	mtx.Unlock()

	// The canceled callback must not run.
	require.Never(
		t, func() bool {
			select {
			case <-expired:
				return true
			default:
				return false
			}
		}, time.Second, time.Millisecond,
		"canceled timer callback ran",
	)
}

// TestAutoLockerScheduleRunsCallback verifies that a live generation executes
// its callback.
func TestAutoLockerScheduleRunsCallback(t *testing.T) {
	t.Parallel()

	// timer is the autoLocker under test.
	var timer autoLockTimer

	// mtx is the mutex passed to the timer callback.
	var mtx sync.Mutex

	// expired is closed when the callback runs.
	expired := make(chan struct{})

	// Schedule a normal timer without canceling or replacing it.
	mtx.Lock()
	timer.schedule(
		time.Millisecond, &mtx, func() {
			close(expired)
		},
	)
	mtx.Unlock()

	// The callback must run because its generation is still current.
	require.Eventually(
		t, func() bool {
			select {
			case <-expired:
				return true
			default:
				return false
			}
		}, time.Second, time.Millisecond,
	)
}
