package keyvault

import (
	"sync"
	"time"
)

// autoLockTimer tracks scheduled auto-lock timers and invalidates stale
// callbacks by generation.
type autoLockTimer struct {
	// timer holds the active auto lock timer, if one is currently scheduled.
	// It is stopped and cleared whenever the schedule is canceled or replaced.
	timer *time.Timer

	// generation identifies the currently valid timer schedule. Each cancel or
	// reschedule increments it, so callbacks from older timers can detect that
	// they are stale and return without modifying vault state.
	generation uint64
}

// cancelScheduled invalidates the current lock generation, preventing stale
// timer callbacks from clearing newer vault state. It also stops and removes
// the active timer, if one exists.
//
// Callers must hold the vault mutex that protects the associated runtime state.
func (t *autoLockTimer) cancelScheduled() {
	t.generation++

	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
}

// schedule arms a new auto lock timer and records the generation associated
// with it. If the timer callback runs after a later cancel or reschedule, the
// generation check causes the stale callback to return without changing vault
// state.
//
// Callers must hold the same vault mutex that protects the associated runtime
// state.
func (t *autoLockTimer) schedule(timeout time.Duration, mtx sync.Locker,
	lock func()) {

	// Snapshot a unique generation for this schedule so the callback can tell
	// whether it is still current.
	t.generation++
	generation := t.generation

	t.timer = time.AfterFunc(timeout, func() {
		mtx.Lock()
		defer mtx.Unlock()

		// Ignore callbacks from an older generation after cancel or reschedule.
		if generation != t.generation {
			return
		}

		lock()
	})
}
