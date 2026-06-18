package keyvault

import "time"

// Lock locks the vault, clears any pending automatic lock, and erases runtime
// secret material from memory.
func (v *DBVault) Lock() {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	v.clearRuntimeAndLock()
}

// clearRuntimeAndLock clears unlocked state and pending timers, locking the
// vault.
//
// This method must be called with v.mtx held.
func (v *DBVault) clearRuntimeAndLock() {
	v.timer.cancelScheduled()

	if v.unlockedState != nil {
		v.unlockedState.zero()
		v.unlockedState = nil
	}
}

// scheduleLocking schedules the automatic lock timeout after a successful
// unlock.
//
// This method must be called with v.mtx held.
func (v *DBVault) scheduleLocking(timeout time.Duration) {
	if timeout < 0 {
		return
	}

	if timeout == 0 {
		timeout = defaultVaultUnlockTimeout
	}

	v.timer.schedule(timeout, &v.mtx, v.clearRuntimeAndLock)
}
