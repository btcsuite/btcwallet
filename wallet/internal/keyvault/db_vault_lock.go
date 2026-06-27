package keyvault

// Lock locks the vault erasing runtime secret material from memory.
func (v *DBVault) Lock() {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	v.clearRuntimeAndLock()
}

// clearRuntimeAndLock clears unlocked state, locking the vault.
//
// This method must be called with v.mtx held.
func (v *DBVault) clearRuntimeAndLock() {
	if v.unlockedState != nil {
		v.unlockedState.zero()
		v.unlockedState = nil
	}
}
