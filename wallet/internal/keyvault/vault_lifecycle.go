package keyvault

// Lock locks the vault erasing runtime secret material from memory.
func (v *WalletVault) Lock() {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	v.clearRuntimeAndLock()
}

// clearRuntimeAndLock clears unlocked state, locking the vault.
//
// This method must be called with v.mtx held.
func (v *WalletVault) clearRuntimeAndLock() {
	if v.unlockedState != nil {
		// Zero runtime secrets before dropping references. Waiting for GC would
		// leave spend-capable key material readable in heap memory until an
		// implementation-dependent collection cycle.
		v.unlockedState.zero()
		v.unlockedState = nil
	}
}

// IsLocked reports whether the vault currently has unlocked runtime state.
func (v *WalletVault) IsLocked() bool {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	return v.unlockedState == nil
}
