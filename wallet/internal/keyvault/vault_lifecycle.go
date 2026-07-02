package keyvault

// IsLocked reports whether the vault currently has unlocked runtime state.
func (v *WalletVault) IsLocked() bool {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	return v.unlockedState == nil
}
