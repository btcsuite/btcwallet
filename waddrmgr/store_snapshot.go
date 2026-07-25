package waddrmgr

// managerScopeSnapshot contains the complete durable state for one key scope.
type managerScopeSnapshot struct {
	state     KeyScopeState
	accounts  []AccountState
	addresses []AddressState
}

// ManagerSnapshot is an opaque, transaction-independent copy of the durable
// address-manager state needed to reconstruct a Manager.
type ManagerSnapshot struct {
	state  ManagerState
	sync   SyncState
	scopes []managerScopeSnapshot
}

// copyManagerState detaches root manager byte slices from backend-owned rows.
func copyManagerState(state ManagerState) ManagerState {
	state.MasterPubParams = copyBytes(state.MasterPubParams)
	state.MasterPrivParams = copyBytes(state.MasterPrivParams)
	state.EncryptedCryptoPubKey = copyBytes(state.EncryptedCryptoPubKey)
	state.EncryptedCryptoPrivKey = copyBytes(state.EncryptedCryptoPrivKey)
	state.EncryptedCryptoScriptKey = copyBytes(
		state.EncryptedCryptoScriptKey,
	)
	state.EncryptedMasterHDPubKey = copyBytes(state.EncryptedMasterHDPubKey)
	state.EncryptedMasterHDPrivKey = copyBytes(state.EncryptedMasterHDPrivKey)

	return state
}

// copySyncState detaches optional sync metadata from backend-owned rows.
func copySyncState(state SyncState) SyncState {
	if state.BirthdayBlock != nil {
		birthdayBlock := *state.BirthdayBlock
		state.BirthdayBlock = &birthdayBlock
	}

	return state
}

// copyKeyScopeState detaches key-scope byte slices from backend-owned rows.
func copyKeyScopeState(state KeyScopeState) KeyScopeState {
	state.EncryptedCoinPubKey = copyBytes(state.EncryptedCoinPubKey)
	state.EncryptedCoinPrivKey = copyBytes(state.EncryptedCoinPrivKey)

	return state
}

// copyAccountState detaches account keys and optional schema metadata from
// backend-owned rows.
func copyAccountState(state AccountState) AccountState {
	state.EncryptedPubKey = copyBytes(state.EncryptedPubKey)
	state.EncryptedPrivKey = copyBytes(state.EncryptedPrivKey)
	if state.AddrSchema != nil {
		addrSchema := *state.AddrSchema
		state.AddrSchema = &addrSchema
	}

	return state
}

// copyAddressState detaches address material and optional path metadata from
// backend-owned rows.
func copyAddressState(state AddressState) AddressState {
	state.Hash = copyBytes(state.Hash)
	state.EncryptedPubKey = copyBytes(state.EncryptedPubKey)
	state.EncryptedPrivKey = copyBytes(state.EncryptedPrivKey)
	state.EncryptedHash = copyBytes(state.EncryptedHash)
	state.EncryptedScript = copyBytes(state.EncryptedScript)

	if state.Branch != nil {
		branch := *state.Branch
		state.Branch = &branch
	}
	if state.Index != nil {
		index := *state.Index
		state.Index = &index
	}
	if state.WitnessVersion != nil {
		witnessVersion := *state.WitnessVersion
		state.WitnessVersion = &witnessVersion
	}
	if state.IsSecretScript != nil {
		isSecretScript := *state.IsSecretScript
		state.IsSecretScript = &isSecretScript
	}

	return state
}

// ReadManagerSnapshot copies all durable state needed to reconstruct a Manager.
// It performs no passphrase work, decryption, key derivation, or address
// validation, so callers may invoke it inside a short read transaction.
func ReadManagerSnapshot(store ManagerReadStore) (*ManagerSnapshot, error) {
	managerState, err := store.ManagerState()
	if err != nil {
		return nil, err
	}

	syncState, err := store.SyncState()
	if err != nil {
		return nil, err
	}

	scopeStates, err := store.KeyScopes()
	if err != nil {
		return nil, err
	}

	snapshot := &ManagerSnapshot{
		state:  copyManagerState(managerState),
		sync:   copySyncState(syncState),
		scopes: make([]managerScopeSnapshot, 0, len(scopeStates)),
	}
	for _, scopeState := range scopeStates {
		accounts, err := store.Accounts(scopeState.Scope)
		if err != nil {
			return nil, err
		}

		addresses, err := store.ActiveAddresses(scopeState.Scope)
		if err != nil {
			return nil, err
		}

		scopeSnapshot := managerScopeSnapshot{
			state:     copyKeyScopeState(scopeState),
			accounts:  make([]AccountState, len(accounts)),
			addresses: make([]AddressState, len(addresses)),
		}
		for i := range accounts {
			scopeSnapshot.accounts[i] = copyAccountState(accounts[i])
		}
		for i := range addresses {
			scopeSnapshot.addresses[i] = copyAddressState(addresses[i])
		}

		snapshot.scopes = append(snapshot.scopes, scopeSnapshot)
	}

	return snapshot, nil
}
