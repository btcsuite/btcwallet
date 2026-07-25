package waddrmgr

import (
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
)

// AddressFromStore returns a managed address from any registered key scope.
func (m *Manager) AddressFromStore(store ManagerReadStore,
	addr address.Address) (ManagedAddress, error) {

	m.mtx.RLock()
	defer m.mtx.RUnlock()

	for _, scopedManager := range m.scopedManagers {
		managed, err := scopedManager.AddressFromStore(store, addr)
		if err == nil {
			return managed, nil
		}
	}

	str := fmt.Sprintf("unable to find key for addr %v", addr)
	return nil, managerError(ErrAddressNotFound, str, nil)
}

// AddrAccountFromStore returns the manager and account owning an address.
func (m *Manager) AddrAccountFromStore(store ManagerReadStore,
	addr address.Address) (*ScopedKeyManager, uint32, error) {

	m.mtx.RLock()
	defer m.mtx.RUnlock()

	for _, scopedManager := range m.scopedManagers {
		account, err := scopedManager.AddrAccountFromStore(store, addr)
		if err == nil {
			return scopedManager, account, nil
		}
	}

	str := fmt.Sprintf("unable to find key for addr %v", addr)
	return nil, 0, managerError(ErrAddressNotFound, str, nil)
}

// LookupAccountFromStore returns the first scoped account matching a name.
func (m *Manager) LookupAccountFromStore(store ManagerReadStore,
	name string) (KeyScope, uint32, error) {

	m.mtx.RLock()
	defer m.mtx.RUnlock()

	for scope, scopedManager := range m.scopedManagers {
		account, err := scopedManager.LookupAccountFromStore(store, name)
		if err == nil {
			return scope, account, nil
		}
	}

	str := fmt.Sprintf("account name '%s' not found", name)
	return KeyScope{}, 0, managerError(ErrAccountNotFound, str, nil)
}

// ForEachAccountAddressFromStore visits every matching account address across
// registered key scopes.
func (m *Manager) ForEachAccountAddressFromStore(store ManagerReadStore,
	account uint32, fn func(ManagedAddress) error) error {

	m.mtx.RLock()
	defer m.mtx.RUnlock()

	for _, scopedManager := range m.scopedManagers {
		err := scopedManager.ForEachAccountAddressFromStore(
			store, account, fn,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// ForEachActiveAddressFromStore visits every active address across registered
// key scopes.
func (m *Manager) ForEachActiveAddressFromStore(store ManagerReadStore,
	fn func(address.Address) error) error {

	m.mtx.RLock()
	defer m.mtx.RUnlock()

	for _, scopedManager := range m.scopedManagers {
		if err := scopedManager.ForEachActiveAddressFromStore(
			store, fn,
		); err != nil {

			return err
		}
	}

	return nil
}

// ForEachRelevantActiveAddressFromStore visits default-scope addresses and
// change addresses retained in non-default scopes.
func (m *Manager) ForEachRelevantActiveAddressFromStore(
	store ManagerReadStore, fn func(address.Address) error) error {

	m.mtx.RLock()
	defer m.mtx.RUnlock()

	for scope, scopedManager := range m.scopedManagers {
		var err error
		if IsDefaultScope(scope) {
			err = scopedManager.ForEachActiveAddressFromStore(store, fn)
		} else {
			err = scopedManager.ForEachInternalActiveAddressFromStore(
				store, fn,
			)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

// MarkUsedFromStore marks an address used in its registered key scope.
func (m *Manager) MarkUsedFromStore(tx ManagerReadWriteTx,
	addr address.Address) error {

	m.mtx.RLock()
	defer m.mtx.RUnlock()

	for _, scopedManager := range m.scopedManagers {
		_, err := scopedManager.AddressFromStore(tx, addr)
		if err != nil {
			continue
		}

		return scopedManager.MarkUsedFromStore(tx, addr)
	}

	str := fmt.Sprintf("unable to find key for addr %v", addr)
	return managerError(ErrAddressNotFound, str, nil)
}

// IsWatchOnlyAccountFromStore reports whether one account lacks private HD
// material.
func (m *Manager) IsWatchOnlyAccountFromStore(store ManagerReadStore,
	scope KeyScope, account uint32) (bool, error) {

	if m.WatchOnly() || account == ImportedAddrAccount {
		return true, nil
	}

	state, err := store.Account(scope, account)
	if err != nil {
		return false, err
	}

	return len(state.EncryptedPrivKey) == 0, nil
}

// AddressFromStoreStates reconstructs a managed address from detached durable
// account and address state without reading a Store.
func (m *Manager) AddressFromStoreStates(account AccountState,
	state AddressState) (ManagedAddress, error) {

	m.mtx.RLock()
	manager := m.scopedManagers[state.Scope]
	m.mtx.RUnlock()
	if manager == nil {
		str := fmt.Sprintf("scope %v not found", state.Scope)
		return nil, managerError(ErrScopeNotFound, str, nil)
	}

	return manager.ManagedAddressFromStoreStates(account, state)
}
