// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"fmt"

	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
)

// ManagerSnapshot reads the manager root state, the chain sync state, and every
// key scope with its accounts inside the current runtime transaction. It is the
// durable read a restarting wallet uses to reconstruct its in-memory caches.
func (r *RuntimeStore) ManagerSnapshot() (walletstore.ManagerSnapshot, error) {
	store := r.addr()

	manager, err := store.ManagerState()
	if err != nil {
		return walletstore.ManagerSnapshot{}, fmt.Errorf(
			"load manager state: %w", err)
	}

	syncState, err := store.SyncState()
	if err != nil {
		return walletstore.ManagerSnapshot{}, fmt.Errorf(
			"load sync state: %w", err)
	}

	scopes, err := store.KeyScopes()
	if err != nil {
		return walletstore.ManagerSnapshot{}, fmt.Errorf(
			"load key scopes: %w", err)
	}

	snapshot := walletstore.ManagerSnapshot{
		Manager:   manager,
		SyncState: syncState,
	}
	for _, scope := range scopes {
		accounts, err := store.Accounts(scope.Scope)
		if err != nil {
			return walletstore.ManagerSnapshot{}, fmt.Errorf(
				"load accounts for scope %v: %w", scope.Scope, err)
		}

		snapshot.Scopes = append(snapshot.Scopes, walletstore.ScopeSnapshot{
			Scope:    scope,
			Accounts: accounts,
		})
	}

	return snapshot, nil
}

// LoadManagerSnapshot reads the durable manager root state, chain sync state,
// and every key scope with its accounts in one read-only transaction.
func (r *runtimeStore) LoadManagerSnapshot(ctx context.Context) (
	walletstore.ManagerSnapshot, error) {

	var snapshot walletstore.ManagerSnapshot

	err := r.store.RuntimeView(ctx, func(rt *RuntimeStore) error {
		var err error

		snapshot, err = rt.ManagerSnapshot()

		return err
	}, nil)
	if err != nil {
		return walletstore.ManagerSnapshot{}, err
	}

	return snapshot, nil
}
