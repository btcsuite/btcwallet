// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import "github.com/btcsuite/btcwallet/waddrmgr"

// ManagerSnapshot is the durable address-manager state a restarting wallet
// reads to reconstruct its in-memory caches before any further runtime
// operation. It is returned by RuntimeStore.LoadManagerSnapshot as one
// consistent read, so the wallet never reaches the low-level PersistenceStore
// boundary to open.
type ManagerSnapshot struct {
	// Manager is the durable root address-manager state, carrying the master
	// key parameters and the encrypted crypto and master-HD keys needed to
	// reconstruct the secret core.
	Manager waddrmgr.ManagerState

	// SyncState is the durable chain position: start block, synced tip, and
	// birthday metadata.
	SyncState waddrmgr.SyncState

	// Scopes are every durable key scope with its accounts, in storage order.
	Scopes []ScopeSnapshot
}

// ScopeSnapshot is one durable key scope together with all of its accounts.
type ScopeSnapshot struct {
	// Scope is the durable key-scope state, including its encrypted coin-type
	// keys, address schema, and last allocated account.
	Scope waddrmgr.KeyScopeState

	// Accounts are all durable accounts in the scope, in storage order.
	Accounts []waddrmgr.AccountState
}
