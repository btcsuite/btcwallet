// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sqlwallet

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/runtime"
)

// SQLWallet is the opt-in SQL-backed wallet. All fields are unexported: it
// exposes no walletdb database, no concrete address or transaction manager, and
// no raw transaction callback, so a caller cannot reach a bucket or a concrete
// manager through it. It owns a semantic runtime coordinator, the minimal
// secret core its derivation needs, and the scope and account caches
// reconstructed from durable state.
type SQLWallet struct {
	name     string
	walletID int64
	params   *chaincfg.Params

	// conn is the SQL connection pool backing this wallet. It is closed by
	// Close and is never exposed.
	conn *sql.DB

	// coordinator drives durable runtime mutations under the per-wallet
	// mutation gate. runtimeStore is the semantic store it owns; the wallet
	// also reads durable snapshots directly through it.
	coordinator  *runtime.Coordinator
	runtimeStore walletstore.RuntimeStore

	// mu guards keyring lock state and the scope caches. It is acquired only
	// to snapshot the material a derivation needs, then released before the
	// coordinator's mutation gate is taken, so the one lock order is wallet
	// mutex -> coordinator gate.
	mu sync.Mutex

	// keyring is the minimal secret core: it decrypts account extended keys
	// for derivation and is unlocked with the private passphrase.
	keyring *waddrmgr.ManagerKeyring

	// scopes maps a key scope to its reconstructed account cache.
	scopes map[waddrmgr.KeyScope]*scopeCache

	// syncedTip is the wallet's synced block reconstructed from durable state
	// at open, standing in for the manager's sync-state cache.
	syncedTip walletstore.BlockRef
}

// Address is a derived chained address returned by NextAddress: its legacy
// script-address identity and the derivation path it was produced at.
type Address struct {
	// ScriptAddress is the address's legacy script-address identity bytes,
	// the same identity the durable address row is keyed by.
	ScriptAddress []byte

	// Scope is the key scope the address belongs to.
	Scope waddrmgr.KeyScope

	// Account is the account number the address belongs to.
	Account uint32

	// Branch is the derivation branch, external or internal.
	Branch uint32

	// Index is the child index the address was derived at.
	Index uint32
}

// Name returns the wallet's name.
func (w *SQLWallet) Name() string {
	return w.name
}

// Unlock derives the private key material from the private passphrase, making
// account private keys available. It mirrors the dual-passphrase hierarchy the
// salvage schema preserves: the public passphrase decrypted the public crypto
// key at open, and the private passphrase decrypts the private crypto key now.
func (w *SQLWallet) Unlock(_ context.Context, privPassphrase []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// The keyring error is returned unwrapped so callers can classify a wrong
	// private passphrase with waddrmgr.IsError, which does not unwrap.
	return w.keyring.Unlock(privPassphrase)
}

// Lock zeroes the private key material, returning the wallet to its locked
// state. Address derivation still works from the public account key.
func (w *SQLWallet) Lock() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.keyring.Lock()
}

// SyncedTip returns the wallet's synced block as reconstructed from durable
// state at open. It demonstrates that the cache is rebuilt from durable state
// before any further operation.
func (w *SQLWallet) SyncedTip() walletstore.BlockRef {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.syncedTip
}

// NextAddress derives and commits the next chained address for one account
// branch end to end: it derives the address from the account extended key
// outside the mutation gate, then inserts the address row and advances the
// branch index atomically through the semantic runtime coordinator, which
// publishes the new next index into its cache only after the durable commit.
//
// Only the account's public key is used to derive the address, so it works for
// a locked wallet; unlocking additionally makes the private account key
// available.
func (w *SQLWallet) NextAddress(ctx context.Context, scope waddrmgr.KeyScope,
	account, branch uint32) (Address, error) {

	// Snapshot the derivation inputs under the wallet mutex, then release it
	// before entering the coordinator's mutation gate.
	acctKey, addrType, err := w.derivationInputs(scope, account, branch)
	if err != nil {
		return Address{}, err
	}
	defer acctKey.Zero()

	operationID, err := randomOperationID()
	if err != nil {
		return Address{}, err
	}

	prepare := runtime.ChainedAddressPreparer(
		scope, account, branch, addrType, acctKey, w.params, 1,
	)

	key := runtime.BranchKey{Scope: scope, Account: account, Branch: branch}

	result, err := w.coordinator.DeriveNextAddresses(
		ctx, key, prepare, operationID,
	)
	if err != nil {
		return Address{}, fmt.Errorf("sqlwallet: derive address: %w", err)
	}

	if len(result.Addresses) == 0 {
		return Address{}, fmt.Errorf("sqlwallet: no address committed for "+
			"scope %v account %d branch %d", scope, account, branch)
	}

	committed := result.Addresses[0]

	return Address{
		ScriptAddress: committed.AddressID,
		Scope:         scope,
		Account:       account,
		Branch:        branch,
		Index:         *committed.State.Index,
	}, nil
}

// derivationInputs snapshots the account extended key and the branch address
// type a derivation needs, under the wallet mutex. The returned key is a fresh
// copy the caller must zero; it is unaffected by a concurrent Lock.
func (w *SQLWallet) derivationInputs(scope waddrmgr.KeyScope, account,
	branch uint32) (*hdkeychain.ExtendedKey, waddrmgr.AddressType, error) {

	w.mu.Lock()
	defer w.mu.Unlock()

	cache, ok := w.scopes[scope]
	if !ok {
		return nil, 0, fmt.Errorf("sqlwallet: scope %v not found", scope)
	}

	state, ok := cache.accounts[account]
	if !ok {
		return nil, 0, fmt.Errorf("sqlwallet: account %d not found in "+
			"scope %v", account, scope)
	}

	addrType, err := branchAddrType(cache.schema, state.AddrSchema, branch)
	if err != nil {
		return nil, 0, err
	}

	acctKey, err := w.keyring.AccountKey(state)
	if err != nil {
		return nil, 0, fmt.Errorf("sqlwallet: account key: %w", err)
	}

	return acctKey, addrType, nil
}

// Close zeroes the in-memory secret material and closes the SQL connection. The
// wallet must not be used after Close returns.
func (w *SQLWallet) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.keyring.Close()

	if err := w.conn.Close(); err != nil {
		return fmt.Errorf("sqlwallet: close database: %w", err)
	}

	return nil
}

// branchAddrType selects the address type for a derivation branch, honoring an
// account's address-schema override when present, otherwise the scope schema.
// It is the minimal accountAddrType the derivation needs.
func branchAddrType(scopeSchema waddrmgr.ScopeAddrSchema,
	override *waddrmgr.ScopeAddrSchema, branch uint32) (waddrmgr.AddressType,
	error) {

	schema := scopeSchema
	if override != nil {
		schema = *override
	}

	switch branch {
	case waddrmgr.ExternalBranch:
		return schema.ExternalAddrType, nil

	case waddrmgr.InternalBranch:
		return schema.InternalAddrType, nil

	default:
		return 0, fmt.Errorf("sqlwallet: unsupported branch %d", branch)
	}
}
