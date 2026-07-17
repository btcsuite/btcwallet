// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package runtime

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
)

// AddressPreparer derives count chained addresses starting at expectedStart and
// returns the prepared address rows plus the branch's next index past the
// consumed range. It is run during preparation, outside the mutation gate and
// any write transaction; skipping an invalid child advances the next index, so
// the returned next index can exceed expectedStart plus the address count.
type AddressPreparer func(expectedStart uint32) ([]walletstore.PreparedAddress,
	uint32, error)

// AccountPreparer derives the account key material for the account number the
// coordinator is about to allocate and returns the account state template. It
// is run during preparation, outside the mutation gate; on a stale allocation
// the coordinator rereads the last account and the caller re-prepares for the
// new number.
type AccountPreparer func(newAccount uint32) (waddrmgr.AccountState, error)

// AddressDerivation is the result of committing a batch of derived addresses
// through the coordinator.
type AddressDerivation struct {
	// Addresses are the committed address rows in derivation order. It is
	// empty on a replay, whose durable rows are already persisted.
	Addresses []walletstore.PreparedAddress

	// AllocatedStart is the first index reserved by the batch.
	AllocatedStart uint32

	// NextIndex is the branch's new next index after the batch.
	NextIndex uint32

	// Replayed is true when the durable state was not changed because the
	// operation had already committed.
	Replayed bool
}

// ScopeEnsured is the result of ensuring a key scope through the coordinator.
type ScopeEnsured struct {
	// Created is true when this call created the scope.
	Created bool
}

// AccountEnsured is the result of ensuring an account through the coordinator.
type AccountEnsured struct {
	// Account is the account's number, whether newly allocated or the number
	// of the pre-existing account with the requested name.
	Account uint32

	// Created is true when this call created the account.
	Created bool
}

// CachedLastAccount returns the cached last allocated account for a scope,
// taking the mutation gate in shared mode. The boolean is false when the scope
// is not cached yet.
func (c *Coordinator) CachedLastAccount(scope waddrmgr.KeyScope) (uint32, bool) {
	c.gate.RLock()
	defer c.gate.RUnlock()

	last, ok := c.lastAccount[scope]

	return last, ok
}

// DeriveNextAddresses derives and commits the next chained addresses for a
// branch following the Cache And Commit Protocol: it reads the expected next
// index and derives the addresses without the gate, then inserts them and
// advances the branch index under the gate, publishing the new next index only
// after the durable commit. A stale expected index reloads the cache and
// returns ErrStaleAccountIndex so the caller re-derives from the fresh index.
func (c *Coordinator) DeriveNextAddresses(ctx context.Context, key BranchKey,
	prepare AddressPreparer, operationID []byte) (AddressDerivation, error) {

	// Prepare without the gate: read the expected next index, then derive the
	// addresses for it. The derivation, which skips invalid children, happens
	// entirely outside the gate and the write transaction.
	expected, cached := c.CachedNextIndex(key)
	if !cached {
		var err error

		expected, err = c.store.CurrentBranchIndex(
			ctx, key.Scope, key.Account, key.Branch,
		)
		if err != nil {
			return AddressDerivation{}, err
		}
	}

	addresses, final, err := prepare(expected)
	if err != nil {
		return AddressDerivation{}, err
	}

	return runGated(
		c, ctx, walletstore.ErrStaleAccountIndex,
		// commit: revalidate the expected index against the cache under the
		// gate, then insert the prepared rows and advance the branch.
		func() (AddressDerivation, error) {
			if current, ok := c.cache[key]; ok && current != expected {
				return AddressDerivation{},
					walletstore.ErrStaleAccountIndex
			}

			res, err := c.store.CommitDerivedAddresses(
				ctx, walletstore.CommitDerivedAddressesRequest{
					Scope:         key.Scope,
					Account:       key.Account,
					Branch:        key.Branch,
					ExpectedIndex: expected,
					FinalIndex:    final,
					Addresses:     addresses,
					OperationID:   operationID,
				},
			)
			if err != nil {
				return AddressDerivation{}, err
			}

			return AddressDerivation{
				Addresses:      res.Addresses,
				AllocatedStart: res.AllocatedStart,
				NextIndex:      res.NextIndex,
				Replayed:       res.Replayed,
			}, nil
		},
		// resolve: reread the durable journal after an ambiguous commit.
		func() (AddressDerivation, bool, error) {
			res, found, err := c.store.LookupDerivedAddresses(
				ctx, operationID,
			)
			if err != nil || !found {
				return AddressDerivation{}, found, err
			}

			return AddressDerivation{
				Addresses:      res.Addresses,
				AllocatedStart: res.AllocatedStart,
				NextIndex:      res.NextIndex,
				Replayed:       res.Replayed,
			}, true, nil
		},
		// reload: refresh the cache from durable state after a conflict.
		func() { c.reloadIndex(ctx, key) },
		// publish: record the new next index under the gate; no event.
		func(r AddressDerivation) []walletstore.Event {
			c.publishIndex(key, r.NextIndex)

			return nil
		},
	)
}

// EnsureScope ensures a key scope exists following the Cache And Commit
// Protocol: the scope is created under the gate and marked known only after the
// durable commit. It is idempotent.
func (c *Coordinator) EnsureScope(ctx context.Context,
	state waddrmgr.KeyScopeState) (ScopeEnsured, error) {

	return runGated(
		c, ctx, nil,
		// commit: create the scope if absent.
		func() (ScopeEnsured, error) {
			res, err := c.store.EnsureScope(
				ctx, walletstore.EnsureScopeRequest{State: state},
			)
			if err != nil {
				return ScopeEnsured{}, err
			}

			return ScopeEnsured{Created: res.Created}, nil
		},
		// resolve: nil, the scope creation keeps no journal.
		nil,
		// reload: nothing to reload for an idempotent existence check.
		func() {},
		// publish: mark the scope known under the gate; no event.
		func(ScopeEnsured) []walletstore.Event {
			c.publishScope(state.Scope)

			return nil
		},
	)
}

// EnsureAccount ensures an account with the given name exists following the
// Cache And Commit Protocol: it reads the expected last account and derives the
// account key without the gate, then allocates the next number and creates the
// account under the gate, publishing the new last account only after the durable
// commit. A stale last account reloads the cache and returns ErrStaleLastAccount
// so the caller re-derives for the new number.
func (c *Coordinator) EnsureAccount(ctx context.Context, scope waddrmgr.KeyScope,
	name string, prepare AccountPreparer) (AccountEnsured, error) {

	// Prepare without the gate: read the expected last account, compute the
	// next number, and derive the account key for it.
	expectedLast, cached := c.CachedLastAccount(scope)
	if !cached {
		var err error

		expectedLast, err = c.store.CurrentLastAccount(ctx, scope)
		if err != nil {
			return AccountEnsured{}, err
		}
	}

	newAccount, err := walletstore.NextAccountNumber(expectedLast)
	if err != nil {
		return AccountEnsured{}, err
	}

	template, err := prepare(newAccount)
	if err != nil {
		return AccountEnsured{}, err
	}

	return runGated(
		c, ctx, walletstore.ErrStaleLastAccount,
		// commit: revalidate the expected last account against the cache
		// under the gate, then allocate and create the account.
		func() (AccountEnsured, error) {
			if current, ok := c.lastAccount[scope]; ok &&
				current != expectedLast {

				return AccountEnsured{},
					walletstore.ErrStaleLastAccount
			}

			res, err := c.store.EnsureAccount(
				ctx, walletstore.EnsureAccountRequest{
					Scope:               scope,
					Name:                name,
					ExpectedLastAccount: expectedLast,
					Template:            template,
				},
			)
			if err != nil {
				return AccountEnsured{}, err
			}

			return AccountEnsured{
				Account: res.Account,
				Created: res.Created,
			}, nil
		},
		// resolve: nil, the account creation keeps no journal.
		nil,
		// reload: refresh the last account from durable state.
		func() { c.reloadLastAccount(ctx, scope) },
		// publish: advance the last account under the gate when this call
		// created the account; a returned existing account leaves it.
		func(r AccountEnsured) []walletstore.Event {
			if r.Created {
				c.publishLastAccount(scope, r.Account)
			}

			return nil
		},
	)
}

// RenameAccount renames an account following the Cache And Commit Protocol: the
// rename runs under the gate, rejecting a name owned by another account with
// waddrmgr.ErrDuplicateAccount. The name index is maintained atomically with the
// rename by the backend.
func (c *Coordinator) RenameAccount(ctx context.Context,
	req walletstore.RenameAccountRequest) error {

	_, err := runGated(
		c, ctx, nil,
		func() (struct{}, error) {
			_, err := c.store.RenameAccount(ctx, req)

			return struct{}{}, err
		},
		nil,
		func() {},
		func(struct{}) []walletstore.Event { return nil },
	)

	return err
}

// publishScope records a created scope as known under the exclusive gate.
func (c *Coordinator) publishScope(scope waddrmgr.KeyScope) {
	if _, ok := c.scopes[scope]; !ok {
		if c.beforePublish != nil {
			c.beforePublish()
		}

		c.scopes[scope] = struct{}{}
	}
}

// publishLastAccount records a scope's new last allocated account under the
// exclusive gate. It publishes only when the cached value changes, so an
// idempotent replay produces no duplicate cache mutation.
func (c *Coordinator) publishLastAccount(scope waddrmgr.KeyScope,
	account uint32) {

	if current, ok := c.lastAccount[scope]; !ok || current != account {
		if c.beforePublish != nil {
			c.beforePublish()
		}

		c.lastAccount[scope] = account
	}
}

// reloadLastAccount refreshes the cached last allocated account from durable
// state under the exclusive gate, used after a cross-process allocation or an
// unresolved ambiguous commit.
func (c *Coordinator) reloadLastAccount(ctx context.Context,
	scope waddrmgr.KeyScope) {

	last, err := c.store.CurrentLastAccount(ctx, scope)
	if err == nil {
		c.lastAccount[scope] = last
	}
}

// ChainedAddressPreparer returns an AddressPreparer that derives count chained
// addresses of the given type from the account key through the address manager's
// own derivation, so the runtime preparation and the live manager produce the
// same legacy address identities. It is the production preparer the live wallet
// wires in Phase 2B; only the account's public key is used, so it works for a
// watch-only or locked account.
func ChainedAddressPreparer(scope waddrmgr.KeyScope, account, branch uint32,
	addrType waddrmgr.AddressType, acctKey *hdkeychain.ExtendedKey,
	params *chaincfg.Params, count uint32) AddressPreparer {

	return func(expectedStart uint32) ([]walletstore.PreparedAddress, uint32,
		error) {

		derived, next, err := waddrmgr.DeriveChainedAddresses(
			acctKey, branch, addrType, params, expectedStart, count,
		)
		if err != nil {
			return nil, 0, err
		}

		prepared := make([]walletstore.PreparedAddress, len(derived))
		for i := range derived {
			branchNum := derived[i].Branch
			index := derived[i].Index
			hash := sha256.Sum256(derived[i].AddressID)

			prepared[i] = walletstore.PreparedAddress{
				AddressID: derived[i].AddressID,
				State: waddrmgr.AddressState{
					Scope:      scope,
					Hash:       hash[:],
					Account:    account,
					Type:       waddrmgr.AddressChain,
					AddedAt:    time.Now(),
					SyncStatus: waddrmgr.AddressSyncFull,
					Branch:     &branchNum,
					Index:      &index,
				},
			}
		}

		return prepared, next, nil
	}
}
