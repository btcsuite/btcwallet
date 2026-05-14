// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"iter"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
)

// runtimeCache is the wallet-private seam between wallet managers and the
// durable db.Store. The initial implementation is a pure pass-through.
// Real caching with bounded invalidation will land in a later change.
type runtimeCache interface {
	// GetAccount returns a single account by query. The result mirrors
	// the underlying db.AccountStore.GetAccount contract.
	GetAccount(ctx context.Context,
		query db.GetAccountQuery) (*db.AccountInfo, error)

	// ListAccounts returns accounts matching the given query. The result
	// mirrors the underlying db.AccountStore.ListAccounts contract.
	ListAccounts(ctx context.Context,
		query db.ListAccountsQuery) ([]db.AccountInfo, error)

	// GetAddress returns a single address by query. The result mirrors
	// the underlying db.AddressStore.GetAddress contract.
	GetAddress(ctx context.Context,
		query db.GetAddressQuery) (*db.AddressInfo, error)

	// ListAddresses returns one page of addresses for the given query.
	// Mirrors the underlying db.AddressStore.ListAddresses contract.
	ListAddresses(ctx context.Context, query db.ListAddressesQuery) (
		page.Result[db.AddressInfo, uint32], error)

	// IterAddresses returns an iterator over addresses matching the
	// query. Mirrors the underlying db.AddressStore.IterAddresses
	// contract.
	IterAddresses(ctx context.Context,
		query db.ListAddressesQuery) iter.Seq2[db.AddressInfo, error]
}

// storeRuntimeCache is the initial pass-through implementation of
// runtimeCache. It does not actually cache anything yet; reads delegate to
// the durable db.Store.
//
// TODO(yy): replace this pass-through with a real cache once the bounded
// invalidation story is designed.
type storeRuntimeCache struct {
	// store is the durable persistence layer the cache reads through.
	store db.Store
}

// newStoreRuntimeCache constructs a storeRuntimeCache backed by the given
// store.
func newStoreRuntimeCache(store db.Store) *storeRuntimeCache {
	return &storeRuntimeCache{store: store}
}

// GetAccount delegates to the underlying db.Store.
//
// NOTE: pass-through today. See storeRuntimeCache's TODO(yy).
//
// TODO(yy): drop the wrapcheck exemption once the cache layer wraps
// store errors with its own typed errors.
//
//nolint:wrapcheck
func (c *storeRuntimeCache) GetAccount(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	return c.store.GetAccount(ctx, query)
}

// ListAccounts delegates to the underlying db.Store.
//
// NOTE: pass-through today. See storeRuntimeCache's TODO(yy).
//
// TODO(yy): drop the wrapcheck exemption once the cache layer wraps
// store errors with its own typed errors.
//
//nolint:wrapcheck
func (c *storeRuntimeCache) ListAccounts(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	return c.store.ListAccounts(ctx, query)
}

// GetAddress delegates to the underlying db.Store.
//
// NOTE: pass-through today. See storeRuntimeCache's TODO(yy).
//
// TODO(yy): drop the wrapcheck exemption once the cache layer wraps
// store errors with its own typed errors.
//
//nolint:wrapcheck
func (c *storeRuntimeCache) GetAddress(ctx context.Context,
	query db.GetAddressQuery) (*db.AddressInfo, error) {

	return c.store.GetAddress(ctx, query)
}

// ListAddresses delegates to the underlying db.Store.
//
// NOTE: pass-through today. See storeRuntimeCache's TODO(yy).
//
// TODO(yy): drop the wrapcheck exemption once the cache layer wraps
// store errors with its own typed errors.
//
//nolint:wrapcheck
func (c *storeRuntimeCache) ListAddresses(ctx context.Context,
	query db.ListAddressesQuery) (page.Result[db.AddressInfo, uint32],
	error) {

	return c.store.ListAddresses(ctx, query)
}

// IterAddresses delegates to the underlying db.Store.
//
// NOTE: pass-through today. See storeRuntimeCache's TODO(yy).
func (c *storeRuntimeCache) IterAddresses(ctx context.Context,
	query db.ListAddressesQuery) iter.Seq2[db.AddressInfo, error] {

	return c.store.IterAddresses(ctx, query)
}

// Compile-time assertion that storeRuntimeCache satisfies runtimeCache.
var _ runtimeCache = (*storeRuntimeCache)(nil)
