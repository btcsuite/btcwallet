package itest

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/runtime"
	"github.com/stretchr/testify/require"
)

// addrStoreScope is the key scope the address-store vector seeds its account
// under.
var addrStoreScope = waddrmgr.KeyScopeBIP0084

// addrStoreParams is the chain the address-store vector derives addresses for.
// The identity computation only, not the durable storage, depends on it, so it
// is the same on every backend.
var addrStoreParams = &chaincfg.MainNetParams

// addrStoreBlockHeight hands out distinct block heights so each address-store
// wallet's fixtures never collide in the shared conformance database.
var addrStoreBlockHeight atomic.Int32

// addrStoreSeed is a fixed BIP-32 seed the vector derives its account key from.
var addrStoreSeed = []byte{
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
}

// testAddressStore runs the Phase 2A1 address, account, and scope vector against
// one backend through the runtime coordinator, proving the exit gate for the
// derivation, allocation, and rename operations. It runs on KV, SQLite, and
// PostgreSQL, so passing on every backend proves the observable-differential
// parity: the same operations yield the same public results and typed errors.
func testAddressStore(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	t.Run("scope and account lifecycle", func(t *testing.T) {
		testAddressScopeAndAccount(t, harness)
	})
	t.Run("derive addresses", func(t *testing.T) {
		testAddressDerive(t, harness)
	})
	t.Run("invalid child range", func(t *testing.T) {
		testAddressInvalidChildRange(t, harness)
	})
	t.Run("commit failure keeps caches", func(t *testing.T) {
		testAddressCommitFailure(t, harness)
	})
	t.Run("stale reloads cache", func(t *testing.T) {
		testAddressStaleReload(t, harness)
	})
}

// testAddressScopeAndAccount proves the scope/account differential vector:
// idempotent scope creation, compare-and-swap account-number allocation,
// name-based idempotency, and rename with the typed duplicate error.
func testAddressScopeAndAccount(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	coord, walletID := newAddrCoordinator(t, harness, "addr-lifecycle")

	// EnsureScope creates the scope the first time and is a no-op after.
	scopeState := waddrmgr.KeyScopeState{
		Scope:       addrStoreScope,
		AddrSchema:  waddrmgr.ScopeAddrMap[addrStoreScope],
		LastAccount: waddrmgr.NoAccountAllocated,
	}

	created, err := coord.EnsureScope(ctx, scopeState)
	require.NoError(t, err)
	require.True(t, created.Created)

	again, err := coord.EnsureScope(ctx, scopeState)
	require.NoError(t, err)
	require.False(t, again.Created)

	// The first account allocates number 0, the second a distinct number 1.
	prepare := fixedAccountPreparer()

	alpha, err := coord.EnsureAccount(ctx, addrStoreScope, "alpha", prepare)
	require.NoError(t, err)
	require.Equal(t, uint32(0), alpha.Account)
	require.True(t, alpha.Created)

	// Re-ensuring the same name returns the same account and creates nothing.
	alphaAgain, err := coord.EnsureAccount(
		ctx, addrStoreScope, "alpha", prepare,
	)
	require.NoError(t, err)
	require.Equal(t, uint32(0), alphaAgain.Account)
	require.False(t, alphaAgain.Created)

	beta, err := coord.EnsureAccount(ctx, addrStoreScope, "beta", prepare)
	require.NoError(t, err)
	require.Equal(t, uint32(1), beta.Account)
	require.True(t, beta.Created)

	// The durable last account advanced exactly to the last allocation.
	require.Equal(t, uint32(1), durableLastAccount(t, harness, walletID))

	// Rename account 0, then a rename onto the still-taken "beta" name is
	// rejected with the typed duplicate error, while renaming to its own
	// current name is a permitted no-op.
	require.NoError(t, coord.RenameAccount(ctx, db.RenameAccountRequest{
		Scope:   addrStoreScope,
		Account: 0,
		NewName: "renamed",
	}))

	err = coord.RenameAccount(ctx, db.RenameAccountRequest{
		Scope:   addrStoreScope,
		Account: 0,
		NewName: "beta",
	})
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrDuplicateAccount))

	require.NoError(t, coord.RenameAccount(ctx, db.RenameAccountRequest{
		Scope:   addrStoreScope,
		Account: 1,
		NewName: "beta",
	}))
}

// testAddressDerive proves the ordinary derivation commit: the real derivation
// preparer produces the manager's own address identities, the commit inserts the
// rows and advances the branch atomically, and the coordinator publishes the new
// next index into its cache only after the durable commit.
func testAddressDerive(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	coord, walletID := newAddrCoordinator(t, harness, "addr-derive")
	seedAddrAccount(t, harness.newStore(walletID), 0, "derive-account")

	acctKey := deriveAddrAccountKey(t)
	key := runtime.BranchKey{
		Scope:   addrStoreScope,
		Account: 0,
		Branch:  waddrmgr.ExternalBranch,
	}

	prepare := runtime.ChainedAddressPreparer(
		addrStoreScope, 0, waddrmgr.ExternalBranch, waddrmgr.WitnessPubKey,
		acctKey, addrStoreParams, 3,
	)

	res, err := coord.DeriveNextAddresses(ctx, key, prepare, []byte("derive-1"))
	require.NoError(t, err)
	require.Equal(t, uint32(0), res.AllocatedStart)
	require.Equal(t, uint32(3), res.NextIndex)
	require.Len(t, res.Addresses, 3)
	require.False(t, res.Replayed)

	// The committed identities match the manager's own derivation.
	want, wantNext, err := waddrmgr.DeriveChainedAddresses(
		acctKey, waddrmgr.ExternalBranch, waddrmgr.WitnessPubKey,
		addrStoreParams, 0, 3,
	)
	require.NoError(t, err)
	require.Equal(t, uint32(3), wantNext)

	for i, committed := range res.Addresses {
		require.Equal(t, want[i].AddressID, committed.AddressID)
		require.Equal(t, uint32(i), *committed.State.Index)
	}

	// The branch advanced durably and three address rows are persisted.
	require.Equal(t, uint32(3), durableBranchIndex(
		t, harness, walletID, waddrmgr.ExternalBranch,
	))
	require.Len(t, durableAddresses(t, harness, walletID, 0), 3)

	// The cache was published to the committed next index.
	cached, ok := coord.CachedNextIndex(key)
	require.True(t, ok)
	require.Equal(t, uint32(3), cached)
}

// testAddressInvalidChildRange proves the invalid-child exit gate: when a
// derivation skips an invalid child, the committed range is exactly the consumed
// range, so the branch advances past the skipped index and only the derived
// addresses are persisted.
func testAddressInvalidChildRange(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	coord, walletID := newAddrCoordinator(t, harness, "addr-invalid-child")

	// Seed the account with its external branch already at index 5.
	seedAddrAccountAt(t, harness.newStore(walletID), 0, "gap-account", 5)

	key := runtime.BranchKey{
		Scope:   addrStoreScope,
		Account: 0,
		Branch:  waddrmgr.ExternalBranch,
	}

	// The preparer models a skipped invalid child at index 6: two addresses
	// land at 5 and 7, and the branch must advance to 8.
	prepare := gappedAddressPreparer(0, waddrmgr.ExternalBranch,
		[]uint32{5, 7}, 8)

	res, err := coord.DeriveNextAddresses(ctx, key, prepare, []byte("gap-1"))
	require.NoError(t, err)
	require.Equal(t, uint32(5), res.AllocatedStart)
	require.Equal(t, uint32(8), res.NextIndex)
	require.Len(t, res.Addresses, 2)

	// The branch advanced to 8, past the skipped index 6.
	require.Equal(t, uint32(8), durableBranchIndex(
		t, harness, walletID, waddrmgr.ExternalBranch,
	))

	// Exactly the two derived addresses are persisted, at indices 5 and 7.
	persisted := durableAddresses(t, harness, walletID, 0)
	require.Len(t, persisted, 2)

	indexes := make(map[uint32]struct{})
	for _, addr := range persisted {
		require.NotNil(t, addr.Index)
		indexes[*addr.Index] = struct{}{}
	}

	require.Contains(t, indexes, uint32(5))
	require.Contains(t, indexes, uint32(7))
	require.NotContains(t, indexes, uint32(6))
}

// testAddressCommitFailure proves a rejected commit mutates neither durable
// state nor the coordinator caches, for both address derivation and account
// allocation.
func testAddressCommitFailure(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	fpCtx := db.WithFailpoints(ctx, &db.Failpoints{
		BeforeCommit: func() error { return errForcedCommitFailure },
	})

	var publishes atomic.Int32

	coord, walletID := newAddrCoordinator(
		t, harness, "addr-commit-fail",
		runtime.WithBeforePublish(func() { publishes.Add(1) }),
	)
	seedAddrAccount(t, harness.newStore(walletID), 0, "fail-account")

	key := runtime.BranchKey{
		Scope:   addrStoreScope,
		Account: 0,
		Branch:  waddrmgr.ExternalBranch,
	}
	prepare := gappedAddressPreparer(0, waddrmgr.ExternalBranch,
		[]uint32{0, 1}, 2)

	_, err := coord.DeriveNextAddresses(fpCtx, key, prepare, []byte("fail-1"))
	require.Error(t, err)

	// Nothing changed: the branch index is still zero, no address rows exist,
	// and the cache was never published.
	require.Equal(t, uint32(0), durableBranchIndex(
		t, harness, walletID, waddrmgr.ExternalBranch,
	))
	require.Empty(t, durableAddresses(t, harness, walletID, 0))
	require.Equal(t, int32(0), publishes.Load())

	_, ok := coord.CachedNextIndex(key)
	require.False(t, ok)

	// A rejected account allocation likewise changes nothing.
	scopeState := waddrmgr.KeyScopeState{
		Scope:       addrStoreScope,
		AddrSchema:  waddrmgr.ScopeAddrMap[addrStoreScope],
		LastAccount: waddrmgr.NoAccountAllocated,
	}
	_, err = coord.EnsureScope(ctx, scopeState)
	require.NoError(t, err)

	// The seeded scope already owns account 0, so its last account is 0; a
	// rejected allocation of account 1 leaves it there and publishes nothing.
	_, err = coord.EnsureAccount(
		fpCtx, addrStoreScope, "fail-acct", fixedAccountPreparer(),
	)
	require.Error(t, err)
	require.Equal(t, uint32(0), durableLastAccount(t, harness, walletID))

	_, ok = coord.CachedLastAccount(addrStoreScope)
	require.False(t, ok)

	// A later clean derivation still succeeds, confirming the account was
	// otherwise usable.
	res, err := coord.DeriveNextAddresses(
		ctx, key, gappedAddressPreparer(0, waddrmgr.ExternalBranch,
			[]uint32{0}, 1), []byte("ok-1"),
	)
	require.NoError(t, err)
	require.Equal(t, uint32(1), res.NextIndex)
}

// testAddressStaleReload proves the cross-process conflict path: when a second
// coordinator advances the durable branch behind the first, the first
// coordinator's next derivation fails with the typed stale error and reloads its
// cache from durable state.
func testAddressStaleReload(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	coord, walletID := newAddrCoordinator(t, harness, "addr-stale")
	seedAddrAccount(t, harness.newStore(walletID), 0, "stale-account")

	key := runtime.BranchKey{
		Scope:   addrStoreScope,
		Account: 0,
		Branch:  waddrmgr.ExternalBranch,
	}

	// Warm the first coordinator's cache to index 1.
	_, err := coord.DeriveNextAddresses(
		ctx, key, gappedAddressPreparer(0, waddrmgr.ExternalBranch,
			[]uint32{0}, 1), []byte("warm-1"),
	)
	require.NoError(t, err)

	cached, ok := coord.CachedNextIndex(key)
	require.True(t, ok)
	require.Equal(t, uint32(1), cached)

	// A second coordinator, modeling another wallet instance, advances the
	// durable branch to index 2.
	other := runtime.New(harness.newRuntimeStore(walletID))
	_, err = other.DeriveNextAddresses(
		ctx, key, gappedAddressPreparer(0, waddrmgr.ExternalBranch,
			[]uint32{1}, 2), []byte("other-1"),
	)
	require.NoError(t, err)

	// The first coordinator's cached expected index is now stale, so its
	// compare-and-swap fails and it reloads the cache from durable state.
	_, err = coord.DeriveNextAddresses(
		ctx, key, gappedAddressPreparer(0, waddrmgr.ExternalBranch,
			[]uint32{1}, 2), []byte("stale-1"),
	)
	require.ErrorIs(t, err, db.ErrStaleAccountIndex)

	reloaded, ok := coord.CachedNextIndex(key)
	require.True(t, ok)
	require.Equal(t, uint32(2), reloaded)

	// After the reload the first coordinator allocates again from the fresh
	// durable value.
	res, err := coord.DeriveNextAddresses(
		ctx, key, gappedAddressPreparer(0, waddrmgr.ExternalBranch,
			[]uint32{2}, 3), []byte("post-1"),
	)
	require.NoError(t, err)
	require.Equal(t, uint32(2), res.AllocatedStart)
	require.Equal(t, uint32(3), res.NextIndex)
}

// testAddressConcurrentAllocation proves the concurrent-allocation exit gate for
// SQL: two coordinators over two stores backed by the same database cannot
// allocate the same address index or account number. The database compare-and-
// swap makes one win and the other observe the typed stale error, after which
// the loser re-prepares and allocates a distinct value.
func testAddressConcurrentAllocation(t *testing.T,
	harness *managerStoreHarness) {

	t.Helper()

	t.Run("address index", func(t *testing.T) {
		testConcurrentAddressIndex(t, harness)
	})
	t.Run("account number", func(t *testing.T) {
		testConcurrentAccountNumber(t, harness)
	})
}

// testConcurrentAddressIndex races two coordinators to allocate the same branch
// index and asserts exactly one wins while the other is told the index is stale.
func testConcurrentAddressIndex(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	_, walletID := newAddrCoordinator(t, harness, "addr-race-index")
	seedAddrAccount(t, harness.newStore(walletID), 0, "race-account")

	coordA := runtime.New(harness.newRuntimeStore(walletID))
	coordB := runtime.New(harness.newRuntimeStore(walletID))
	key := runtime.BranchKey{
		Scope:   addrStoreScope,
		Account: 0,
		Branch:  waddrmgr.ExternalBranch,
	}

	// A two-party barrier makes both coordinators finish reading the expected
	// index before either commits, so they genuinely contend for the same
	// index instead of one observing the other's advance.
	var barrier sync.WaitGroup
	barrier.Add(2)

	prepare := func(expectedStart uint32) ([]db.PreparedAddress, uint32,
		error) {

		barrier.Done()
		barrier.Wait()

		return addrRows(0, waddrmgr.ExternalBranch, expectedStart),
			expectedStart + 1, nil
	}

	results := make(chan error, 2)
	for _, name := range []string{"a", "b"} {
		coord := coordA
		if name == "b" {
			coord = coordB
		}

		go func(name string, c *runtime.Coordinator) {
			_, err := c.DeriveNextAddresses(
				ctx, key, prepare, []byte("race-"+name),
			)
			results <- err
		}(name, coord)
	}

	errs := []error{<-results, <-results}
	requireOneWinnerOneStale(t, errs, db.ErrStaleAccountIndex)

	// Exactly one address was allocated at index 0 and the branch advanced
	// once.
	require.Equal(t, uint32(1), durableBranchIndex(
		t, harness, walletID, waddrmgr.ExternalBranch,
	))
	require.Len(t, durableAddresses(t, harness, walletID, 0), 1)
}

// testConcurrentAccountNumber races two coordinators to allocate the next
// account number and asserts one wins account 0 while the other is told the last
// account is stale, then re-prepares and allocates the distinct account 1.
func testConcurrentAccountNumber(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	seedCoord, walletID := newAddrCoordinator(t, harness, "addr-race-account")
	_, err := seedCoord.EnsureScope(ctx, waddrmgr.KeyScopeState{
		Scope:       addrStoreScope,
		AddrSchema:  waddrmgr.ScopeAddrMap[addrStoreScope],
		LastAccount: waddrmgr.NoAccountAllocated,
	})
	require.NoError(t, err)

	coordA := runtime.New(harness.newRuntimeStore(walletID))
	coordB := runtime.New(harness.newRuntimeStore(walletID))

	// A two-party barrier makes both coordinators finish reading the expected
	// last account before either commits, so they contend for the same number.
	var barrier sync.WaitGroup
	barrier.Add(2)

	prepare := func(uint32) (waddrmgr.AccountState, error) {
		barrier.Done()
		barrier.Wait()

		return waddrmgr.AccountState{
			Type:            waddrmgr.AccountDefault,
			EncryptedPubKey: []byte{1},
		}, nil
	}

	results := make(chan error, 2)
	for _, name := range []string{"a", "b"} {
		coord := coordA
		if name == "b" {
			coord = coordB
		}

		go func(name string, c *runtime.Coordinator) {
			_, err := c.EnsureAccount(
				ctx, addrStoreScope, "acct-"+name, prepare,
			)
			results <- err
		}(name, coord)
	}

	errs := []error{<-results, <-results}
	requireOneWinnerOneStale(t, errs, db.ErrStaleLastAccount)

	// The winner allocated account 0. The loser reloaded and allocates the
	// distinct account 1 on retry, so no number is reused.
	require.Equal(t, uint32(0), durableLastAccount(t, harness, walletID))

	loser := coordB
	if errs[0] != nil {
		loser = coordA
	}

	retry, err := loser.EnsureAccount(
		ctx, addrStoreScope, "acct-retry", fixedAccountPreparer(),
	)
	require.NoError(t, err)
	require.Equal(t, uint32(1), retry.Account)
	require.Equal(t, uint32(1), durableLastAccount(t, harness, walletID))
}

// requireOneWinnerOneStale asserts exactly one of two concurrent results
// succeeded and the other failed with the expected typed stale error.
func requireOneWinnerOneStale(t *testing.T, errs []error, stale error) {
	t.Helper()

	require.Len(t, errs, 2)

	winners, stales := 0, 0
	for _, err := range errs {
		if err == nil {
			winners++

			continue
		}

		require.ErrorIs(t, err, stale)

		stales++
	}

	require.Equal(t, 1, winners, "exactly one winner")
	require.Equal(t, 1, stales, "exactly one stale loser")
}

// newAddrCoordinator creates an isolated wallet and a coordinator over its
// runtime store for the address-store vector.
func newAddrCoordinator(t *testing.T, harness *managerStoreHarness, name string,
	opts ...runtime.Option) (*runtime.Coordinator, int64) {

	t.Helper()

	height := 5000 + addrStoreBlockHeight.Add(2)
	walletID := harness.createWallet(
		t, name, testBlock(height-1), testBlock(height),
	)

	return runtime.New(harness.newRuntimeStore(walletID), opts...), walletID
}

// seedAddrAccount seeds the address-store scope and one account at branch index
// zero through the backend-neutral store.
func seedAddrAccount(t *testing.T, store db.Store, account uint32,
	name string) {

	t.Helper()

	seedAddrAccountAt(t, store, account, name, 0)
}

// seedAddrAccountAt seeds the address-store scope and one account whose external
// branch starts at nextExternal.
func seedAddrAccountAt(t *testing.T, store db.Store, account uint32, name string,
	nextExternal uint32) {

	t.Helper()

	err := store.Update(context.Background(), func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		err := addr.PutKeyScope(waddrmgr.KeyScopeState{
			Scope:       addrStoreScope,
			AddrSchema:  waddrmgr.ScopeAddrMap[addrStoreScope],
			LastAccount: account,
		})
		if err != nil {
			return err
		}

		return addr.PutAccount(waddrmgr.AccountState{
			Scope:             addrStoreScope,
			Account:           account,
			Type:              waddrmgr.AccountDefault,
			Name:              name,
			EncryptedPubKey:   []byte{1},
			NextExternalIndex: nextExternal,
		})
	}, func() {})
	require.NoError(t, err)
}

// deriveAddrAccountKey derives the deterministic account key the derivation
// vector uses.
func deriveAddrAccountKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	acctKey, err := hdkeychain.NewMaster(addrStoreSeed, addrStoreParams)
	require.NoError(t, err)

	return acctKey
}

// fixedAccountPreparer returns an account preparer that produces a default
// account template with placeholder encrypted key material, standing in for the
// live manager's derive-and-encrypt step.
func fixedAccountPreparer() runtime.AccountPreparer {
	return func(uint32) (waddrmgr.AccountState, error) {
		return waddrmgr.AccountState{
			Type:            waddrmgr.AccountDefault,
			EncryptedPubKey: []byte{1},
		}, nil
	}
}

// gappedAddressPreparer returns an address preparer that produces prepared rows
// at the given indexes and advances the branch to final, modeling a derivation
// that may have skipped invalid children between the indexes.
func gappedAddressPreparer(account, branch uint32, indexes []uint32,
	final uint32) runtime.AddressPreparer {

	return func(uint32) ([]db.PreparedAddress, uint32, error) {
		return addrRows(account, branch, indexes...), final, nil
	}
}

// addrRows builds placeholder prepared address rows at the given indexes for one
// account branch, standing in for a derivation's output in tests that do not
// exercise the real key derivation.
func addrRows(account, branch uint32, indexes ...uint32) []db.PreparedAddress {
	rows := make([]db.PreparedAddress, len(indexes))
	for i, index := range indexes {
		branchNum := branch
		addrIndex := index
		rows[i] = db.PreparedAddress{
			AddressID: []byte(fmt.Sprintf(
				"addr-%d-%d-%d", account, branch, index,
			)),
			State: waddrmgr.AddressState{
				Scope:      addrStoreScope,
				Account:    account,
				Type:       waddrmgr.AddressChain,
				AddedAt:    time.Unix(1, 0),
				SyncStatus: waddrmgr.AddressSyncFull,
				Branch:     &branchNum,
				Index:      &addrIndex,
			},
		}
	}

	return rows
}

// durableBranchIndex reads the account's current next index for one branch from
// a fresh runtime store, bypassing any coordinator cache.
func durableBranchIndex(t *testing.T, harness *managerStoreHarness,
	walletID int64, branch uint32) uint32 {

	t.Helper()

	index, err := harness.newRuntimeStore(walletID).CurrentBranchIndex(
		context.Background(), addrStoreScope, 0, branch,
	)
	require.NoError(t, err)

	return index
}

// durableLastAccount reads the scope's current last allocated account from a
// fresh runtime store, bypassing any coordinator cache.
func durableLastAccount(t *testing.T, harness *managerStoreHarness,
	walletID int64) uint32 {

	t.Helper()

	last, err := harness.newRuntimeStore(walletID).CurrentLastAccount(
		context.Background(), addrStoreScope,
	)
	require.NoError(t, err)

	return last
}

// durableAddresses reads all persisted addresses for one account through the
// backend-neutral store.
func durableAddresses(t *testing.T, harness *managerStoreHarness,
	walletID int64, account uint32) []waddrmgr.AddressState {

	t.Helper()

	var addrs []waddrmgr.AddressState

	err := harness.newStore(walletID).View(
		context.Background(), func(tx db.ReadTx) error {
			var err error

			addrs, err = tx.Addr().AccountAddresses(
				addrStoreScope, account,
			)

			return err
		}, func() {},
	)
	require.NoError(t, err)

	return addrs
}
