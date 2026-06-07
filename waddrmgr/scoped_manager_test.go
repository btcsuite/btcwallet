package waddrmgr

import (
	"bytes"
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// TestNewAccountCachesAccountInfo verifies that creating a new account makes it
// visible in the scoped-manager cache without requiring a follow-up read.
func TestNewAccountCachesAccountInfo(t *testing.T) {
	t.Parallel()

	// Arrange: Create and unlock a manager, then fetch the scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		return mgr.Unlock(ns, privPassphrase)
	})
	require.NoError(t, err)

	acctStore, err := mgr.FetchScopedKeyManager(KeyScopeBIP0044)
	require.NoError(t, err)

	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok)

	var account uint32

	// Act: Create the new account through the scoped manager.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		account, err = scopedMgr.NewAccount(ns, "acct-1")

		return err
	})
	require.NoError(t, err)
	require.Contains(t, scopedMgr.ActiveAccounts(), account)

	// Assert: The new account is immediately visible in the cache.
	scopedMgr.mtx.RLock()
	acctInfo, ok := scopedMgr.acctInfo[account]
	scopedMgr.mtx.RUnlock()
	require.True(t, ok)
	require.Equal(t, "acct-1", acctInfo.acctName)
	require.Equal(t, uint32(0), acctInfo.nextExternalIndex)
	require.Equal(t, uint32(0), acctInfo.nextInternalIndex)
}

// TestNewAccountWatchingOnlyCachesAccountInfo verifies that importing a
// watch-only account updates the scoped-manager cache immediately.
func TestNewAccountWatchingOnlyCachesAccountInfo(t *testing.T) {
	t.Parallel()

	// Arrange: Create the manager, fetch the scoped manager, and derive the
	// account public key to import.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	acctStore, err := mgr.FetchScopedKeyManager(KeyScopeBIP0044)
	require.NoError(t, err)

	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok)

	accountKey := deriveTestAccountKey(t)
	require.NotNil(t, accountKey)

	acctKeyPub, err := accountKey.Neuter()
	require.NoError(t, err)

	var account uint32

	// Act: Import the watching-only account.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		account, err = scopedMgr.NewAccountWatchingOnly(
			ns, "watch-1", acctKeyPub, 123, nil,
		)

		return err
	})
	require.NoError(t, err)
	require.Contains(t, scopedMgr.ActiveAccounts(), account)

	// Assert: The imported account metadata is immediately visible in the
	// cache.
	scopedMgr.mtx.RLock()
	acctInfo, ok := scopedMgr.acctInfo[account]
	scopedMgr.mtx.RUnlock()
	require.True(t, ok)
	require.Equal(t, "watch-1", acctInfo.acctName)
	require.Equal(t, uint32(123), acctInfo.masterKeyFingerprint)
	require.Nil(t, acctInfo.addrSchema)
}

// TestIsImportedAccountAcceptsLegacyImportedAccount verifies that the legacy
// imported-address pseudo-account does not go through account-row loading.
func TestIsImportedAccountAcceptsLegacyImportedAccount(t *testing.T) {
	t.Parallel()

	// Arrange: Create the manager and fetch the scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	acctStore, err := mgr.FetchScopedKeyManager(KeyScopeBIP0044)
	require.NoError(t, err)

	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok)

	// Act: Classify the legacy imported-address pseudo-account.
	var imported bool

	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		imported, err = scopedMgr.IsImportedAccount(
			ns, ImportedAddrAccount,
		)

		return err
	})

	// Assert: The classifier handles the pseudo-account without attempting
	// to load account-row key material that does not exist for it.
	require.NoError(t, err)
	require.True(t, imported)
}

// TestScopedManagerAddressCacheBounded verifies that the scoped-manager address
// cache stays within its configured capacity while still reloading evicted
// addresses from disk.
func TestScopedManagerAddressCacheBounded(t *testing.T) {
	t.Parallel()

	// Arrange: Create and unlock a manager, then replace the scoped address
	// cache with a one-entry cache.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		return mgr.Unlock(ns, privPassphrase)
	})
	require.NoError(t, err)

	acctStore, err := mgr.FetchScopedKeyManager(KeyScopeBIP0084)
	require.NoError(t, err)

	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok)

	scopedMgr.addrs = newAddrCache(1)

	var firstAddr ManagedAddress

	// Act: Derive two addresses so the first is evicted, then load the first
	// address again from disk.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		addrs, err := scopedMgr.NextExternalAddresses(ns, DefaultAccountNum, 2)
		if err != nil {
			return err
		}

		firstAddr = addrs[0]

		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, scopedMgr.addrs.Len())

	// Assert: The evicted address can still be reloaded and the cache remains
	// bounded.
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		addr, err := scopedMgr.Address(ns, firstAddr.Address())
		require.NoError(t, err)
		require.Equal(t, firstAddr.Address().String(), addr.Address().String())

		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, scopedMgr.addrs.Len())
}

// TestForEachActiveAddressIgnoresCacheEviction verifies that active-address
// iteration still walks the full DB-backed address set after cache eviction.
func TestForEachActiveAddressIgnoresCacheEviction(t *testing.T) {
	t.Parallel()

	// Arrange: Create and unlock a manager, then force the scoped address cache
	// down to one entry.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		return mgr.Unlock(ns, privPassphrase)
	})
	require.NoError(t, err)

	acctStore, err := mgr.FetchScopedKeyManager(KeyScopeBIP0084)
	require.NoError(t, err)

	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok)

	scopedMgr.addrs = newAddrCache(1)

	// Act: Derive two addresses so one is evicted, then iterate the active
	// addresses from the DB-backed manager state.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		_, err := scopedMgr.NextExternalAddresses(ns, DefaultAccountNum, 2)

		return err
	})
	require.NoError(t, err)
	require.Equal(t, 1, scopedMgr.addrs.Len())

	var seen []string

	// Assert: Iteration still sees both active addresses even though the cache
	// only holds one entry.
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		return scopedMgr.ForEachActiveAddress(
			ns, func(addr btcutil.Address) error {
				seen = append(seen, addr.String())
				return nil
			},
		)
	})
	require.NoError(t, err)
	require.Len(t, seen, 2)
}

// TestScopedManagerAddressEvictionLocksSecrets verifies that evicting an
// address from the bounded cache zeroes any cleartext private key bytes held by
// that managed address.
func TestScopedManagerAddressEvictionLocksSecrets(t *testing.T) {
	t.Parallel()

	// Arrange: Create and unlock a manager, then force the scoped address cache
	// down to one entry.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		return mgr.Unlock(ns, privPassphrase)
	})
	require.NoError(t, err)

	acctStore, err := mgr.FetchScopedKeyManager(KeyScopeBIP0084)
	require.NoError(t, err)

	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok)

	scopedMgr.addrs = newAddrCache(1)

	var firstAddr *managedAddress

	// Act: Derive one address, capture its cleartext key bytes, then derive a
	// second address so the first is evicted.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		addrs, err := scopedMgr.NextExternalAddresses(ns, DefaultAccountNum, 1)
		if err != nil {
			return err
		}

		var ok bool

		firstAddr, ok = addrs[0].(*managedAddress)
		if !ok {
			return nil
		}

		return nil
	})
	require.NoError(t, err)
	require.NotNil(t, firstAddr)
	require.NotEmpty(t, firstAddr.privKeyCT)

	firstPrivKeyCT := firstAddr.privKeyCT

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		_, err := scopedMgr.NextExternalAddresses(ns, DefaultAccountNum, 1)

		return err
	})
	require.NoError(t, err)

	// Assert: Eviction zeroes and clears the original managed address's
	// cleartext private key bytes.
	require.Nil(t, firstAddr.privKeyCT)
	require.True(t, bytes.Equal(
		firstPrivKeyCT, make([]byte, len(firstPrivKeyCT)),
	))
	require.Equal(t, 1, scopedMgr.addrs.Len())
}

// TestDeriveAddrs verifies that DeriveAddrs correctly derives addresses using
// in-memory state, producing the same results as database-backed derivation.
func TestDeriveAddrs(t *testing.T) {
	t.Parallel()

	// Initialize a new address manager with a clean database for testing.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	// Unlock the manager to allow full functionality, although DeriveAddrs
	// works without unlocking (tested separately). We unlock here to
	// ensure DeriveFromKeyPath (the baseline) has access to private keys
	// if needed by its internal logic.
	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		return mgr.Unlock(ns, privPassphrase)
	})
	require.NoError(t, err)

	// Fetch the default BIP0044 scoped manager.
	scope := KeyScopeBIP0044
	acctStore, err := mgr.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	// Cast to the concrete type to access the method under test.
	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok, "expected *ScopedKeyManager")

	account := uint32(DefaultAccountNum)

	// Pre-load account into cache (required for DeriveAddrs).
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		_, err := scopedMgr.AccountProperties(ns, account)

		return err
	})
	require.NoError(t, err)

	// NOTE: We define it here instead of using anonymous struct as this
	// struct is needed for the `assertDBCorrectness`.
	type testCase struct {
		name       string
		branch     uint32
		startIndex uint32
		count      uint32
	}

	// We define a set of test cases covering different branches
	// (internal/external) and index ranges to ensure robust derivation. We
	// also test large batches to verify performance and correctness at
	// scale.
	tests := []testCase{
		{
			name:       "External Branch, Index 0-4",
			branch:     ExternalBranch,
			startIndex: 0,
			count:      5,
		},
		{
			name:       "Internal Branch, Index 10-14",
			branch:     InternalBranch,
			startIndex: 10,
			count:      5,
		},
		{
			name:       "Large Batch",
			branch:     ExternalBranch,
			startIndex: 100,
			count:      50,
		},
		{
			name:       "Single Address",
			branch:     ExternalBranch,
			startIndex: 1000,
			count:      1,
		},
		{
			name:       "Zero Addresses",
			branch:     ExternalBranch,
			startIndex: 0,
			count:      0,
		},
	}

	accountNum := hdkeychain.HardenedKeyStart + account

	// assertDBCorrectness is a helper closure that verifies the results
	// returned by DeriveAddrs against the baseline DeriveFromKeyPath
	// method. This ensures that the in-memory derivation logic produces
	// identical addresses and scripts as the database-backed logic.
	assertDBCorrectness := func(t *testing.T, tc testCase,
		addrs []btcutil.Address) {

		t.Helper()

		err := walletdb.View(db, func(tx walletdb.ReadTx) error {
			ns := tx.ReadBucket(waddrmgrNamespaceKey)

			for i := range tc.count {
				index := tc.startIndex + i

				// Construct the derivation path for the
				// baseline check.
				path := DerivationPath{
					InternalAccount: account,
					Account:         accountNum,
					Branch:          tc.branch,
					Index:           index,
				}

				// Derive using the standard DB-backed method.
				managedAddr, err := scopedMgr.DeriveFromKeyPath(
					ns, path,
				)
				require.NoError(t, err)

				// Compare the resulting address string.
				expectedAddr := managedAddr.Address()
				require.Equal(t, expectedAddr.String(),
					addrs[i].String(), "Address mismatch "+
						"at index %d", index)

				// Compare the resulting script.
				require.Equal(t, expectedAddr.ScriptAddress(),
					addrs[i].ScriptAddress())
			}

			return nil
		})
		require.NoError(t, err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Call the new in-memory derivation method. This
			// should return the derived addresses and scripts
			// without further DB access.
			addrs, scripts, err := scopedMgr.DeriveAddrs(
				account, tc.branch, tc.startIndex, tc.count,
			)
			require.NoError(t, err)
			require.Len(t, addrs, int(tc.count))
			require.Len(t, scripts, int(tc.count))

			// Verify the results against the established,
			// database-backed DeriveFromKeyPath method to ensure
			// correctness.
			assertDBCorrectness(t, tc, addrs)
		})
	}
}

// TestDeriveAddrsLocked verifies that DeriveAddrs works even when the wallet
// is locked (using extended public keys).
func TestDeriveAddrsLocked(t *testing.T) {
	t.Parallel()

	// Initialize the manager. By default, it is locked.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	// Confirm the manager is indeed locked.
	require.True(t, mgr.IsLocked())

	scope := KeyScopeBIP0044
	acctStore, err := mgr.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok)

	// Pre-load the account into the cache using a read-only transaction.
	// AccountProperties only needs public keys, so it works while locked.
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		_, err := scopedMgr.AccountProperties(ns, DefaultAccountNum)

		return err
	})
	require.NoError(t, err)

	// Attempt to derive addresses while locked. This should succeed
	// because it uses the cached extended public keys.
	addrs, _, err := scopedMgr.DeriveAddrs(
		DefaultAccountNum, ExternalBranch, 0, 5,
	)

	// Verify success and result count.
	require.NoError(t, err, "DeriveAddrs should succeed when locked")
	require.Len(t, addrs, 5)
}

// TestDeriveAddrsOverflow verifies that DeriveAddrs returns an error when the
// requested range of child indexes overflows uint32.
func TestDeriveAddrsOverflow(t *testing.T) {
	t.Parallel()

	// Arrange: Setup the environment with a zero-valued ScopedKeyManager,
	// as the overflow check is performed before any other logic or state
	// access.
	var s ScopedKeyManager

	// Act: Execute the function under test with a range that triggers a
	// uint32 overflow (startIndex + count > math.MaxUint32).
	startIndex := uint32(math.MaxUint32 - 5)
	count := uint32(10)
	_, _, err := s.DeriveAddrs(0, 0, startIndex, count)

	// Assert: Verify that the expected overflow error is returned.
	require.Error(t, err)
	require.True(t, IsError(err, ErrTooManyAddresses))
	require.Contains(t, err.Error(), "child index overflow")
}

// TestDeriveAddr verifies that DeriveAddr correctly derives a single address
// using in-memory state.
func TestDeriveAddr(t *testing.T) {
	t.Parallel()

	// Initialize manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	// Unlock manager to allow full functionality.
	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		return mgr.Unlock(ns, privPassphrase)
	})
	require.NoError(t, err)

	// Fetch scoped manager.
	scope := KeyScopeBIP0044
	acctStore, err := mgr.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok)

	account := uint32(DefaultAccountNum)

	// Pre-load account into cache.
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		_, err := scopedMgr.AccountProperties(ns, account)

		return err
	})
	require.NoError(t, err)

	// Define test parameters.
	branch := ExternalBranch
	index := uint32(0)

	// Call DeriveAddr (In-Memory).
	addr, script, err := scopedMgr.DeriveAddr(account, branch, index)
	require.NoError(t, err)

	// Verify against Baseline (DeriveFromKeyPath via DB).
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		path := DerivationPath{
			InternalAccount: account,
			Account:         hdkeychain.HardenedKeyStart + account,
			Branch:          branch,
			Index:           index,
		}

		managedAddr, err := scopedMgr.DeriveFromKeyPath(ns, path)
		require.NoError(t, err)

		// Compare address string and script hash.
		require.Equal(t, managedAddr.Address().String(),
			addr.String())
		require.Equal(t, managedAddr.Address().ScriptAddress(),
			addr.ScriptAddress())

		// Verify returned script matches expected P2PKH script.
		expectedScript, _ := txscript.PayToAddrScript(
			managedAddr.Address(),
		)
		require.Equal(t, expectedScript, script)

		return nil
	})
	require.NoError(t, err)
}

// TestEvictDerivedAddressesUnlocked verifies that EvictDerivedAddresses removes
// exactly the addresses derived over the given range from the recent-address
// cache, leaving addresses outside the range cached. This is the in-memory undo
// a rolled-back scan-batch horizon extension relies on so unpersisted
// scan-derived addresses do not stay observable through the cache.
func TestEvictDerivedAddressesUnlocked(t *testing.T) {
	t.Parallel()

	// Arrange: an unlocked manager with a handful of derived external
	// addresses cached.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		return mgr.Unlock(ns, privPassphrase)
	})
	require.NoError(t, err)

	acctStore, err := mgr.FetchScopedKeyManager(KeyScopeBIP0084)
	require.NoError(t, err)

	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok)

	const lastIndex = 4

	var derived []ManagedAddress

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := scopedMgr.ExtendAddresses(
			ns, DefaultAccountNum, lastIndex, ExternalBranch,
		)
		if err != nil {
			return err
		}

		// Re-derive the addresses for indices [0, lastIndex] so the test
		// can address the exact cache keys ExtendAddresses inserted.
		for index := uint32(0); index <= lastIndex; index++ {
			addr, _, err := scopedMgr.DeriveAddr(
				DefaultAccountNum, ExternalBranch, index,
			)
			if err != nil {
				return err
			}

			ma, err := scopedMgr.Address(ns, addr)
			if err != nil {
				return err
			}

			derived = append(derived, ma)
		}

		return nil
	})
	require.NoError(t, err)
	require.Len(t, derived, lastIndex+1)

	// Sanity check: every derived address starts out cached.
	for _, ma := range derived {
		_, err := scopedMgr.addrs.Get(addrKey(ma.Address().ScriptAddress()))
		require.NoError(t, err)
	}

	// Act: evict the addresses derived over the upper part of the range,
	// leaving index 0 cached.
	const evictFrom = 1
	scopedMgr.EvictDerivedAddresses(
		DefaultAccountNum, ExternalBranch, evictFrom, lastIndex+1,
	)

	// Assert: indices in [evictFrom, lastIndex] are gone from the cache while
	// index 0 stays cached, proving the eviction is bounded to the range.
	for index, ma := range derived {
		key := addrKey(ma.Address().ScriptAddress())
		_, err := scopedMgr.addrs.Get(key)

		if index < evictFrom {
			require.NoError(t, err)
			continue
		}

		require.Error(t, err)
	}
}

// TestEvictDerivedAddressesLockedDropsPending verifies that
// EvictDerivedAddresses discards the pending unlock-derivation entries an
// extension queued while the manager was locked. A rolled-back scan batch must
// not leave addresses queued for private-key derivation on the next unlock when
// their persisted rows were rolled back.
func TestEvictDerivedAddressesLockedDropsPending(t *testing.T) {
	t.Parallel()

	// Arrange: a locked manager. Extending addresses while locked queues the
	// derived children for derivation on the next unlock.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	acctStore, err := mgr.FetchScopedKeyManager(KeyScopeBIP0084)
	require.NoError(t, err)

	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok)

	require.True(t, mgr.IsLocked())

	const lastIndex = 3

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		return scopedMgr.ExtendAddresses(
			ns, DefaultAccountNum, lastIndex, ExternalBranch,
		)
	})
	require.NoError(t, err)

	// Sanity check: the locked extension queued the children for unlock-time
	// derivation.
	require.NotEmpty(t, scopedMgr.deriveOnUnlock)

	// Act: evict the queued range.
	scopedMgr.EvictDerivedAddresses(
		DefaultAccountNum, ExternalBranch, 0, lastIndex+1,
	)

	// Assert: no pending unlock-derivation entries remain for the evicted
	// branch range.
	for _, info := range scopedMgr.deriveOnUnlock {
		stillQueued := info.branch == ExternalBranch &&
			info.index <= lastIndex
		require.False(t, stillQueued)
	}
}

// TestEvictDerivedAddressesLockedKeepsOtherAccountsPending verifies that
// EvictDerivedAddresses only removes pending unlock-derivation entries for the
// requested account. A rolled-back scan batch for one account must not discard
// pending private-key derivations queued by another account at the same branch
// and child indexes.
func TestEvictDerivedAddressesLockedKeepsOtherAccountsPending(t *testing.T) {
	t.Parallel()

	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	acctStore, err := mgr.FetchScopedKeyManager(KeyScopeBIP0084)
	require.NoError(t, err)

	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok)

	var otherAccount uint32

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := mgr.Unlock(ns, privPassphrase)
		if err != nil {
			return err
		}

		otherAccount, err = scopedMgr.NewAccount(ns, "acct-1")

		return err
	})
	require.NoError(t, err)
	require.NoError(t, mgr.Lock())
	require.True(t, mgr.IsLocked())

	const lastIndex = 2

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := scopedMgr.ExtendAddresses(
			ns, DefaultAccountNum, lastIndex, ExternalBranch,
		)
		if err != nil {
			return err
		}

		return scopedMgr.ExtendAddresses(
			ns, otherAccount, lastIndex, ExternalBranch,
		)
	})
	require.NoError(t, err)

	countPending := func(account uint32) int {
		count := 0
		for _, info := range scopedMgr.deriveOnUnlock {
			matches := info.managedAddr.InternalAccount() == account &&
				info.branch == ExternalBranch &&
				info.index <= lastIndex
			if matches {
				count++
			}
		}

		return count
	}

	defaultPending := countPending(DefaultAccountNum)
	otherPending := countPending(otherAccount)

	require.GreaterOrEqual(t, defaultPending, int(lastIndex+1))
	require.Equal(t, int(lastIndex+1), otherPending)

	scopedMgr.EvictDerivedAddresses(
		DefaultAccountNum, ExternalBranch, 0, lastIndex+1,
	)

	require.Zero(t, countPending(DefaultAccountNum))
	require.Equal(t, otherPending, countPending(otherAccount))
}
