package waddrmgr

import (
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

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
