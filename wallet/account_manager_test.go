// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

const (
	// testAccountName is a constant for the account name used in the tests.
	testAccountName = "test"
)

// TestNewAccount tests that the NewAccount method works as expected.
func TestNewAccount(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	defer cleanup()

	// We'll start by creating a new account under the BIP0084 scope. We
	// expect this to succeed.
	scope := waddrmgr.KeyScopeBIP0084
	account, err := w.NewAccount(
		context.Background(), scope, testAccountName,
	)
	require.NoError(t, err, "unable to create new account")

	// The new account should be the first account created, so it should have
	// an index of 1.
	require.Equal(t, uint32(1), account.AccountNumber, "expected account 1")

	// We should be able to retrieve the account by its name.
	_, err = w.AccountName(scope, account.AccountNumber)
	require.NoError(t, err, "unable to retrieve account")

	// We should not be able to create a new account with the same name.
	_, err = w.NewAccount(context.Background(), scope, testAccountName)
	require.Error(t, err, "expected error when creating duplicate account")

	// We should not be able to create a new account when the wallet is
	// locked.
	err = w.addrStore.Lock()
	require.NoError(t, err)

	_, err = w.NewAccount(context.Background(), scope, "test2")
	require.Error(
		t, err, "expected error when creating account while wallet is "+
			"locked",
	)
}

// TestListAccounts tests that the ListAccounts method works as expected.
func TestListAccounts(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	defer cleanup()

	// We'll start by creating a new account under the BIP0084 scope.
	scope := waddrmgr.KeyScopeBIP0084
	_, err := w.NewAccount(context.Background(), scope, testAccountName)
	require.NoError(t, err, "unable to create new account")

	// Now, we'll list all accounts and check that we have the default
	// account and the new account.
	accounts, err := w.ListAccounts(context.Background())
	require.NoError(t, err, "unable to list accounts")

	// We should have five accounts, the four default accounts and the new
	// account.
	require.Len(t, accounts.Accounts, 5, "expected five accounts")

	// The first account should be the default account.
	require.Equal(
		t, "default", accounts.Accounts[0].AccountName,
		"expected default account",
	)
	require.Equal(
		t, uint32(0), accounts.Accounts[0].AccountNumber,
		"expected default account number",
	)
	require.Equal(
		t, btcutil.Amount(0), accounts.Accounts[0].TotalBalance,
		"expected zero balance for default account",
	)

	// The new account should also be present.
	var found bool
	for _, acc := range accounts.Accounts {
		if acc.AccountName == testAccountName {
			found = true
			require.Equal(
				t, uint32(1), acc.AccountNumber,
				"expected new account number",
			)
			require.Equal(
				t, btcutil.Amount(0), acc.TotalBalance,
				"expected zero balance for new account",
			)
		}
	}
	require.True(t, found, "expected to find new account")
}

// getOrCreateAddress is a helper function to get an address for a given
// account, or create a new one if none exist.
func getOrCreateAddress(t *testing.T, w *Wallet, scope waddrmgr.KeyScope,
	account uint32) btcutil.Address {

	var addr btcutil.Address
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		scopedMgr, err := w.addrStore.FetchScopedKeyManager(scope)
		if err != nil {
			return err
		}

		var addrs []waddrmgr.ManagedAddress
		err = scopedMgr.ForEachAccountAddress(
			addrmgrNs, account,
			func(addr waddrmgr.ManagedAddress) error {
				addrs = append(addrs, addr)
				return nil
			},
		)
		if err != nil || len(addrs) == 0 {
			derivedAddrs, err := scopedMgr.NextExternalAddresses(
				addrmgrNs, account, 1,
			)
			if err != nil {
				return err
			}
			addr = derivedAddrs[0].Address()
		} else {
			addr = addrs[0].Address()
		}

		return nil
	})
	require.NoError(t, err)

	return addr
}

// TestCreateResultForScope tests that the createResultForScope helper function
// works as expected.
func TestCreateResultForScope(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	defer cleanup()

	// We'll create a new account under the BIP0084 scope to have a
	// predictable state with more than just the default account.
	scope := waddrmgr.KeyScopeBIP0084
	acc1Name := "test account"
	_, err := w.NewAccount(context.Background(), scope, acc1Name)
	require.NoError(t, err)

	// We'll now create a balance map for a few addresses. We need to
	// derive some addresses first to have something to work with.
	addrToBalance := make(map[string]btcutil.Amount)
	defaultAddr := getOrCreateAddress(t, w, scope, 0)
	acc1Addr := getOrCreateAddress(t, w, scope, 1)

	// Assign some balances to our derived addresses.
	addrToBalance[defaultAddr.String()] = 100
	addrToBalance[acc1Addr.String()] = 200

	// Now, we'll call createResultForScope within a read transaction and
	// verify the results.
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		scopedMgr, err := w.addrStore.FetchScopedKeyManager(scope)
		require.NoError(t, err)

		// Call the function under test.
		results, err := createResultForScope(
			scopedMgr, addrmgrNs, addrToBalance,
		)
		require.NoError(t, err)

		// The BIP0084 scope should have two accounts: the default one
		// and the one we just created.
		require.Len(t, results, 2, "expected two accounts for scope")

		// Check the default account's result.
		require.Equal(t, "default", results[0].AccountName)
		require.Equal(t, uint32(0), results[0].AccountNumber)
		require.Equal(t, btcutil.Amount(100), results[0].TotalBalance)

		// Check the new account's result.
		require.Equal(t, acc1Name, results[1].AccountName)
		require.Equal(t, uint32(1), results[1].AccountNumber)
		require.Equal(t, btcutil.Amount(200), results[1].TotalBalance)

		return nil
	})
	require.NoError(t, err)
}

// TestListAccountsByScope tests that the ListAccountsByScope method works as
// expected.
func TestListAccountsByScope(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	defer cleanup()

	// We'll create two new accounts, one under the BIP0084 scope and one
	// under the BIP0049 scope.
	scopeBIP84 := waddrmgr.KeyScopeBIP0084
	accBIP84Name := "test bip84"
	_, err := w.NewAccount(context.Background(), scopeBIP84, accBIP84Name)
	require.NoError(t, err)

	scopeBIP49 := waddrmgr.KeyScopeBIP0049Plus
	accBIP49Name := "test bip49"
	_, err = w.NewAccount(context.Background(), scopeBIP49, accBIP49Name)
	require.NoError(t, err)

	// Now, we'll list the accounts for the BIP0084 scope and check that
	// we only get the default account for that scope and the new account we
	// created.
	accountsBIP84, err := w.ListAccountsByScope(
		context.Background(), scopeBIP84,
	)
	require.NoError(t, err)

	// We should have two accounts, the default account and the new account.
	require.Len(t, accountsBIP84.Accounts, 2)

	// The first account should be the default account.
	require.Equal(t, "default", accountsBIP84.Accounts[0].AccountName)
	require.Equal(t, uint32(0), accountsBIP84.Accounts[0].AccountNumber)

	// The second account should be the new account.
	require.Equal(t, accBIP84Name, accountsBIP84.Accounts[1].AccountName)
	require.Equal(t, uint32(1), accountsBIP84.Accounts[1].AccountNumber)

	// Now, we'll do the same for the BIP0049 scope.
	accountsBIP49, err := w.ListAccountsByScope(
		context.Background(), scopeBIP49,
	)
	require.NoError(t, err)

	// We should have two accounts, the default account and the new account.
	require.Len(t, accountsBIP49.Accounts, 2)

	// The first account should be the default account.
	require.Equal(t, "default", accountsBIP49.Accounts[0].AccountName)
	require.Equal(t, uint32(0), accountsBIP49.Accounts[0].AccountNumber)

	// The second account should be the new account.
	require.Equal(t, accBIP49Name, accountsBIP49.Accounts[1].AccountName)
	require.Equal(t, uint32(1), accountsBIP49.Accounts[1].AccountNumber)
}

// TestListAccountsByName tests that the ListAccountsByName method works as
// expected.
func TestListAccountsByName(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	defer cleanup()

	// We'll create two new accounts, one under the BIP0084 scope and one
	// under the BIP0049 scope.
	scopeBIP84 := waddrmgr.KeyScopeBIP0084
	accBIP84Name := "test bip84"
	_, err := w.NewAccount(context.Background(), scopeBIP84, accBIP84Name)
	require.NoError(t, err)

	scopeBIP49 := waddrmgr.KeyScopeBIP0049Plus
	accBIP49Name := "test bip49"
	_, err = w.NewAccount(context.Background(), scopeBIP49, accBIP49Name)
	require.NoError(t, err)

	// Now, we'll list the accounts for the BIP0084 scope and check that
	// we only get the default account for that scope and the new account we
	// created.
	accountsBIP84, err := w.ListAccountsByName(
		context.Background(), accBIP84Name,
	)
	require.NoError(t, err)

	// We should have one account.
	require.Len(t, accountsBIP84.Accounts, 1)

	// The first account should be the new account.
	require.Equal(t, accBIP84Name, accountsBIP84.Accounts[0].AccountName)
	require.Equal(t, uint32(1), accountsBIP84.Accounts[0].AccountNumber)

	// Now, we'll do the same for the BIP0049 scope.
	accountsBIP49, err := w.ListAccountsByName(
		context.Background(), accBIP49Name,
	)
	require.NoError(t, err)

	// We should have one account.
	require.Len(t, accountsBIP49.Accounts, 1)

	// The first account should be the new account.
	require.Equal(t, accBIP49Name, accountsBIP49.Accounts[0].AccountName)
	require.Equal(t, uint32(1), accountsBIP49.Accounts[0].AccountNumber)

	// We should get an empty result if we query for a non-existent
	// account.
	accounts, err := w.ListAccountsByName(
		context.Background(), "non-existent",
	)
	require.NoError(t, err)
	require.Len(t, accounts.Accounts, 0)
}