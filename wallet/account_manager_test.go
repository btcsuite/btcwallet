// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
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
	require.Empty(t, accounts.Accounts)
}

// TestGetAccount tests that the GetAccount method works as expected.
func TestGetAccount(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	defer cleanup()

	// We'll create a new account under the BIP0084 scope.
	scope := waddrmgr.KeyScopeBIP0084
	_, err := w.NewAccount(context.Background(), scope, testAccountName)
	require.NoError(t, err)

	// We should be able to get the new account.
	account, err := w.GetAccount(context.Background(), scope, testAccountName)
	require.NoError(t, err)
	require.Equal(t, testAccountName, account.AccountName)
	require.Equal(t, uint32(1), account.AccountNumber)
	require.Equal(t, btcutil.Amount(0), account.TotalBalance)

	// We should also be able to get the default account.
	account, err = w.GetAccount(context.Background(), scope, "default")
	require.NoError(t, err)
	require.Equal(t, "default", account.AccountName)
	require.Equal(t, uint32(0), account.AccountNumber)
	require.Equal(t, btcutil.Amount(0), account.TotalBalance)

	// We should get an error when trying to get a non-existent account.
	_, err = w.GetAccount(context.Background(), scope, "non-existent")
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound),
		"expected ErrAccountNotFound",
	)
}

// TestRenameAccount tests that the RenameAccount method works as expected.
func TestRenameAccount(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	defer cleanup()

	// We'll create a new account under the BIP0084 scope.
	scope := waddrmgr.KeyScopeBIP0084
	oldName := "old name"
	newName := "new name"
	_, err := w.NewAccount(context.Background(), scope, oldName)
	require.NoError(t, err)

	// We should be able to rename the account.
	err = w.RenameAccount(context.Background(), scope, oldName, newName)
	require.NoError(t, err)

	// We should be able to get the account by its new name.
	account, err := w.GetAccount(context.Background(), scope, newName)
	require.NoError(t, err)
	require.Equal(t, newName, account.AccountName)

	// We should not be able to get the account by its old name.
	_, err = w.GetAccount(context.Background(), scope, oldName)
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound),
		"expected ErrAccountNotFound",
	)

	// We should not be able to rename an account to an existing name.
	err = w.RenameAccount(context.Background(), scope, newName, "default")
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrDuplicateAccount),
		"expected ErrDuplicateAccount",
	)

	// We should not be able to rename a non-existent account.
	err = w.RenameAccount(
		context.Background(), scope, "non-existent", "new name 2",
	)
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound),
		"expected ErrAccountNotFound",
	)
}

// TestBalance tests that the Balance method works as expected.
func TestBalance(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	defer cleanup()

	// We'll create a new account under the BIP0084 scope.
	scope := waddrmgr.KeyScopeBIP0084
	_, err := w.NewAccount(context.Background(), scope, testAccountName)
	require.NoError(t, err)

	// The balance should be zero initially.
	balance, err := w.Balance(
		context.Background(), 1, scope, testAccountName,
	)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(0), balance)

	// Now, we'll add a UTXO to the account.
	addr, err := w.NewAddress(1, scope)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	rec, err := wtxmgr.NewTxRecordFromMsgTx(&wire.MsgTx{
		TxIn: []*wire.TxIn{
			{},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    100,
				PkScript: pkScript,
			},
		},
	}, time.Now())
	require.NoError(t, err)

	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		err := w.txStore.InsertTx(ns, rec, &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				Height: 1,
			},
		})
		if err != nil {
			return err
		}

		return w.txStore.AddCredit(ns, rec, &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				Height: 1,
			},
		}, 0, false)
	})
	require.NoError(t, err)

	// Now, we'll update the wallet's sync state.
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		return w.addrStore.SetSyncedTo(addrmgrNs, &waddrmgr.BlockStamp{
			Height: 1,
		})
	})
	require.NoError(t, err)

	// The balance should now be 100.
	balance, err = w.Balance(
		context.Background(), 1, scope, testAccountName,
	)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(100), balance)

	// We should get an error when trying to get the balance of a
	// non-existent account.
	_, err = w.Balance(context.Background(), 1, scope, "non-existent")
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound),
		"expected ErrAccountNotFound",
	)
}

// TestImportAccount tests that the ImportAccount works as expected.
func TestImportAccount(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	defer cleanup()

	// We'll start by creating a new account under the BIP0084 scope.
	scope := waddrmgr.KeyScopeBIP0084
	addrType := waddrmgr.WitnessPubKey
	masterPriv := "tprv8ZgxMBicQKsPeWwrFuNjEGTTDSY4mRLwd2KDJAPGa1AY" +
		"quw38bZqNMSuB3V1Va3hqJBo9Pt8Sx7kBQer5cNMrb8SYquoWPt9" +
		"Y3BZdhdtUcw"
	root, err := hdkeychain.NewKeyFromString(masterPriv)
	require.NoError(t, err)
	acctPubKey := deriveAcctPubKey(t, root, scope, hardenedKey(0))

	// We should be able to import the account.
	props, err := w.ImportAccount(
		context.Background(), testAccountName, acctPubKey,
		root.ParentFingerprint(), addrType, false,
	)
	require.NoError(t, err)
	require.Equal(t, testAccountName, props.AccountName)

	// We should be able to get the account by its name.
	_, err = w.GetAccount(context.Background(), scope, testAccountName)
	require.NoError(t, err)

	// We should not be able to import an account with the same name.
	_, err = w.ImportAccount(
		context.Background(), testAccountName, acctPubKey,
		root.ParentFingerprint(), addrType, false,
	)
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrDuplicateAccount),
		"expected ErrDuplicateAccount",
	)

	// We should be able to do a dry run of the import.
	dryRunName := "dry run"
	_, err = w.ImportAccount(
		context.Background(), dryRunName, acctPubKey,
		root.ParentFingerprint(), addrType, true,
	)
	require.NoError(t, err)

	// The account should not have been imported.
	_, err = w.GetAccount(context.Background(), scope, dryRunName)
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound),
		"expected ErrAccountNotFound",
	)
}

// TestExtractAddrFromPKScript tests that the extractAddrFromPKScript
// helper function works as expected.
func TestExtractAddrFromPKScript(t *testing.T) {
	t.Parallel()

	w, cleanup := testWallet(t)
	defer cleanup()

	w.chainParams = &chaincfg.MainNetParams

	p2pkhAddr, err := btcutil.DecodeAddress(
		"17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem", w.chainParams,
	)
	require.NoError(t, err)

	p2shAddr, err := btcutil.DecodeAddress(
		"347N1Thc213QqfYCz3PZkjoJpNv5b14kBd", w.chainParams,
	)
	require.NoError(t, err)

	p2wpkhAddr, err := btcutil.DecodeAddress(
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", w.chainParams,
	)
	require.NoError(t, err)

	testCases := []struct {
		name   string
		script func() []byte
		addr   string
	}{
		{
			name: "p2pkh",
			script: func() []byte {
				pkScript, err := txscript.PayToAddrScript(
					p2pkhAddr,
				)
				require.NoError(t, err)

				return pkScript
			},
			addr: p2pkhAddr.String(),
		},
		{
			name: "p2sh",
			script: func() []byte {
				pkScript, err := txscript.PayToAddrScript(
					p2shAddr,
				)
				require.NoError(t, err)

				return pkScript
			},
			addr: p2shAddr.String(),
		},
		{
			name: "p2wpkh",
			script: func() []byte {
				pkScript, err := txscript.PayToAddrScript(
					p2wpkhAddr,
				)
				require.NoError(t, err)

				return pkScript
			},
			addr: p2wpkhAddr.String(),
		},
		{
			name: "op_return",
			script: func() []byte {
				pkScript, err := txscript.NewScriptBuilder().
					AddOp(txscript.OP_RETURN).
					AddData([]byte("test")).
					Script()
				require.NoError(t, err)

				return pkScript
			},
			addr: "",
		},
		{
			name:   "invalid script",
			script: func() []byte { return []byte("invalid") },
			addr:   "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			addr := extractAddrFromPKScript(
				testCase.script(), w.chainParams,
			)
			if addr == nil {
				require.Empty(t, testCase.addr)
			} else {
				require.Equal(t, testCase.addr, addr.String())
			}
		})
	}
}

// addTestUTXOForBalance is a helper function to add a UTXO to the wallet.
func addTestUTXOForBalance(t *testing.T, w *Wallet, scope waddrmgr.KeyScope,
	account uint32, amount btcutil.Amount) {

	addr, err := w.NewAddress(account, scope)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	rec, err := wtxmgr.NewTxRecordFromMsgTx(&wire.MsgTx{
		TxIn: []*wire.TxIn{
			{},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    int64(amount),
				PkScript: pkScript,
			},
		},
	}, time.Now())
	require.NoError(t, err)

	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		block := &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Height: 1},
		}

		err := w.txStore.InsertTx(ns, rec, block)
		if err != nil {
			return err
		}

		return w.txStore.AddCredit(ns, rec, block, 0, false)
	})
	require.NoError(t, err)
}

// TestFetchAccountBalances tests that the fetchAccountBalances helper function
// works as expected.
func TestFetchAccountBalances(t *testing.T) {
	t.Parallel()

	// setupTestCase is a helper closure to set up a test case.
	//
	// This function initializes a new test wallet and populates it with a
	// predictable set of accounts and unspent transaction outputs (UTXOs).
	// This provides a consistent starting state for each test case,
	// ensuring that tests are isolated and repeatable.
	//
	// The initial state of the wallet is as follows:
	//
	// Accounts:
	// - The default account (number 0) is implicitly created for each key
	//   scope.
	// - "acc1-bip84": A named account (number 1) under the BIP0084 key
	//   scope.
	// - "acc1-bip49": A named account (number 1) under the BIP0049 key
	//   scope.
	//
	// UTXOs:
	// - 100 satoshis are credited to the default account in the BIP0084
	//   scope.
	// - 200 satoshis are credited to the "acc1-bip84" account.
	// - 300 satoshis are credited to the "acc1-bip49" account.
	//
	// Sync State:
	// - The wallet is marked as synced up to block height 1. This is
	//   necessary for the UTXOs to be considered confirmed and spendable.
	//
	// The function returns the fully initialized wallet and a cleanup
	// function that should be deferred by the caller to ensure that the
	// wallet's resources are properly released after the test completes.
	setupTestCase := func(t *testing.T) (*Wallet, func()) {
		w, cleanup := testWallet(t)
		ctx := context.Background()

		// Create accounts.
		_, err := w.NewAccount(
			ctx, waddrmgr.KeyScopeBIP0084, "acc1-bip84",
		)
		require.NoError(t, err)
		_, err = w.NewAccount(
			ctx, waddrmgr.KeyScopeBIP0049Plus, "acc1-bip49",
		)
		require.NoError(t, err)

		// Add UTXOs.
		addTestUTXOForBalance(t, w, waddrmgr.KeyScopeBIP0084, 0, 100)
		addTestUTXOForBalance(t, w, waddrmgr.KeyScopeBIP0084, 1, 200)
		addTestUTXOForBalance(t, w, waddrmgr.KeyScopeBIP0049Plus, 1, 300)

		// Update sync state.
		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			bs := &waddrmgr.BlockStamp{Height: 1}

				return w.addrStore.SetSyncedTo(addrmgrNs, bs)
			})
		require.NoError(t, err)

		return w, cleanup
	}

	testCases := []struct {
		name             string
		setup            func(t *testing.T, w *Wallet)
		filters          []filterOption
		expectedBalances scopedBalances
	}{
		{
			name:    "no filters",
			filters: nil,
			expectedBalances: scopedBalances{
				waddrmgr.KeyScopeBIP0084:     {0: 100, 1: 200},
				waddrmgr.KeyScopeBIP0049Plus: {1: 300},
			},
		},
		{
			name: "filter by scope",
			filters: []filterOption{
				withScope(waddrmgr.KeyScopeBIP0084),
			},
			expectedBalances: scopedBalances{
				waddrmgr.KeyScopeBIP0084: {0: 100, 1: 200},
			},
		},
		{
			name: "account with no balance",
			setup: func(t *testing.T, w *Wallet) {
				_, err := w.NewAccount(
					context.Background(),
					waddrmgr.KeyScopeBIP0084, "no-balance",
				)
				require.NoError(t, err)
			},
			filters: nil,
			expectedBalances: scopedBalances{
				waddrmgr.KeyScopeBIP0084:     {0: 100, 1: 200},
				waddrmgr.KeyScopeBIP0049Plus: {1: 300},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, cleanup := setupTestCase(t)
			defer cleanup()

			if tc.setup != nil {
				tc.setup(t, w)
			}

			var balances scopedBalances

			err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
				var err error

					balances, err = w.fetchAccountBalances(
						tx, tc.filters...,
					)

					return err
				})

			require.NoError(t, err)
			require.Equal(t, tc.expectedBalances, balances)
		})
	}
}

// TestListAccountsWithBalances tests that the listAccountsWithBalances helper
// function works as expected.
func TestListAccountsWithBalances(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, cleanup := testWallet(t)
	defer cleanup()

	// We'll create two new accounts under the BIP0084 scope to have a
	// predictable state.
	scope := waddrmgr.KeyScopeBIP0084
	acc1Name := "test account"
	_, err := w.NewAccount(context.Background(), scope, acc1Name)
	require.NoError(t, err)

	acc2Name := "no balance account"
	_, err = w.NewAccount(context.Background(), scope, acc2Name)
	require.NoError(t, err)

	// We'll now create a balance map for some of the accounts. We
	// intentionally leave out the second new account to test the zero
	// balance case.
	balances := map[uint32]btcutil.Amount{
		0: 100, // Default account
		1: 200, // "test account"
	}

	// Now, we'll call listAccountsWithBalances within a read transaction
	// and verify the results.
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		scopedMgr, err := w.addrStore.FetchScopedKeyManager(scope)
		require.NoError(t, err)

		// Call the function under test.
		results, err := listAccountsWithBalances(
			scopedMgr, addrmgrNs, balances,
		)
		require.NoError(t, err)

		// The BIP0084 scope should have three accounts: the default
		// one and the two we just created.
		require.Len(t, results, 3, "expected three accounts for scope")

		// Check the default account's result.
		require.Equal(t, "default", results[0].AccountName)
		require.Equal(t, uint32(0), results[0].AccountNumber)
		require.Equal(t, btcutil.Amount(100), results[0].TotalBalance)

		// Check the first new account's result.
		require.Equal(t, acc1Name, results[1].AccountName)
		require.Equal(t, uint32(1), results[1].AccountNumber)
		require.Equal(t, btcutil.Amount(200), results[1].TotalBalance)

		// Check the second new account's result (zero balance).
		require.Equal(t, acc2Name, results[2].AccountName)
		require.Equal(t, uint32(2), results[2].AccountNumber)
		require.Equal(t, btcutil.Amount(0), results[2].TotalBalance)

		return nil
	})
	require.NoError(t, err)
}
