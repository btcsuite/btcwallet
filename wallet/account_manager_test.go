// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"testing"

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
