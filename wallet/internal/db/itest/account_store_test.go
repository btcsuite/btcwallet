//go:build itest

package itest

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestCreateAccounts verifies that Create**Account correctly creates accounts
// across all standard key scopes between multiple wallets.
func TestCreateAccounts(t *testing.T) {
	t.Parallel()
	store, _ := NewTestStore(t)

	// Create 3 wallets to ensure wallet_id scoping works.
	for i := range 3 {
		walletID := newWallet(t, store, "wallet-"+strconv.Itoa(i))

		for _, tc := range DerivedAccountCases {
			params := tc.DerivedParams(walletID)
			info, err := store.CreateDerivedAccount(t.Context(), params)
			require.NoError(t, err)
			require.NotNil(t, info)
			requireAccountMatches(t, info, tc)
		}

		for _, tc := range ImportedAccountCases {
			params := tc.ImportedParams(walletID)
			props, err := store.CreateImportedAccount(t.Context(), params)
			require.NoError(t, err)
			require.NotNil(t, props)
			requireAccountPropertiesMatches(t, props, tc)
			require.NotEmpty(t, props.EncryptedPublicKey)
		}
	}
}

// TestCreateDerivedAccountErrors verifies that CreateDerivedAccount returns
// appropriate errors for invalid inputs.
func TestCreateDerivedAccountErrors(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "wallet-create-derived-account-errors")

	tests := []struct {
		name    string
		params  db.CreateDerivedAccountParams
		wantErr error
	}{
		{
			name: "missing name",
			params: db.CreateDerivedAccountParams{
				WalletID: walletID,
				Scope:    db.KeyScopeBIP0084,
				Name:     "",
			},
			wantErr: db.ErrMissingAccountName,
		},
		{
			name: "unknown scope",
			params: db.CreateDerivedAccountParams{
				WalletID: walletID,
				Scope:    db.KeyScope{Purpose: 999, Coin: 999},
				Name:     "unknown-scope-account",
			},
			wantErr: db.ErrUnknownKeyScope,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			info, err := store.CreateDerivedAccount(t.Context(), tc.params)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, info)
		})
	}
}

// TestCreateDerivedAccountDuplicateName verifies that creating a derived
// account with a duplicate name in the same scope fails.
func TestCreateDerivedAccountDuplicateName(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "duplicate-name-wallet")

	params := db.CreateDerivedAccountParams{
		WalletID: walletID,
		Scope:    db.KeyScopeBIP0084,
		Name:     "duplicate-account",
	}

	_, err := store.CreateDerivedAccount(t.Context(), params)
	require.NoError(t, err)

	// Attempt to create second account with same name in same scope.
	_, err = store.CreateDerivedAccount(t.Context(), params)
	require.Error(t, err)
	require.ErrorContains(t, err, "constraint")
}

// TestCreateDerivedAccountSameNameDifferentScopes verifies that accounts with
// the same name can exist in different scopes.
func TestCreateDerivedAccountSameNameDifferentScopes(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "multi-scope-wallet")

	accountName := "shared-name"
	scopes := []db.KeyScope{
		db.KeyScopeBIP0084,
		db.KeyScopeBIP0086,
		db.KeyScopeBIP0044,
		db.KeyScopeBIP0049Plus,
	}

	for _, scope := range scopes {
		params := db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    scope,
			Name:     accountName,
		}

		info, err := store.CreateDerivedAccount(t.Context(), params)
		require.NoError(t, err)
		require.Equal(t, accountName, info.AccountName)
		require.Equal(t, scope, info.KeyScope)
	}
}

// TestCreateDerivedAccountSequentialNumbers verifies that derived accounts
// within the same scope receive sequential account numbers starting from 0.
func TestCreateDerivedAccountSequentialNumbers(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "sequential-wallet")

	scope := db.KeyScopeBIP0084
	const numAccounts = 5

	for i := range numAccounts {
		params := db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    scope,
			Name:     "account-" + strconv.Itoa(i),
		}

		info, err := store.CreateDerivedAccount(t.Context(), params)
		require.NoError(t, err)
		require.Equal(t, uint32(i), info.AccountNumber,
			"account %d should have number %d", i, i)
	}
}

// TestCreateDerivedAccountConcurrent verifies that concurrent account creation
// yields unique, sequential account numbers without errors.
func TestCreateDerivedAccountConcurrent(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "concurrent-wallet")

	scope := db.KeyScopeBIP0084

	const workers = 20
	results := make([]uint32, workers)
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			info, err := store.CreateDerivedAccount(
				ctx, db.CreateDerivedAccountParams{
					WalletID: walletID,
					Scope:    scope,
					Name:     "acct-concurrent-" + strconv.Itoa(i),
				},
			)
			require.NoError(t, err)
			results[i] = info.AccountNumber
		}(i)
	}

	wg.Wait()

	// Verify all numbers are unique and sequential.
	sort.Slice(results, func(i, j int) bool {
		return results[i] < results[j]
	})
	for i := range workers {
		require.Equal(t, uint32(i), results[i])
	}
}

// TestCreateImportedAccountErrors verifies that CreateImportedAccount returns
// appropriate errors for invalid inputs.
func TestCreateImportedAccountErrors(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "wallet-create-imported-account-errors")

	tests := []struct {
		name    string
		params  db.CreateImportedAccountParams
		wantErr error
	}{
		{
			name: "missing name",
			params: db.CreateImportedAccountParams{
				WalletID:           walletID,
				Name:               "",
				Scope:              db.KeyScopeBIP0084,
				EncryptedPublicKey: RandomBytes(32),
			},
			wantErr: db.ErrMissingAccountName,
		},
		{
			name: "missing public key",
			params: db.CreateImportedAccountParams{
				WalletID:           walletID,
				Name:               "missing-pubkey",
				Scope:              db.KeyScopeBIP0084,
				EncryptedPublicKey: nil,
			},
			wantErr: db.ErrMissingAccountPublicKey,
		},
		{
			name: "unknown scope",
			params: db.CreateImportedAccountParams{
				WalletID:           walletID,
				Name:               "unknown-scope",
				Scope:              db.KeyScope{Purpose: 999, Coin: 999},
				EncryptedPublicKey: RandomBytes(32),
			},
			wantErr: db.ErrUnknownKeyScope,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			props, err := store.CreateImportedAccount(t.Context(), tc.params)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, props)
		})
	}
}

// TestCreateImportedAccountDuplicateName verifies that creating an imported
// account with a duplicate name in the same scope fails.
func TestCreateImportedAccountDuplicateName(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "imported-duplicate-name-wallet")

	params := db.CreateImportedAccountParams{
		WalletID:           walletID,
		Name:               "duplicate-imported",
		Scope:              db.KeyScopeBIP0084,
		EncryptedPublicKey: RandomBytes(32),
	}

	_, err := store.CreateImportedAccount(t.Context(), params)
	require.NoError(t, err)

	// Attempt to create second imported account with same name in same
	// scope.
	params.EncryptedPublicKey = RandomBytes(32)
	_, err = store.CreateImportedAccount(t.Context(), params)
	require.Error(t, err)
	require.ErrorContains(t, err, "constraint")
}

// TestGetAccount verifies that GetAccount correctly retrieves accounts
// by name or account number.
func TestGetAccount(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "wallet-get-account")

	createAllAccounts(t, store, walletID)

	for _, tc := range AllAccountCases {
		accNumber := uint32(0)

		t.Run("by name-"+tc.Name, func(t *testing.T) {
			query := getAccountQueryByName(walletID, tc.Scope, tc.Name)
			info, err := store.GetAccount(t.Context(), query)
			require.NoError(t, err)
			require.NotNil(t, info)
			requireAccountMatches(t, info, tc)
			accNumber = info.AccountNumber
		})

		if tc.Origin == db.ImportedAccount {
			continue
		}

		t.Run(fmt.Sprintf("by number-%d-%s", accNumber, tc.Name),
			func(t *testing.T) {

				query := getAccountQueryByNumber(walletID, tc.Scope, accNumber)
				info, err := store.GetAccount(t.Context(), query)
				require.NoError(t, err)
				require.NotNil(t, info)
				requireAccountMatches(t, info, tc)
			})
	}
}

// TestGetAccountNotFound verifies that GetAccount returns ErrAccountNotFound
// when querying a non-existent account.
func TestGetAccountNotFound(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "wallet-get-account-not-found")

	createAllAccounts(t, store, walletID)

	scope := db.KeyScopeBIP0084

	t.Run("by name", func(t *testing.T) {
		t.Parallel()

		query := getAccountQueryByName(walletID, scope, "non-existent")
		info, err := store.GetAccount(t.Context(), query)
		require.ErrorIs(t, err, db.ErrAccountNotFound)
		require.Nil(t, info)
	})

	t.Run("by number", func(t *testing.T) {
		t.Parallel()

		query := getAccountQueryByNumber(walletID, scope, 99999)
		info, err := store.GetAccount(t.Context(), query)
		require.ErrorIs(t, err, db.ErrAccountNotFound)
		require.Nil(t, info)
	})
}

// TestListAccounts verifies that ListAccounts returns accounts for a
// wallet with various filters.
func TestListAccounts(t *testing.T) {
	t.Parallel()

	// Ensure that has at least 3 accounts to be tested.
	require.GreaterOrEqual(t, len(AllAccountCases), 3)

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "wallet-list-accounts")

	createAllAccounts(t, store, walletID)

	t.Run("all accounts", func(t *testing.T) {
		t.Parallel()

		query := db.ListAccountsQuery{WalletID: walletID}
		accounts, err := store.ListAccounts(t.Context(), query)
		require.NoError(t, err)
		require.Len(t, accounts, len(AllAccountCases))
		for _, tc := range AllAccountCases {
			acc := findAccountInList(t, accounts, tc)
			requireAccountMatches(t, &acc, tc)
		}
	})

	t.Run("filter by scope", func(t *testing.T) {
		t.Parallel()

		scope := db.KeyScopeBIP0084
		query := db.ListAccountsQuery{
			WalletID: walletID,
			Scope:    &scope,
		}
		accounts, err := store.ListAccounts(t.Context(), query)
		require.NoError(t, err)

		cases := FilterAccountsByScope(scope)

		require.Len(t, accounts, len(cases))
		for _, tc := range cases {
			acc := findAccountInList(t, accounts, tc)
			requireAccountMatches(t, &acc, tc)
		}
	})

	t.Run("filter by name", func(t *testing.T) {
		t.Parallel()

		// Ensure that has at least 3 derived accounts to be tested.
		require.GreaterOrEqual(t, len(DerivedAccountCases), 3)

		// Pick an acc that exists in our fixtures.
		tc := DerivedAccountCases[1]
		query := db.ListAccountsQuery{
			WalletID: walletID,
			Name:     &tc.Name,
		}
		accounts, err := store.ListAccounts(t.Context(), query)
		require.NoError(t, err)
		require.Len(t, accounts, 1)
		requireAccountMatches(t, &accounts[0], tc)
	})

	t.Run("empty result", func(t *testing.T) {
		t.Parallel()

		// Create a new wallet with no accounts.
		emptyWalletID := newWallet(t, store, "wallet-list-empty")
		query := db.ListAccountsQuery{WalletID: emptyWalletID}
		accounts, err := store.ListAccounts(t.Context(), query)
		require.NoError(t, err)
		require.Empty(t, accounts)
	})
}

// TestListAccountsOrdering verifies that ListAccounts returns derived accounts
// ordered by account number, with imported accounts (NULL account_number) last.
func TestListAccountsOrdering(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "wallet-list-ordering")

	scope := db.KeyScopeBIP0084

	// Create accounts in mixed order: imported, derived, imported, derived.
	createImportedAccount(t, store, walletID, scope, "imported-first")
	createDerivedAccount(t, store, walletID, scope, "derived-0")
	createImportedAccount(t, store, walletID, scope, "imported-second")
	createDerivedAccount(t, store, walletID, scope, "derived-1")

	query := db.ListAccountsQuery{
		WalletID: walletID,
		Scope:    &scope,
	}
	accounts, err := store.ListAccounts(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, accounts, 4)

	// Derived accounts should come first (ordered by account number).
	require.Equal(t, "derived-0", accounts[0].AccountName)
	require.Equal(t, db.DerivedAccount, accounts[0].Origin)
	require.Equal(t, uint32(0), accounts[0].AccountNumber)

	require.Equal(t, "derived-1", accounts[1].AccountName)
	require.Equal(t, db.DerivedAccount, accounts[1].Origin)
	require.Equal(t, uint32(1), accounts[1].AccountNumber)

	// Imported accounts should come last.
	require.Equal(t, db.ImportedAccount, accounts[2].Origin)
	require.Equal(t, db.ImportedAccount, accounts[3].Origin)
}

// TestAccountCreatedAtTimestamp verifies that accounts have their CreatedAt
// field properly set and that it reflects the order of account creation.
func TestAccountCreatedAtTimestamp(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "wallet-created-at")

	scope := db.KeyScopeBIP0084

	// Create three accounts with slight delays to ensure different
	// timestamps.
	var accounts []db.AccountInfo
	for i := range 3 {
		time.Sleep(1 * time.Second)
		params := db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    scope,
			Name:     fmt.Sprintf("account-%d", i),
		}
		info, err := store.CreateDerivedAccount(t.Context(), params)
		require.NoError(t, err)
		accounts = append(accounts, *info)
	}

	// Verify all accounts have CreatedAt populated.
	for i, acc := range accounts {
		require.False(t, acc.CreatedAt.IsZero(),
			"account %d should have CreatedAt set", i)
		require.WithinDuration(t, time.Now(), acc.CreatedAt, 5*time.Second,
			"account %d CreatedAt should be recent", i)
	}

	// Verify accounts are ordered by creation time.
	require.True(t, accounts[0].CreatedAt.Before(accounts[1].CreatedAt),
		"account 0 should have CreatedAt before account 1")
	require.True(t, accounts[1].CreatedAt.Before(accounts[2].CreatedAt),
		"account 1 should have CreatedAt before account 2")
}

// TestRenameAccount verifies that RenameAccount successfully renames accounts
// by name and by account number.
func TestRenameAccount(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "wallet-rename-account")

	scope := db.KeyScopeBIP0084

	// Create two accounts to rename. First account should get number 0.
	createDerivedAccount(t, store, walletID, scope, "original-name-1")
	createDerivedAccount(t, store, walletID, scope, "original-name-2")

	t.Run("rename by name", func(t *testing.T) {
		oldName := "original-name-1"
		newName := "renamed-by-name"

		err := store.RenameAccount(t.Context(), db.RenameAccountParams{
			WalletID: walletID,
			Scope:    scope,
			OldName:  oldName,
			NewName:  newName,
		})
		require.NoError(t, err)

		// Verify the rename worked.
		query := getAccountQueryByName(walletID, scope, newName)
		info, err := store.GetAccount(t.Context(), query)
		require.NoError(t, err)
		require.Equal(t, newName, info.AccountName)
		require.Equal(t, uint32(0), info.AccountNumber)

		// Verify the old name no longer exists.
		oldQuery := getAccountQueryByName(walletID, scope, oldName)
		_, err = store.GetAccount(t.Context(), oldQuery)
		require.ErrorIs(t, err, db.ErrAccountNotFound)
	})

	t.Run("rename by number", func(t *testing.T) {
		// First derived account has number 0.
		accNum := uint32(0)
		newName := "renamed-by-number"

		err := store.RenameAccount(t.Context(), db.RenameAccountParams{
			WalletID:      walletID,
			Scope:         scope,
			AccountNumber: &accNum,
			NewName:       newName,
		})
		require.NoError(t, err)

		// Verify the rename worked.
		query := getAccountQueryByNumber(walletID, scope, accNum)
		info, err := store.GetAccount(t.Context(), query)
		require.NoError(t, err)
		require.Equal(t, newName, info.AccountName)
	})
}

// TestRenameAccountErrors verifies that RenameAccount returns appropriate
// errors for invalid inputs and missing accounts.
func TestRenameAccountErrors(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletID := newWallet(t, store, "wallet-rename-account-errors")

	createAllAccounts(t, store, walletID)

	nonExistentName := "nonexistent"
	nonExistentNum := uint32(99999)

	tests := []struct {
		name    string
		params  db.RenameAccountParams
		wantErr error
	}{
		{
			name: "not found",
			params: db.RenameAccountParams{
				WalletID: walletID,
				Scope:    db.KeyScopeBIP0084,
				OldName:  nonExistentName,
				NewName:  "new-name",
			},
			wantErr: db.ErrAccountNotFound,
		},
		{
			name: "invalid - both set",
			params: db.RenameAccountParams{
				WalletID:      walletID,
				Scope:         db.KeyScopeBIP0084,
				OldName:       nonExistentName,
				AccountNumber: &nonExistentNum,
				NewName:       "new-name",
			},
			wantErr: db.ErrInvalidAccountQuery,
		},
		{
			name: "invalid - neither set",
			params: db.RenameAccountParams{
				WalletID: walletID,
				Scope:    db.KeyScopeBIP0084,
				NewName:  "new-name",
			},
			wantErr: db.ErrInvalidAccountQuery,
		},
		{
			name: "invalid - empty new name",
			params: db.RenameAccountParams{
				WalletID: walletID,
				Scope:    db.KeyScopeBIP0084,
				OldName:  nonExistentName,
				NewName:  "",
			},
			wantErr: db.ErrMissingAccountName,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := store.RenameAccount(t.Context(), tc.params)
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestCreateDerivedAccountMaxAccountNumber verifies that CreateDerivedAccount
// returns ErrMaxAccountNumberReached when the account number counter exceeds
// the maximum uint32 value.
func TestCreateDerivedAccountMaxAccountNumber(t *testing.T) {
	t.Parallel()

	store, queries := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-max-account")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "account-0")
	scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)
	SetLastAccountNumber(t, queries, scopeID, math.MaxUint32-1)

	// This should succeed with account_number = MaxUint32.
	info, err := store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    db.KeyScopeBIP0084,
			Name:     "account-max",
		},
	)
	require.NoError(t, err)
	require.Equal(t, uint32(math.MaxUint32), info.AccountNumber)

	// This should fail; the next allocation would be MaxUint32 + 1, which
	// overflows uint32.
	_, err = store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    db.KeyScopeBIP0084,
			Name:     "account-overflow",
		},
	)
	require.ErrorIs(t, err, db.ErrMaxAccountNumberReached)
}

// newWallet creates a new wallet with the given name using the provided
// store and returns its ID.
func newWallet(t *testing.T, store db.WalletStore, name string) uint32 {
	t.Helper()

	walletParams := CreateWalletParamsFixture(name)
	walletInfo, err := store.CreateWallet(t.Context(), walletParams)
	require.NoError(t, err)

	return walletInfo.ID
}

// createAllAccounts creates all accounts from AllAccountCases for the given
// wallet ID using the provided account store.
func createAllAccounts(t *testing.T, store db.AccountStore, walletID uint32) {
	t.Helper()

	for _, tc := range AllAccountCases {
		switch tc.Origin {
		case db.DerivedAccount:
			params := tc.DerivedParams(walletID)
			_, err := store.CreateDerivedAccount(t.Context(), params)
			require.NoError(t, err)

		case db.ImportedAccount:
			params := tc.ImportedParams(walletID)
			_, err := store.CreateImportedAccount(t.Context(), params)
			require.NoError(t, err)
		}
	}
}

// getAccountQueryByName creates a GetAccountQuery for looking up an account
// by name within a specific wallet and scope.
func getAccountQueryByName(walletID uint32, scope db.KeyScope,
	name string) db.GetAccountQuery {

	return db.GetAccountQuery{
		WalletID: walletID,
		Scope:    scope,
		Name:     &name,
	}
}

// getAccountQueryByNumber creates a GetAccountQuery for looking up an
// account by account number within a specific wallet and scope.
func getAccountQueryByNumber(walletID uint32, scope db.KeyScope,
	num uint32) db.GetAccountQuery {

	return db.GetAccountQuery{
		WalletID:      walletID,
		Scope:         scope,
		AccountNumber: &num,
	}
}

// createDerivedAccount creates a new derived account with the given name,
// scope, and wallet ID using the provided account store.
func createDerivedAccount(t *testing.T, store db.AccountStore, walletID uint32,
	scope db.KeyScope, name string) {

	t.Helper()

	_, err := store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    scope,
			Name:     name,
		},
	)
	require.NoError(t, err)
}

// createImportedAccount creates a new imported account with the given name,
// scope, and wallet ID using the provided account store. A random public key
// is generated for the account.
func createImportedAccount(t *testing.T, store db.AccountStore, walletID uint32,
	scope db.KeyScope, name string) {

	t.Helper()

	_, err := store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:           walletID,
			Name:               name,
			Scope:              scope,
			EncryptedPublicKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)
}

// requireAccountMatches asserts that the provided AccountInfo matches the
// expected AccountTestCase, including name, scope, origin, watch-only status,
// and creation timestamp.
func requireAccountMatches(t *testing.T, info *db.AccountInfo,
	tc AccountTestCase) {

	t.Helper()

	require.Equal(t, tc.Name, info.AccountName)
	require.Equal(t, tc.Scope, info.KeyScope)
	require.Equal(t, tc.Origin, info.Origin)
	require.Equal(t, tc.IsWatchOnly, info.IsWatchOnly)

	// Verify CreatedAt is populated and recent.
	require.False(t, info.CreatedAt.IsZero(), "CreatedAt should be set")
	require.WithinDuration(t, time.Now(), info.CreatedAt, 5*time.Second,
		"CreatedAt should be recent")
}

// requireAccountPropertiesMatches asserts that the provided AccountProperties
// matches the expected AccountTestCase, including name, scope, origin,
// watch-only status, and creation timestamp.
func requireAccountPropertiesMatches(t *testing.T, props *db.AccountProperties,
	tc AccountTestCase) {

	t.Helper()

	require.Equal(t, tc.Name, props.AccountName)
	require.Equal(t, tc.Scope, props.KeyScope)
	require.Equal(t, tc.Origin, props.Origin)
	require.Equal(t, tc.IsWatchOnly, props.IsWatchOnly)

	// Verify CreatedAt is populated and recent.
	require.False(t, props.CreatedAt.IsZero(), "CreatedAt should be set")
	require.WithinDuration(t, time.Now(), props.CreatedAt, 5*time.Second,
		"CreatedAt should be recent")
}

// findAccountInList searches for an account in the provided list that matches
// the expected AccountTestCase by name and scope. It fails the test if the
// account is not found.
func findAccountInList(t *testing.T, accounts []db.AccountInfo,
	tc AccountTestCase) db.AccountInfo {

	t.Helper()

	i := slices.IndexFunc(accounts, func(acc db.AccountInfo) bool {
		return acc.AccountName == tc.Name && acc.KeyScope == tc.Scope
	})
	require.GreaterOrEqual(t, i, 0, "expected account %s in list", tc.Name)

	return accounts[i]
}
