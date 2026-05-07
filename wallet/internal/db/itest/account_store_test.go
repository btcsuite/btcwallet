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
	store := NewTestStore(t)

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
			require.NotEmpty(t, props.PublicKey)
		}
	}
}

// TestCreateDerivedAccountRejectsWalletScopeMismatch verifies that the
// composite wallet/scope invariant is enforced by the database on direct
// derived-account inserts.
func TestCreateDerivedAccountRejectsWalletScopeMismatch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	firstWalletID := newWallet(
		t, store, "wallet-raw-derived-account-mismatch-a",
	)
	secondWalletID := newWallet(
		t, store, "wallet-raw-derived-account-mismatch-b",
	)
	createDerivedAccount(
		t, store, firstWalletID, db.KeyScopeBIP0084, "seed-derived-scope",
	)

	firstScopeID := GetKeyScopeID(t, queries, firstWalletID, db.KeyScopeBIP0084)

	err := createDerivedAccountRaw(
		t, store.DB(), secondWalletID, firstScopeID, 0, "raw-derived-mismatch",
	)
	require.Error(t, err)
	require.ErrorContains(t, err, "constraint")
}

// TestCreateImportedAccountRejectsWalletScopeMismatch verifies that the
// composite wallet/scope invariant is enforced by the database on direct
// imported-account inserts.
func TestCreateImportedAccountRejectsWalletScopeMismatch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	firstWalletID := newWallet(
		t, store, "wallet-raw-imported-account-mismatch-a",
	)
	secondWalletID := newWallet(
		t, store, "wallet-raw-imported-account-mismatch-b",
	)
	CreateImportedAccount(
		t, store, firstWalletID, db.KeyScopeBIP0084, "seed-imported-scope",
	)

	firstScopeID := GetKeyScopeID(t, queries, firstWalletID, db.KeyScopeBIP0084)

	err := createImportedAccountRaw(
		t, store.DB(), secondWalletID, firstScopeID, "raw-imported-mismatch",
	)
	require.Error(t, err)
	require.ErrorContains(t, err, "constraint")
}

// TestWatchOnlyAccountSecretTriggers verifies that account_secrets rejects
// watch-only parent accounts while still allowing inserts and updates for
// non-watch-only parents.
func TestWatchOnlyAccountSecretTriggers(t *testing.T) {
	t.Parallel()

	t.Run("watch-only insert is rejected", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)
		queries := store.Queries()

		walletInfo, err := store.CreateWallet(
			t.Context(), CreateWatchOnlyWalletParams("watch-only-account-insert"),
		)
		require.NoError(t, err)

		props, err := store.CreateImportedAccount(
			t.Context(), db.CreateImportedAccountParams{
				WalletID:  walletInfo.ID,
				Name:      "watch-only-imported",
				Scope:     db.KeyScopeBIP0084,
				PublicKey: RandomBytes(32),
			},
		)
		require.NoError(t, err)
		require.True(t, props.IsWatchOnly)

		scopeID := GetKeyScopeID(t, queries, walletInfo.ID, db.KeyScopeBIP0084)
		accountID := GetAccountID(t, queries, scopeID, "watch-only-imported")

		err = insertAccountSecretRaw(
			t, store.DB(), accountID, RandomBytes(32),
		)
		require.Error(t, err)
		requireDriverConstraintError(t, err)
	})

	t.Run("watch-only empty-but-non-nil insert is rejected", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)
		queries := store.Queries()

		walletInfo, err := store.CreateWallet(
			t.Context(), CreateWatchOnlyWalletParams("watch-only-account-empty"),
		)
		require.NoError(t, err)

		props, err := store.CreateImportedAccount(
			t.Context(), db.CreateImportedAccountParams{
				WalletID:  walletInfo.ID,
				Name:      "watch-only-empty",
				Scope:     db.KeyScopeBIP0084,
				PublicKey: RandomBytes(32),
			},
		)
		require.NoError(t, err)
		require.True(t, props.IsWatchOnly)

		scopeID := GetKeyScopeID(t, queries, walletInfo.ID, db.KeyScopeBIP0084)
		accountID := GetAccountID(t, queries, scopeID, "watch-only-empty")

		err = insertAccountSecretRaw(t, store.DB(), accountID, []byte{})
		require.Error(t, err)
		requireDriverConstraintError(t, err)
	})

	t.Run("non-watch-only insert and update succeed", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)
		queries := store.Queries()
		walletID := newWallet(t, store, "spendable-account-secret")

		props, err := store.CreateImportedAccount(
			t.Context(), db.CreateImportedAccountParams{
				WalletID:  walletID,
				Name:      "spendable-imported",
				Scope:     db.KeyScopeBIP0084,
				PublicKey: RandomBytes(32),
			},
		)
		require.NoError(t, err)
		require.True(t, props.IsWatchOnly)

		scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)
		accountID := GetAccountID(t, queries, scopeID, "spendable-imported")

		err = insertAccountSecretRaw(
			t, store.DB(), accountID, RandomBytes(32),
		)
		require.NoError(t, err)

		err = updateAccountSecretRaw(
			t, store.DB(), accountID, RandomBytes(32),
		)
		require.NoError(t, err)
	})
}

// TestCreateDerivedAccountErrors verifies that CreateDerivedAccount returns
// appropriate errors for invalid inputs.
func TestCreateDerivedAccountErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		params  db.CreateDerivedAccountParams
		wantErr error
	}{
		{
			name: "missing name",
			params: db.CreateDerivedAccountParams{
				Scope: db.KeyScopeBIP0084,
				Name:  "",
			},
			wantErr: db.ErrMissingAccountName,
		},
		{
			name: "unknown scope",
			params: db.CreateDerivedAccountParams{
				Scope: db.KeyScope{Purpose: 999, Coin: 999},
				Name:  "unknown-scope-account",
			},
			wantErr: db.ErrUnknownKeyScope,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)
			walletID := newWallet(t, store, tc.name+"-wallet")
			tc.params.WalletID = walletID

			info, err := store.CreateDerivedAccount(t.Context(), tc.params)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, info)
		})
	}
}

// TestCreateDerivedAccountMissingWallet verifies that CreateDerivedAccount
// returns ErrWalletNotFound when the wallet does not exist.
func TestCreateDerivedAccountMissingWallet(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := db.CreateDerivedAccountParams{
		WalletID: 99999,
		Scope:    db.KeyScopeBIP0084,
		Name:     "missing-wallet-account",
	}

	info, err := store.CreateDerivedAccount(t.Context(), params)
	require.ErrorIs(t, err, db.ErrWalletNotFound)
	require.Nil(t, info)
}

// TestCreateDerivedAccountDuplicateName verifies that creating a derived
// account with a duplicate name in the same scope fails.
func TestCreateDerivedAccountDuplicateName(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	walletID := newWallet(t, store, "duplicate-name-wallet")

	params := db.CreateDerivedAccountParams{
		WalletID: walletID,
		Scope:    db.KeyScopeBIP0084,
		Name:     "duplicate-account",
	}

	_, err := store.CreateDerivedAccount(t.Context(), params)
	require.NoError(t, err)

	before := store.StatsSnapshot()

	// Attempt to create second account with same name in same scope.
	_, err = store.CreateDerivedAccount(t.Context(), params)
	require.Error(t, err)
	requireConstraintSQLError(t, err)

	after := store.StatsSnapshot()
	require.Equal(t, before.Unhealthy, after.Unhealthy)
	require.Equal(t, before.RetryAttempts, after.RetryAttempts)
	require.Equal(t, before.RetrySuccesses, after.RetrySuccesses)
	require.Equal(t, before.RetryExhausted, after.RetryExhausted)
	require.Equal(t, before.AmbiguousTxCommits, after.AmbiguousTxCommits)
	require.Equal(t, before.Errors.Backend, after.Errors.Backend)
	require.Equal(t, before.Errors.TotalErrs+1, after.Errors.TotalErrs)
	require.Equal(
		t,
		before.Errors.PermanentErrs+1,
		after.Errors.PermanentErrs,
	)
	require.Equal(t, before.Errors.Constraint+1, after.Errors.Constraint)
	require.Equal(t, before.Errors.TransientErrs, after.Errors.TransientErrs)
	require.Equal(t, before.Errors.FatalErrs, after.Errors.FatalErrs)
}

// TestCreateDerivedAccountSameNameDifferentScopes verifies that accounts with
// the same name can exist in different scopes.
func TestCreateDerivedAccountSameNameDifferentScopes(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

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

	store := NewTestStore(t)

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

// TestCreateDerivedAccountIgnoresImportedAccounts verifies that imported
// accounts do not consume the persisted next derived-account number.
func TestCreateDerivedAccountIgnoresImportedAccounts(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "mixed-account-number-wallet")

	first, err := store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    db.KeyScopeBIP0084,
			Name:     "derived-0",
		},
	)
	require.NoError(t, err)
	require.Equal(t, uint32(0), first.AccountNumber)

	props, err := store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:  walletID,
			Scope:     db.KeyScopeBIP0084,
			Name:      "imported-account",
			PublicKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)
	require.Equal(t, uint32(0), props.AccountNumber)

	second, err := store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    db.KeyScopeBIP0084,
			Name:     "derived-1",
		},
	)
	require.NoError(t, err)
	require.Equal(t, uint32(1), second.AccountNumber)
}

// TestCreateDerivedAccountConcurrent verifies that concurrent account creation
// yields unique, sequential account numbers without errors.
func TestCreateDerivedAccountConcurrent(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	walletID := newWallet(t, store, "concurrent-wallet")

	scope := db.KeyScopeBIP0084

	const workers = 20

	type createResult struct {
		number uint32
		err    error
	}

	resultCh := make(chan createResult, workers)

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
			if err != nil {
				resultCh <- createResult{err: err}
				return
			}

			resultCh <- createResult{number: info.AccountNumber}
		}(i)
	}

	wg.Wait()
	close(resultCh)

	results := make([]uint32, 0, workers)
	for result := range resultCh {
		require.NoError(t, result.err)
		results = append(results, result.number)
	}

	require.Len(t, results, workers)

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

	tests := []struct {
		name    string
		params  db.CreateImportedAccountParams
		wantErr error
	}{
		{
			name: "missing name",
			params: db.CreateImportedAccountParams{
				Name:      "",
				Scope:     db.KeyScopeBIP0084,
				PublicKey: RandomBytes(32),
			},
			wantErr: db.ErrMissingAccountName,
		},
		{
			name: "missing public key",
			params: db.CreateImportedAccountParams{
				Name:      "missing-pubkey",
				Scope:     db.KeyScopeBIP0084,
				PublicKey: nil,
			},
			wantErr: db.ErrMissingAccountPublicKey,
		},
		{
			name: "unknown scope",
			params: db.CreateImportedAccountParams{
				Name:      "unknown-scope",
				Scope:     db.KeyScope{Purpose: 999, Coin: 999},
				PublicKey: RandomBytes(32),
			},
			wantErr: db.ErrUnknownKeyScope,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)
			walletID := newWallet(t, store, tc.name+"-wallet")
			tc.params.WalletID = walletID

			props, err := store.CreateImportedAccount(t.Context(), tc.params)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, props)
		})
	}
}

// TestCreateImportedAccountMissingWallet verifies that CreateImportedAccount
// returns ErrWalletNotFound when the wallet does not exist.
func TestCreateImportedAccountMissingWallet(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := db.CreateImportedAccountParams{
		WalletID:  99999,
		Name:      "missing-wallet-imported",
		Scope:     db.KeyScopeBIP0084,
		PublicKey: RandomBytes(32),
	}

	props, err := store.CreateImportedAccount(t.Context(), params)
	require.ErrorIs(t, err, db.ErrWalletNotFound)
	require.Nil(t, props)
}

// TestCreateImportedAccountValidationPrecedesWalletLookup verifies that basic
// input validation still wins over wallet lookup failures.
func TestCreateImportedAccountValidationPrecedesWalletLookup(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	props, err := store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			WalletID:  99999,
			Name:      "",
			Scope:     db.KeyScopeBIP0084,
			PublicKey: RandomBytes(32),
		},
	)
	require.ErrorIs(t, err, db.ErrMissingAccountName)
	require.Nil(t, props)
}

// TestWatchOnlyHierarchyAccountRules is the canonical wallet-to-account
// watch-only matrix for derived and imported accounts.
func TestWatchOnlyHierarchyAccountRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		walletParams    func(string) db.CreateWalletParams
		wantWatchOnly   bool
		wantErr         error
		createAccountFn func(*testing.T, db.AccountStore, uint32) (bool, error)
	}{
		{
			name:          "standard wallet derived account is spendable",
			walletParams:  CreateWalletParamsFixture,
			wantWatchOnly: false,
			createAccountFn: func(t *testing.T, store db.AccountStore,
				walletID uint32) (bool, error) {

				info, err := store.CreateDerivedAccount(
					t.Context(), db.CreateDerivedAccountParams{
						WalletID: walletID,
						Scope:    db.KeyScopeBIP0084,
						Name:     "drv-std",
					},
				)
				if err != nil {
					return false, err
				}

				return info.IsWatchOnly, nil
			},
		},
		{
			name:          "watch-only wallet derived account is watch-only",
			walletParams:  CreateWatchOnlyWalletParams,
			wantWatchOnly: true,
			createAccountFn: func(t *testing.T, store db.AccountStore,
				walletID uint32) (bool, error) {

				info, err := store.CreateDerivedAccount(
					t.Context(), db.CreateDerivedAccountParams{
						WalletID: walletID,
						Scope:    db.KeyScopeBIP0084,
						Name:     "drv-wo",
					},
				)
				if err != nil {
					return false, err
				}

				return info.IsWatchOnly, nil
			},
		},
		{
			name:          "standard wallet imported account with private key is spendable",
			walletParams:  CreateWalletParamsFixture,
			wantWatchOnly: false,
			createAccountFn: func(t *testing.T, store db.AccountStore,
				walletID uint32) (bool, error) {

				props, err := store.CreateImportedAccount(
					t.Context(), db.CreateImportedAccountParams{
						WalletID:            walletID,
						Name:                db.DefaultImportedAccountName,
						Scope:               db.KeyScopeBIP0084,
						PublicKey:           RandomBytes(32),
						EncryptedPrivateKey: RandomBytes(32),
					},
				)
				if err != nil {
					return false, err
				}

				return props.IsWatchOnly, nil
			},
		},
		{
			name:          "standard wallet imported account without private key is watch-only",
			walletParams:  CreateWalletParamsFixture,
			wantWatchOnly: true,
			createAccountFn: func(t *testing.T, store db.AccountStore,
				walletID uint32) (bool, error) {

				props, err := store.CreateImportedAccount(
					t.Context(), db.CreateImportedAccountParams{
						WalletID:  walletID,
						Name:      db.DefaultImportedAccountName,
						Scope:     db.KeyScopeBIP0084,
						PublicKey: RandomBytes(32),
					},
				)
				if err != nil {
					return false, err
				}

				return props.IsWatchOnly, nil
			},
		},
		{
			name:          "watch-only wallet imported account without private key is watch-only",
			walletParams:  CreateWatchOnlyWalletParams,
			wantWatchOnly: true,
			createAccountFn: func(t *testing.T, store db.AccountStore,
				walletID uint32) (bool, error) {

				props, err := store.CreateImportedAccount(
					t.Context(), db.CreateImportedAccountParams{
						WalletID:  walletID,
						Name:      db.DefaultImportedAccountName,
						Scope:     db.KeyScopeBIP0084,
						PublicKey: RandomBytes(32),
					},
				)
				if err != nil {
					return false, err
				}

				return props.IsWatchOnly, nil
			},
		},
		{
			name:         "watch-only wallet imported account with private key is rejected",
			walletParams: CreateWatchOnlyWalletParams,
			wantErr:      db.ErrWatchOnlyViolation,
			createAccountFn: func(t *testing.T, store db.AccountStore,
				walletID uint32) (bool, error) {

				props, err := store.CreateImportedAccount(
					t.Context(), db.CreateImportedAccountParams{
						WalletID:            walletID,
						Name:                "hardware",
						Scope:               db.KeyScopeBIP0084,
						PublicKey:           RandomBytes(32),
						EncryptedPrivateKey: RandomBytes(32),
					},
				)
				if err != nil {
					return false, err
				}

				return props.IsWatchOnly, nil
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := NewTestStore(t)

			walletInfo, err := store.CreateWallet(
				t.Context(), tc.walletParams("watch-only-account-matrix"),
			)
			require.NoError(t, err)

			isWatchOnly, err := tc.createAccountFn(t, store, walletInfo.ID)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantWatchOnly, isWatchOnly)
		})
	}
}

// TestCreateImportedAccountDuplicateName verifies that creating an imported
// account with a duplicate name in the same scope fails.
func TestCreateImportedAccountDuplicateName(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	walletID := newWallet(t, store, "imported-duplicate-name-wallet")

	params := db.CreateImportedAccountParams{
		WalletID:  walletID,
		Name:      "duplicate-imported",
		Scope:     db.KeyScopeBIP0084,
		PublicKey: RandomBytes(32),
	}

	_, err := store.CreateImportedAccount(t.Context(), params)
	require.NoError(t, err)

	// Attempt to create second imported account with same name in same
	// scope.
	params.PublicKey = RandomBytes(32)
	_, err = store.CreateImportedAccount(t.Context(), params)
	require.Error(t, err)
	require.ErrorContains(t, err, "constraint")
}

// TestGetAccount verifies that GetAccount correctly retrieves accounts
// by name or account number.
func TestGetAccount(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

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

// TestGetAccountWatchOnlyMapping verifies that GetAccount preserves
// representative watch-only flags on read.
func TestGetAccountWatchOnlyMapping(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-watch")
	scope := db.KeyScopeBIP0084

	createDerivedAccount(t, store, walletID, scope, "derived")

	_, err := store.CreateImportedAccount(t.Context(), db.CreateImportedAccountParams{
		WalletID:  walletID,
		Name:      db.DefaultImportedAccountName,
		Scope:     scope,
		PublicKey: RandomBytes(32),
	})
	require.NoError(t, err)

	derived, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, "derived"),
	)
	require.NoError(t, err)
	require.False(t, derived.IsWatchOnly)

	imported, err := store.GetAccount(
		t.Context(), getAccountQueryByName(
			walletID, scope, db.DefaultImportedAccountName,
		),
	)
	require.NoError(t, err)
	require.True(t, imported.IsWatchOnly)
}

// TestGetAccountNotFound verifies that GetAccount returns ErrAccountNotFound
// when querying a non-existent account.
func TestGetAccountNotFound(t *testing.T) {
	t.Parallel()

	scope := db.KeyScopeBIP0084

	t.Run("by name", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)
		walletID := newWallet(t, store, "wallet-get-account-not-found-name")
		createAllAccounts(t, store, walletID)

		query := getAccountQueryByName(walletID, scope, "non-existent")
		info, err := store.GetAccount(t.Context(), query)
		require.ErrorIs(t, err, db.ErrAccountNotFound)
		require.Nil(t, info)
	})

	t.Run("by number", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)
		walletID := newWallet(t, store, "wallet-get-account-not-found-number")
		createAllAccounts(t, store, walletID)

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

	t.Run("all accounts", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)
		walletID := newWallet(t, store, "wallet-list-accounts-all")
		createAllAccounts(t, store, walletID)

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

		store := NewTestStore(t)
		walletID := newWallet(t, store, "wallet-list-accounts-scope")
		createAllAccounts(t, store, walletID)

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

		store := NewTestStore(t)
		walletID := newWallet(t, store, "wallet-list-accounts-name")
		createAllAccounts(t, store, walletID)

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

		store := NewTestStore(t)

		// Create a new wallet with no accounts.
		emptyWalletID := newWallet(t, store, "wallet-list-empty")
		query := db.ListAccountsQuery{WalletID: emptyWalletID}
		accounts, err := store.ListAccounts(t.Context(), query)
		require.NoError(t, err)
		require.Empty(t, accounts)
	})
}

// TestListAccountsWatchOnlyMapping verifies that ListAccounts preserves
// representative watch-only flags on read.
func TestListAccountsWatchOnlyMapping(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-watch")
	scope := db.KeyScopeBIP0084

	createDerivedAccount(t, store, walletID, scope, "derived")

	_, err := store.CreateImportedAccount(t.Context(), db.CreateImportedAccountParams{
		WalletID:  walletID,
		Name:      db.DefaultImportedAccountName,
		Scope:     scope,
		PublicKey: RandomBytes(32),
	})
	require.NoError(t, err)

	accounts, err := store.ListAccounts(t.Context(), db.ListAccountsQuery{
		WalletID: walletID,
		Scope:    &scope,
	})
	require.NoError(t, err)

	derived := findAccountInList(t, accounts, AccountTestCase{
		Name:  "derived",
		Scope: scope,
	})
	imported := findAccountInList(t, accounts, AccountTestCase{
		Name:  db.DefaultImportedAccountName,
		Scope: scope,
	})

	require.False(t, derived.IsWatchOnly)
	require.True(t, imported.IsWatchOnly)
}

// TestListAccountsOrdering verifies that ListAccounts returns derived accounts
// ordered by account number, with imported accounts (NULL account_number) last.
func TestListAccountsOrdering(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	walletID := newWallet(t, store, "wallet-list-ordering")

	scope := db.KeyScopeBIP0084

	// Create accounts in mixed order: imported, derived, imported, derived.
	CreateImportedAccount(t, store, walletID, scope, "imported-first")
	createDerivedAccount(t, store, walletID, scope, "derived-0")
	CreateImportedAccount(t, store, walletID, scope, "imported-second")
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

	store := NewTestStore(t)

	walletID := newWallet(t, store, "wallet-created-at")

	scope := db.KeyScopeBIP0084

	type createdAccount struct {
		info        db.AccountInfo
		createdNear time.Time
	}

	accounts := make([]createdAccount, 0, 3)
	for i := range 3 {
		createdNear := time.Now()
		params := db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    scope,
			Name:     fmt.Sprintf("account-%d", i),
		}
		info, err := store.CreateDerivedAccount(t.Context(), params)
		require.NoError(t, err)

		accounts = append(accounts, createdAccount{
			info:        *info,
			createdNear: createdNear,
		})
	}

	// Verify all accounts have CreatedAt populated.
	for i, acc := range accounts {
		require.False(t, acc.info.CreatedAt.IsZero(),
			"account %d should have CreatedAt set", i)
		require.WithinDuration(t, acc.createdNear, acc.info.CreatedAt,
			5*time.Second, "account %d CreatedAt should track creation", i)
	}

	require.False(
		t, accounts[0].info.CreatedAt.After(accounts[1].info.CreatedAt),
		"account 0 should not have CreatedAt after account 1")
	require.False(
		t, accounts[1].info.CreatedAt.After(accounts[2].info.CreatedAt),
		"account 1 should not have CreatedAt after account 2")
}

// TestRenameAccount verifies that RenameAccount successfully renames accounts
// by name and by account number.
func TestRenameAccount(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

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

	accountNumber := uint32(99999)
	accountPointer := &accountNumber

	tests := []struct {
		name    string
		params  db.RenameAccountParams
		wantErr error
	}{
		{
			name: "not found",
			params: db.RenameAccountParams{
				Scope:   db.KeyScopeBIP0084,
				OldName: "nonexistent",
				NewName: "new-name",
			},
			wantErr: db.ErrAccountNotFound,
		},
		{
			name: "invalid - both set",
			params: db.RenameAccountParams{
				Scope:         db.KeyScopeBIP0084,
				OldName:       "nonexistent",
				AccountNumber: accountPointer,
				NewName:       "new-name",
			},
			wantErr: db.ErrInvalidAccountQuery,
		},
		{
			name: "invalid - neither set",
			params: db.RenameAccountParams{
				Scope:   db.KeyScopeBIP0084,
				NewName: "new-name",
			},
			wantErr: db.ErrInvalidAccountQuery,
		},
		{
			name: "invalid - empty new name",
			params: db.RenameAccountParams{
				Scope:   db.KeyScopeBIP0084,
				OldName: "nonexistent",
				NewName: "",
			},
			wantErr: db.ErrMissingAccountName,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)
			walletID := newWallet(t, store, "wallet-rename-account-errors")
			createAllAccounts(t, store, walletID)
			tc.params.WalletID = walletID

			err := store.RenameAccount(t.Context(), tc.params)
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestCreateDerivedAccountMaxAccountNumber verifies that accounts can be
// created up to the maximum account number (math.MaxUint32), but the next
// account creation fails due to overflow.
func TestCreateDerivedAccountMaxAccountNumber(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	dbConn := store.DB()
	walletID := newWallet(t, store, "wallet-max-account")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "account-0")

	scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)

	CreateAccountWithNumber(t, queries, scopeID, math.MaxUint32-1,
		"account-near-max")

	// Set the counter to MaxUint32 so the next allocation gives us MaxUint32
	UpdateKeyScopeNextAccountNumber(t, dbConn, scopeID, math.MaxUint32)

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

// CreateImportedAccount creates a new imported account with the given name,
// scope, and wallet ID using the provided account store. A random public key
// is generated for the account.
func CreateImportedAccount(t *testing.T, store db.AccountStore, walletID uint32,
	scope db.KeyScope, name string) {

	t.Helper()

	_, err := store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:  walletID,
			Name:      name,
			Scope:     scope,
			PublicKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)
}

// requireAccountMatches asserts that the provided AccountInfo matches the
// expected AccountTestCase's core identity fields and creation timestamp.
func requireAccountMatches(t *testing.T, info *db.AccountInfo,
	tc AccountTestCase) {

	t.Helper()

	require.Equal(t, tc.Name, info.AccountName)
	require.Equal(t, tc.Scope, info.KeyScope)
	require.Equal(t, tc.Origin, info.Origin)

	// Verify CreatedAt is populated and not in the future. The account may
	// have been created several seconds earlier in the test when parallel
	// database setup runs under the race detector, so a strict "recent"
	// assertion here is unnecessarily flaky.
	require.False(t, info.CreatedAt.IsZero(), "CreatedAt should be set")
	require.False(t, info.CreatedAt.After(time.Now().Add(5*time.Second)),
		"CreatedAt should not be in the future")
}

// requireAccountPropertiesMatches asserts that the provided AccountProperties
// matches the expected AccountTestCase's core identity fields and creation
// timestamp.
func requireAccountPropertiesMatches(t *testing.T, props *db.AccountProperties,
	tc AccountTestCase) {

	t.Helper()

	require.Equal(t, tc.Name, props.AccountName)
	require.Equal(t, tc.Scope, props.KeyScope)
	require.Equal(t, tc.Origin, props.Origin)

	// Verify CreatedAt is populated and not in the future. Imported-account
	// test fixtures can be created well before these assertions run under
	// heavy CI contention, so only the forward-time invariant is stable here.
	require.False(t, props.CreatedAt.IsZero(), "CreatedAt should be set")
	require.False(t, props.CreatedAt.After(time.Now().Add(5*time.Second)),
		"CreatedAt should not be in the future")
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
