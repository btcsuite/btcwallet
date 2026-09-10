//go:build itest

package itest

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

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
			t.Context(),
			CreateWatchOnlyWalletParams("watch-only-account-insert"),
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

	t.Run(
		"watch-only empty-but-non-nil insert is rejected",
		func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)
			queries := store.Queries()

			walletInfo, err := store.CreateWallet(
				t.Context(),
				CreateWatchOnlyWalletParams("watch-only-account-empty"),
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

			scopeID := GetKeyScopeID(
				t, queries, walletInfo.ID, db.KeyScopeBIP0084,
			)
			accountID := GetAccountID(
				t, queries, scopeID, "watch-only-empty",
			)

			err = insertAccountSecretRaw(t, store.DB(), accountID, []byte{})
			require.Error(t, err)
			requireDriverConstraintError(t, err)
		},
	)

	t.Run("non-watch-only update succeeds", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)
		queries := store.Queries()
		walletID := newWallet(t, store, "spendable-account-secret")

		// CreateImportedAccount with EncryptedPrivateKey inserts the
		// secret row via the API path (the spendable wallet invariant
		// from ADR 0012 requires private-key material on imported
		// accounts), so the test exercises the trigger's UPDATE allow
		// path on the already-inserted row. The "insert is rejected"
		// subtests above cover the watch-only direction of the
		// trigger; this subtest covers the non-watch-only UPDATE path.
		props, err := store.CreateImportedAccount(
			t.Context(), db.CreateImportedAccountParams{
				WalletID:            walletID,
				Name:                "spendable-imported",
				Scope:               db.KeyScopeBIP0084,
				PublicKey:           RandomBytes(32),
				EncryptedPrivateKey: RandomBytes(32),
			},
		)
		require.NoError(t, err)
		require.False(t, props.IsWatchOnly)

		scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)
		accountID := GetAccountID(t, queries, scopeID, "spendable-imported")

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

			info, err := store.CreateDerivedAccount(
				t.Context(), tc.params, SpendableDeriveFn(),
			)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, info)
		})
	}
}

// TestCreateDerivedAccountPersistsNoChainSync verifies both policy values pass
// through the real SQL derived-account create and read paths unchanged.
func TestCreateDerivedAccountPersistsNoChainSync(t *testing.T) {
	t.Parallel()

	// Arrange: create one isolated wallet and two valid derived-account
	// requests that differ only in the policy value being persisted.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "derived-no-chain-sync")
	falseParams := db.CreateDerivedAccountParams{
		WalletID:    walletID,
		Scope:       db.KeyScopeBIP0084,
		Name:        "derived-policy-false",
		NoChainSync: false,
	}
	trueParams := falseParams
	trueParams.Name = "derived-policy-true"
	trueParams.NoChainSync = true

	// Act: create both accounts and independently reload each row through the
	// normal Store read path.
	createdFalse, createFalseErr := store.CreateDerivedAccount(
		t.Context(), falseParams, SpendableDeriveFn(),
	)
	createdTrue, createTrueErr := store.CreateDerivedAccount(
		t.Context(), trueParams, SpendableDeriveFn(),
	)
	loadedFalse, loadFalseErr := store.GetAccount(
		t.Context(), getAccountQueryByName(
			walletID, falseParams.Scope, falseParams.Name,
		),
	)
	loadedTrue, loadTrueErr := store.GetAccount(
		t.Context(), getAccountQueryByName(
			walletID, trueParams.Scope, trueParams.Name,
		),
	)

	// Assert: both creation results and both fresh reads retain their exact
	// values, covering the default and non-default policies equally.
	require.NoError(t, createFalseErr)
	require.NoError(t, createTrueErr)
	require.NoError(t, loadFalseErr)
	require.NoError(t, loadTrueErr)
	require.False(t, createdFalse.NoChainSync)
	require.True(t, createdTrue.NoChainSync)
	require.False(t, loadedFalse.NoChainSync)
	require.True(t, loadedTrue.NoChainSync)
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

	info, err := store.CreateDerivedAccount(
		t.Context(), params, SpendableDeriveFn(),
	)
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

	_, err := store.CreateDerivedAccount(
		t.Context(), params, SpendableDeriveFn(),
	)
	require.NoError(t, err)

	// Attempt to create second account with same name in same scope.
	_, err = store.CreateDerivedAccount(
		t.Context(), params, SpendableDeriveFn(),
	)

	require.ErrorIs(t, err, db.ErrAccountNameConflict)
	requireConstraintSQLError(t, err)
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

		info, err := store.CreateDerivedAccount(
			t.Context(), params, SpendableDeriveFn(),
		)
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

		info, err := store.CreateDerivedAccount(
			t.Context(), params, SpendableDeriveFn(),
		)
		require.NoError(t, err)
		require.Equal(t, uint32(i), accountNumberNotNil(t, info.AccountNumber),
			"account %d should have number %d", i, i)
	}
}

// TestCreateDerivedAccountMaxAccountNumber verifies that CreateDerivedAccount
// allocates the last valid account number and then reports overflow on the
// next allocation.
func TestCreateDerivedAccountMaxAccountNumber(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "max-account-wallet")

	// Arrange: create a derived account and seed the scope near the limit.
	createDerivedAccount(
		t, store, walletID, db.KeyScopeBIP0084, "seed-derived-account",
	)
	scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)
	CreateAccountWithNumber(
		t, queries, scopeID, db.MaxAccountNumber-1, "account-max-minus-one",
	)
	UpdateKeyScopeNextAccountNumber(t, store.DB(), scopeID, db.MaxAccountNumber)

	// Act: allocate the last valid account number.
	info, err := store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    db.KeyScopeBIP0084,
			Name:     "account-max",
		},
		SpendableDeriveFn(),
	)

	// Assert: the max allocation succeeds, and the next one fails.
	require.NoError(t, err)
	require.Equal(t, db.MaxAccountNumber,
		accountNumberNotNil(t, info.AccountNumber))

	_, err = store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    db.KeyScopeBIP0084,
			Name:     "account-overflow",
		},
		SpendableDeriveFn(),
	)
	require.ErrorIs(t, err, db.ErrMaxAccountNumberReached)
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
		number *uint32
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
				SpendableDeriveFn(),
			)
			if err != nil {
				resultCh <- createResult{err: err}
				return
			}

			resultCh <- createResult{
				number: info.AccountNumber,
			}
		}(i)
	}

	wg.Wait()
	close(resultCh)

	results := make([]uint32, 0, workers)
	for result := range resultCh {
		require.NoError(t, result.err)
		results = append(results, accountNumberNotNil(t, result.number))
	}

	require.Len(t, results, workers)

	// Verify all numbers are unique and sequential.
	sort.Slice(
		results, func(i, j int) bool {
			return results[i] < results[j]
		},
	)

	for i := range workers {
		require.Equal(t, uint32(i), results[i])
	}
}

// TestCreateDerivedAccountExactConcurrent verifies a sparse first account and
// competing exact/sequential requests share one monotonic allocation cursor.
func TestCreateDerivedAccountExactConcurrent(t *testing.T) {
	t.Parallel()

	// Arrange: use a new scope to prove sparse creation needs no fillers.
	store := NewTestStore(t)
	number := uint32(7)
	params := db.CreateDerivedAccountParams{
		WalletID:      newWallet(t, store, "exact-race"),
		Scope:         db.KeyScopeBIP0084,
		Name:          "sparse",
		AccountNumber: &number,
	}
	first, err := store.CreateDerivedAccount(
		t.Context(), params, SpendableDeriveFn(),
	)
	require.NoError(t, err)
	require.Equal(t, number, *first.AccountNumber)

	var count int

	err = store.DB().QueryRowContext(
		t.Context(), "SELECT count(*) FROM accounts",
	).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	type result struct {
		info  *db.AccountInfo
		err   error
		exact bool
	}

	results := make(chan result, 2)
	start := make(chan struct{})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// Act: release both bounded requests together. Buffered results let both
	// workers exit before the owner asserts outcomes; no worker calls FailNow.
	number++

	for i := range 2 {
		request := params

		request.Name = "racer-" + strconv.Itoa(i)
		if i == 1 {
			request.AccountNumber = nil
		}

		go func() {
			<-start

			info, err := store.CreateDerivedAccount(
				ctx, request, SpendableDeriveFn(),
			)
			results <- result{info, err, request.AccountNumber != nil}
		}()
	}

	close(start)

	outcomes := []result{<-results, <-results}

	// Assert: only exact allocation may lose to a number conflict. Every
	// success is unique and the next sequential allocation follows their max.
	seen := map[uint32]bool{7: true}

	largest := uint32(7)
	for _, outcome := range outcomes {
		if outcome.err != nil {
			require.True(t, outcome.exact)
			require.ErrorIs(t, outcome.err, db.ErrAccountNumberConflict)
			require.Nil(t, outcome.info)

			continue
		}

		n := *outcome.info.AccountNumber
		require.False(t, seen[n])
		seen[n] = true
		largest = max(largest, n)
	}

	params.AccountNumber = nil
	params.Name = "next"
	next, err := store.CreateDerivedAccount(
		t.Context(), params, SpendableDeriveFn(),
	)
	require.NoError(t, err)
	require.Equal(t, largest+1, *next.AccountNumber)
}
