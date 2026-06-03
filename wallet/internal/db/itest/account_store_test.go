//go:build itest

package itest

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)



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

	before := store.StatsSnapshot()

	// Attempt to create second account with same name in same scope.
	_, err = store.CreateDerivedAccount(
		t.Context(), params, SpendableDeriveFn(),
	)
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
		require.Equal(t, uint32(i), info.AccountNumber,
			"account %d should have number %d", i, i)
	}
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
				SpendableDeriveFn(),
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
	sort.Slice(
		results, func(i, j int) bool {
			return results[i] < results[j]
		},
	)

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

	props, err := store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:  99999,
			Name:      "",
			Scope:     db.KeyScopeBIP0084,
			PublicKey: RandomBytes(32),
		},
	)
	require.ErrorIs(t, err, db.ErrMissingAccountName)
	require.Nil(t, props)
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

		t.Run(
			"by name-"+tc.Name, func(t *testing.T) {
				query := getAccountQueryByName(walletID, tc.Scope, tc.Name)
				info, err := store.GetAccount(t.Context(), query)
				require.NoError(t, err)
				require.NotNil(t, info)
				requireAccountMatches(t, info, tc)
				accNumber = info.AccountNumber
			},
		)

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
			},
		)
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

	_, err := store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:  walletID,
			Name:      db.DefaultImportedAccountName,
			Scope:     scope,
			PublicKey: RandomBytes(32),
		},
	)
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

// TestGetAccountReturnsPublicKeyAndFingerprint verifies that derived and
// imported accounts re-read through GetAccount carry the public key and
// master fingerprint that were persisted at creation. Regression test
// for the pre-fix gap where AccountRowToInfo passed `nil, 0` for both
// fields on the lightweight read path.
func TestGetAccountReturnsPublicKeyAndFingerprint(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-pubkey-roundtrip")
	scope := db.KeyScopeBIP0084

	derived, err := store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    scope,
			Name:     "derived",
		}, SpendableDeriveFn(),
	)
	require.NoError(t, err)
	require.NotEmpty(t, derived.PublicKey)
	require.NotZero(t, derived.MasterKeyFingerprint)

	derivedRead, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, "derived"),
	)
	require.NoError(t, err)
	require.Equal(t, derived.PublicKey, derivedRead.PublicKey)
	require.Equal(t,
		derived.MasterKeyFingerprint, derivedRead.MasterKeyFingerprint,
	)

	importedPubKey := RandomBytes(32)
	_, err = store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:  walletID,
			Name:      "imported",
			Scope:     scope,
			PublicKey: importedPubKey,
		},
	)
	require.NoError(t, err)

	importedRead, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, "imported"),
	)
	require.NoError(t, err)
	require.Equal(t, importedPubKey, importedRead.PublicKey)
}

// TestListAccountsReturnsPublicKey verifies that the bulk read path
// also surfaces the persisted PublicKey on every returned account.
func TestListAccountsReturnsPublicKey(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-pubkey-list")
	scope := db.KeyScopeBIP0084

	createDerivedAccount(t, store, walletID, scope, "first")
	createDerivedAccount(t, store, walletID, scope, "second")

	accounts, err := store.ListAccounts(
		t.Context(), db.ListAccountsQuery{
			WalletID: walletID,
			Scope:    &scope,
		},
	)
	require.NoError(t, err)
	require.NotEmpty(t, accounts)

	for _, acc := range accounts {
		require.NotEmpty(t, acc.PublicKey, acc.AccountName)
	}
}

// TestGetAccountPopulatesBalance verifies that GetAccount returns the
// confirmed and unconfirmed UTXO totals on the AccountInfo, sourced from
// the dedicated AccountBalance query that the adapter dispatches
// alongside the account row fetch.
func TestGetAccountPopulatesBalance(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-balance")
	scope := db.KeyScopeBIP0084

	queries := store.Queries()
	syncBlock := CreateBlockFixture(t, queries, 200)
	confirmedBlock := CreateBlockFixture(t, queries, 100)

	err := store.UpdateWallet(
		t.Context(), db.UpdateWalletParams{
			WalletID: walletID,
			SyncedTo: &syncBlock,
		},
	)
	require.NoError(t, err)

	createDerivedAccount(t, store, walletID, scope, "funded")
	createDerivedAccount(t, store, walletID, scope, "empty")

	addr := newDerivedAddress(t, store, walletID, scope, "funded", false)

	confirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 24000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(
		t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       confirmedTx,
			Received: time.Unix(1710000000, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	unconfirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 26000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(
		t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       unconfirmedTx,
			Received: time.Unix(1710000100, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	funded, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, "funded"),
	)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(24000), funded.ConfirmedBalance)
	require.Equal(t, btcutil.Amount(26000), funded.UnconfirmedBalance)

	byNumber, err := store.GetAccount(
		t.Context(),
		getAccountQueryByNumber(walletID, scope, funded.AccountNumber),
	)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(24000), byNumber.ConfirmedBalance)
	require.Equal(t, btcutil.Amount(26000), byNumber.UnconfirmedBalance)

	empty, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, "empty"),
	)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(0), empty.ConfirmedBalance)
	require.Equal(t, btcutil.Amount(0), empty.UnconfirmedBalance)
}

// TestGetAccountSkipBalanceZerosFields verifies that GetAccount with
// SkipBalance=true skips the dedicated AccountBalance dispatch on both
// the by-name and by-number selectors and leaves the balance fields at
// zero even when UTXOs exist on the account.
func TestGetAccountSkipBalanceZerosFields(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-balance-skip")
	scope := db.KeyScopeBIP0084

	queries := store.Queries()
	syncBlock := CreateBlockFixture(t, queries, 200)
	confirmedBlock := CreateBlockFixture(t, queries, 100)

	err := store.UpdateWallet(
		t.Context(), db.UpdateWalletParams{
			WalletID: walletID,
			SyncedTo: &syncBlock,
		},
	)
	require.NoError(t, err)

	createDerivedAccount(t, store, walletID, scope, "funded")

	addr := newDerivedAddress(t, store, walletID, scope, "funded", false)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 24000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(
		t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000200, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	byNameQuery := getAccountQueryByName(walletID, scope, "funded")
	byNameQuery.SkipBalance = true

	infoByName, err := store.GetAccount(t.Context(), byNameQuery)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(0), infoByName.ConfirmedBalance)
	require.Equal(t, btcutil.Amount(0), infoByName.UnconfirmedBalance)

	byNumberQuery := getAccountQueryByNumber(
		walletID, scope, infoByName.AccountNumber,
	)
	byNumberQuery.SkipBalance = true

	infoByNumber, err := store.GetAccount(t.Context(), byNumberQuery)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(0), infoByNumber.ConfirmedBalance)
	require.Equal(t, btcutil.Amount(0), infoByNumber.UnconfirmedBalance)
}

// TestListAccountsPopulatesBalance verifies that ListAccounts returns
// confirmed/unconfirmed totals on every returned AccountInfo, sourced
// from the AccountBalances batch query dispatched alongside the row
// fetch.
func TestListAccountsPopulatesBalance(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-balance")
	scope := db.KeyScopeBIP0084

	queries := store.Queries()
	syncBlock := CreateBlockFixture(t, queries, 200)
	confirmedBlock := CreateBlockFixture(t, queries, 100)

	err := store.UpdateWallet(
		t.Context(), db.UpdateWalletParams{
			WalletID: walletID,
			SyncedTo: &syncBlock,
		},
	)
	require.NoError(t, err)

	createDerivedAccount(t, store, walletID, scope, "first")
	createDerivedAccount(t, store, walletID, scope, "second")
	createDerivedAccount(t, store, walletID, scope, "empty")

	firstAddr := newDerivedAddress(t, store, walletID, scope, "first", false)
	secondAddr := newDerivedAddress(
		t, store, walletID, scope, "second", false,
	)

	firstTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 12000, PkScript: firstAddr.ScriptPubKey}},
	)
	err = store.CreateTx(
		t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       firstTx,
			Received: time.Unix(1710000200, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	secondTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: secondAddr.ScriptPubKey}},
	)
	err = store.CreateTx(
		t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       secondTx,
			Received: time.Unix(1710000300, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	verify := func(t *testing.T,
		accounts []db.AccountInfo, label string) {

		t.Helper()

		byName := make(map[string]db.AccountInfo, len(accounts))
		for _, acc := range accounts {
			byName[acc.AccountName] = acc
		}

		require.Contains(t, byName, "first", label)
		require.Equal(t, btcutil.Amount(12000),
			byName["first"].ConfirmedBalance, label+": first")
		require.Equal(t, btcutil.Amount(0),
			byName["first"].UnconfirmedBalance, label+": first")

		require.Contains(t, byName, "second", label)
		require.Equal(t, btcutil.Amount(0),
			byName["second"].ConfirmedBalance, label+": second")
		require.Equal(t, btcutil.Amount(7000),
			byName["second"].UnconfirmedBalance, label+": second")

		require.Contains(t, byName, "empty", label)
		require.Equal(t, btcutil.Amount(0),
			byName["empty"].ConfirmedBalance, label+": empty")
		require.Equal(t, btcutil.Amount(0),
			byName["empty"].UnconfirmedBalance, label+": empty")
	}

	byScope, err := store.ListAccounts(
		t.Context(), db.ListAccountsQuery{
			WalletID: walletID,
			Scope:    &scope,
		},
	)
	require.NoError(t, err)
	verify(t, byScope, "by scope")

	all, err := store.ListAccounts(
		t.Context(), db.ListAccountsQuery{
			WalletID: walletID,
		},
	)
	require.NoError(t, err)
	verify(t, all, "all")
}

// TestListAccountsSkipBalanceZerosFields verifies that ListAccounts with
// SkipBalance=true skips the AccountBalances dispatch on each of the
// three list selectors (scope-filtered, name-filtered, unfiltered) and
// returns zero balance fields even when UTXOs exist.
func TestListAccountsSkipBalanceZerosFields(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-skip-balance")
	scope := db.KeyScopeBIP0084

	queries := store.Queries()
	syncBlock := CreateBlockFixture(t, queries, 200)
	confirmedBlock := CreateBlockFixture(t, queries, 100)

	err := store.UpdateWallet(
		t.Context(), db.UpdateWalletParams{
			WalletID: walletID,
			SyncedTo: &syncBlock,
		},
	)
	require.NoError(t, err)

	createDerivedAccount(t, store, walletID, scope, "funded")

	addr := newDerivedAddress(t, store, walletID, scope, "funded", false)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 9000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(
		t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000400, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	verify := func(t *testing.T,
		accounts []db.AccountInfo, label string) {

		t.Helper()

		require.NotEmpty(t, accounts, label)

		found := false
		for _, acc := range accounts {
			if acc.AccountName == "funded" {
				found = true
			}

			require.Equal(t, btcutil.Amount(0),
				acc.ConfirmedBalance,
				label+": "+acc.AccountName)
			require.Equal(t, btcutil.Amount(0),
				acc.UnconfirmedBalance,
				label+": "+acc.AccountName)
		}

		require.True(t, found,
			label+": funded account missing from result")
	}

	byScope, err := store.ListAccounts(
		t.Context(), db.ListAccountsQuery{
			WalletID:    walletID,
			Scope:       &scope,
			SkipBalance: true,
		},
	)
	require.NoError(t, err)
	verify(t, byScope, "by scope")

	name := "funded"
	byName, err := store.ListAccounts(
		t.Context(), db.ListAccountsQuery{
			WalletID:    walletID,
			Name:        &name,
			SkipBalance: true,
		},
	)
	require.NoError(t, err)
	verify(t, byName, "by name")

	all, err := store.ListAccounts(
		t.Context(), db.ListAccountsQuery{
			WalletID:    walletID,
			SkipBalance: true,
		},
	)
	require.NoError(t, err)
	verify(t, all, "all")
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

	_, err := store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:  walletID,
			Name:      db.DefaultImportedAccountName,
			Scope:     scope,
			PublicKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)

	accounts, err := store.ListAccounts(
		t.Context(), db.ListAccountsQuery{
			WalletID: walletID,
			Scope:    &scope,
		},
	)
	require.NoError(t, err)

	derived := findAccountInList(
		t, accounts, AccountTestCase{
			Name:  "derived",
			Scope: scope,
		},
	)
	imported := findAccountInList(
		t, accounts, AccountTestCase{
			Name:  db.DefaultImportedAccountName,
			Scope: scope,
		},
	)

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

		err := store.RenameAccount(
			t.Context(), db.RenameAccountParams{
				WalletID: walletID,
				Scope:    scope,
				OldName:  oldName,
				NewName:  newName,
			},
		)
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

		err := store.RenameAccount(
			t.Context(), db.RenameAccountParams{
				WalletID:      walletID,
				Scope:         scope,
				AccountNumber: &accNum,
				NewName:       newName,
			},
		)
		require.NoError(t, err)

		// Verify the rename worked.
		query := getAccountQueryByNumber(walletID, scope, accNum)
		info, err := store.GetAccount(t.Context(), query)
		require.NoError(t, err)
		require.Equal(t, newName, info.AccountName)
	})
}

// TestRenameAccountRejectsImported verifies that imported accounts cannot be
// renamed through the account store.
func TestRenameAccountRejectsImported(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-rename-imported")
	scope := db.KeyScopeBIP0084
	name := "imported-rename"

	CreateImportedAccount(t, store, walletID, scope, name)

	err := store.RenameAccount(t.Context(), db.RenameAccountParams{
		WalletID: walletID,
		Scope:    scope,
		OldName:  name,
		NewName:  "renamed-imported",
	})
	require.ErrorIs(t, err, db.ErrAccountNotFound)

	info, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, name),
	)
	require.NoError(t, err)
	require.Equal(t, name, info.AccountName)

	_, err = store.GetAccount(
		t.Context(), getAccountQueryByName(
			walletID, scope, "renamed-imported",
		),
	)
	require.ErrorIs(t, err, db.ErrAccountNotFound)
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
// created up to the wallet-compatible maximum account number, but the next
// account creation fails.
func TestCreateDerivedAccountMaxAccountNumber(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	dbConn := store.DB()
	walletID := newWallet(t, store, "wallet-max-account")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "account-0")

	scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)

	CreateAccountWithNumber(t, queries, scopeID, db.MaxAccountNumber-1,
		"account-near-max")

	// Set the counter to MaxAccountNumber so the next allocation gives us
	// the highest account number that the wallet can derive safely.
	UpdateKeyScopeNextAccountNumber(t, dbConn, scopeID, db.MaxAccountNumber)

	// This should succeed with account_number = MaxAccountNumber.
	info, err := store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    db.KeyScopeBIP0084,
			Name:     "account-max",
		},
		SpendableDeriveFn(),
	)
	require.NoError(t, err)
	require.Equal(t, db.MaxAccountNumber, info.AccountNumber)

	// This should fail; the next allocation would collide with the legacy
	// imported-account child reserved above MaxAccountNumber.
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
			_, err := store.CreateDerivedAccount(
				t.Context(), params, SpendableDeriveFn(),
			)
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
		SpendableDeriveFn(),
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

// requireAccountPropertiesMatches asserts that the provided AccountInfo
// matches the expected AccountTestCase's core identity fields and creation
// timestamp.
func requireAccountPropertiesMatches(t *testing.T, props *db.AccountInfo,
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

	i := slices.IndexFunc(
		accounts, func(acc db.AccountInfo) bool {
			return acc.AccountName == tc.Name && acc.KeyScope == tc.Scope
		},
	)
	require.GreaterOrEqual(t, i, 0, "expected account %s in list", tc.Name)

	return accounts[i]
}
