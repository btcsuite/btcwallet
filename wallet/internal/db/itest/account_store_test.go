//go:build itest

package itest

import (
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

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
			Credits:  map[uint32]btcutil.Address{0: nil},
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
			Credits:  map[uint32]btcutil.Address{0: nil},
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
			Credits:  map[uint32]btcutil.Address{0: nil},
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

||||||| parent of f535f020 (wallet: split itest ListAccounts tests)

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
			Credits:  map[uint32]btcutil.Address{0: nil},
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
			Credits:  map[uint32]btcutil.Address{0: nil},
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
			Credits:  map[uint32]btcutil.Address{0: nil},
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
		info, err := store.CreateDerivedAccount(
			t.Context(), params, SpendableDeriveFn(),
		)
		require.NoError(t, err)

		accounts = append(
			accounts, createdAccount{
				info:        *info,
				createdNear: createdNear,
			},
		)
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
