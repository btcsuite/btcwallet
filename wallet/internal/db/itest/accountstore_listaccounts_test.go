//go:build itest

package itest

import (
	"slices"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/wire/v2"
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
			if acc.AccountName == fundedAccountName {
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

	name := fundedAccountName
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
			WalletID:            walletID,
			Name:                "imported-xpub",
			Scope:               scope,
			PublicKey:           RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
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
			Name:  "imported-xpub",
			Scope: scope,
		},
	)

	require.False(t, derived.IsWatchOnly)
	// ADR 0012: an imported account on a spendable wallet carries
	// private-key material, so it inherits the wallet's spendable state.
	require.False(t, imported.IsWatchOnly)
}

// TestListAccountsOrdering verifies that ListAccounts returns derived accounts
// ordered by account number, with imported accounts (NULL account_number) last.
func TestListAccountsOrdering(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	walletID := newWallet(t, store, "wallet-list-ordering")

	scope := db.KeyScopeBIP0084

	// Create accounts in mixed order: imported, derived, imported, derived.
	CreateImportedAccount(t, store, walletID, scope, "imported-first", false)
	createDerivedAccount(t, store, walletID, scope, "derived-0")
	CreateImportedAccount(t, store, walletID, scope, "imported-second", false)
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
	require.False(t, accounts[0].IsImported)
	require.Equal(
		t, uint32(0), accountNumberValue(t, accounts[0].AccountNumber),
	)

	require.Equal(t, "derived-1", accounts[1].AccountName)
	require.False(t, accounts[1].IsImported)
	require.Equal(
		t, uint32(1), accountNumberValue(t, accounts[1].AccountNumber),
	)

	// Imported accounts should come last.
	require.True(t, accounts[2].IsImported)
	require.True(t, accounts[3].IsImported)
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
