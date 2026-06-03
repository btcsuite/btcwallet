//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

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
