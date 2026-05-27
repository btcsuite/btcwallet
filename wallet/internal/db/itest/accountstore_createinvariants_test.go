//go:build itest

package itest

import (
	"fmt"
	"strconv"
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
			info, err := store.CreateDerivedAccount(
				t.Context(), params, SpendableDeriveFn(),
			)
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

// TestAccountWalletIDImmutable verifies that raw account reparenting updates
// cannot change wallet ownership after insert.
func TestAccountWalletIDImmutable(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()

	sourceWalletID := newWallet(t, store, "account-wallet-immutable-source")
	targetWalletID := newWallet(t, store, "account-wallet-immutable-target")

	CreateImportedAccount(
		t, store, sourceWalletID, db.KeyScopeBIP0084, "source-imported",
		false,
	)
	createDerivedAccount(
		t, store, targetWalletID, db.KeyScopeBIP0084, "target-derived",
	)

	sourceScopeID := GetKeyScopeID(
		t, queries, sourceWalletID, db.KeyScopeBIP0084,
	)
	targetScopeID := GetKeyScopeID(
		t, queries, targetWalletID, db.KeyScopeBIP0084,
	)
	sourceAccountID := GetAccountID(
		t, queries, sourceScopeID, "source-imported",
	)

	err := reparentAccountRaw(
		t, store.DB(), sourceAccountID, targetWalletID, targetScopeID,
	)
	require.Error(t, err)
	requireDriverConstraintError(t, err)

	accountInfo, err := store.GetAccount(
		t.Context(), getAccountQueryByName(
			sourceWalletID, db.KeyScopeBIP0084, "source-imported",
		),
	)
	require.NoError(t, err)
	require.NotNil(t, accountInfo)
	require.Equal(t, "source-imported", accountInfo.AccountName)
	require.Equal(
		t, sourceAccountID,
		GetAccountID(t, queries, sourceScopeID, "source-imported"),
	)
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
		SpendableDeriveFn(),
	)
	require.NoError(t, err)
	require.Equal(t, uint32(0), first.AccountNumber)

	props, err := store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:            walletID,
			Scope:               db.KeyScopeBIP0084,
			Name:                "imported-account",
			PublicKey:           RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
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
		SpendableDeriveFn(),
	)
	require.NoError(t, err)
	require.Equal(t, uint32(1), second.AccountNumber)
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

				t.Helper()
				info, err := store.CreateDerivedAccount(
					t.Context(), db.CreateDerivedAccountParams{
						WalletID: walletID,
						Scope:    db.KeyScopeBIP0084,
						Name:     "drv-std",
					},
					SpendableDeriveFn(),
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

				t.Helper()
				info, err := store.CreateDerivedAccount(
					t.Context(), db.CreateDerivedAccountParams{
						WalletID: walletID,
						Scope:    db.KeyScopeBIP0084,
						Name:     "drv-wo",
					},
					SpendableDeriveFn(),
				)
				if err != nil {
					return false, err
				}

				return info.IsWatchOnly, nil
			},
		},
		{
			name: "standard wallet imported account with " +
				"private key is spendable",
			walletParams:  CreateWalletParamsFixture,
			wantWatchOnly: false,
			createAccountFn: func(t *testing.T, store db.AccountStore,
				walletID uint32) (bool, error) {

				t.Helper()
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
			name: "standard wallet imported account without " +
				"private key is rejected",
			walletParams: CreateWalletParamsFixture,
			wantErr:      db.ErrSpendableWalletNeedsAccountPrivKey,
			createAccountFn: func(t *testing.T, store db.AccountStore,
				walletID uint32) (bool, error) {

				t.Helper()
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
			name: "watch-only wallet imported account without " +
				"private key is watch-only",
			walletParams:  CreateWatchOnlyWalletParams,
			wantWatchOnly: true,
			createAccountFn: func(t *testing.T, store db.AccountStore,
				walletID uint32) (bool, error) {

				t.Helper()
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
			name: "watch-only wallet imported account with " +
				"private key is rejected",
			walletParams: CreateWatchOnlyWalletParams,
			wantErr:      db.ErrWatchOnlyViolation,
			createAccountFn: func(t *testing.T, store db.AccountStore,
				walletID uint32) (bool, error) {

				t.Helper()
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
			require.ErrorIs(t, err, tc.wantErr)

			if tc.wantErr != nil {
				return
			}

			require.Equal(t, tc.wantWatchOnly, isWatchOnly)
		})
	}
}
