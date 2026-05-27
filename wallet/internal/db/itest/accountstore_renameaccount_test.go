//go:build itest

package itest

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

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

	CreateImportedAccount(t, store, walletID, scope, name, false)

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
