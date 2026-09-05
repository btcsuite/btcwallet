//go:build itest

package itest

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

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
		false,
	)

	firstScopeID := GetKeyScopeID(t, queries, firstWalletID, db.KeyScopeBIP0084)

	err := createImportedAccountRaw(
		t, store.DB(), secondWalletID, firstScopeID, "raw-imported-mismatch",
	)
	require.Error(t, err)
	require.ErrorContains(t, err, "constraint")
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
				Name:                "",
				Scope:               db.KeyScopeBIP0084,
				PublicKey:           RandomBytes(32),
				EncryptedPrivateKey: RandomBytes(32),
			},
			wantErr: db.ErrMissingAccountName,
		},
		{
			name: "missing public key",
			params: db.CreateImportedAccountParams{
				Name:                "missing-pubkey",
				Scope:               db.KeyScopeBIP0084,
				PublicKey:           nil,
				EncryptedPrivateKey: RandomBytes(32),
			},
			wantErr: db.ErrMissingAccountPublicKey,
		},
		{
			name: "unknown scope",
			params: db.CreateImportedAccountParams{
				Name:                "unknown-scope",
				Scope:               db.KeyScope{Purpose: 999, Coin: 999},
				PublicKey:           RandomBytes(32),
				EncryptedPrivateKey: RandomBytes(32),
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
		WalletID:            99999,
		Name:                "missing-wallet-imported",
		Scope:               db.KeyScopeBIP0084,
		PublicKey:           RandomBytes(32),
		EncryptedPrivateKey: RandomBytes(32),
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
			WalletID:            99999,
			Name:                "",
			Scope:               db.KeyScopeBIP0084,
			PublicKey:           RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
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
		WalletID:            walletID,
		Name:                "duplicate-imported",
		Scope:               db.KeyScopeBIP0084,
		PublicKey:           RandomBytes(32),
		EncryptedPrivateKey: RandomBytes(32),
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
