//go:build itest

package itest

import (
	"context"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestGetAccountSecret verifies that GetAccountSecret returns account rows
// with encrypted private key material, watch-only nil material, and not-found
// errors as distinct outcomes.
func TestGetAccountSecret(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-account-secret")
	scope := db.KeyScopeBIP0084
	pubKey := []byte("derived-account-pubkey")
	privKey := []byte("encrypted-account-privkey")

	const fingerprint = uint32(0xAABBCCDD)

	derived, err := store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    scope,
			Name:     "derived",
		}, func(_ context.Context, _ db.KeyScope, _ uint32,
			walletIsWatchOnly bool) (*db.DerivedAccountData, error) {

			require.False(t, walletIsWatchOnly)

			return &db.DerivedAccountData{
				PublicKey:            pubKey,
				EncryptedPrivateKey:  privKey,
				MasterKeyFingerprint: fingerprint,
			}, nil
		},
	)
	require.NoError(t, err)

	secret, err := store.GetAccountSecret(
		t.Context(), db.GetAccountSecretQuery{
			WalletID:      walletID,
			Scope:         scope,
			AccountNumber: derived.AccountNumber,
		},
	)
	require.NoError(t, err)
	require.Equal(t, walletID, secret.WalletID)
	require.Equal(t, scope, secret.Scope)
	require.Equal(t, *derived.AccountNumber, secret.AccountNumber)
	require.Equal(t, "derived", secret.AccountName)
	require.Equal(t, pubKey, secret.PublicKey)
	require.Equal(t, privKey, secret.EncryptedPrivateKey)
	require.Equal(t, fingerprint, secret.MasterKeyFingerprint)

	watchOnlyName := "watch-only-import"
	watchOnlyWalletID := newWatchOnlyWallet(
		t, store, "watch-only-get-account-secret",
	)
	_, err = store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:  watchOnlyWalletID,
			Name:      watchOnlyName,
			Scope:     scope,
			PublicKey: []byte("watch-only-pubkey"),
		},
	)
	require.NoError(t, err)

	secret, err = store.GetAccountSecret(
		t.Context(), db.GetAccountSecretQuery{
			WalletID: watchOnlyWalletID,
			Scope:    scope,
			Name:     &watchOnlyName,
		},
	)
	require.NoError(t, err)
	require.Equal(t, watchOnlyName, secret.AccountName)
	require.Nil(t, secret.EncryptedPrivateKey)

	missing := uint32(999)
	_, err = store.GetAccountSecret(
		t.Context(), db.GetAccountSecretQuery{
			WalletID:      walletID,
			Scope:         scope,
			AccountNumber: &missing,
		},
	)
	require.ErrorIs(t, err, db.ErrAccountNotFound)
}
