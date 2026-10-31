//go:build itest

package itest

import (
	"context"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// derivedAccountName is the derived-account name the account-secret tests use.
const derivedAccountName = "derived"

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
			Name:     derivedAccountName,
		}, func(_ context.Context, _ db.KeyScope, _ uint32,
			walletIsWatchOnly bool) (*db.DerivedAccountData,
			error) {

			require.False(t, walletIsWatchOnly)

			return &db.DerivedAccountData{
				PublicKey:            pubKey,
				EncryptedPrivateKey:  privKey,
				MasterKeyFingerprint: fingerprint,
			}, nil
		},
	)
	require.NoError(t, err)

	require.NotNil(t, derived.AccountNumber,
		"a derived account always carries a BIP44 account number")

	secret, err := store.GetAccountSecret(
		t.Context(), db.GetAccountSecretQuery{
			WalletID:      walletID,
			Scope:         scope,
			AccountNumber: *derived.AccountNumber,
		},
	)
	require.NoError(t, err)

	// AccountSecret carries only the encrypted private key. Identity and the
	// account xpub are public metadata, covered by the GetAccount tests.
	require.Equal(t, privKey, secret.EncryptedPrivateKey)

	// A derived account on a watch-only wallet resolves through the same
	// account-number selector but carries no private material. Imported
	// accounts are not covered here: they are created from an extended
	// public key, so they never hold account-level signing material and are
	// unreachable through this query by design.
	watchOnlyWalletID := newWatchOnlyWallet(
		t, store, "watch-only-get-account-secret",
	)
	watchOnly, err := store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: watchOnlyWalletID,
			Scope:    scope,
			Name:     "watch-only-derived",
		}, func(_ context.Context, _ db.KeyScope, _ uint32,
			walletIsWatchOnly bool) (*db.DerivedAccountData,
			error) {

			require.True(t, walletIsWatchOnly)

			return &db.DerivedAccountData{
				PublicKey: []byte("watch-only-pubkey"),
			}, nil
		},
	)
	require.NoError(t, err)
	require.NotNil(t, watchOnly.AccountNumber)

	secret, err = store.GetAccountSecret(
		t.Context(), db.GetAccountSecretQuery{
			WalletID:      watchOnlyWalletID,
			Scope:         scope,
			AccountNumber: *watchOnly.AccountNumber,
		},
	)
	require.NoError(t, err)
	require.Nil(t, secret.EncryptedPrivateKey,
		"a watch-only account has no private material to expose")

	_, err = store.GetAccountSecret(
		t.Context(), db.GetAccountSecretQuery{
			WalletID:      walletID,
			Scope:         scope,
			AccountNumber: 999,
		},
	)
	require.ErrorIs(t, err, db.ErrAccountNotFound)
}
