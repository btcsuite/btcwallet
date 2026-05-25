//go:build itest

package itest

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestGetEncryptedHDSeed verifies retrieving the encrypted HD seed.
func TestGetEncryptedHDSeed(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("seed-wallet")
	expectedSeed := params.EncryptedMasterPrivKey

	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
	require.NoError(t, err)
	require.Equal(t, expectedSeed, seed)
}

// TestGetWalletSecrets verifies retrieving all stored wallet secret material.
func TestGetWalletSecrets(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("wallet-secrets-read")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	secrets, err := store.GetWalletSecrets(t.Context(), created.ID)
	require.NoError(t, err)
	require.NotNil(t, secrets)
	require.Equal(t, params.MasterKeyPrivParams, secrets.MasterPrivParams)
	require.Equal(
		t, params.EncryptedCryptoPrivKey, secrets.EncryptedCryptoPrivKey,
	)
	require.Equal(
		t, params.EncryptedCryptoScriptKey,
		secrets.EncryptedCryptoScriptKey,
	)
	require.Equal(
		t, params.EncryptedMasterPrivKey, secrets.EncryptedMasterHdPrivKey,
	)
}

// TestGetWalletSecretsWatchOnly verifies watch-only wallets return their
// stored secret row without promoting empty fields to not-found.
func TestGetWalletSecretsWatchOnly(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWatchOnlyWalletParams("watch-only-wallet-secrets-read")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	secrets, err := store.GetWalletSecrets(t.Context(), created.ID)
	require.NoError(t, err)
	require.NotNil(t, secrets)
	require.Empty(t, secrets.MasterPrivParams)
	require.Empty(t, secrets.EncryptedCryptoPrivKey)
	require.Empty(t, secrets.EncryptedMasterHdPrivKey)
	require.Empty(t, secrets.EncryptedCryptoScriptKey)
}

// TestGetWalletSecretsNotFound verifies missing wallets map to
// ErrWalletNotFound.
func TestGetWalletSecretsNotFound(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	before := store.StatsSnapshot()

	secrets, err := store.GetWalletSecrets(t.Context(), 99999)
	require.Nil(t, secrets)
	require.ErrorIs(t, err, db.ErrWalletNotFound)

	after := store.StatsSnapshot()
	require.Equal(t, before, after)
}

// TestGetWalletSecretsMissingSecretsRow verifies an existing wallet with a
// missing wallet_secrets row returns ErrSecretNotFound rather than
// ErrWalletNotFound.
func TestGetWalletSecretsMissingSecretsRow(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("wallet-secrets-missing-row")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	err = deleteWalletSecretRaw(t, store.DB(), created.ID)
	require.NoError(t, err)

	secrets, err := store.GetWalletSecrets(t.Context(), created.ID)
	require.Nil(t, secrets)
	require.ErrorIs(t, err, db.ErrSecretNotFound)
}

// TestGetEncryptedHDSeedWatchOnly verifies that watch-only wallets
// have no encrypted seed.
func TestGetEncryptedHDSeedWatchOnly(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWatchOnlyWalletParams("watch-only-seed")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
	require.Nil(t, seed, "watch-only wallets should not have HD seed")
	require.ErrorIs(t, err, db.ErrSecretNotFound)
}

// TestGetEncryptedHDSeedMissingSecretsRow verifies an existing wallet with a
// missing wallet_secrets row returns ErrSecretNotFound rather than
// ErrWalletNotFound.
func TestGetEncryptedHDSeedMissingSecretsRow(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("seed-missing-row")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	err = deleteWalletSecretRaw(t, store.DB(), created.ID)
	require.NoError(t, err)

	seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
	require.Nil(t, seed)
	require.ErrorIs(t, err, db.ErrSecretNotFound)
}
