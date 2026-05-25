//go:build itest

package itest

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestWatchOnlyWalletRejectsWalletSecrets verifies that watch-only
// wallets allow script-encryption material while still rejecting
// private wallet secrets.
func TestWatchOnlyWalletRejectsWalletSecrets(t *testing.T) {
	t.Parallel()

	t.Run("create with no private secrets succeeds", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)

		params := CreateWatchOnlyWalletParams("watch-only-create-ok")
		info, err := store.CreateWallet(t.Context(), params)
		require.NoError(t, err)
		require.NotNil(t, info)
		require.True(t, info.IsWatchOnly)
	})

	t.Run(
		"create with empty-but-non-nil private secrets succeeds",
		func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)

			params := CreateWatchOnlyWalletParams("watch-only-create-empty")
			params.MasterKeyPrivParams = []byte{}
			params.EncryptedCryptoPrivKey = []byte{}
			params.EncryptedMasterPrivKey = []byte{}

			info, err := store.CreateWallet(t.Context(), params)
			require.NoError(t, err)
			require.NotNil(t, info)
			require.True(t, info.IsWatchOnly)

			seed, err := store.GetEncryptedHDSeed(t.Context(), info.ID)
			require.Nil(t, seed)
			require.ErrorIs(t, err, db.ErrSecretNotFound)
		},
	)

	t.Run("create with script key only succeeds", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)

		params := CreateWatchOnlyWalletParams("watch-only-create-script")
		params.EncryptedCryptoScriptKey = RandomBytes(32)

		info, err := store.CreateWallet(t.Context(), params)
		require.NoError(t, err)
		require.NotNil(t, info)
		require.True(t, info.IsWatchOnly)

		seed, err := store.GetEncryptedHDSeed(t.Context(), info.ID)
		require.Nil(t, seed)
		require.ErrorIs(t, err, db.ErrSecretNotFound)
	})

	t.Run("create with private secrets is rejected", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)

		params := CreateWatchOnlyWalletParams("watch-only-create-reject")
		params.MasterKeyPrivParams = RandomBytes(16)

		_, err := store.CreateWallet(t.Context(), params)
		require.Error(t, err)
		require.ErrorIs(t, err, db.ErrWatchOnlyViolation)
	})

	t.Run("update with script key only succeeds", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)

		created, err := store.CreateWallet(
			t.Context(),
			CreateWatchOnlyWalletParams("watch-only-update-script"),
		)
		require.NoError(t, err)

		err = store.UpdateWalletSecrets(
			t.Context(), db.UpdateWalletSecretsParams{
				WalletID:                 created.ID,
				EncryptedCryptoScriptKey: RandomBytes(32),
			},
		)
		require.NoError(t, err)

		seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
		require.Nil(t, seed)
		require.ErrorIs(t, err, db.ErrSecretNotFound)
	})

	t.Run(
		"update with empty-but-non-nil private secrets succeeds",
		func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)

			created, err := store.CreateWallet(
				t.Context(),
				CreateWatchOnlyWalletParams("watch-only-update-empty"),
			)
			require.NoError(t, err)

			err = store.UpdateWalletSecrets(
				t.Context(), db.UpdateWalletSecretsParams{
					WalletID:                 created.ID,
					MasterPrivParams:         []byte{},
					EncryptedCryptoPrivKey:   []byte{},
					EncryptedMasterHdPrivKey: []byte{},
				},
			)
			require.NoError(t, err)

			seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
			require.Nil(t, seed)
			require.ErrorIs(t, err, db.ErrSecretNotFound)
		},
	)

	t.Run("update with private secrets is rejected", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)

		created, err := store.CreateWallet(
			t.Context(),
			CreateWatchOnlyWalletParams("watch-only-update-reject"),
		)
		require.NoError(t, err)

		err = store.UpdateWalletSecrets(
			t.Context(), db.UpdateWalletSecretsParams{
				WalletID:                 created.ID,
				MasterPrivParams:         RandomBytes(16),
				EncryptedCryptoPrivKey:   RandomBytes(32),
				EncryptedMasterHdPrivKey: RandomBytes(32),
			},
		)
		require.Error(t, err)
		require.ErrorIs(t, err, db.ErrWatchOnlyViolation)
	})
}

// TestWatchOnlyWalletSecretTriggers verifies that wallet_secrets rejects
// watch-only parent wallets while still allowing inserts and updates for
// non-watch-only parents.
func TestWatchOnlyWalletSecretTriggers(t *testing.T) {
	t.Parallel()

	t.Run("watch-only insert is rejected", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)

		walletInfo, err := store.CreateWallet(
			t.Context(),
			CreateWatchOnlyWalletParams("watch-only-wallet-secret-insert"),
		)
		require.NoError(t, err)

		err = insertWalletSecretRaw(
			t, store.DB(), walletInfo.ID, RandomBytes(16), RandomBytes(32),
			RandomBytes(32), RandomBytes(32),
		)
		require.Error(t, err)
		requireDriverConstraintError(t, err)
	})

	t.Run("watch-only script-only insert succeeds", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)

		walletInfo, err := store.CreateWallet(
			t.Context(),
			CreateWatchOnlyWalletParams("watch-only-wallet-secret-script-only"),
		)
		require.NoError(t, err)

		err = deleteWalletSecretRaw(t, store.DB(), walletInfo.ID)
		require.NoError(t, err)

		err = insertWalletSecretRaw(
			t, store.DB(), walletInfo.ID, nil, nil, RandomBytes(32), nil,
		)
		require.NoError(t, err)
	})

	t.Run(
		"watch-only empty-but-non-nil insert is rejected",
		func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)

			walletInfo, err := store.CreateWallet(
				t.Context(),
				CreateWatchOnlyWalletParams(
					"watch-only-wallet-secret-empty-insert",
				),
			)
			require.NoError(t, err)

			err = insertWalletSecretRaw(
				t, store.DB(), walletInfo.ID, []byte{}, nil, RandomBytes(32),
				nil,
			)
			require.Error(t, err)
			requireDriverConstraintError(t, err)
		},
	)

	t.Run("watch-only update is rejected", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)

		params := CreateWatchOnlyWalletParams("watch-only-wallet-secret-update")
		params.EncryptedCryptoScriptKey = RandomBytes(32)

		walletInfo, err := store.CreateWallet(t.Context(), params)
		require.NoError(t, err)

		seed, err := store.GetEncryptedHDSeed(t.Context(), walletInfo.ID)
		require.Nil(t, seed)
		require.ErrorIs(t, err, db.ErrSecretNotFound)

		err = updateWalletSecretRaw(
			t, store.DB(), walletInfo.ID, nil, nil, RandomBytes(32), nil,
		)
		require.NoError(t, err)

		err = updateWalletSecretRaw(
			t, store.DB(), walletInfo.ID, RandomBytes(16), RandomBytes(32),
			RandomBytes(32), RandomBytes(32),
		)
		require.Error(t, err)
		requireDriverConstraintError(t, err)

		err = updateWalletSecretRaw(
			t, store.DB(), walletInfo.ID, []byte{}, nil, RandomBytes(32),
			nil,
		)
		require.Error(t, err)
		requireDriverConstraintError(t, err)
	})

	t.Run("non-watch-only insert and update succeed", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)

		walletID := newWallet(t, store, "spendable-wallet-secret-trigger")

		err := deleteWalletSecretRaw(t, store.DB(), walletID)
		require.NoError(t, err)

		insertedSeed := RandomBytes(32)
		err = insertWalletSecretRaw(
			t, store.DB(), walletID, RandomBytes(16), RandomBytes(32),
			RandomBytes(32), insertedSeed,
		)
		require.NoError(t, err)

		seed, err := store.GetEncryptedHDSeed(t.Context(), walletID)
		require.NoError(t, err)
		require.Equal(t, insertedSeed, seed)

		updatedSeed := RandomBytes(32)
		err = updateWalletSecretRaw(
			t, store.DB(), walletID, RandomBytes(16), RandomBytes(32),
			RandomBytes(32), updatedSeed,
		)
		require.NoError(t, err)

		seed, err = store.GetEncryptedHDSeed(t.Context(), walletID)
		require.NoError(t, err)
		require.Equal(t, updatedSeed, seed)
	})
}

// TestWalletWatchOnlyImmutable verifies that raw wallet updates cannot change
// the watch-only flag after wallet creation.
func TestWalletWatchOnlyImmutable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		walletName       string
		params           func(string) db.CreateWalletParams
		updatedWatchOnly bool
	}{
		{
			name:             "spendable wallet cannot become watch-only",
			walletName:       "wallet-watch-only-immutable-spendable",
			params:           CreateWalletParamsFixture,
			updatedWatchOnly: true,
		},
		{
			name:             "watch-only wallet cannot become spendable",
			walletName:       "wallet-watch-only-immutable-watch-only",
			params:           CreateWatchOnlyWalletParams,
			updatedWatchOnly: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)

			created, err := store.CreateWallet(
				t.Context(), tc.params(tc.walletName),
			)
			require.NoError(t, err)

			err = updateWalletWatchOnlyRaw(
				t, store.DB(), created.ID, tc.updatedWatchOnly,
			)
			require.Error(t, err)
			requireDriverConstraintError(t, err)

			walletInfo, err := store.GetWallet(t.Context(), tc.walletName)
			require.NoError(t, err)
			require.NotNil(t, walletInfo)
			require.Equal(t, created.IsWatchOnly, walletInfo.IsWatchOnly)
		})
	}
}

// TestUpdateWalletSecrets checks that updating the wallet secrets works
// correctly.
func TestUpdateWalletSecrets(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("secrets-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	newSecrets := db.UpdateWalletSecretsParams{
		WalletID:                 created.ID,
		MasterPrivParams:         RandomBytes(16),
		EncryptedCryptoPrivKey:   RandomBytes(32),
		EncryptedCryptoScriptKey: RandomBytes(32),
		EncryptedMasterHdPrivKey: RandomBytes(32),
	}

	err = store.UpdateWalletSecrets(t.Context(), newSecrets)
	require.NoError(t, err)

	seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
	require.NoError(t, err)
	require.Equal(t, newSecrets.EncryptedMasterHdPrivKey, seed)
}
