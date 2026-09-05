//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestCreateWallet verifies that CreateWallet correctly creates a wallet
// and returns its information.
func TestCreateWallet(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	params := CreateWalletParamsFixture("test-wallet")
	info, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)
	require.NotNil(t, info)

	require.Equal(t, uint32(1), info.ID, "first wallet ID should be 1")
	require.Equal(t, params.Name, info.Name)
	require.Equal(t, params.IsImported, info.IsImported)
	require.Equal(t, params.ManagerVersion, info.ManagerVersion)
	require.Equal(t, params.IsWatchOnly, info.IsWatchOnly)

	require.Nil(t, info.SyncedTo)
	require.Nil(t, info.BirthdayBlock)
	require.True(t, info.Birthday.IsZero())
}

// TestCreateWalletWithBirthday checks that CreateWallet correctly sets the
// wallet's birthday timestamp.
func TestCreateWalletWithBirthday(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("birthday-wallet")
	birthday := time.Now().UTC().Add(-30 * 24 * time.Hour)
	params.Birthday = birthday

	info, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)
	require.NotNil(t, info)

	require.Equal(t, birthday.Unix(), info.Birthday.Unix())
	require.Nil(t, info.BirthdayBlock)
}

// TestCreateWalletDuplicateName verifies that creating a wallet with a
// duplicate name fails with an appropriate error.
func TestCreateWalletDuplicateName(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	params := CreateWalletParamsFixture("duplicate-wallet")

	_, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	before := store.StatsSnapshot()

	// Attempt to create second wallet with same name.
	_, err = store.CreateWallet(t.Context(), params)
	require.Error(t, err, "expected error creating duplicate wallet")
	requireConstraintSQLError(t, err)

	after := store.StatsSnapshot()
	require.Equal(t, before.Unhealthy, after.Unhealthy)
	require.Equal(t, before.RetryAttempts, after.RetryAttempts)
	require.Equal(t, before.RetrySuccesses, after.RetrySuccesses)
	require.Equal(t, before.RetryExhausted, after.RetryExhausted)
	require.Equal(t, before.AmbiguousTxCommits, after.AmbiguousTxCommits)
	require.Equal(t, before.Errors.Backend, after.Errors.Backend)
	require.Equal(t, before.Errors.TotalErrs+1, after.Errors.TotalErrs)
	require.Equal(
		t, before.Errors.PermanentErrs+1, after.Errors.PermanentErrs,
	)
	require.Equal(t, before.Errors.Constraint+1, after.Errors.Constraint)
	require.Equal(t, before.Errors.TransientErrs, after.Errors.TransientErrs)
	require.Equal(t, before.Errors.FatalErrs, after.Errors.FatalErrs)
}

// TestCreateWalletVariants tests different wallet types.
func TestCreateWalletVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params func(string) db.CreateWalletParams
	}{
		{
			name:   "imported wallet",
			params: CreateImportedWalletParams,
		},
		{
			name:   "watch-only wallet",
			params: CreateWatchOnlyWalletParams,
		},
		{
			name:   "standard wallet",
			params: CreateWalletParamsFixture,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			params := tc.params(tc.name)
			store := NewTestStore(t)

			info, err := store.CreateWallet(t.Context(), params)
			require.NoError(t, err)
			require.NotNil(t, info)
			require.Equal(t, params.IsImported, info.IsImported)
			require.Equal(t, params.IsWatchOnly, info.IsWatchOnly)
		})
	}
}

// TestCreateWatchOnlyWalletSecrets verifies that watch-only wallet creation
// requires script-encryption material while rejecting private wallet secrets.
func TestCreateWatchOnlyWalletSecrets(t *testing.T) {
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
		"create with missing passphrase params is rejected",
		func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)

			params := CreateWatchOnlyWalletParams("watch-only-create-empty")
			params.MasterKeyPrivParams = []byte{}

			_, err := store.CreateWallet(t.Context(), params)
			require.ErrorIs(t, err, db.ErrMissingField)
			require.ErrorContains(
				t, err,
				"wallet \"watch-only-create-empty\" master private parameters",
			)
		})

	t.Run(
		"create with passphrase params and script key succeeds",
		func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)

			params := CreateWatchOnlyWalletParams("watch-only-create-script")
			params.MasterKeyPrivParams = RandomBytes(16)
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
		params.EncryptedCryptoPrivKey = RandomBytes(32)

		_, err := store.CreateWallet(t.Context(), params)
		require.Error(t, err)
		require.ErrorIs(t, err, db.ErrWatchOnlyViolation)
	})
}

// TestCreateSpendableWalletRejectsIncompleteSecrets verifies that spendable
// wallet creation rejects missing private wallet secret material.
func TestCreateSpendableWalletRejectsIncompleteSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		mutate      func(*db.CreateWalletParams)
		wantErr     error
		wantContain string
	}{
		{
			name: "missing encrypted private crypto key",
			mutate: func(params *db.CreateWalletParams) {
				params.EncryptedCryptoPrivKey = nil
			},
			wantErr:     db.ErrMissingField,
			wantContain: "private crypto key",
		},
		{
			name: "missing encrypted master HD private key",
			mutate: func(params *db.CreateWalletParams) {
				params.EncryptedMasterPrivKey = nil
			},
			wantErr:     db.ErrMissingField,
			wantContain: "master HD private key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)
			params := CreateWalletParamsFixture(test.name)
			test.mutate(&params)

			_, err := store.CreateWallet(t.Context(), params)

			require.ErrorIs(t, err, test.wantErr)
			require.ErrorContains(t, err, test.wantContain)
		})
	}
}
