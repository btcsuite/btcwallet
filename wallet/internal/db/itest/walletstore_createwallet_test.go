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

// TestCreateWalletDuplicateName verifies an occupied name retains the shared
// duplicate identity, SQL classification and constraint accounting.
func TestCreateWalletDuplicateName(t *testing.T) {
	t.Parallel()

	// Arrange: Occupy the name, then snapshot counters so a duplicate must
	// retain both its shared identity and normal constraint accounting.
	store := NewTestStore(t)
	params := CreateWalletParamsFixture("duplicate-wallet")
	_, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	before := store.StatsSnapshot()

	// Act: Repeat the same creation request against the occupied name.
	duplicate, err := store.CreateWallet(t.Context(), params)

	// Assert: Domain matching must retain the SQL wrapper and the duplicate's
	// single constraint count; callers receive no newly created Wallet.
	require.ErrorIs(t, err, db.ErrWalletExists)
	requireConstraintSQLError(t, err)
	require.Nil(t, duplicate)

	after := store.StatsSnapshot()
	require.Equal(t, before.Errors.Constraint+1, after.Errors.Constraint)
}

// TestCreateWalletPreservesOtherUniqueErrors verifies uniqueness outside the
// wallet-name index remains a SQL constraint error rather than a duplicate.
func TestCreateWalletPreservesOtherUniqueErrors(t *testing.T) {
	t.Parallel()

	// Arrange: Add an independent unique index so a different wallet name can
	// fail at the same insert without colliding with the name admission rule.
	store := NewTestStore(t)
	params := CreateWalletParamsFixture("original-wallet")
	_, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)
	_, err = store.DB().ExecContext(t.Context(),
		"CREATE UNIQUE INDEX uidx_test_wallets_version "+
			"ON wallets (manager_version)",
	)
	require.NoError(t, err)

	replacement := CreateWalletParamsFixture("different-wallet")

	// Act: Collide only with the injected non-name constraint.
	created, err := store.CreateWallet(t.Context(), replacement)

	// Assert: Keep the original SQL classification without reporting that the
	// distinct name was already occupied or returning a created wallet.
	requireConstraintSQLError(t, err)
	require.NotErrorIs(t, err, db.ErrWalletExists)
	require.Nil(t, created)
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
