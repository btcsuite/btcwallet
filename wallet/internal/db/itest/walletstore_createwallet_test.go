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
