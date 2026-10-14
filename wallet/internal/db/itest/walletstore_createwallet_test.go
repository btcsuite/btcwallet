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

// TestCreateWalletDuplicateName verifies rejection preserves all creation rows
// and credentials across reopening, despite different replacement inputs.
func TestCreateWalletDuplicateName(t *testing.T) {
	t.Parallel()

	// Arrange: Retain the original identity, secrets and sync timestamp so a
	// rejected replacement cannot silently change any creation row.
	store, reopen := newReopenableTestStore(t, mockDeriveFunc())
	params := CreateWalletParamsFixture("duplicate-wallet")
	params.Birthday = time.Unix(100, 0).UTC()

	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)
	secrets, err := store.GetWalletSecrets(t.Context(), created.ID)
	require.NoError(t, err)

	var updatedAt time.Time

	err = store.DB().QueryRowContext(t.Context(),
		"SELECT updated_at FROM wallet_sync_states",
	).Scan(&updatedAt)
	require.NoError(t, err)

	replacement := CreateWalletParamsFixture(params.Name)
	replacement.IsImported = true
	replacement.ManagerVersion = params.ManagerVersion + 1
	replacement.Birthday = params.Birthday.Add(time.Hour)

	// Act: Attempt the same name with new metadata and encrypted credentials.
	duplicate, err := store.CreateWallet(t.Context(), replacement)

	// Assert: Reopen the real database before comparing every creation row;
	// this rejects both an extra row and a persisted replacement of the winner.
	require.ErrorIs(t, err, db.ErrWalletExists)
	require.Nil(t, duplicate)
	require.NoError(t, store.Close())
	store = reopen()

	saved, err := store.GetWallet(t.Context(), params.Name)
	require.NoError(t, err)
	require.Equal(t, created, saved)
	savedSecrets, err := store.GetWalletSecrets(t.Context(), created.ID)
	require.NoError(t, err)
	require.Equal(t, secrets, savedSecrets)

	var savedUpdatedAt time.Time

	err = store.DB().QueryRowContext(t.Context(),
		"SELECT updated_at FROM wallet_sync_states",
	).Scan(&savedUpdatedAt)
	require.NoError(t, err)
	require.Equal(t, updatedAt, savedUpdatedAt)

	var counts [3]int

	err = store.DB().QueryRowContext(t.Context(), `SELECT
		(SELECT count(*) FROM wallets),
		(SELECT count(*) FROM wallet_secrets),
		(SELECT count(*) FROM wallet_sync_states)`).
		Scan(&counts[0], &counts[1], &counts[2])
	require.NoError(t, err)
	require.Equal(t, [3]int{1, 1, 1}, counts)
}

// TestCreateWalletConcurrentDuplicate verifies insert-only creation chooses
// one durable winner without replacing its encrypted credentials.
func TestCreateWalletConcurrentDuplicate(t *testing.T) {
	t.Parallel()

	// Arrange: Give two same-name requests different credentials and hold both
	// at one barrier; result indices identify the winner's original payload.
	store := NewTestStore(t)
	requests := []db.CreateWalletParams{
		CreateWalletParamsFixture("concurrent-wallet"),
		CreateWalletParamsFixture("concurrent-wallet"),
	}

	type createResult struct {
		index int
		info  *db.WalletInfo
		err   error
	}

	ctx := t.Context()
	ready := make(chan struct{}, len(requests))
	start := make(chan struct{})

	results := make(chan createResult, len(requests))
	for index, request := range requests {
		go func() {
			ready <- struct{}{}

			select {
			case <-start:

			case <-ctx.Done():
				return
			}

			info, err := store.CreateWallet(ctx, request)
			results <- createResult{
				index: index,
				info:  info,
				err:   err,
			}
		}()
	}

	// Act: Release only after both callers reached the barrier, then collect
	// their completed operations before making any assertions.
	for range requests {
		<-ready
	}

	close(start)

	winner, loser := <-results, <-results
	if winner.err != nil {
		winner, loser = loser, winner
	}

	// Assert: Exactly one committed request owns the sole wallet, secret and
	// sync rows; every encrypted field still belongs to that winning request.
	require.NoError(t, winner.err)
	require.ErrorIs(t, loser.err, db.ErrWalletExists)
	require.Nil(t, loser.info)
	saved, err := store.GetWallet(t.Context(), requests[winner.index].Name)
	require.NoError(t, err)
	require.Equal(t, winner.info, saved)
	secrets, err := store.GetWalletSecrets(t.Context(), winner.info.ID)
	require.NoError(t, err)

	params := requests[winner.index]
	require.Equal(t, &db.WalletSecrets{
		MasterPrivParams:         params.MasterKeyPrivParams,
		EncryptedCryptoPrivKey:   params.EncryptedCryptoPrivKey,
		EncryptedCryptoScriptKey: params.EncryptedCryptoScriptKey,
		EncryptedMasterHdPrivKey: params.EncryptedMasterPrivKey,
	}, secrets)

	var counts [3]int

	err = store.DB().QueryRowContext(t.Context(), `SELECT
		(SELECT count(*) FROM wallets),
		(SELECT count(*) FROM wallet_secrets),
		(SELECT count(*) FROM wallet_sync_states)`).
		Scan(&counts[0], &counts[1], &counts[2])
	require.NoError(t, err)
	require.Equal(t, [3]int{1, 1, 1}, counts)
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

	// Assert: Preserve the original SQL classification and roll back the failed
	// request, without reporting that its distinct name was already occupied.
	requireConstraintSQLError(t, err)
	require.NotErrorIs(t, err, db.ErrWalletExists)
	require.Nil(t, created)
	_, err = store.GetWallet(t.Context(), replacement.Name)
	require.ErrorIs(t, err, db.ErrWalletNotFound)
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
