//go:build itest

package itest

import (
	"database/sql"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestWatchOnlyKeyScopeSecretTriggers verifies that key_scope_secrets models
// watch-only scopes as absent rows while still rejecting direct private-key
// writes for watch-only parents and allowing inserts/updates for spendable
// parents.
func TestWatchOnlyKeyScopeSecretTriggers(t *testing.T) {
	t.Parallel()

	t.Run("watch-only scopes keep secrets row absent", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)
		queries := store.Queries()

		walletInfo, err := store.CreateWallet(
			t.Context(),
			CreateWatchOnlyWalletParams("watch-only-key-scope-secret-insert"),
		)
		require.NoError(t, err)

		CreateImportedAccount(
			t, store, walletInfo.ID, db.KeyScopeBIP0084,
			"watch-only-key-scope-scope-absent",
		)

		scopeID := GetKeyScopeID(t, queries, walletInfo.ID, db.KeyScopeBIP0084)

		_, err = queries.GetKeyScopeSecrets(t.Context(), scopeID)
		require.ErrorIs(t, err, sql.ErrNoRows)

		err = deleteKeyScopeSecretRaw(t, store.DB(), scopeID)
		require.NoError(t, err)
	})

	t.Run("watch-only insert is rejected", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)
		queries := store.Queries()

		walletInfo, err := store.CreateWallet(
			t.Context(),
			CreateWatchOnlyWalletParams("watch-only-key-scope-secret-insert"),
		)
		require.NoError(t, err)

		CreateImportedAccount(
			t, store, walletInfo.ID, db.KeyScopeBIP0084,
			"watch-only-key-scope-scope-insert",
		)

		scopeID := GetKeyScopeID(t, queries, walletInfo.ID, db.KeyScopeBIP0084)

		err = insertKeyScopeSecretRaw(t, store.DB(), scopeID, RandomBytes(32))
		require.Error(t, err)
		requireDriverConstraintError(t, err)
	})

	t.Run("non-watch-only insert and update succeed", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)
		queries := store.Queries()
		walletID := newWallet(t, store, "spendable-key-scope-secret-trigger")

		createDerivedAccount(
			t, store, walletID, db.KeyScopeBIP0084,
			"spendable-key-scope-account",
		)

		scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)

		err := deleteKeyScopeSecretRaw(t, store.DB(), scopeID)
		require.NoError(t, err)

		insertedPrivKey := RandomBytes(32)
		err = insertKeyScopeSecretRaw(t, store.DB(), scopeID, insertedPrivKey)
		require.NoError(t, err)

		updatedPrivKey := RandomBytes(32)
		err = updateKeyScopeSecretRaw(t, store.DB(), scopeID, updatedPrivKey)
		require.NoError(t, err)
	})
}

// TestKeyScopeWalletIDImmutable verifies that raw scope updates cannot change
// wallet ownership after insert.
func TestKeyScopeWalletIDImmutable(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()

	sourceWalletID := newWallet(t, store, "scope-wallet-immutable-source")
	createDerivedAccount(
		t, store, sourceWalletID, db.KeyScopeBIP0084, "scope-wallet-source",
	)

	scopeID := GetKeyScopeID(t, queries, sourceWalletID, db.KeyScopeBIP0084)
	targetWalletID := newWallet(t, store, "scope-wallet-immutable-target")

	err := updateKeyScopeWalletIDRaw(t, store.DB(), scopeID, targetWalletID)
	require.Error(t, err)
	requireDriverConstraintError(t, err)

	require.Equal(
		t, scopeID,
		GetKeyScopeID(t, queries, sourceWalletID, db.KeyScopeBIP0084),
	)
}
