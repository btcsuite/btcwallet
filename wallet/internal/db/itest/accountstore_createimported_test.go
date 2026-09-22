//go:build itest

package itest

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
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

// TestCreateImportedAccountPersistsNoChainSync verifies both policy values pass
// through the real SQL imported-account create and read paths unchanged.
func TestCreateImportedAccountPersistsNoChainSync(t *testing.T) {
	t.Parallel()

	// Arrange: create one isolated spendable wallet and two valid imported
	// account requests that differ only in the policy value being persisted.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "imported-no-chain-sync-wallet")
	falseParams := db.CreateImportedAccountParams{
		WalletID:            walletID,
		Name:                "imported-policy-false",
		Scope:               db.KeyScopeBIP0084,
		PublicKey:           RandomBytes(32),
		EncryptedPrivateKey: RandomBytes(32),
		NoChainSync:         false,
	}
	trueParams := db.CreateImportedAccountParams{
		WalletID:            walletID,
		Name:                "imported-policy-true",
		Scope:               db.KeyScopeBIP0084,
		PublicKey:           RandomBytes(32),
		EncryptedPrivateKey: RandomBytes(32),
		NoChainSync:         true,
	}

	// Act: create both accounts and independently reload each row through the
	// normal Store read path.
	createdFalse, createFalseErr := store.CreateImportedAccount(
		t.Context(), falseParams,
	)
	createdTrue, createTrueErr := store.CreateImportedAccount(
		t.Context(), trueParams,
	)
	loadedFalse, loadFalseErr := store.GetAccount(
		t.Context(), getAccountQueryByName(
			walletID, falseParams.Scope, falseParams.Name,
		),
	)
	loadedTrue, loadTrueErr := store.GetAccount(
		t.Context(), getAccountQueryByName(
			walletID, trueParams.Scope, trueParams.Name,
		),
	)

	// Assert: both creation results and both fresh reads retain their exact
	// values, covering the default and non-default policies equally.
	require.NoError(t, createFalseErr)
	require.NoError(t, createTrueErr)
	require.NoError(t, loadFalseErr)
	require.NoError(t, loadTrueErr)
	require.False(t, createdFalse.NoChainSync)
	require.True(t, createdTrue.NoChainSync)
	require.False(t, loadedFalse.NoChainSync)
	require.True(t, loadedTrue.NoChainSync)
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

// TestCreateImportedAccountIdentity tests script ownership admission through
// the concrete Store, including metadata normalization and disjoint branches.
func TestCreateImportedAccountIdentity(t *testing.T) {
	t.Parallel()

	// Arrange: construct equal payloads with different serialization metadata,
	// plus independent public-key and chain-code changes for allowed controls.
	master, err := hdkeychain.NewMaster(
		bytes.Repeat([]byte{0xCC}, 32), &chaincfg.SimNetParams,
	)
	require.NoError(t, err)
	key, err := master.Neuter()
	require.NoError(t, err)
	pub, err := key.ECPubKey()
	require.NoError(t, err)

	alias := hdkeychain.NewExtendedKey(
		chaincfg.MainNetParams.HDPublicKeyID[:], pub.SerializeCompressed(),
		key.ChainCode(), []byte{1, 2, 3, 4}, 3, 42, false,
	)
	other, err := key.Derive(1)
	require.NoError(t, err)

	otherChain := hdkeychain.NewExtendedKey(
		chaincfg.MainNetParams.HDPublicKeyID[:], pub.SerializeCompressed(),
		bytes.Repeat([]byte{0xDD}, 32), []byte{1, 2, 3, 4}, 3, 42, false,
	)
	plus := db.ScopeAddrMap[db.KeyScopeBIP0049Plus]
	strict := db.ScopeAddrSchema{
		ExternalAddrType: db.NestedWitnessPubKey,
		InternalAddrType: db.NestedWitnessPubKey,
	}
	swapped := db.ScopeAddrSchema{
		ExternalAddrType: db.WitnessPubKey,
		InternalAddrType: db.NestedWitnessPubKey,
	}

	tests := []struct {
		name        string
		ownerScope  db.KeyScope
		ownerSchema *db.ScopeAddrSchema
		scope       db.KeyScope
		schema      *db.ScopeAddrSchema
		key         string
		dryRun      bool
		want        error
	}{
		{
			name:       "same scope",
			ownerScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0084,
			key:        alias.String(),
			want:       db.ErrAccountIdentityCollision,
		},
		{
			name:       "internal overlap across scopes",
			ownerScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0049Plus,
			key:        alias.String(),
			want:       db.ErrAccountIdentityCollision,
		},
		{
			name:       "strict nested disjoint",
			ownerScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0049Plus,
			schema:     &strict,
			key:        alias.String(),
		},
		{
			name:        "external overlap",
			ownerScope:  db.KeyScopeBIP0049Plus,
			ownerSchema: &strict,
			scope:       db.KeyScope{Purpose: 100, Coin: 0},
			schema:      &plus,
			key:         alias.String(),
			want:        db.ErrAccountIdentityCollision,
		},
		{
			name:       "cross branch equality is disjoint",
			ownerScope: db.KeyScopeBIP0049Plus,
			scope:      db.KeyScope{Purpose: 100, Coin: 0},
			schema:     &swapped,
			key:        alias.String(),
		},
		{
			name:       "different payload",
			ownerScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0084,
			key:        other.String(),
		},
		{
			name:       "same pubkey different chain code",
			ownerScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0084,
			key:        otherChain.String(),
		},
		{
			name:       "preview collision",
			ownerScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0084,
			key:        alias.String(),
			dryRun:     true,
			want:       db.ErrAccountIdentityCollision,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: the existing owner has no children and is excluded
			// from chain sync, which must not hide its script ownership.
			store := NewTestStore(t)
			walletID := newWallet(t, store, "identity")
			owner := db.CreateImportedAccountParams{
				WalletID:            walletID,
				Name:                "owner",
				Scope:               tc.ownerScope,
				AddrSchema:          tc.ownerSchema,
				PublicKey:           []byte(key.String()),
				EncryptedPrivateKey: RandomBytes(32),
				NoChainSync:         true,
			}
			_, err := store.CreateImportedAccount(t.Context(), owner)
			require.NoError(t, err)

			query := db.ListAccountsQuery{
				WalletID:    walletID,
				SkipBalance: true,
			}
			before, err := store.ListAccounts(t.Context(), query)
			require.NoError(t, err)

			candidate := owner
			candidate.Name, candidate.PublicKey = "candidate", []byte(tc.key)
			candidate.Scope, candidate.AddrSchema = tc.scope, tc.schema
			candidate.MasterFingerprint, candidate.DryRun = 123, tc.dryRun

			// Act: attempt the second import within the real SQL write.
			info, err := store.CreateImportedAccount(t.Context(), candidate)

			// Assert: collisions return no row and no secret or child/watch
			// fact; disjoint identities remain admitted with their secrets.
			require.ErrorIs(t, err, tc.want)
			after, err := store.ListAccounts(t.Context(), query)
			require.NoError(t, err)

			if tc.want != nil {
				require.Nil(t, info)
				require.Equal(t, before, after)
			} else {
				require.NotNil(t, info)
				require.Len(t, after, 2)
			}

			var secrets, addresses, children int

			err = store.DB().QueryRowContext(t.Context(), `
				SELECT (SELECT count(*) FROM account_secrets),
				       (SELECT count(*) FROM addresses),
				       (SELECT count(*) FROM derived_addresses)
			`).Scan(&secrets, &addresses, &children)
			require.NoError(t, err)
			require.Equal(t, len(after), secrets)
			require.Zero(t, addresses)
			require.Zero(t, children)

			// Act: occupy the original name with the normalized alias twice.
			owner.PublicKey = []byte(alias.String())
			for range 2 {
				info, err = store.CreateImportedAccount(t.Context(), owner)

				// Assert: uniqueness precedence is stable across retries.
				require.ErrorIs(t, err, db.ErrAccountNameConflict)
				require.Nil(t, info)
			}
		})
	}
}
