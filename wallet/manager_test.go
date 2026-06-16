package wallet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	kvdb "github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestWalletID verifies that Wallet.ID returns the cached runtime ID.
func TestWalletID(t *testing.T) {
	t.Parallel()

	w := &Wallet{id: 42}

	require.Equal(t, uint32(42), w.ID())
}

// TestManagerCreateSuccess verifies that a wallet can be successfully created
// in various modes. It checks that the Manager correctly initializes the
// wallet structure and registers it for tracking.
func TestManagerCreateSuccess(t *testing.T) {
	t.Parallel()

	// Pre-calculate common setup values to be used in multiple test cases.
	// This ensures we have valid cryptographic material ready for import
	// scenarios.
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	rootKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)

	// Create an account XPub for ModeShell testing.
	// Derive account key: m/44'/0'/0'
	acctKey, err := rootKey.Derive(hdkeychain.HardenedKeyStart + 44)
	require.NoError(t, err)
	acctKey, err = acctKey.Derive(hdkeychain.HardenedKeyStart + 0)
	require.NoError(t, err)
	acctKey, err = acctKey.Derive(hdkeychain.HardenedKeyStart + 0)
	require.NoError(t, err)
	acctXPub, err := acctKey.Neuter()
	require.NoError(t, err)

	// Arrange: Define test cases for different creation modes.
	tests := []struct {
		name   string
		params CreateWalletParams
	}{

		{
			name: "ModeGenSeed",
			params: CreateWalletParams{
				Mode:              ModeGenSeed,
				PubPassphrase:     []byte("public"),
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			},
		},
		{
			name: "ModeImportSeed",
			params: CreateWalletParams{
				Mode:              ModeImportSeed,
				Seed:              seed,
				PubPassphrase:     []byte("public"),
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			},
		},
		{
			name: "ModeImportExtKey",
			params: CreateWalletParams{
				Mode:              ModeImportExtKey,
				RootKey:           rootKey,
				PubPassphrase:     []byte("public"),
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			},
		},
		{
			name: "ModeShell",
			params: CreateWalletParams{
				Mode: ModeShell,
				InitialAccounts: []WatchOnlyAccount{{
					Scope:                waddrmgr.KeyScopeBIP0049Plus,
					XPub:                 acctXPub,
					MasterKeyFingerprint: 0,
					Name:                 "test-shell-account",
					AddrType:             waddrmgr.NestedWitnessPubKey,
				}},
				WatchOnly:     true,
				PubPassphrase: []byte("public"),
				Birthday:      time.Now(),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := NewManager()
			cfg := Config{
				DB:             testKVDBConfig(t),
				Chain:          &bwmock.Chain{},
				ChainParams:    &chainParams,
				Name:           "test-wallet",
				PubPassphrase:  []byte("public"),
				RecoveryWindow: MinRecoveryWindow,
			}

			// Attempt to create the wallet with the specified parameters.
			w, err := m.Create(cfg, tc.params)

			// Verify that the wallet was created successfully and returned
			// without error.
			require.NoError(t, err)
			require.NotNil(t, w)
			require.Zero(t, w.ID())

			// Verify internal state: Ensure the manager is tracking the
			// newly created wallet in its internal map, keyed by the
			// configuration name.
			m.RLock()
			loadedW, ok := m.wallets["test-wallet"]
			m.RUnlock()
			require.True(t, ok)
			require.Same(t, w, loadedW)

			// If ModeShell, verify account was imported.
			if tc.params.Mode == ModeShell {
				info, err := w.cache.GetAccount(
					t.Context(), db.GetAccountQuery{
						WalletID: w.id,
						Scope: db.KeyScope(
							tc.params.InitialAccounts[0].Scope,
						),
						Name: &tc.params.InitialAccounts[0].Name,
					},
				)
				require.NoError(t, err)
				require.Equal(
					t, tc.params.InitialAccounts[0].Name,
					info.AccountName,
				)
			}
		})
	}
}

// TestManagerCreateError verifies that wallet creation fails when invalid
// parameters are provided. This ensures that the Manager correctly validates
// inputs before attempting to modify the database.
func TestManagerCreateError(t *testing.T) {
	t.Parallel()

	// Pre-calculate cryptographic material to construct specific test
	// scenarios.
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	rootKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)

	pubKey, err := rootKey.Neuter()
	require.NoError(t, err)

	tests := []struct {
		name        string
		params      CreateWalletParams
		expectedErr string
	}{
		{
			name: "ModeImportSeed missing seed",
			params: CreateWalletParams{
				Mode: ModeImportSeed,
				Seed: nil,
			},
			expectedErr: "seed is required",
		},
		{
			name: "ModeImportExtKey missing key",
			params: CreateWalletParams{
				Mode:    ModeImportExtKey,
				RootKey: nil,
			},
			expectedErr: "root key is required",
		},
		{
			name: "Public Key for Non-WatchOnly",
			params: CreateWalletParams{
				Mode:      ModeImportExtKey,
				RootKey:   pubKey,
				WatchOnly: false,
			},
			expectedErr: "private key required",
		},
		{
			name: "Unknown Mode",
			params: CreateWalletParams{
				Mode: ModeUnknown,
			},
			expectedErr: "unknown mode",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := NewManager()
			cfg := Config{
				DB:             testKVDBConfig(t),
				Chain:          &bwmock.Chain{},
				ChainParams:    &chainParams,
				Name:           "test-wallet",
				RecoveryWindow: MinRecoveryWindow,
			}

			// Attempt to create the wallet. We expect this to fail due to
			// the invalid parameters configured in the test case.
			_, err := m.Create(cfg, tc.params)

			// Verify that the error matches our expectation.
			require.Error(t, err)
			require.ErrorContains(t, err, tc.expectedErr)
		})
	}
}

// TestCreateWalletParams_Validate verifies that the validate method enforces
// the correct constraints for each creation mode.
func TestCreateWalletParams_Validate(t *testing.T) {
	t.Parallel()

	// Pre-calculate cryptographic material to construct specific test
	// scenarios.
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	rootKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)

	tests := []struct {
		name        string
		params      CreateWalletParams
		expectedErr string
	}{
		{
			name: "ModeGenSeed with Seed",
			params: CreateWalletParams{
				Mode: ModeGenSeed,
				Seed: seed,
			},
			expectedErr: "seed should not be set for ModeGenSeed",
		},
		{
			name: "ModeGenSeed with RootKey",
			params: CreateWalletParams{
				Mode:    ModeGenSeed,
				RootKey: rootKey,
			},
			expectedErr: "root key should not be set for ModeGenSeed",
		},
		{
			name: "ModeImportSeed with RootKey",
			params: CreateWalletParams{
				Mode:    ModeImportSeed,
				Seed:    seed,
				RootKey: rootKey,
			},
			expectedErr: "root key should not be set for ModeImportSeed",
		},
		{
			name: "ModeImportExtKey with Seed",
			params: CreateWalletParams{
				Mode:    ModeImportExtKey,
				RootKey: rootKey,
				Seed:    seed,
			},
			expectedErr: "seed should not be set for ModeImportExtKey",
		},
		{
			name: "ModeShell with Seed",
			params: CreateWalletParams{
				Mode: ModeShell,
				Seed: seed,
			},
			expectedErr: "seed should not be set for ModeShell",
		},
		{
			name: "Unknown Mode",
			params: CreateWalletParams{
				Mode: ModeUnknown,
			},
			expectedErr: "unknown mode",
		},
		{
			name: "InitialAccounts with ModeGenSeed",
			params: CreateWalletParams{
				Mode: ModeGenSeed,
				InitialAccounts: []WatchOnlyAccount{{
					Name: "test",
				}},
			},
			expectedErr: "initial accounts should only " +
				"be set for ModeShell",
		}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.params.validate()
			require.Error(t, err)
			require.ErrorContains(t, err, tc.expectedErr)
		})
	}
}

// TestManagerCreate_InvalidConfig verifies that the Create method performs
// configuration validation before proceeding with any operations.
func TestManagerCreate_InvalidConfig(t *testing.T) {
	t.Parallel()

	m := NewManager()

	// Call Create with an empty Config struct. This should fail because
	// required fields like Chain and ChainParams are missing.
	w, err := m.Create(Config{}, CreateWalletParams{})

	require.ErrorIs(t, err, ErrMissingParam)
	require.ErrorContains(t, err, "Chain")
	require.Nil(t, w)
}

// TestManagerLoadSuccess verifies that an existing wallet can be successfully
// loaded from the database. This tests the persistence and restoration flow.
func TestManagerLoadSuccess(t *testing.T) {
	t.Parallel()

	m := NewManager()
	cfg := Config{
		DB:             testKVDBConfig(t),
		Chain:          &bwmock.Chain{},
		ChainParams:    &chainParams,
		Name:           "test-wallet",
		PubPassphrase:  []byte("public"),
		RecoveryWindow: MinRecoveryWindow,
	}
	params := CreateWalletParams{
		Mode:              ModeGenSeed,
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	wCreated, err := m.Create(cfg, params)
	require.NoError(t, err)
	require.NotNil(t, wCreated)
	require.NoError(t, wCreated.closeRuntimeStore())

	// Create a new Manager instance to simulate a fresh start (e.g., daemon
	// restart) and attempt to load the wallet from the existing database.
	m2 := NewManager()
	w, err := m2.Load(cfg)

	// Verify that the load operation succeeded and returned a valid wallet.
	require.NoError(t, err)
	require.NotNil(t, w)

	// Ensure the loaded wallet is correctly registered in the new manager.
	m2.RLock()
	loadedW, ok := m2.wallets["test-wallet"]
	m2.RUnlock()
	require.True(t, ok)
	require.Same(t, w, loadedW)
	require.Zero(t, w.ID())

	// The master HD fingerprint is read through the Store during load. A
	// ModeGenSeed wallet persists a master HD public key, so the cached
	// fingerprint is non-zero and matches the value resolved at create time.
	require.NotZero(t, w.masterFingerprint)
	require.Equal(t, wCreated.masterFingerprint, w.masterFingerprint)
}

// TestManagerLoad_ExistingWallet verifies that if Load is called for a wallet
// that is already managed in memory, the Manager detects this.
func TestManagerLoad_ExistingWallet(t *testing.T) {
	t.Parallel()

	m := NewManager()
	cfg := Config{
		DB:             testKVDBConfig(t),
		Chain:          &bwmock.Chain{},
		ChainParams:    &chainParams,
		Name:           "test-wallet",
		PubPassphrase:  []byte("public"),
		RecoveryWindow: MinRecoveryWindow,
	}
	params := CreateWalletParams{
		Mode:              ModeGenSeed,
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	wCreated, err := m.Create(cfg, params)
	require.NoError(t, err)

	// Attempt to load the same wallet again using the same manager instance.
	// Since it's already loaded in memory, the manager should return the
	// existing instance rather than reloading from disk.
	wLoaded, err := m.Load(cfg)

	// Verify that we got the same wallet instance back.
	require.NoError(t, err)
	require.Same(t, wCreated, wLoaded)
}

// TestManagerLoadError verifies that Load properly handles invalid
// configurations and corrupted or uninitialized databases.
func TestManagerLoadError(t *testing.T) {
	t.Parallel()

	t.Run("Invalid Config", func(t *testing.T) {
		t.Parallel()

		m := NewManager()

		// Attempt to load with an empty config. This should fail validation.
		w, err := m.Load(Config{})
		require.ErrorContains(t, err, "missing config parameter")
		require.Nil(t, w)
	})

	t.Run("Uninitialized DB", func(t *testing.T) {
		t.Parallel()

		m := NewManager()
		cfg := Config{
			DB:          testKVDBConfig(t),
			Chain:       &bwmock.Chain{},
			ChainParams: &chainParams,
			Name:        "test",
		}

		// Attempt to load from a database that has valid buckets but no
		// wallet data (waddrmgr is not initialized). This should fail
		// at the database loading step.
		w, err := m.Load(cfg)

		// We expect an error from waddrmgr.Open indicating the address
		// manager namespace is missing or invalid.
		require.Error(t, err)
		require.Nil(t, w)
	})
}

// TestManagerString verifies that the String representation of the Manager
// correctly lists the tracked wallets in alphabetical order.
func TestManagerString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setup    func(*Manager)
		expected string
	}{
		{
			name:     "empty",
			setup:    func(m *Manager) {},
			expected: "active_wallets=[]",
		},
		{
			name: "multiple sorted",
			setup: func(m *Manager) {
				m.wallets["wallet-b"] = &Wallet{}
				m.wallets["wallet-a"] = &Wallet{}
			},
			expected: "active_wallets=[wallet-a wallet-b]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := NewManager()
			tc.setup(m)
			require.Equal(t, tc.expected, m.String())
		})
	}
}

// TestManager_deriveFromSeed verifies the internal helper method
// deriveFromSeed, checking that it correctly derives a master private key
// from a seed and validates inputs.
func TestManager_deriveFromSeed(t *testing.T) {
	t.Parallel()

	m := NewManager()
	cfg := Config{ChainParams: &chainParams}

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
		require.NoError(t, err)

		key, err := m.deriveFromSeed(cfg, seed)

		// Verify we got a valid private extended key.
		require.NoError(t, err)
		require.NotNil(t, key)
		require.True(t, key.IsPrivate())
	})

	t.Run("Empty Seed", func(t *testing.T) {
		t.Parallel()

		key, err := m.deriveFromSeed(cfg, nil)
		require.ErrorIs(t, err, ErrWalletParams)
		require.ErrorContains(t, err, "seed is required")
		require.Nil(t, key)
	})

	t.Run("Invalid Seed Length", func(t *testing.T) {
		t.Parallel()

		// Providing a seed that is too short for hdkeychain.NewMaster.
		key, err := m.deriveFromSeed(cfg, []byte{0x01})
		require.ErrorContains(t, err, "failed to derive master key")
		require.Nil(t, key)
	})
}

// TestManager_genRootKey verifies the internal helper method genRootKey,
// ensuring it generates a random seed and derives a valid master key.
func TestManager_genRootKey(t *testing.T) {
	t.Parallel()

	m := NewManager()
	cfg := Config{ChainParams: &chainParams}

	key, err := m.genRootKey(cfg)

	// Verify we got a valid private extended key.
	require.NoError(t, err)
	require.NotNil(t, key)
	require.True(t, key.IsPrivate())
}

// TestManager_deriveRootKey verifies the high-level key derivation logic,
// checking that it correctly dispatches to the appropriate helper based on
// the creation mode.
func TestManager_deriveRootKey(t *testing.T) {
	t.Parallel()

	m := NewManager()
	cfg := Config{ChainParams: &chainParams}

	// 1. ModeShell: Should return nil/nil (no root key for shell).
	t.Run("ModeShell", func(t *testing.T) {
		t.Parallel()

		key, err := m.deriveRootKey(cfg, CreateWalletParams{Mode: ModeShell})
		require.NoError(t, err)
		require.Nil(t, key)
	})

	t.Run("ModeUnknown", func(t *testing.T) {
		t.Parallel()

		key, err := m.deriveRootKey(cfg, CreateWalletParams{Mode: ModeUnknown})
		require.ErrorIs(t, err, ErrWalletParams)
		require.ErrorContains(t, err, "unknown mode")
		require.Nil(t, key)
	})

	// 3. ModeGenSeed: Should return a newly generated private key.
	t.Run("ModeGenSeed", func(t *testing.T) {
		t.Parallel()

		key, err := m.deriveRootKey(cfg, CreateWalletParams{Mode: ModeGenSeed})
		require.NoError(t, err)
		require.NotNil(t, key)
		require.True(t, key.IsPrivate())
	})
}

// TestValidateInitialAccountsModeUpfront verifies the ADR 0012 invariant:
// a non-watch-only wallet cannot ship with InitialAccounts. The validator
// runs before the kvdb wallet create so the failure is atomic and no
// half-created wallet is left on disk.
func TestValidateInitialAccountsModeUpfront(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		params  CreateWalletParams
		wantErr bool
	}{
		{
			name: "watch-only with initial accounts is fine",
			params: CreateWalletParams{
				WatchOnly: true,
				InitialAccounts: []WatchOnlyAccount{{
					Name: "imported-xpub",
				}},
			},
		},
		{
			name: "spendable with no initial accounts is fine",
			params: CreateWalletParams{
				WatchOnly: false,
			},
		},
		{
			name: "spendable with initial accounts is rejected",
			params: CreateWalletParams{
				WatchOnly: false,
				InitialAccounts: []WatchOnlyAccount{{
					Name: "imported-xpub",
				}},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateInitialAccountsMode(tc.params)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrWalletParams)

				return
			}

			require.NoError(t, err)
		})
	}
}

// deriveTestAccountXPub derives the account-level extended public key for
// m/purpose'/coin'/index' from rootKey, for building initial-account imports.
func deriveTestAccountXPub(t *testing.T, rootKey *hdkeychain.ExtendedKey,
	purpose, coin, index uint32) *hdkeychain.ExtendedKey {

	t.Helper()

	key, err := rootKey.Derive(hdkeychain.HardenedKeyStart + purpose)
	require.NoError(t, err)
	key, err = key.Derive(hdkeychain.HardenedKeyStart + coin)
	require.NoError(t, err)
	key, err = key.Derive(hdkeychain.HardenedKeyStart + index)
	require.NoError(t, err)
	xpub, err := key.Neuter()
	require.NoError(t, err)

	return xpub
}

// TestValidateInitialAccountsDuplicate verifies that validateInitialAccounts
// rejects two initial accounts sharing the same (scope, name) before any store
// is written, while still accepting the same name under different scopes and a
// well-formed unique set. Duplicates must fail here because the durable
// per-account import would otherwise reject the second copy only after the
// wallet had already been committed.
func TestValidateInitialAccountsDuplicate(t *testing.T) {
	t.Parallel()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)
	rootKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)

	xpub49 := deriveTestAccountXPub(t, rootKey, 49, 0, 0)
	xpub84 := deriveTestAccountXPub(t, rootKey, 84, 0, 0)

	cfg := Config{ChainParams: &chainParams}

	tests := []struct {
		name     string
		accounts []WatchOnlyAccount
		wantErr  bool
	}{
		{
			name: "duplicate scope and name rejected",
			accounts: []WatchOnlyAccount{
				{
					Scope:    waddrmgr.KeyScopeBIP0049Plus,
					Name:     "dup",
					XPub:     xpub49,
					AddrType: waddrmgr.NestedWitnessPubKey,
				},
				{
					Scope:    waddrmgr.KeyScopeBIP0049Plus,
					Name:     "dup",
					XPub:     xpub49,
					AddrType: waddrmgr.NestedWitnessPubKey,
				},
			},
			wantErr: true,
		},
		{
			name: "same name different scope allowed",
			accounts: []WatchOnlyAccount{
				{
					Scope:    waddrmgr.KeyScopeBIP0049Plus,
					Name:     "shared",
					XPub:     xpub49,
					AddrType: waddrmgr.NestedWitnessPubKey,
				},
				{
					Scope:    waddrmgr.KeyScopeBIP0084,
					Name:     "shared",
					XPub:     xpub84,
					AddrType: waddrmgr.WitnessPubKey,
				},
			},
		},
		{
			// Two entries that collide on the xpub-derived effective
			// scope and name yet declare different Scope fields must
			// be rejected up front: the import keys off the effective
			// scope (here both NestedWitnessPubKey -> m/49'/0'), so
			// the declared scopes are irrelevant to the real conflict
			// (T4). This fails before the fix, which deduped on the
			// declared Scope and let the pair through to collide
			// mid-import.
			name: "duplicate effective scope different declared scope " +
				"rejected",
			accounts: []WatchOnlyAccount{
				{
					Scope:    waddrmgr.KeyScopeBIP0049Plus,
					Name:     "collide",
					XPub:     xpub49,
					AddrType: waddrmgr.NestedWitnessPubKey,
				},
				{
					Scope:    waddrmgr.KeyScopeBIP0084,
					Name:     "collide",
					XPub:     xpub84,
					AddrType: waddrmgr.NestedWitnessPubKey,
				},
			},
			wantErr: true,
		},
		{
			name: "unique set allowed",
			accounts: []WatchOnlyAccount{
				{
					Scope:    waddrmgr.KeyScopeBIP0049Plus,
					Name:     "one",
					XPub:     xpub49,
					AddrType: waddrmgr.NestedWitnessPubKey,
				},
				{
					Scope:    waddrmgr.KeyScopeBIP0084,
					Name:     "two",
					XPub:     xpub84,
					AddrType: waddrmgr.WitnessPubKey,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateInitialAccounts(cfg, CreateWalletParams{
				InitialAccounts: tc.accounts,
			})
			if tc.wantErr {
				require.ErrorIs(t, err, ErrWalletParams)

				return
			}

			require.NoError(t, err)
		})
	}
}

// TestManagerCreateDuplicateInitialAccounts verifies that Create rejects a
// shell wallet whose InitialAccounts contain a duplicate (scope, name) before
// any store is written, and leaves nothing durable behind: the wallet is not
// registered and a subsequent corrected create with the same name succeeds.
func TestManagerCreateDuplicateInitialAccounts(t *testing.T) {
	t.Parallel()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)
	rootKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)
	xpub := deriveTestAccountXPub(t, rootKey, 49, 0, 0)

	m := NewManager()
	cfg := Config{
		DB:             testKVDBConfig(t),
		Chain:          &bwmock.Chain{},
		ChainParams:    &chainParams,
		Name:           "dup-wallet",
		PubPassphrase:  []byte("public"),
		RecoveryWindow: MinRecoveryWindow,
	}
	dupParams := CreateWalletParams{
		Mode:      ModeShell,
		WatchOnly: true,
		InitialAccounts: []WatchOnlyAccount{
			{
				Scope:    waddrmgr.KeyScopeBIP0049Plus,
				Name:     "dup",
				XPub:     xpub,
				AddrType: waddrmgr.NestedWitnessPubKey,
			},
			{
				Scope:    waddrmgr.KeyScopeBIP0049Plus,
				Name:     "dup",
				XPub:     xpub,
				AddrType: waddrmgr.NestedWitnessPubKey,
			},
		},
		PubPassphrase: []byte("public"),
		Birthday:      time.Now(),
	}

	// Act: the duplicate must be rejected before any store write.
	w, err := m.Create(cfg, dupParams)
	require.ErrorIs(t, err, ErrWalletParams)
	require.Nil(t, w)

	// Assert: nothing durable was left behind. The wallet is not cached,
	// and a corrected create reusing the same name (single account) works,
	// which it could not if a partial wallet row or legacy wallet remained.
	m.RLock()
	_, ok := m.wallets[cfg.Name]
	m.RUnlock()
	require.False(t, ok)

	okParams := dupParams
	okParams.InitialAccounts = dupParams.InitialAccounts[:1]
	w, err = m.Create(cfg, okParams)
	require.NoError(t, err)
	require.NotNil(t, w)
	t.Cleanup(func() {
		require.NoError(t, w.closeRuntimeStore())
	})
}

// TestManagerCreateDiscardsWalletOnSeedError verifies that when default-account
// seeding fails after Load has already registered the wallet and opened its
// stores, Create tears the wallet down: it closes the runtime stores and
// removes the wallet from the manager cache instead of leaving a partial
// wallet behind. Without this cleanup a corrected retry would be blocked and
// the store handles would leak.
//
//nolint:paralleltest // Mutates the package-level runtimeStoreFactory.
func TestManagerCreateDiscardsWalletOnSeedError(t *testing.T) {
	// Arrange: a spendable SQLite-backed create so the SQL path runs
	// default-account seeding after Load.
	cfg, params := sqliteCreateConfig(t)

	oldFactory := runtimeStoreFactory
	t.Cleanup(func() {
		runtimeStoreFactory = oldFactory
	})

	// The factory returns a mock store whose default-account seeding fails,
	// plus a close hook we can observe to confirm the stores were released.
	errSeed := errors.New("seed boom")
	store := &walletmock.Store{}
	store.On(
		"CreateDerivedAccount", mock.Anything, mock.Anything,
		mock.Anything,
	).Return(nil, errSeed)

	closed := 0
	runtimeStoreFactory = func(context.Context, Config,
		*kvdb.StoreHandle) (*runtimeStoreHandle, error) {

		return &runtimeStoreHandle{
			store:      store,
			walletInfo: &db.WalletInfo{ID: 7},
			closeFn: func() error {
				closed++
				return nil
			},
		}, nil
	}

	// Act: create the wallet; seeding fails on the post-Load path.
	m := NewManager()
	w, err := m.Create(cfg, params)

	// Assert: the create fails with the seeding error, no wallet is
	// returned, the wallet is not left registered, and its runtime store
	// was closed exactly once.
	require.ErrorIs(t, err, errSeed)
	require.ErrorContains(t, err, "seed default accounts")
	require.Nil(t, w)

	m.RLock()
	_, ok := m.wallets[cfg.Name]
	m.RUnlock()
	require.False(t, ok, "wallet must not be left in the manager cache")

	require.Equal(t, 1, closed, "runtime store must be closed once")
}
