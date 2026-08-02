package wallet

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
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

			m := testKVDBManager(t)
			cfg := Config{
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

			m := testKVDBManager(t)
			cfg := Config{
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

	m := testKVDBManager(t)

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

	dbPath := testKVDBPath(t)

	m := testKVDBManagerAt(t, dbPath)
	cfg := Config{
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

	// Release the database so a second Manager can open the same file: one
	// bbolt handle per file, and the Manager owns it.
	require.NoError(t, m.Close())

	// Open a second Manager over the same database to simulate a fresh start
	// (e.g. daemon restart) and load the wallet from it.
	m2 := testKVDBManagerAt(t, dbPath)
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

	dbPath := testKVDBPath(t)

	m := testKVDBManagerAt(t, dbPath)
	cfg := Config{
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

		m := testKVDBManager(t)

		// Attempt to load with an empty config. This should fail validation.
		w, err := m.Load(Config{})
		require.ErrorContains(t, err, "missing config parameter")
		require.Nil(t, w)
	})

	t.Run("Uninitialized DB", func(t *testing.T) {
		t.Parallel()

		m := testKVDBManager(t)
		cfg := Config{
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

			m := testKVDBManager(t)
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

	m := testKVDBManager(t)
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

	m := testKVDBManager(t)
	cfg := Config{ChainParams: &chainParams}

	// With no configured kvdb path there is no legacy wallet to recover, so
	// genRootKey takes the fresh-generation branch.
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

	m := testKVDBManager(t)
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

// TestManagerKVDBRejectsSecondName verifies that a kvdb Manager serves one
// wallet per database.
//
// The deprecated kvdb backend owns one live address manager, so it rejects a
// second wallet name. Restart-stable name identity is a separate question;
// this covers the in-process limit retained until kvdb support is removed.
func TestManagerKVDBRejectsSecondName(t *testing.T) {
	t.Parallel()

	m := testKVDBManager(t)
	cfg := Config{
		Chain:          &bwmock.Chain{},
		ChainParams:    &chainParams,
		Name:           "first",
		PubPassphrase:  []byte("public"),
		RecoveryWindow: MinRecoveryWindow,
	}
	params := CreateWalletParams{
		Mode:              ModeGenSeed,
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	first, err := m.Create(cfg, params)
	require.NoError(t, err)
	require.NotNil(t, first)

	// A different name on the same Manager is refused.
	second := cfg
	second.Name = "second"

	_, err = m.Create(second, params)
	require.ErrorIs(t, err, ErrInvalidParam)
	require.ErrorContains(t, err, "one wallet per database")

	_, err = m.Load(second)
	require.ErrorIs(t, err, ErrInvalidParam)

	// The rejected call did not replace the backend's wallet: the original
	// name still resolves to the same wallet, and that wallet still works.
	again, err := m.Load(cfg)
	require.NoError(t, err)
	require.Same(t, first, again)

	startLoadedWalletForTest(t, again)
	_, err = again.ListAccounts(t.Context())
	require.NoError(t, err)
}

// TestManagerCreateFailureLeavesManagerReusable verifies that a failed Create
// leaves no durable trace in the Manager: the wallet is not published, the name
// is still free, and the database the Manager opened is released exactly once
// by Close. The harness relies on this — it registers the Manager before any
// Create so that a failing Create still closes the database it opened.
func TestManagerCreateFailureLeavesManagerReusable(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		manager func(testing.TB) *Manager
		pubPass []byte
	}{{
		name:    "kvdb",
		manager: testKVDBManager,
		pubPass: []byte("public"),
	}, {
		name:    "sqlite",
		manager: testSQLiteManager,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := tc.manager(t)
			cfg := Config{
				Chain:          &bwmock.Chain{},
				ChainParams:    &chainParams,
				Name:           testWalletName,
				PubPassphrase:  tc.pubPass,
				RecoveryWindow: MinRecoveryWindow,
			}

			// Arrange + Act: a seed too short for BIP32 fails root
			// derivation, after the Manager has already opened its
			// database.
			seed, err := hdkeychain.GenerateSeed(
				hdkeychain.RecommendedSeedLen,
			)
			require.NoError(t, err)

			w, err := m.Create(cfg, CreateWalletParams{
				Mode:              ModeImportSeed,
				Seed:              seed[:hdkeychain.MinSeedBytes-1],
				PubPassphrase:     tc.pubPass,
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			})
			require.ErrorIs(t, err, hdkeychain.ErrInvalidSeedLen)
			require.Nil(t, w)

			// Assert: nothing was published, so the name is free and
			// a corrected create succeeds over the same database.
			w, err = m.Create(cfg, CreateWalletParams{
				Mode:              ModeImportSeed,
				Seed:              seed,
				PubPassphrase:     tc.pubPass,
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			})
			require.NoError(t, err)
			require.NotNil(t, w)

			// Close releases the one database the Manager owns. It is
			// called once, after quiescence.
			require.NoError(t, m.Close())
		})
	}
}

// TestManagerIgnoresPerWalletDBAndChainParams verifies that the Manager owns
// the database and the network for every wallet it serves: a per-wallet Config
// that leaves both unset still yields a working wallet on the Manager's own
// database and chain parameters, on both backends.
// Config.DB is deprecated and Config.ChainParams is overwritten, so neither
// can steer a wallet somewhere the Manager did not open.
func TestManagerIgnoresPerWalletDBAndChainParams(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		backend DBBackend
		file    string
		pubPass []byte
	}{{
		name:    "kvdb",
		backend: DBBackendKVDB,
		file:    "wallet.db",
		pubPass: []byte("public"),
	}, {
		name:    "sqlite",
		backend: DBBackendSQLite,
		file:    "wallet.sqlite",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dbPath := filepath.Join(t.TempDir(), tc.file)
			open := func() (*Manager, error) {
				return NewManager(
					t.Context(), ManagerConfig{
						Backend:     tc.backend,
						DataSource:  dbPath,
						ChainParams: &chainParams,
					},
				)
			}

			seed, err := hdkeychain.GenerateSeed(
				hdkeychain.RecommendedSeedLen,
			)
			require.NoError(t, err)

			m, err := open()
			require.NoError(t, err)

			// Arrange: no DB and no network at all — the Manager
			// must supply both.
			cfg := Config{
				Chain:          &bwmock.Chain{},
				ChainParams:    nil,
				DB:             nil,
				Name:           testWalletName,
				PubPassphrase:  tc.pubPass,
				RecoveryWindow: MinRecoveryWindow,
			}

			w, err := m.Create(cfg, CreateWalletParams{
				Mode:              ModeImportSeed,
				Seed:              seed,
				PubPassphrase:     tc.pubPass,
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			})
			require.NoError(t, err)

			// Assert: a *fresh* Manager over the same database performs
			// a real Load with the same nil-field Config, so the
			// injection is proven off the cached-hit path too.
			require.NoError(t, m.Close())

			reopened, err := open()
			require.NoError(t, err)
			t.Cleanup(func() { _ = reopened.Close() })

			fresh, err := reopened.Load(cfg)
			require.NoError(t, err)
			require.NotSame(t, w, fresh)
		})
	}
}

// TestManagerCreateHonoursCreatePubPassphrase verifies that a kvdb wallet is
// created under CreateWalletParams.PubPassphrase, not Config.PubPassphrase. The
// two are separate credentials — the request's is the create one, the config's
// is what a later Load supplies — so a test that sets them to the same bytes
// cannot tell the two apart and would mask a create path reading the wrong
// field.
func TestManagerCreateHonoursCreatePubPassphrase(t *testing.T) {
	t.Parallel()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	dbPath := testKVDBPath(t)

	createPub := []byte("create-public-passphrase")
	configPub := []byte("config-public-passphrase")

	// Arrange + Act: create under createPub while the Config names configPub.
	m := testKVDBManagerAt(t, dbPath)
	cfg := Config{
		Chain:          &bwmock.Chain{},
		ChainParams:    &chainParams,
		Name:           testWalletName,
		PubPassphrase:  configPub,
		RecoveryWindow: MinRecoveryWindow,
	}
	w, err := m.Create(cfg, CreateWalletParams{
		Mode:              ModeImportSeed,
		Seed:              seed,
		PubPassphrase:     createPub,
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	})
	require.NoError(t, err)
	require.NotNil(t, w)
	require.NoError(t, m.Close())

	// Assert: a fresh Manager opens the wallet with the passphrase it was
	// created under.
	loadCfg := cfg
	loadCfg.PubPassphrase = createPub

	reopened := testKVDBManagerAt(t, dbPath)
	loaded, err := reopened.Load(loadCfg)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	require.NoError(t, reopened.Close())
}
