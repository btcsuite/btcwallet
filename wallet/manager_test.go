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
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestWalletID verifies that Wallet.ID returns the cached runtime ID.
func TestWalletID(t *testing.T) {
	t.Parallel()

	w := &Wallet{id: 42}

	require.Equal(t, uint32(42), w.ID())
}

// TestManagerBuildsWalletsFromRuntimePolicy verifies sibling SQL Wallets use
// identical Manager policy while retaining independent mutable snapshots.
func TestManagerBuildsWalletsFromRuntimePolicy(t *testing.T) {
	t.Parallel()

	// Arrange: Configure two exact Store creations and a distinctive Manager
	// snapshot; the caller Config values deliberately conflict with that policy.
	const secondWalletName = "second"

	store := &walletmock.Store{}
	for i, name := range []string{"first", secondWalletName} {
		walletID := uint32(i + 1)
		store.On(
			"CreateWallet", mock.Anything,
			mock.MatchedBy(func(params db.CreateWalletParams) bool {
				return params.Name == name
			}),
		).Return(&db.WalletInfo{
			ID:          walletID,
			Name:        name,
			IsWatchOnly: true,
		}, nil).Once()
	}

	chainSource := &bwmock.Chain{}
	manager := testSQLManager(t, store)
	manager.config.ChainSource = chainSource
	manager.config.SyncMethod = SyncMethodFullBlocks
	manager.config.WalletSyncRetryInterval = 2 * time.Second
	manager.config.RecoveryWindow = 12
	manager.config.AutoLockDuration = 3 * time.Minute
	manager.config.MaxCFilterItems = 50
	params := CreateWalletParams{
		Mode:              ModeShell,
		WatchOnly:         true,
		PrivatePassphrase: []byte("private"),
	}

	// Act: Create two Wallets while supplying conflicting per-call policy,
	// then mutate one Wallet's network snapshot after both are assembled.
	first, err := manager.Create(Config{
		Name:           "first",
		Chain:          &bwmock.Chain{},
		RecoveryWindow: 99,
	}, params)
	require.NoError(t, err)
	second, err := manager.Create(Config{Name: "second"}, params)
	require.NoError(t, err)

	first.cfg.ChainParams.Name = "mutated"

	// Assert: Verify the caller-owned source is shared while scalar policy is
	// identical, network snapshots are independent, and each Store call occurs
	// exactly once.
	require.Same(t, chainSource, first.cfg.Chain)
	require.Same(t, chainSource, second.cfg.Chain)
	require.Equal(t, SyncMethodFullBlocks, first.cfg.SyncMethod)
	require.Equal(t, first.cfg.SyncMethod, second.cfg.SyncMethod)
	require.Equal(t, 2*time.Second, first.cfg.WalletSyncRetryInterval)
	require.Equal(t, first.cfg.WalletSyncRetryInterval,
		second.cfg.WalletSyncRetryInterval)
	require.Equal(t, uint32(12), first.cfg.RecoveryWindow)
	require.Equal(t, first.cfg.RecoveryWindow, second.cfg.RecoveryWindow)
	require.Equal(t, 3*time.Minute, first.cfg.AutoLockDuration)
	require.Equal(t, first.cfg.AutoLockDuration, second.cfg.AutoLockDuration)
	require.Equal(t, uint32(50), first.cfg.MaxCFilterItems)
	require.Equal(t, first.cfg.MaxCFilterItems, second.cfg.MaxCFilterItems)
	require.NotEqual(t, first.cfg.ChainParams.Name,
		second.cfg.ChainParams.Name)
	store.AssertExpectations(t)
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
				Chain:         &bwmock.Chain{},
				ChainParams:   &chainParams,
				Name:          "test-wallet",
				PubPassphrase: []byte("public"),
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

// TestCreateWalletParamsPolicy verifies the complete creation-mode matrix and
// proves every rejected combination fails before backend creation.
func TestCreateWalletParamsPolicy(t *testing.T) {
	t.Parallel()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	rootKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)
	rootXPub, err := rootKey.Neuter()
	require.NoError(t, err)

	accountKey, err := rootKey.Derive(hdkeychain.HardenedKeyStart + 44)
	require.NoError(t, err)
	accountKey, err = accountKey.Derive(hdkeychain.HardenedKeyStart)
	require.NoError(t, err)
	accountKey, err = accountKey.Derive(hdkeychain.HardenedKeyStart)
	require.NoError(t, err)
	accountXPub, err := accountKey.Neuter()
	require.NoError(t, err)

	initialXPub := []WatchOnlyAccount{{XPub: accountXPub}}
	initialXPrv := []WatchOnlyAccount{{XPub: rootKey}}
	initialNil := []WatchOnlyAccount{{}}

	tests := []struct {
		name       string
		params     CreateWalletParams
		valid      bool
		wantErrMsg string
	}{
		{
			name:   "generated seed spendable",
			params: CreateWalletParams{Mode: ModeGenSeed},
			valid:  true,
		},
		{
			name:   "imported seed spendable",
			params: CreateWalletParams{Mode: ModeImportSeed, Seed: seed},
			valid:  true,
		},
		{
			name: "private root spendable",
			params: CreateWalletParams{Mode: ModeImportExtKey,
				RootKey: rootKey},
			valid: true,
		},
		{
			name: "watch-only shell with XPub",
			params: CreateWalletParams{Mode: ModeShell, WatchOnly: true,
				InitialAccounts: initialXPub},
			valid: true,
		},
		{
			name:   "unknown mode",
			params: CreateWalletParams{Mode: ModeUnknown},
		},
		{
			name:   "generated seed watch-only",
			params: CreateWalletParams{Mode: ModeGenSeed, WatchOnly: true},
		},
		{
			name:   "generated seed with explicit seed",
			params: CreateWalletParams{Mode: ModeGenSeed, Seed: seed},
		},
		{
			name:   "generated seed with root key",
			params: CreateWalletParams{Mode: ModeGenSeed, RootKey: rootKey},
		},
		{
			name: "generated seed with initial account",
			params: CreateWalletParams{Mode: ModeGenSeed,
				InitialAccounts: initialXPub,
			},
		},
		{
			name: "imported seed watch-only",
			params: CreateWalletParams{Mode: ModeImportSeed, Seed: seed,
				WatchOnly: true},
		},
		{
			name:   "imported seed missing seed",
			params: CreateWalletParams{Mode: ModeImportSeed},
		},
		{
			name: "imported seed with root key",
			params: CreateWalletParams{Mode: ModeImportSeed, Seed: seed,
				RootKey: rootKey},
		},
		{
			name: "imported seed with initial account",
			params: CreateWalletParams{Mode: ModeImportSeed, Seed: seed,
				InitialAccounts: initialXPub,
			},
		},
		{
			name: "private root watch-only",
			params: CreateWalletParams{Mode: ModeImportExtKey,
				RootKey: rootKey, WatchOnly: true},
		},
		{
			name:   "extended root missing key",
			params: CreateWalletParams{Mode: ModeImportExtKey},
		},
		{
			name: "XPub root spendable",
			params: CreateWalletParams{Mode: ModeImportExtKey,
				RootKey: rootXPub},
		},
		{
			name: "XPub root watch-only",
			params: CreateWalletParams{Mode: ModeImportExtKey,
				RootKey: rootXPub, WatchOnly: true},
		},
		{
			name: "extended root with seed",
			params: CreateWalletParams{Mode: ModeImportExtKey,
				RootKey: rootKey, Seed: seed},
		},
		{
			name: "extended root with initial account",
			params: CreateWalletParams{Mode: ModeImportExtKey,
				RootKey:         rootKey,
				InitialAccounts: initialXPub,
			},
		},
		{
			name:   "spendable shell",
			params: CreateWalletParams{Mode: ModeShell},
		},
		{
			name: "shell with seed",
			params: CreateWalletParams{Mode: ModeShell, Seed: seed,
				WatchOnly: true},
		},
		{
			name: "shell with root key",
			params: CreateWalletParams{Mode: ModeShell, RootKey: rootKey,
				WatchOnly: true},
		},
		{
			name: "shell with nil account key",
			params: CreateWalletParams{Mode: ModeShell, WatchOnly: true,
				InitialAccounts: initialNil,
			},
			wantErrMsg: "needs XPub",
		},
		{
			name: "shell with private account key",
			params: CreateWalletParams{Mode: ModeShell, WatchOnly: true,
				InitialAccounts: initialXPrv,
			},
			wantErrMsg: "needs XPub, not XPrv",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			backend := &recordingManagerBackend{}
			m := &Manager{
				wallets: make(map[string]*Wallet),
				backend: backend,
				config: ManagerConfig{
					ChainSource: &bwmock.Chain{},
					ChainParams: chainParams,
				},
			}
			cfg := Config{
				Chain: &bwmock.Chain{}, Name: "test-wallet",
			}

			wallet, err := m.Create(cfg, tc.params)
			require.Nil(t, wallet)

			if tc.valid {
				require.ErrorIs(
					t, err, errRecordingManagerBackendCreate,
				)
				require.True(t, backend.createCalled)

				return
			}

			require.ErrorIs(t, err, ErrWalletParams)

			if tc.wantErrMsg != "" {
				require.ErrorContains(t, err, tc.wantErrMsg)
			}

			require.False(t, backend.createCalled)
		})
	}
}

var errRecordingManagerBackendCreate = errors.New("backend create called")

// recordingManagerBackend records whether Manager.Create reached backend
// mutation during creation-policy tests.
type recordingManagerBackend struct{ createCalled bool }

// recordingManagerBackend implements managerBackend.
var _ managerBackend = (*recordingManagerBackend)(nil)

// create records an unexpected backend creation attempt.
func (b *recordingManagerBackend) create(_ context.Context, _ Config,
	_ CreateWalletParams, _ *hdkeychain.ExtendedKey) (*walletData, error) {

	b.createCalled = true

	return nil, errRecordingManagerBackendCreate
}

// load is not used by creation-policy tests.
func (*recordingManagerBackend) load(context.Context, Config) (*walletData,
	error) {

	return nil, ErrInvalidParam
}

// close is not used by creation-policy tests.
func (*recordingManagerBackend) close() error {
	return nil
}

// TestManagerLoadSuccess verifies that an existing wallet can be successfully
// loaded from the database. This tests the persistence and restoration flow.
func TestManagerLoadSuccess(t *testing.T) {
	t.Parallel()

	dbPath := testKVDBPath(t)

	m := testKVDBManagerAt(t, dbPath)
	cfg := Config{
		Chain:         &bwmock.Chain{},
		ChainParams:   &chainParams,
		Name:          "test-wallet",
		PubPassphrase: []byte("public"),
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
		Chain:         &bwmock.Chain{},
		ChainParams:   &chainParams,
		Name:          "test-wallet",
		PubPassphrase: []byte("public"),
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

	t.Run("Missing Wallet", func(t *testing.T) {
		t.Parallel()

		// Arrange a fresh kvdb-backed Manager whose database has never
		// contained wallet state. This distinguishes absence from a
		// partially initialized or corrupt wallet.
		m := testKVDBManager(t)
		cfg := Config{
			Chain:       &bwmock.Chain{},
			ChainParams: &chainParams,
			Name:        "test",
		}

		// Act by loading the never-created wallet through the public
		// Manager boundary.
		w, err := m.Load(cfg)

		// Assert that the Manager replaces the internal database sentinel
		// with its public missing-wallet contract and returns no partial
		// Wallet.
		require.ErrorIs(t, err, ErrWalletNotFound)
		require.NotErrorIs(t, err, db.ErrWalletNotFound)
		require.Nil(t, w)
	})
}

// TestManagerLoadMissingSQLite verifies that a real SQLite wallet miss obeys
// the public Manager contract without exposing its internal database sentinel.
func TestManagerLoadMissingSQLite(t *testing.T) {
	t.Parallel()

	// Arrange a Manager over a fresh real SQLite database with a wallet name
	// that has never been created.
	m := testSQLiteManager(t)

	const walletName = "no-such-wallet"

	// Act by loading the absent wallet through the public Manager method.
	w, err := m.Load(Config{
		Chain: &bwmock.Chain{},
		Name:  walletName,
	})

	// Assert that callers receive only the wallet-owned sentinel, retain the
	// requested name for context, and never receive a partial Wallet.
	require.ErrorIs(t, err, ErrWalletNotFound)
	require.NotErrorIs(t, err, db.ErrWalletNotFound)
	require.ErrorContains(t, err, walletName)
	require.Nil(t, w)
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

	// ModeShell should return nil/nil because it has no root key.
	t.Run("ModeShell", func(t *testing.T) {
		t.Parallel()

		key, err := m.deriveRootKey(cfg, CreateWalletParams{Mode: ModeShell})
		require.NoError(t, err)
		require.Nil(t, key)
	})

	// ModeGenSeed should return a newly generated private key.
	t.Run("ModeGenSeed", func(t *testing.T) {
		t.Parallel()

		key, err := m.deriveRootKey(cfg, CreateWalletParams{Mode: ModeGenSeed})
		require.NoError(t, err)
		require.NotNil(t, key)
		require.True(t, key.IsPrivate())
	})
}

// TestManagerKVDBCreateWatchOnlyShell verifies that the legacy kvdb backend
// creates a rootless watch-only wallet, which is the one watch-only shape its
// format can represent and what the legacy watch-only constructor built.
func TestManagerKVDBCreateWatchOnlyShell(t *testing.T) {
	t.Parallel()

	params := CreateWalletParams{
		Mode:              ModeShell,
		WatchOnly:         true,
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	w, err := testKVDBManager(t).Create(testWatchOnlyConfig(), params)
	require.NoError(t, err)
	require.NotNil(t, w)
	require.True(t, w.IsWatchOnly())

	// No root key was supplied, so no master fingerprint is cached. The value
	// is unobservable on a watch-only wallet regardless: it is reported only
	// for derived accounts, which such a wallet cannot have.
	require.Zero(t, w.masterFingerprint)
}

// testWatchOnlyConfig returns the wallet Config shared by the watch-only
// Manager tests.
func testWatchOnlyConfig() Config {
	return Config{
		Chain:         &bwmock.Chain{},
		ChainParams:   &chainParams,
		Name:          "watch-only",
		PubPassphrase: []byte("public"),
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
		Chain:         &bwmock.Chain{},
		ChainParams:   &chainParams,
		Name:          "first",
		PubPassphrase: []byte("public"),
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
				Chain:         &bwmock.Chain{},
				ChainParams:   &chainParams,
				Name:          testWalletName,
				PubPassphrase: tc.pubPass,
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
		Chain:         &bwmock.Chain{},
		ChainParams:   &chainParams,
		Name:          testWalletName,
		PubPassphrase: configPub,
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
