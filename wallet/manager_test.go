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
	// snapshot shared by both identity-only creation requests.
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

	// Act: Create two Wallets with different durable names, then mutate one
	// Wallet's network snapshot after both are assembled.
	params.Name = "first"
	first, err := manager.Create(params)
	require.NoError(t, err)

	params.Name = secondWalletName
	second, err := manager.Create(params)
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
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			},
		},
		{
			name: "ModeImportSeed",
			params: CreateWalletParams{
				Mode:              ModeImportSeed,
				Seed:              seed,
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			},
		},
		{
			name: "ModeImportExtKey",
			params: CreateWalletParams{
				Mode:              ModeImportExtKey,
				RootKey:           rootKey,
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
				WatchOnly: true,
				Birthday:  time.Now(),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := testKVDBManager(t)

			// Act: Attach the durable identity to the mode-specific request and
			// create it through the Manager-owned runtime policy.
			params := tc.params
			params.Name = testWalletName
			params.PubPassphrase = []byte("public")
			w, err := m.Create(params)

			// Verify that the wallet was created successfully and returned
			// without error.
			require.NoError(t, err)
			require.NotNil(t, w)
			require.Zero(t, w.ID())

			// Verify internal state: Ensure the manager is tracking the
			// newly created wallet in its internal map, keyed by the
			// durable request name.
			m.RLock()
			loadedW, ok := m.wallets[testWalletName]
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

			// Arrange: Install a strict backend expectation only when the
			// input is valid enough to reach durable creation. Invalid cases
			// intentionally leave the mock with no accepted calls.
			backend := &managerBackendMock{}
			params := tc.params
			params.Name = testWalletName

			if tc.valid {
				backend.On(
					"create", mock.Anything, params,
					mock.Anything,
				).Return(nil, errManagerBackendCreate).Once()
			}

			m := &Manager{
				wallets: make(map[string]*Wallet),
				backend: backend,
				config: ManagerConfig{
					ChainSource: &bwmock.Chain{},
					ChainParams: chainParams,
				},
			}

			// Act: Ask Manager to create from the selected parameter shape,
			// allowing validation to decide whether backend mutation begins.
			wallet, err := m.Create(params)

			// Assert: Valid parameters reach exactly one expected backend
			// call; invalid parameters stop at validation with no mock call.
			require.Nil(t, wallet)

			if tc.valid {
				require.ErrorIs(t, err, errManagerBackendCreate)
			} else {
				require.ErrorIs(t, err, ErrWalletParams)

				if tc.wantErrMsg != "" {
					require.ErrorContains(t, err, tc.wantErrMsg)
				}
			}

			backend.AssertExpectations(t)
		})
	}
}

var errManagerBackendCreate = errors.New("backend create called")

// managerBackendMock is the strict Manager storage-boundary test double.
type managerBackendMock struct {
	mock.Mock
}

// managerBackendMock implements managerBackend.
var _ managerBackend = (*managerBackendMock)(nil)

// listWallets returns the durable data configured by the current test.
func (b *managerBackendMock) listWallets(
	ctx context.Context) ([]*walletData, error) {

	args := b.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	//nolint:forcetypeassert // The strict expectation owns this return type.
	return args.Get(0).([]*walletData), args.Error(1)
}

// create returns the storage result configured by the current test.
func (b *managerBackendMock) create(ctx context.Context,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey) (
	*walletData, error) {

	args := b.Called(ctx, params, rootKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	//nolint:forcetypeassert // The strict expectation owns this return type.
	return args.Get(0).(*walletData), args.Error(1)
}

// load returns the identity lookup configured by the current test.
func (b *managerBackendMock) load(ctx context.Context,
	params LoadWalletParams) (*walletData, error) {

	args := b.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	//nolint:forcetypeassert // The strict expectation owns this return type.
	return args.Get(0).(*walletData), args.Error(1)
}

// close returns the configured backend ownership-release result.
func (b *managerBackendMock) close() error {
	args := b.Called()
	return args.Error(0)
}

// TestManagerCreateRejectsMissingIdentityBeforeAssembly verifies Create
// rejects an absent durable key before Store work.
func TestManagerCreateRejectsMissingIdentityBeforeAssembly(t *testing.T) {
	t.Parallel()

	// Arrange: Give Create a strict Store mock with no expectations. The
	// otherwise empty request makes the missing durable identity the only
	// relevant input.
	store := &walletmock.Store{}
	manager := testSQLManager(t, store)

	// Act: Invoke Create without the durable identity required for cache and
	// Store selection.
	w, err := manager.Create(CreateWalletParams{})

	// Assert: The identity error is primary, no partial Wallet escapes, and
	// the strict Store confirms validation happened before durable work or
	// Wallet assembly.
	require.ErrorIs(t, err, ErrMissingParam)
	require.ErrorContains(t, err, "Name")
	require.Nil(t, w)
	store.AssertExpectations(t)
}

// TestManagerLoadSuccess verifies that an existing KVDB wallet can be reopened
// with the empty public passphrase supported by the legacy address manager.
func TestManagerLoadSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Use one database path for both Managers and deliberately omit
	// the public passphrase from the creation request. The private passphrase
	// remains non-empty because spendable wallets require it.
	dbPath := testKVDBPath(t)

	m := testKVDBManagerAt(t, dbPath)
	params := CreateWalletParams{
		Name:              testWalletName,
		Mode:              ModeGenSeed,
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	// Act: Create the wallet through the first Manager using the empty public
	// credential that the underlying KVDB format accepts.
	wCreated, err := m.Create(params)

	// Assert: Creation succeeds and returns the live wallet that will later be
	// compared with the reopened metadata.
	require.NoError(t, err)
	require.NotNil(t, wCreated)

	// Act: Release the first bbolt handle, then open the same wallet through a
	// second Manager while again supplying the empty public passphrase.
	require.NoError(t, m.Close())
	m2 := testKVDBManagerAt(t, dbPath)
	w, err := m2.Load(LoadWalletParams{
		Name:          params.Name,
		PubPassphrase: params.PubPassphrase,
	})

	// Assert: Reopening succeeds, registers the Wallet under its durable name,
	// and restores the same persisted master fingerprint.
	require.NoError(t, err)
	require.NotNil(t, w)

	m2.RLock()
	loadedW, ok := m2.wallets[testWalletName]
	m2.RUnlock()
	require.True(t, ok)
	require.Same(t, w, loadedW)
	require.Zero(t, w.ID())

	require.NotZero(t, w.masterFingerprint)
	require.Equal(t, wCreated.masterFingerprint, w.masterFingerprint)
}

// TestManagerLoadExistingWallet verifies that if Load is called for a wallet
// that is already managed in memory, the Manager detects this.
func TestManagerLoadExistingWallet(t *testing.T) {
	t.Parallel()

	dbPath := testKVDBPath(t)

	m := testKVDBManagerAt(t, dbPath)
	params := CreateWalletParams{
		Name:              testWalletName,
		Mode:              ModeGenSeed,
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	wCreated, err := m.Create(params)
	require.NoError(t, err)

	// Attempt to load the same wallet again using the same manager instance.
	// Since it's already loaded in memory, the manager should return the
	// existing instance rather than reloading from disk.
	wLoaded, err := m.Load(LoadWalletParams{
		Name:          params.Name,
		PubPassphrase: params.PubPassphrase,
	})

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

		// Arrange: Use a valid kvdb Manager so the empty request name is the
		// only invalid input observed before cache or backend lookup.
		m := testKVDBManager(t)

		// Act: Attempt to load without the required durable identity.
		w, err := m.Load(LoadWalletParams{})

		// Assert: The shared request boundary rejects the call before backend
		// lookup and does not expose a partial Wallet.
		require.ErrorIs(t, err, ErrMissingParam)
		require.ErrorContains(t, err, "missing config parameter")
		require.ErrorContains(t, err, "Name")
		require.Nil(t, w)
	})

	t.Run("Missing Wallet", func(t *testing.T) {
		t.Parallel()

		// Arrange a fresh kvdb-backed Manager whose database has never
		// contained wallet state. This distinguishes absence from a
		// partially initialized or corrupt wallet.
		m := testKVDBManager(t)
		// Act by loading the never-created wallet through the public
		// Manager boundary.
		w, err := m.Load(LoadWalletParams{
			Name:          "test",
			PubPassphrase: []byte("public"),
		})

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
	w, err := m.Load(LoadWalletParams{Name: walletName})

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

// TestManagerDeriveFromSeed verifies the internal helper method
// deriveFromSeed, checking that it correctly derives a master private key
// from a seed and validates inputs.
func TestManagerDeriveFromSeed(t *testing.T) {
	t.Parallel()

	m := testKVDBManager(t)

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
		require.NoError(t, err)

		key, err := m.deriveFromSeed(seed)

		// Verify we got a valid private extended key.
		require.NoError(t, err)
		require.NotNil(t, key)
		require.True(t, key.IsPrivate())
	})

	t.Run("Empty Seed", func(t *testing.T) {
		t.Parallel()

		key, err := m.deriveFromSeed(nil)
		require.ErrorIs(t, err, ErrWalletParams)
		require.ErrorContains(t, err, "seed is required")
		require.Nil(t, key)
	})

	t.Run("Invalid Seed Length", func(t *testing.T) {
		t.Parallel()

		// Providing a seed that is too short for hdkeychain.NewMaster.
		key, err := m.deriveFromSeed([]byte{0x01})
		require.ErrorContains(t, err, "failed to derive master key")
		require.Nil(t, key)
	})
}

// TestManagerGenRootKey verifies the internal helper method genRootKey,
// ensuring it generates a random seed and derives a valid master key.
func TestManagerGenRootKey(t *testing.T) {
	t.Parallel()

	m := testKVDBManager(t)

	// With no configured kvdb path there is no legacy wallet to recover, so
	// genRootKey takes the fresh-generation branch.
	key, err := m.genRootKey()

	// Verify we got a valid private extended key.
	require.NoError(t, err)
	require.NotNil(t, key)
	require.True(t, key.IsPrivate())
}

// TestManagerDeriveRootKey verifies the high-level key derivation logic,
// checking that it correctly dispatches to the appropriate helper based on
// the creation mode.
func TestManagerDeriveRootKey(t *testing.T) {
	t.Parallel()

	m := testKVDBManager(t)

	// ModeShell should return nil/nil because it has no root key.
	t.Run("ModeShell", func(t *testing.T) {
		t.Parallel()

		key, err := m.deriveRootKey(CreateWalletParams{Mode: ModeShell})
		require.NoError(t, err)
		require.Nil(t, key)
	})

	// ModeGenSeed should return a newly generated private key.
	t.Run("ModeGenSeed", func(t *testing.T) {
		t.Parallel()

		key, err := m.deriveRootKey(CreateWalletParams{Mode: ModeGenSeed})
		require.NoError(t, err)
		require.NotNil(t, key)
		require.True(t, key.IsPrivate())
	})
}

// TestManagerKVDBCreateWatchOnlyShell verifies that the legacy kvdb backend
// creates a rootless watch-only wallet with an empty private passphrase,
// preserving the behavior of the legacy watch-only constructor.
func TestManagerKVDBCreateWatchOnlyShell(t *testing.T) {
	t.Parallel()

	params := CreateWalletParams{
		Name:          testWalletName,
		Mode:          ModeShell,
		WatchOnly:     true,
		PubPassphrase: []byte("public"),
		Birthday:      time.Now(),
	}

	w, err := testKVDBManager(t).Create(params)
	require.NoError(t, err)
	require.NotNil(t, w)
	require.True(t, w.IsWatchOnly())

	// No root key was supplied, so no master fingerprint is cached. The value
	// is unobservable on a watch-only wallet regardless: it is reported only
	// for derived accounts, which such a wallet cannot have.
	require.Zero(t, w.masterFingerprint)
}

// TestManagerKVDBRejectsSecondCreate verifies the legacy backend enforces its
// one-Wallet limit even when the second request has another runtime name.
func TestManagerKVDBRejectsSecondCreate(t *testing.T) {
	t.Parallel()

	// Arrange: Create the one Wallet the kvdb backend can keep open.
	m := testKVDBManager(t)
	params := CreateWalletParams{
		Name:              "first",
		Mode:              ModeGenSeed,
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	first, err := m.Create(params)
	require.NoError(t, err)
	require.NotNil(t, first)

	// Act: Attempt to create a sibling identity through the same Manager.
	params.Name = "second"
	second, err := m.Create(params)

	// Assert: The backend reports its single-Wallet constraint and does not
	// return a second runtime instance.
	require.ErrorIs(t, err, ErrInvalidParam)
	require.ErrorContains(t, err, "one wallet per database")
	require.Nil(t, second)
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
	}{{
		name:    "kvdb",
		manager: testKVDBManager,
	}, {
		name:    "sqlite",
		manager: testSQLiteManager,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := tc.manager(t)
			// Arrange + Act: a seed too short for BIP32 fails root
			// derivation, after the Manager has already opened its
			// database.
			seed, err := hdkeychain.GenerateSeed(
				hdkeychain.RecommendedSeedLen,
			)
			require.NoError(t, err)

			w, err := m.Create(CreateWalletParams{
				Name:              testWalletName,
				Mode:              ModeImportSeed,
				Seed:              seed[:hdkeychain.MinSeedBytes-1],
				PubPassphrase:     []byte("public"),
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			})
			require.ErrorIs(t, err, hdkeychain.ErrInvalidSeedLen)
			require.Nil(t, w)

			// Assert: nothing was published, so the name is free and
			// a corrected create succeeds over the same database.
			w, err = m.Create(CreateWalletParams{
				Name:              testWalletName,
				Mode:              ModeImportSeed,
				Seed:              seed,
				PubPassphrase:     []byte("public"),
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
