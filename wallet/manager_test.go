package wallet

import (
	"context"
	"errors"
	"iter"
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
		store.On("GetWallet", mock.Anything, name).Return(
			&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil,
		).Once()
		store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
			WalletID: walletID,
		}).
			Return([]db.AccountInfo{}, nil).Once()
		store.On("DeleteExpiredLeases", mock.Anything, walletID).
			Return(nil).Once()
	}

	chainSource := createTestChain(t)
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

			m.started.Store(true)

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

// close returns the configured backend ownership-release result.
func (b *managerBackendMock) close() error {
	args := b.Called()
	return args.Error(0)
}

// newManagerLifecycleTest supplies strict backend and chain dependencies;
// fixture cleanup joins runtime work before verifying their expected calls.
func newManagerLifecycleTest(t *testing.T,
	backend *managerBackendMock) *Manager {

	t.Helper()

	chain := &bwmock.Chain{}
	manager := &Manager{
		wallets: make(map[string]*Wallet),
		backend: backend,
		config: ManagerConfig{
			ChainSource: chain,
			ChainParams: chainParams,
		},
	}

	// LIFO cleanup keeps the mocked dependencies alive until shutdown joins.
	t.Cleanup(func() {
		backend.AssertExpectations(t)
		chain.AssertExpectations(t)
	})
	t.Cleanup(func() {
		_ = manager.Stop()
	})

	return manager
}

// TestManagerStartStopPublishesStableSet verifies only the admitted Start
// returns the complete ordered set, without rebuilding an active runtime.
func TestManagerStartStopPublishesStableSet(t *testing.T) {
	t.Parallel()

	// Arrange: Hold discovery to exercise overlapping Start admission, then
	// use real Wallet startup dependencies to verify ordered publication.
	entered := make(chan struct{})
	release := make(chan struct{})

	data := make([]*walletData, 0, 2)
	for i, name := range []string{"first", "second"} {
		_, deps := createTestWalletWithMocks(t)
		id := uint32(i + 1)

		deps.store.On("GetWallet", mock.Anything, name).Return(
			&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil,
		).Once()
		deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
			WalletID: id,
		}).Return([]db.AccountInfo{}, nil).Once()
		deps.store.On("DeleteExpiredLeases", mock.Anything, id).
			Return(nil).Once()
		deps.vault.On("Lock").Return().Once()
		data = append(data, &walletData{
			id:    id,
			name:  name,
			store: deps.store,
			vault: deps.vault,
		})
	}

	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Run(func(mock.Arguments) {
		close(entered)
		<-release
	}).Return(data, nil).Once()
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	chain, ok := manager.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)
	chain.On("IsCurrent").Return(false).Maybe()

	// Carry both results so rejected calls cannot leak partially built sets.
	type startOutcome struct {
		wallets []*Wallet
		err     error
	}

	result := make(chan startOutcome, 1)

	// Act: Attempt another Start during discovery and after publication.
	// Only the first call owns startup; neither rejected call may list again.
	go func() {
		wallets, err := manager.Start(t.Context())
		result <- startOutcome{
			wallets: wallets,
			err:     err,
		}
	}()

	<-entered

	overlapping, overlapErr := manager.Start(t.Context())

	close(release)

	first := <-result
	repeated, repeatErr := manager.Start(t.Context())

	// Assert: Rejections return no pointers, while the admitted call exposes
	// every durable Wallet in the backend's stable identifier order. The
	// repeated-start diagnostic explains the rejection to callers.
	require.ErrorIs(t, overlapErr, ErrStateForbidden)
	require.Nil(t, overlapping)
	require.ErrorIs(t, repeatErr, ErrStateForbidden)
	require.ErrorContains(t, repeatErr, "already started")
	require.Nil(t, repeated)
	require.NoError(t, first.err)
	require.Len(t, first.wallets, 2)

	for i, w := range first.wallets {
		require.Equal(t, uint32(i+1), w.ID())
	}
}

// TestManagerStartFailureCleansPartialSet prevents another Start from
// observing success while a failed attempt still owns partial runtime cleanup.
func TestManagerStartFailureCleansPartialSet(t *testing.T) {
	t.Parallel()

	// Arrange: The second Wallet fails its birthday read. Hold the first
	// Wallet's real vault cleanup so another Start must reject until the
	// admitted call finishes cleaning up its partially started set.
	_, firstDeps := createTestWalletWithMocks(t)
	_, secondDeps := createTestWalletWithMocks(t)
	startErr := errors.New("birthday unavailable")

	firstDeps.store.On("GetWallet", mock.Anything, "first").Return(
		&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil,
	).Once()
	firstDeps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 1,
	}).Return([]db.AccountInfo{}, nil).Once()
	firstDeps.store.On("DeleteExpiredLeases", mock.Anything, uint32(1)).
		Return(nil).Once()
	secondDeps.store.On("GetWallet", mock.Anything, "second").
		Return(nil, startErr).Once()

	cleanupEntered := make(chan struct{})
	releaseCleanup := make(chan struct{})
	firstDeps.vault.On("Lock").Run(func(mock.Arguments) {
		close(cleanupEntered)
		<-releaseCleanup
	}).Return().Once()

	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Return([]*walletData{
		{
			id:    1,
			name:  "first",
			store: firstDeps.store,
			vault: firstDeps.vault,
		},
		{
			id:    2,
			name:  "second",
			store: secondDeps.store,
			vault: secondDeps.vault,
		},
	}, nil).Once()
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	chain, ok := manager.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)
	chain.On("IsCurrent").Return(false).Maybe()

	// Preserve both return values to detect any partial Wallet publication
	// alongside the primary startup failure.
	type startOutcome struct {
		wallets []*Wallet
		err     error
	}

	firstResult := make(chan startOutcome, 1)

	// Act: Reject another Start while the original attempt is held in
	// cleanup, then collect its failure and check terminal admission.
	go func() {
		wallets, err := manager.Start(t.Context())
		firstResult <- startOutcome{
			wallets: wallets,
			err:     err,
		}
	}()

	<-cleanupEntered

	second, secondErr := manager.Start(t.Context())
	select {
	case result := <-firstResult:
		close(releaseCleanup)
		t.Fatalf("Start returned before cleanup completed: %v", result.err)
	default:
	}

	close(releaseCleanup)

	first := <-firstResult
	terminalWallets, terminalErr := manager.Start(t.Context())

	// Assert: No partial pointers escape either call. The admitted call
	// returns its primary failure after storage closes; a later Start
	// cannot reuse the failed Manager.
	require.Nil(t, second)
	require.ErrorIs(t, secondErr, ErrStateForbidden)
	require.Nil(t, first.wallets)
	require.ErrorIs(t, first.err, startErr)
	require.Nil(t, terminalWallets)
	require.ErrorIs(t, terminalErr, ErrManagerStopped)

	w, err := manager.Create(CreateWalletParams{})
	require.Nil(t, w)
	require.ErrorIs(t, err, ErrManagerStopped)
}

// TestManagerStartCancellationCleansUp verifies the caller's cancellation
// reaches discovery and its failure returns only after storage cleanup.
func TestManagerStartCancellationCleansUp(t *testing.T) {
	t.Parallel()

	// Arrange: Discovery waits on the supplied context. The close callback
	// signals the cleanup boundary that must precede the caller's result.
	entered := make(chan struct{})
	closed := make(chan struct{})
	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Run(func(args mock.Arguments) {
		close(entered)
		ctx, ok := args.Get(0).(context.Context)
		if !ok {
			t.Error("discovery requires a context")

			return
		}

		<-ctx.Done()
	}).Return(nil, context.Canceled).Once()
	backend.On("close").Run(func(mock.Arguments) {
		close(closed)
	}).Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	result := make(chan error, 1)

	// Act: Cancel only after discovery has begun, exercising cancellation
	// of accepted work rather than a request rejected before admission.
	go func() {
		_, err := manager.Start(ctx)
		result <- err
	}()

	<-entered
	cancel()

	err := <-result

	// Assert: The caller receives cancellation after synchronous cleanup,
	// with no detached attempt left to hold the backend open.
	require.ErrorIs(t, err, context.Canceled)

	select {
	case <-closed:
	default:
		t.Fatal("Start returned before closing storage")
	}
}

// TestManagerStartCanceledBeforeAdmission verifies canceled startup leaves
// constructor-owned resources available for a later live-context Start.
func TestManagerStartCanceledBeforeAdmission(t *testing.T) {
	t.Parallel()

	// Arrange: Only the later live-context Start may discover Wallets. The
	// fixture closes storage and verifies both strict expectations afterward.
	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Return([]*walletData{}, nil).Once()
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Reject cancellation before admission, then start the same Manager
	// with a live context to prove the rejected call left it usable.
	canceledWallets, canceledErr := manager.Start(ctx)
	wallets, err := manager.Start(t.Context())

	// Assert: The canceled call exposes no handles, while subsequent startup
	// returns the empty durable set without repeating discovery.
	require.Nil(t, canceledWallets)
	require.ErrorIs(t, canceledErr, context.Canceled)
	require.NoError(t, err)
	require.Empty(t, wallets)
}

// TestManagerStopWaitsForCleanup verifies shutdown blocks through backend
// closure, and a repeated Stop has no remaining work.
func TestManagerStopWaitsForCleanup(t *testing.T) {
	t.Parallel()

	// Arrange: Hold closure of the database opened by construction, before
	// any Start has claimed the guard. Shutdown must still reject startup.
	entered := make(chan struct{})
	release := make(chan struct{})
	closeErr := errors.New("backend close")
	backend := &managerBackendMock{}
	backend.On("close").Run(func(mock.Arguments) {
		close(entered)
		<-release
	}).Return(closeErr).Once()
	manager := newManagerLifecycleTest(t, backend)

	first := make(chan error, 1)
	second := make(chan error, 1)
	callingStop := make(chan struct{})

	// Act: Hold shutdown, reject Start, and overlap another
	// Stop. Both Stop callers check the shared completion boundary directly.
	go func() {
		err := manager.Stop()

		select {
		case <-release:
		default:
			t.Error("Stop returned before cleanup was released")
		}

		first <- err
	}()

	<-entered

	wallets, startErr := manager.Start(t.Context())
	go func() {
		close(callingStop)

		err := manager.Stop()

		select {
		case <-release:
		default:
			t.Error("concurrent Stop returned before cleanup was released")
		}

		second <- err
	}()

	<-callingStop
	close(release)

	firstErr := <-first
	secondErr := <-second
	repeatedErr := manager.Stop()

	// Assert: Only the call doing cleanup returns its failure. Neither
	// overlapping nor repeated calls create detached work or replay errors.
	require.Nil(t, wallets)
	require.ErrorIs(t, startErr, ErrStateForbidden)
	require.ErrorIs(t, firstErr, closeErr)
	require.NoError(t, secondErr)
	require.NoError(t, repeatedErr)
}

// TestManagerStopWaitsForStart verifies Stop lets synchronous startup settle
// before closing its storage, and cannot return while that work is still held.
func TestManagerStopWaitsForStart(t *testing.T) {
	t.Parallel()

	// Arrange: Discovery holds the Manager's accepted startup work. Closure
	// checks that this dependency has settled before it releases storage.
	entered := make(chan struct{})
	release := make(chan struct{})
	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Run(func(mock.Arguments) {
		close(entered)
		<-release
	}).Return([]*walletData{}, nil).Once()
	backend.On("close").Run(func(mock.Arguments) {
		select {
		case <-release:
		default:
			t.Error("backend closed during discovery")
		}
	}).Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	started := make(chan error, 1)
	stopped := make(chan error, 1)
	callingStop := make(chan struct{})

	// Act: Queue Stop behind accepted discovery, then let startup settle.
	// After shutdown, attempt Start again to check terminal admission.
	go func() {
		_, err := manager.Start(t.Context())
		started <- err
	}()

	<-entered

	go func() {
		close(callingStop)

		err := manager.Stop()

		select {
		case <-release:
		default:
			t.Error("Stop returned during discovery")
		}

		stopped <- err
	}()

	<-callingStop

	close(release)

	startErr := <-started
	stopErr := <-stopped
	terminalWallets, terminalErr := manager.Start(t.Context())

	// Assert: The admitted Start finishes normally; Stop waits and cleans up
	// exactly once. Terminal startup cannot publish another runtime set.
	require.NoError(t, startErr)
	require.NoError(t, stopErr)
	require.Nil(t, terminalWallets)
	require.ErrorIs(t, terminalErr, ErrManagerStopped)
}

// TestManagerCreateBeforeStart verifies creation rejects an inactive Manager
// before request validation or durable storage access.
func TestManagerCreateBeforeStart(t *testing.T) {
	t.Parallel()

	// Arrange: Leave the Manager unstarted and expect only fixture cleanup.
	// An empty request distinguishes lifecycle admission from validation.
	backend := &managerBackendMock{}
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)

	// Act: Submit creation before any Start has admitted runtime work.
	w, err := manager.Create(CreateWalletParams{})

	// Assert: No Wallet escapes and the lifecycle sentinel takes precedence
	// over request errors; unexpected backend access fails the strict mock.
	require.Nil(t, w)
	require.ErrorIs(t, err, ErrStateForbidden)
}

// TestManagerCreateAfterStop verifies creation rejects a terminal Manager
// without accessing its closed storage or validating the request.
func TestManagerCreateAfterStop(t *testing.T) {
	t.Parallel()

	// Arrange: Complete terminal shutdown before attempting creation. The
	// strict close expectation also covers the fixture's later no-op Stop.
	backend := &managerBackendMock{}
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	require.NoError(t, manager.Stop())

	// Act: Submit an empty request after shutdown has released storage.
	w, err := manager.Create(CreateWalletParams{})

	// Assert: Terminal admission returns no Wallet and preserves the stopped
	// identity instead of reaching validation or closed backend dependencies.
	require.Nil(t, w)
	require.ErrorIs(t, err, ErrManagerStopped)
}

// managerLifecycleCreateParams returns a rootless request so lifecycle tests
// exercise admission and teardown without unrelated random key derivation.
func managerLifecycleCreateParams(name string) CreateWalletParams {
	return CreateWalletParams{
		Name:              name,
		Mode:              ModeShell,
		WatchOnly:         true,
		PrivatePassphrase: []byte("private"),
	}
}

// TestManagerCreateLifecycleSerializesStop verifies accepted creation finishes
// startup before Stop can close storage, and real chain work drains first.
func TestManagerCreateLifecycleSerializesStop(t *testing.T) {
	t.Parallel()

	// Arrange: Block the candidate's runtime read and its chain worker at
	// separate dependencies. Storage closure checks that both have returned.
	_, deps := createTestWalletWithMocks(t)
	startupEntered := make(chan struct{})
	releaseStartup := make(chan struct{})
	chainEntered := make(chan struct{})
	releaseChain := make(chan struct{})

	deps.store.On("GetWallet", mock.Anything, "created").
		Run(func(mock.Arguments) {
			close(startupEntered)
			<-releaseStartup
		}).Return(&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil).Once()
	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 1,
	}).Return([]db.AccountInfo{}, nil).Once()
	deps.store.On("DeleteExpiredLeases", mock.Anything, uint32(1)).
		Return(nil).Once()
	vaultLock := deps.vault.On("Lock").Return().Once()

	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Return([]*walletData{}, nil).Once()

	params := managerLifecycleCreateParams("created")
	backend.On("create", mock.Anything, params, mock.Anything).
		Return(&walletData{
			id:    1,
			name:  params.Name,
			store: deps.store,
			vault: deps.vault,
		}, nil).Once()
	// Vault locking follows worker joins, so storage must close after it.
	backend.On("close").Return(nil).Once().NotBefore(vaultLock)

	manager := newManagerLifecycleTest(t, backend)
	chain, ok := manager.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)
	chain.On("IsCurrent").Run(func(mock.Arguments) {
		close(chainEntered)
		<-releaseChain
	}).Return(false).Once()

	_, err := manager.Start(t.Context())
	require.NoError(t, err)

	type createOutcome struct {
		wallet *Wallet
		err    error
	}

	created := make(chan createOutcome, 1)
	stopped := make(chan error, 1)

	// Act: Accept creation, queue Stop behind its lock, and advance startup
	// into a real chain call before allowing that worker to drain.
	go func() {
		w, err := manager.Create(params)
		created <- createOutcome{
			wallet: w,
			err:    err,
		}
	}()

	<-startupEntered

	go func() { stopped <- manager.Stop() }()

	close(releaseStartup)

	outcome := <-created

	<-chainEntered
	close(releaseChain)

	stopErr := <-stopped

	// Assert: Create publishes a started pointer, whose owned worker joins
	// before the one storage close and whose retained API is then terminal.
	require.NoError(t, outcome.err)
	require.NotNil(t, outcome.wallet)
	require.NoError(t, stopErr)
	require.ErrorIs(t, outcome.wallet.Lock(t.Context()), ErrWalletStopped)
}

// TestManagerCreateLifecycleStartFailureStopsManager verifies a committed
// candidate's startup failure preserves its primary error through teardown.
func TestManagerCreateLifecycleStartFailureStopsManager(t *testing.T) {
	t.Parallel()

	// Arrange: Commit a candidate whose birthday read fails, with an unrelated
	// backend close failure to distinguish creation from the cleanup result.
	_, deps := createTestWalletWithMocks(t)
	createErr := errors.New("candidate birthday")
	closeErr := errors.New("backend close")

	deps.store.On("GetWallet", mock.Anything, "candidate").
		Return(nil, createErr).Once()

	params := managerLifecycleCreateParams("candidate")
	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Return([]*walletData{}, nil).Once()
	backend.On("create", mock.Anything, params, mock.Anything).
		Return(&walletData{
			id:    1,
			name:  params.Name,
			store: deps.store,
			vault: deps.vault,
		}, nil).Once()
	// Hold storage closure so returning a primary Create error cannot hide
	// unfinished terminal cleanup. A concurrent Stop must join that cleanup.
	closing := make(chan struct{})
	release := make(chan struct{})
	backend.On("close").Run(func(mock.Arguments) {
		close(closing)
		<-release
	}).Return(closeErr).Once()

	manager := newManagerLifecycleTest(t, backend)
	_, err := manager.Start(t.Context())
	require.NoError(t, err)

	// Carry both Create results across the blocked cleanup boundary so an
	// inactive candidate cannot escape even when startup reports an error.
	type createOutcome struct {
		wallet *Wallet
		err    error
	}

	created := make(chan createOutcome, 1)
	stopped := make(chan error, 1)

	// Act: Fail post-commit startup, join its held cleanup through Stop, and
	// release storage closure only after checking Create has not returned.
	go func() {
		w, err := manager.Create(params)
		created <- createOutcome{
			wallet: w,
			err:    err,
		}
	}()

	<-closing

	go func() { stopped <- manager.Stop() }()

	select {
	case result := <-created:
		close(release)
		t.Fatalf("Create returned before cleanup completed: %v", result.err)
	default:
	}

	close(release)

	outcome := <-created
	stopErr := <-stopped

	// Assert: No candidate escapes and Create preserves the primary failure
	// and cleanup error only after teardown finishes. Stop has no remaining
	// work and does not replay that earlier call's errors.
	require.Nil(t, outcome.wallet)
	require.ErrorIs(t, outcome.err, createErr)
	require.ErrorIs(t, outcome.err, closeErr)
	require.NoError(t, stopErr)
}

// TestSQLManagerBackendListsWallets verifies ordered complete listing and
// all-or-nothing iterator failures.
func TestSQLManagerBackendListsWallets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rows      []db.WalletInfo
		iterErr   error
		wantIDs   []uint32
		wantNames []string
	}{
		{
			name:      "empty store",
			wantIDs:   []uint32{},
			wantNames: []string{},
		},
		{
			name: "ordered store rows",
			rows: []db.WalletInfo{
				{
					ID:   4,
					Name: "first",
				},
				{
					ID:   9,
					Name: "second",
				},
			},
			wantIDs:   []uint32{4, 9},
			wantNames: []string{"first", "second"},
		},
		{
			name:    "iterator failure",
			iterErr: errDBMock,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Yield ordered rows and an optional terminal error from
			// the Store iterator used by the backend discovery boundary.
			store := &walletmock.Store{}
			sequence := iter.Seq2[db.WalletInfo, error](func(
				yield func(db.WalletInfo, error) bool) {

				for _, row := range test.rows {
					if !yield(row, nil) {
						return
					}
				}

				if test.iterErr != nil {
					yield(db.WalletInfo{}, test.iterErr)
				}
			})
			store.On(
				"IterWallets", mock.Anything, mock.Anything,
			).Return(sequence, nil).Once()

			backend := &sqlManagerBackend{store: store}

			// Act: Resolve the complete startup listing through the SQL
			// backend boundary rather than calling the Store directly.
			wallets, err := backend.listWallets(t.Context())

			// Assert: Iterator failure prevents a partial handoff; otherwise
			// the non-nil result preserves each durable ID and name exactly.
			if test.iterErr != nil {
				require.ErrorIs(t, err, test.iterErr)
				require.Nil(t, wallets)
			} else {
				require.NoError(t, err)
				require.NotNil(t, wallets)

				ids := make([]uint32, 0, len(wallets))
				names := make([]string, 0, len(wallets))

				for _, wallet := range wallets {
					ids = append(ids, wallet.id)
					names = append(names, wallet.name)
				}

				require.Equal(t, test.wantIDs, ids)
				require.Equal(t, test.wantNames, names)
			}

			store.AssertExpectations(t)
		})
	}
}

// TestKVDBManagerBackendListsZeroOrOneWallet verifies legacy startup listing
// treats an uninitialized database as empty and an initialized database as the
// backend's sole anonymous Wallet, without inventing another identity.
func TestKVDBManagerBackendListsZeroOrOneWallet(t *testing.T) {
	t.Parallel()

	t.Run("empty database", func(t *testing.T) {
		t.Parallel()

		// Arrange: Open a fresh legacy database whose address and transaction
		// namespaces have never been created.
		manager := testKVDBManager(t)
		backend, ok := manager.backend.(*kvdbManagerBackend)
		require.True(t, ok)

		// Act: List startup data through the backend's zero-or-one boundary.
		wallets, err := backend.listWallets(t.Context())

		// Assert: Absence is a successful, initialized empty result rather
		// than an attempted load or a missing-Wallet error.
		require.NoError(t, err)
		require.NotNil(t, wallets)
		require.Empty(t, wallets)
	})

	t.Run("initialized database", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create and close the sole legacy Wallet with a non-empty
		// public passphrase, then configure a new Manager with the same bytes.
		// Mutating the caller slice after construction proves listing uses the
		// Manager's immutable copy through the existing load path.
		dbPath := testKVDBPath(t)
		pubPassphrase := []byte("startup-public")
		creator := testKVDBManagerAt(t, dbPath)
		_, err := creator.Create(CreateWalletParams{
			Name:              testWalletName,
			Mode:              ModeShell,
			WatchOnly:         true,
			PubPassphrase:     pubPassphrase,
			PrivatePassphrase: []byte("private"),
			Birthday:          time.Now(),
		})
		require.NoError(t, err)
		require.NoError(t, creator.Stop())

		manager, err := NewManager(t.Context(), ManagerConfig{
			Backend:           DBBackendKVDB,
			DataSource:        dbPath,
			ChainParams:       chainParams,
			ChainSource:       &bwmock.Chain{},
			KVDBPubPassphrase: pubPassphrase,
		})
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = manager.Stop()
		})

		pubPassphrase[0] ^= 0xff

		backend, ok := manager.backend.(*kvdbManagerBackend)
		require.True(t, ok)

		// Act: List the occupied database through the backend boundary.
		wallets, err := backend.listWallets(t.Context())

		// Assert: The existing loader returns one Wallet under kvdb's absent
		// durable name rather than inventing an alias or a second identity.
		require.NoError(t, err)
		require.Len(t, wallets, 1)
		require.Empty(t, wallets[0].name)
	})
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
// by Stop. The harness relies on this — it registers the Manager before any
// Create so that a failing Create still releases the database it opened.
func TestManagerCreateFailureLeavesManagerReusable(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		manager func(testing.TB) *Manager
	}{
		{
			name:    "kvdb",
			manager: testKVDBManager,
		},
		{
			name:    "sqlite",
			manager: testSQLiteManager,
		},
	}

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

			// Stop releases the one database the Manager owns. It is
			// called once, after quiescence.
			require.NoError(t, m.Stop())
		})
	}
}
