package wallet

import (
	"context"
	"encoding/binary"
	"errors"
	"iter"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
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

	manager := testSQLManager(t, store)
	chainSource := manager.config.ChainSource
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

// TestManagerChainRollbackOrder fences both published recipients before one
// Store rollback and permits the next complete connected delivery afterward.
func TestManagerChainRollbackOrder(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		// Arrange: Capacity-one mailboxes first accept an ordinary event.
		// An exact block receipt exposes rollback before both workers
		// acknowledge and detects any lost block hash or timestamp.
		first, firstDeps := createTestWalletWithMocks(t)
		first.cfg.Name = testWalletName
		first.id = 1
		startLoadedWalletForTest(t, first)
		firstDeps.vault.On("Lock").Return().Once()

		second, secondDeps := createTestWalletWithMocks(t)
		second.cfg.Name = "second"
		second.id = 2
		startLoadedWalletForTest(t, second)
		secondDeps.vault.On("Lock").Return().Once()

		backend := &managerBackendMock{}
		backend.On("close").Return(nil).Once()
		m := newManagerLifecycleTest(t, backend)
		m.started.Store(true)
		m.wallets[first.cfg.Name], m.wallets[second.cfg.Name] = first, second
		firstEvents := make(chan chainEvent, 1)
		secondEvents := make(chan chainEvent, 1)
		first.chainEventChan, second.chainEventChan = firstEvents, secondEvents
		event := chain.FilteredBlockConnected{
			Block: &wtxmgr.BlockMeta{Block: wtxmgr.Block{Height: 8}},
		}
		persisted := make(chan struct{})
		expected := db.Block{
			Height: 8, Hash: chainhash.Hash{8}, Timestamp: time.Unix(8, 0),
		}
		backend.On("rollbackToBlock", mock.Anything, expected).
			Run(func(mock.Arguments) { close(persisted) }).Return(nil).Once()

		// Act: One source caller accepts the prior event before rollback;
		// each simulated worker acknowledges only after that event is read.
		require.NoError(t, m.dispatchChainEvent(t.Context(), event))
		require.Equal(t, event, (<-firstEvents).notification)
		require.Equal(t, event, (<-secondEvents).notification)

		rolled := make(chan error, 1)
		go func() {
			rolled <- m.dispatchChainEvent(t.Context(), chain.BlockDisconnected{
				Block: wtxmgr.Block{Height: 8, Hash: expected.Hash},
				Time:  expected.Timestamp,
			})
		}()

		for range 2 {
			var raw chainEvent
			select {
			case raw = <-firstEvents:
			case raw = <-secondEvents:
			}

			req, ok := raw.notification.(prepareRollbackReq)
			require.True(t, ok)
			synctest.Wait()
			require.Empty(t, persisted)
			close(req.readyForRollback)
		}

		// Assert: The sole rollback completes after both receipts; no raw
		// disconnect reaches a Wallet, its full identity matches the backend
		// expectation, and later full fanout still succeeds.
		require.NoError(t, <-rolled)
		require.True(t, m.started.Load())
		require.NoError(t, m.dispatchChainEvent(t.Context(), event))
		require.Equal(t, event, (<-firstEvents).notification)
		require.Equal(t, event, (<-secondEvents).notification)
	})
}

// TestManagerChainRollbackStopsOnError makes definite and ambiguous Store
// outcomes terminal while the operation still owns worker continuation.
func TestManagerChainRollbackStopsOnError(t *testing.T) {
	t.Parallel()

	for _, failure := range []error{errDBMock, dbruntime.ErrAmbiguousTxCommit} {
		t.Run(failure.Error(), func(t *testing.T) {
			t.Parallel()

			// Arrange: Fail the backend operation after the real processor
			// acknowledges readiness. Cleanup must cancel and join that
			// processor before closing storage or releasing completion.
			w, wDeps := createTestWalletWithMocks(t)
			w.cfg.Name = testWalletName
			w.id = 1
			startLoadedWalletForTest(t, w)
			wDeps.vault.On("Lock").Return().Once()

			var req prepareRollbackReq

			var closeErr error

			backend := &managerBackendMock{}
			backend.On("rollbackToBlock", mock.Anything, db.Block{Height: 8}).
				Return(failure).Once()
			backend.On("close").Run(func(mock.Arguments) {
				if !errors.Is(w.state.validateStarted(), ErrWalletStopped) {
					closeErr = errors.New("Store closes before Wallet stop")
					return
				}

				select {
				case <-req.rollbackDone:
					closeErr = errors.New("writers resume before Store close")
				default:
				}
			}).Return(errDBFail).Once()
			m := newManagerLifecycleTest(t, backend)
			m.started.Store(true)
			m.wallets[w.cfg.Name] = w
			events := make(chan chainEvent, 1)
			w.chainEventChan = events
			processor := newSyncer(
				w.cfg, w.addrStore, w.txStore, w, w.store, w.id,
				m.chainSyncer, events,
			)

			result := make(chan error, 1)
			processed := make(chan error, 1)
			event := chain.BlockDisconnected{Block: wtxmgr.Block{Height: 8}}

			// Act: Deliver preparation to the real processor. Its readiness
			// acknowledgement orders the captured request before cleanup;
			// joining it through w.wg exposes a missing cancellation exit.
			go func() { result <- m.dispatchChainEvent(t.Context(), event) }()

			raw := <-events

			var ok bool

			req, ok = raw.notification.(prepareRollbackReq)
			require.True(t, ok)

			w.wg.Add(1)

			go func() {
				defer w.wg.Done()

				processed <- processor.processChainEvent(w.lifetimeCtx, raw)
			}()

			// Assert: The worker exits by cancellation while completion is
			// still held. Storage closes only after its Wallet is stopped;
			// the exact rollback failure survives and later work is rejected.
			rollbackErr := <-result
			require.ErrorIs(t, rollbackErr, failure)
			require.ErrorIs(t, rollbackErr, errDBFail)
			require.ErrorIs(t, <-processed, context.Canceled)
			require.NoError(t, closeErr)
			require.ErrorIs(t, m.dispatchChainEvent(t.Context(), event),
				ErrManagerStopped)
			require.False(t, m.started.Load())
			require.Nil(t, m.backend)
		})
	}
}

// TestManagerChainRollbackWithoutWallet verifies a running pristine KVDB
// Manager accepts disconnects before its first Wallet opens a Store.
func TestManagerChainRollbackWithoutWallet(t *testing.T) {
	t.Parallel()

	// Arrange: The existing fixture starts a pristine database with no Wallet,
	// leaving its Wallet-scoped Store unopened while the reader is running.
	m := testKVDBManager(t)

	// Act: Dispatch a valid disconnect through the normal Manager entry point.
	err := m.dispatchChainEvent(t.Context(), chain.BlockDisconnected{
		Block: wtxmgr.Block{Height: 1},
	})

	// Assert: With no Wallet history to rewind, dispatch succeeds and keeps
	// the Manager running so its first Wallet can still be created.
	require.NoError(t, err)
	require.True(t, m.started.Load())
}

// TestManagerChainRollbackDuringInitializationRetry keeps ordered rollback
// admission live when a stored tip above the backend makes initialization fail.
func TestManagerChainRollbackDuringInitializationRetry(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		// Arrange: A real worker fails its initial historical check because
		// the backend cannot supply the stored tip. A long retry delay exposes
		// whether rollback depends on that initialization succeeding first.
		w, deps := createTestWalletWithMocks(t)
		w.cfg.Name = testWalletName
		w.cfg.WalletSyncRetryInterval = time.Hour
		w.id = 1
		processor := newSyncer(
			w.cfg, w.addrStore, w.txStore, w, w.store, w.id,
			w.chainSyncer, w.chainEventChan,
		)
		w.sync = processor
		w.state = newWalletState(processor)
		startLoadedWalletForTest(t, w)
		deps.vault.On("Lock").Return().Once()

		tip := db.Block{Height: 2, Hash: chainhash.Hash{2}}

		deps.chain.On("IsCurrent").Return(true).Once()
		deps.store.On("GetWallet", mock.Anything, testWalletName).
			Return(&db.WalletInfo{SyncedTo: &tip}, nil).Once()
		deps.store.On("ListSyncedBlocks", mock.Anything,
			db.ListSyncedBlocksQuery{StartHeight: 0, EndHeight: 2}).
			Return([]db.Block{tip}, nil).Once()
		deps.chain.On("GetBlockHashes", int64(0), int64(2)).
			Return([]chainhash.Hash(nil), errChainMock).Once()
		priorWrite := deps.store.On("ApplyTxBatch", mock.Anything,
			db.TxBatchParams{
				WalletID:     w.id,
				Transactions: []db.CreateTxParams{},
			}).Return(nil).Once()

		backend := &managerBackendMock{}
		backend.On("close").Return(nil).Once()
		backend.On("rollbackToBlock", mock.Anything, tip).
			Return(nil).Once().NotBefore(priorWrite)
		m := newManagerLifecycleTest(t, backend)
		m.started.Store(true)
		m.wallets[w.cfg.Name] = w

		// Act: Queue a filtered event before the disconnect, then let the
		// same worker enter retry. No second initialization is permitted by
		// the strict mocks; it must drain this mailbox in its existing wait.
		require.NoError(t, m.dispatchChainEvent(t.Context(),
			chain.FilteredBlockConnected{
				Block: &wtxmgr.BlockMeta{Block: wtxmgr.Block{Height: 3}},
			}))
		w.wg.Go(w.runSyncLoop)
		synctest.Wait()

		err := m.dispatchChainEvent(t.Context(), chain.BlockDisconnected{
			Block: wtxmgr.Block{Height: int32(tip.Height), Hash: tip.Hash},
		})

		// Assert: The prior observation is persisted without advancing the
		// scan checkpoint, then the one full-identity rollback settles while
		// Manager remains available instead of blocking behind retry forever.
		require.NoError(t, err)
		require.True(t, m.started.Load())
	})
}

// TestManagerChainRollbackCreate holds successful Create publication behind
// a running rollback so the new Wallet starts after the shared rewind.
func TestManagerChainRollbackCreate(t *testing.T) {
	t.Parallel()

	// Arrange: Hold the backend rollback for one published Wallet. Return a
	// second Wallet's dependencies only when Create obtains the Manager lock;
	// its existing startup mocks isolate publication from SQL persistence.
	w, wDeps := createTestWalletWithMocks(t)
	w.cfg.Name = testWalletName
	w.id = 1
	startLoadedWalletForTest(t, w)
	wDeps.vault.On("Lock").Return().Once()

	// Register dependency cleanup before Manager cleanup so Stop joins the
	// created Wallet before its fixture verifies the shutdown expectation.
	_, createdDeps := createTestWalletWithMocks(t)
	backend := &managerBackendMock{}
	backend.On("close").Return(nil).Once()
	m := newManagerLifecycleTest(t, backend)
	m.started.Store(true)
	m.wallets[w.cfg.Name] = w

	events := make(chan chainEvent, 1)
	w.chainEventChan = events

	entered, release := make(chan struct{}), make(chan struct{})
	releaseWork := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseWork)
	backend.On("rollbackToBlock", mock.Anything, db.Block{Height: 8}).
		Run(func(mock.Arguments) {
			close(entered)
			<-release
		}).Return(nil).Once()

	params := managerLifecycleCreateParams("created")
	backend.On("create", mock.Anything, params, (*hdkeychain.ExtendedKey)(nil)).
		Return(&walletData{
			id:    2,
			name:  params.Name,
			store: createdDeps.store,
			vault: createdDeps.vault,
		}, nil).Once()
	createdDeps.store.On("GetWallet", mock.Anything, params.Name).
		Return(&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil).Once()
	createdDeps.store.On("ListAccounts", mock.Anything,
		db.ListAccountsQuery{WalletID: 2}).
		Return([]db.AccountInfo{}, nil).Once()
	createdDeps.store.On("DeleteExpiredLeases", mock.Anything, uint32(2)).
		Return(nil).Once()
	createdDeps.vault.On("Lock").Return().Once()

	chainSource, ok := m.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)
	chainSource.On("IsCurrent").Return(false).Maybe()

	// Act: Race Create against the held rollback. The direct mutex probe
	// keeps this regression independent of when the Create goroutine is run.
	rolled, created := make(chan error, 1), make(chan error, 1)
	go func() {
		rolled <- m.dispatchChainEvent(t.Context(),
			chain.BlockDisconnected{Block: wtxmgr.Block{Height: 8}})
	}()

	req, ok := (<-events).notification.(prepareRollbackReq)
	require.True(t, ok)

	// The Manager lock must exclude new writers while the existing worker
	// is still acknowledging, not only while Store rollback is held.
	locked := m.TryLock()
	if locked {
		m.Unlock()
	}

	require.False(t, locked, "Create acquires lock before rollback readiness")
	close(req.readyForRollback)
	<-entered

	locked = m.TryLock()
	if locked {
		m.Unlock()
	}

	require.False(t, locked, "rollback releases Manager lock early")

	go func() {
		_, err := m.Create(params)
		created <- err
	}()

	releaseWork()

	// Assert: Successful publication follows rollback and the fully started
	// created Wallet belongs to a Manager that remains Running.
	require.NoError(t, <-rolled)
	require.NoError(t, <-created)
	require.Contains(t, m.String(), params.Name)
	require.True(t, m.started.Load())
}

// TestManagerChainRollbackStop joins accepted persistence and leaves cleanup
// errors with the public Stop caller when shutdown already owns cancellation.
func TestManagerChainRollbackStop(t *testing.T) {
	t.Parallel()

	// Success retains the existing ordering contract; failure also exposes
	// losing a close error when the reader takes cleanup away from Stop.
	tests := []struct {
		name        string
		rollbackErr error
		closeErr    error
	}{
		{
			name: "successful rollback",
		},
		{
			name:        "failed rollback",
			rollbackErr: errDBMock,
			closeErr:    errDBFail,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Hold backend persistence after readiness. Close records
			// whether rollback settled and Wallet cancellation completed, and
			// whether failure wrongly released the prepared worker first.
			w, deps := createTestWalletWithMocks(t)
			w.cfg.Name = testWalletName
			w.id = 1
			startLoadedWalletForTest(t, w)
			deps.vault.On("Lock").Return().Once()

			backend := &managerBackendMock{}
			m := newManagerLifecycleTest(t, backend)
			m.started.Store(true)
			m.wallets[w.cfg.Name] = w
			events := make(chan chainEvent, 1)
			w.chainEventChan = events
			entered, release := make(chan struct{}), make(chan struct{})
			rolledBack := make(chan struct{})
			releaseWork := sync.OnceFunc(func() { close(release) })
			t.Cleanup(releaseWork)
			backend.On("rollbackToBlock", mock.Anything, db.Block{Height: 8}).
				Run(func(mock.Arguments) {
					close(entered)
					<-release
					close(rolledBack)
				}).Return(test.rollbackErr).Once()

			var req prepareRollbackReq

			var closeOrderErr error

			backend.On("close").Run(func(mock.Arguments) {
				select {
				case <-rolledBack:
				default:
					closeOrderErr = errors.New("Store closes during rollback")
				}

				if !errors.Is(w.state.validateStarted(), ErrWalletStopped) {
					closeOrderErr = errors.New("Store closes before stop")
				}

				if test.rollbackErr != nil {
					select {
					case <-req.rollbackDone:
						closeOrderErr = errors.New("writers resume on failure")
					default:
					}
				}
			}).Return(test.closeErr).Once()

			// Act: Observe Stop's lifetime cancellation while persistence is
			// held. Its lock acquisition then follows rollback settlement, so
			// a failing reader must leave storage cleanup to that waiting Stop.
			rolled, stopped := make(chan error, 1), make(chan error, 1)
			go func() {
				rolled <- m.dispatchChainEvent(t.Context(),
					chain.BlockDisconnected{Block: wtxmgr.Block{Height: 8}})
			}()

			var ok bool

			req, ok = (<-events).notification.(prepareRollbackReq)
			require.True(t, ok)
			close(req.readyForRollback)
			<-entered

			go func() { stopped <- m.Stop() }()

			<-m.lifetimeCtx.Done()
			releaseWork()

			// Assert: Both causes reach their owning caller, and Store closes
			// only after accepted persistence and Wallet shutdown settle.
			// Failure never signals permission for another historical write.
			require.ErrorIs(t, <-rolled, test.rollbackErr)
			require.ErrorIs(t, <-stopped, test.closeErr)
			require.NoError(t, closeOrderErr)
			require.False(t, m.started.Load())
		})
	}
}

// TestManagerChainRollbackStopDuringPreparation keeps Stop able to release both
// a blocked control send and a control whose worker has not acknowledged it.
func TestManagerChainRollbackStopDuringPreparation(t *testing.T) {
	t.Parallel()

	// Capacity is the only variation: an absent consumer blocks either the
	// unbuffered handoff or the ready wait after buffered acceptance.
	tests := []struct {
		name     string
		capacity int
	}{
		{
			name:     "handoff blocked",
			capacity: 0,
		},
		{
			name:     "receipt blocked",
			capacity: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				t.Helper()

				// Arrange: This published Wallet has no mailbox consumer.
				// The backend permits only close, so persistence before worker
				// readiness would fail a strict mock expectation.
				w, wDeps := createTestWalletWithMocks(t)
				w.cfg.Name = testWalletName
				w.id = 1
				startLoadedWalletForTest(t, w)
				wDeps.vault.On("Lock").Return().Once()

				backend := &managerBackendMock{}
				backend.On("close").Return(errDBFail).Once()
				m := newManagerLifecycleTest(t, backend)
				m.started.Store(true)
				m.wallets[w.cfg.Name] = w
				w.chainEventChan = make(chan chainEvent, test.capacity)
				notifications := make(chan any, 1)
				source := &bwmock.Chain{}
				source.On("Notifications").
					Return((<-chan any)(notifications)).Once()
				t.Cleanup(func() { source.AssertExpectations(t) })

				m.chainSyncer = newChainSyncer(source, &chainParams)

				notifications <- chain.BlockDisconnected{
					Block: wtxmgr.Block{Height: 8},
				}

				// Act: The source reader waits for rollback preparation. Stop
				// must release it and join without the callback self-joining.
				m.wg.Add(1)

				go m.startChainSyncer()

				synctest.Wait()

				stopErr := m.Stop()

				// Assert: Shutdown releases the operation without any Store
				// rollback, and the Manager has completed terminal cleanup.
				require.ErrorIs(t, stopErr, errDBFail)
				require.ErrorIs(t, w.state.validateStarted(), ErrWalletStopped)
				require.False(t, m.started.Load())
				require.Nil(t, m.backend)
			})
		})
	}
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

	// Supply zero explicitly so the shell retains its origin metadata.
	fingerprint := MasterFingerprint(0)

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
				InitialAccounts: []ImportAccountParams{{
					XPub:                 acctXPub,
					MasterKeyFingerprint: &fingerprint,
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
							waddrmgr.KeyScopeBIP0049Plus,
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

// createWalletPolicyCase keeps creation inputs and expected outcomes
// together for the single public Manager policy-test loop.
type createWalletPolicyCase struct {
	name       string
	params     CreateWalletParams
	wantErr    error
	wantErrMsg string
}

// TestCreateWalletParamsPolicy proves invalid modes and genesis identities
// fail before backend creation; successful modes have their own creation test.
func TestCreateWalletParamsPolicy(t *testing.T) {
	t.Parallel()

	// Arrange: Keep valid mode inputs together and vary root metadata
	// independently so a missing check cannot be hidden by another failure.
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

	// Supply valid zero metadata so rejection fixtures isolate declared
	// paths and script ownership rather than optional origin presence.
	fingerprint := MasterFingerprint(0)
	initialXPub := []ImportAccountParams{
		{
			Name:                 "initial",
			XPub:                 accountXPub,
			MasterKeyFingerprint: &fingerprint,
			AddrType:             waddrmgr.WitnessPubKey,
		},
	}
	initialXPrv := []ImportAccountParams{{XPub: rootKey}}
	initialNil := []ImportAccountParams{{}}

	tests := []createWalletPolicyCase{
		{
			name: "unknown mode",
			params: CreateWalletParams{
				Mode: ModeUnknown,
			},
		},
		{
			name: "generated seed watch-only",
			params: CreateWalletParams{
				Mode:      ModeGenSeed,
				WatchOnly: true,
			},
		},
		{
			name: "generated seed with explicit seed",
			params: CreateWalletParams{
				Mode: ModeGenSeed,
				Seed: seed,
			},
		},
		{
			name: "generated seed with root key",
			params: CreateWalletParams{
				Mode:    ModeGenSeed,
				RootKey: rootKey,
			},
		},
		{
			name: "generated seed with initial account",
			params: CreateWalletParams{
				Mode:            ModeGenSeed,
				InitialAccounts: initialXPub,
			},
		},
		{
			name: "imported seed watch-only",
			params: CreateWalletParams{
				Mode:      ModeImportSeed,
				Seed:      seed,
				WatchOnly: true,
			},
		},
		{
			name: "imported seed missing seed",
			params: CreateWalletParams{
				Mode: ModeImportSeed,
			},
		},
		{
			name: "imported seed with root key",
			params: CreateWalletParams{
				Mode:    ModeImportSeed,
				Seed:    seed,
				RootKey: rootKey,
			},
		},
		{
			name: "imported seed with initial account",
			params: CreateWalletParams{
				Mode:            ModeImportSeed,
				Seed:            seed,
				InitialAccounts: initialXPub,
			},
		},
		{
			name: "private root watch-only",
			params: CreateWalletParams{
				Mode:      ModeImportExtKey,
				RootKey:   rootKey,
				WatchOnly: true,
			},
		},
		{
			name: "extended root missing key",
			params: CreateWalletParams{
				Mode: ModeImportExtKey,
			},
		},
		{
			name: "XPub root spendable",
			params: CreateWalletParams{
				Mode:    ModeImportExtKey,
				RootKey: rootXPub,
			},
		},
		{
			name: "XPub root watch-only",
			params: CreateWalletParams{
				Mode:      ModeImportExtKey,
				RootKey:   rootXPub,
				WatchOnly: true,
			},
		},
		{
			name: "extended root with seed",
			params: CreateWalletParams{
				Mode:    ModeImportExtKey,
				RootKey: rootKey,
				Seed:    seed,
			},
		},
		{
			name: "extended root with initial account",
			params: CreateWalletParams{
				Mode:            ModeImportExtKey,
				RootKey:         rootKey,
				InitialAccounts: initialXPub,
			},
		},
		{
			name: "spendable shell",
			params: CreateWalletParams{
				Mode: ModeShell,
			},
		},
		{
			name: "shell with seed",
			params: CreateWalletParams{
				Mode:      ModeShell,
				Seed:      seed,
				WatchOnly: true,
			},
		},
		{
			name: "shell with root key",
			params: CreateWalletParams{
				Mode:      ModeShell,
				RootKey:   rootKey,
				WatchOnly: true,
			},
		},
		{
			name: "shell with nil account key",
			params: CreateWalletParams{
				Mode:            ModeShell,
				WatchOnly:       true,
				InitialAccounts: initialNil,
			},
			wantErrMsg: "needs XPub",
		},
		{
			name: "shell with private account key",
			params: CreateWalletParams{
				Mode:            ModeShell,
				WatchOnly:       true,
				InitialAccounts: initialXPrv,
			},
			wantErrMsg: "needs XPub, not XPrv",
		},
	}

	// Keep genesis fixture variants in a data-only builder so every mode and
	// identity row still exercises the same public call and strict mock.
	tests = append(tests, genesisKeyPolicyCases(
		t, rootKey, initialXPub[0],
	)...)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Allow no backend calls so each rejected input must
			// fail before Vault preparation or Store mutation can begin.
			backend := &managerBackendMock{}
			params := tc.params
			params.Name = testWalletName

			// No worker starts here; cancel the owned lifetime without
			// closing the strictly untouched backend used by validation.
			lifetimeCtx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			m := &Manager{
				lifetimeCtx: lifetimeCtx,
				cancel:      cancel,
				wallets:     make(map[string]*Wallet),
				backend:     backend,
				config: ManagerConfig{
					ChainSource: &bwmock.Chain{},
					ChainParams: chainParams,
				},
			}

			m.chainSyncer = newChainSyncer(
				m.config.ChainSource, &m.config.ChainParams,
			)
			m.started.Store(true)

			// Act: Ask Manager to create from the selected parameter shape,
			// allowing validation to decide whether backend mutation begins.
			wallet, err := m.Create(params)

			// Assert: Invalid genesis input stays a validation error, leaves no
			// published Wallet and never crosses the strict backend boundary.
			require.Nil(t, wallet)
			require.Empty(t, m.wallets)
			require.NotErrorIs(t, err, ErrWalletExists)

			require.ErrorIs(t, err, ErrWalletParams)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			}

			if tc.wantErrMsg != "" {
				require.ErrorContains(t, err, tc.wantErrMsg)
			}

			backend.AssertExpectations(t)
		})
	}
}

// genesisKeyPolicyCases constructs only malformed identity fixtures; the
// caller owns Manager invocation, dependency expectations, and assertions.
func genesisKeyPolicyCases(t *testing.T,
	rootKey *hdkeychain.ExtendedKey,
	initialAccount ImportAccountParams) []createWalletPolicyCase {

	t.Helper()

	// Construct malformed roots without a serialization round trip so the
	// public Manager boundary must reject each invalid origin field itself.
	rootPriv, err := rootKey.ECPrivKey()
	require.NoError(t, err)

	rootDepth := hdkeychain.NewExtendedKey(
		rootKey.Version(), rootPriv.Serialize(), rootKey.ChainCode(),
		[]byte{0, 0, 0, 0}, 1, 0, true,
	)
	rootParent := hdkeychain.NewExtendedKey(
		rootKey.Version(), rootPriv.Serialize(), rootKey.ChainCode(),
		[]byte{0, 0, 0, 1}, 0, 0, true,
	)
	rootChild := hdkeychain.NewExtendedKey(
		rootKey.Version(), rootPriv.Serialize(), rootKey.ChainCode(),
		[]byte{0, 0, 0, 0}, 0, 1, true,
	)
	wrongNetworkRoot, err := rootKey.CloneWithVersion(
		chaincfg.MainNetParams.HDPrivateKeyID[:],
	)
	require.NoError(t, err)

	// Keep key material fixed while varying origin metadata and version
	// bytes, proving that neither can distinguish overlapping script owners.
	accountXPub := initialAccount.XPub
	pubKey, err := accountXPub.ECPubKey()
	require.NoError(t, err)

	alias := hdkeychain.NewExtendedKey(
		binary.BigEndian.AppendUint32(
			nil, uint32(waddrmgr.HDVersionTestNetBIP0084),
		),
		pubKey.SerializeCompressed(), accountXPub.ChainCode(),
		[]byte{1, 2, 3, 4}, 3, hdkeychain.HardenedKeyStart+1, false,
	)
	otherFingerprint := MasterFingerprint(1)
	aliasAccount := initialAccount
	aliasAccount.Name = "alias"
	aliasAccount.XPub = alias
	aliasAccount.MasterKeyFingerprint = &otherFingerprint

	// Hybrid BIP49 shares its internal witness branch with the BIP84 alias,
	// so equal payloads still conflict across those different scopes.
	upubVersion := binary.BigEndian.AppendUint32(
		nil, uint32(waddrmgr.HDVersionTestNetBIP0049),
	)
	upub, err := accountXPub.CloneWithVersion(upubVersion)
	require.NoError(t, err)

	plusAccount := initialAccount
	plusAccount.XPub = upub

	// Custom scopes have no canonical schema; leaving their account override
	// absent must fail before dependencies can establish incomplete identity.
	missingSchema := initialAccount
	missingSchema.Scope = &waddrmgr.KeyScope{
		Purpose: 1017,
		Coin:    0,
	}

	// Distinct keys at hardened child zero isolate occupied numbered slots
	// from payload collisions, independently of optional origin metadata.
	otherKey, _ := importAccountTestKey(t, 84)
	numberedFirst := initialAccount
	numberedScope := waddrmgr.KeyScopeBIP0084
	numberedFirst.Scope = &numberedScope
	numberedOther := numberedFirst
	numberedOther.Name = "other"
	numberedOther.XPub = otherKey

	return []createWalletPolicyCase{
		{
			name: "shell custom scope requires schema",
			params: CreateWalletParams{
				Mode:      ModeShell,
				WatchOnly: true,
				InitialAccounts: []ImportAccountParams{
					missingSchema,
				},
			},
			wantErr: ErrInvalidParam,
		},
		{
			name: "shell payload overlap within scope",
			params: CreateWalletParams{
				Mode:      ModeShell,
				WatchOnly: true,
				InitialAccounts: []ImportAccountParams{
					initialAccount,
					aliasAccount,
				},
			},
			wantErr: ErrAccountIdentityCollision,
		},
		{
			name: "shell internal overlap across scopes",
			params: CreateWalletParams{
				Mode:      ModeShell,
				WatchOnly: true,
				InitialAccounts: []ImportAccountParams{
					plusAccount,
					aliasAccount,
				},
			},
			wantErr: ErrAccountIdentityCollision,
		},
		{
			name: "shell declared account number conflict",
			params: CreateWalletParams{
				Mode:      ModeShell,
				WatchOnly: true,
				InitialAccounts: []ImportAccountParams{
					numberedFirst,
					numberedOther,
				},
			},
			wantErr: ErrAccountAlreadyExists,
		},
		{
			name: "root depth must be zero",
			params: CreateWalletParams{
				Mode:    ModeImportExtKey,
				RootKey: rootDepth,
			},
		},
		{
			name: "root parent fingerprint must be zero",
			params: CreateWalletParams{
				Mode:    ModeImportExtKey,
				RootKey: rootParent,
			},
		},
		{
			name: "root child index must be zero",
			params: CreateWalletParams{
				Mode:    ModeImportExtKey,
				RootKey: rootChild,
			},
		},
		{
			name: "root network must match",
			params: CreateWalletParams{
				Mode:    ModeImportExtKey,
				RootKey: wrongNetworkRoot,
			},
		},
	}
}

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

// rollbackToBlock exposes the full block identity to strict expectations,
// so a height-only Manager handoff cannot satisfy the ordering regression.
func (b *managerBackendMock) rollbackToBlock(ctx context.Context,
	block db.Block) error {

	args := b.Called(ctx, block)
	return args.Error(0)
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
	// Manager owns the service lifetime; fixture Stop joins before assertions.
	lifetimeCtx, cancel := context.WithCancel(context.Background())
	manager := &Manager{
		lifetimeCtx: lifetimeCtx,
		cancel:      cancel,
		wallets:     make(map[string]*Wallet),
		backend:     backend,
		config: ManagerConfig{
			ChainSource: chain,
			ChainParams: chainParams,
		},
	}

	manager.chainSyncer = newChainSyncer(chain, &manager.config.ChainParams)

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
	chain.On("Notifications").Return((<-chan any)(nil)).Once()
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
	client, ok := manager.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)
	client.On("Notifications").Return((<-chan any)(nil)).Once()

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
	client, ok := manager.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)
	client.On("Notifications").Return((<-chan any)(nil)).Once()

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

// TestManagerCreateRejectsInvalidInitialAccounts verifies bad import inputs
// cannot persist a candidate or stop an existing Wallet.
func TestManagerCreateRejectsInvalidInitialAccounts(t *testing.T) {
	t.Parallel()

	// Arrange: Use a valid account key and change only its network or address
	// type, so each request reaches the import checks missing from preflight.
	key, _ := importAccountTestKey(t, 44)
	wrongNetwork, err := key.CloneWithVersion(
		chaincfg.MainNetParams.HDPublicKeyID[:],
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		key      *hdkeychain.ExtendedKey
		addrType waddrmgr.AddressType
	}{
		{
			name:     "wrong network",
			key:      wrongNetwork,
			addrType: waddrmgr.WitnessPubKey,
		},
		{
			name:     "unsupported address type",
			key:      key,
			addrType: waddrmgr.PubKeyHash,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Keep one Wallet running in real storage to detect
			// both unwanted shutdown and a leftover candidate row.
			m := testSQLiteManager(t)
			existing, err := m.Create(
				managerLifecycleCreateParams("existing"),
			)
			require.NoError(t, err)

			fingerprint := MasterFingerprint(0)
			params := managerLifecycleCreateParams("candidate")
			params.InitialAccounts = []ImportAccountParams{
				{
					MasterKeyFingerprint: &fingerprint,
					Name:                 "initial-account",
					XPub:                 tc.key,
					AddrType:             tc.addrType,
				},
			}

			// Act: Request another Wallet with invalid initial account
			// input while the first Wallet is still in use.
			candidate, err := m.Create(params)

			// Assert: The request fails without a handle. A public read
			// still works, and corrected input can use the same Wallet
			// name, proving no durable candidate was left behind.
			require.Nil(t, candidate)
			require.ErrorIs(t, err, ErrWalletParams)

			_, err = existing.ListAccounts(t.Context())
			require.NoError(t, err)

			params.InitialAccounts[0].XPub = key
			params.InitialAccounts[0].AddrType = waddrmgr.WitnessPubKey
			candidate, err = m.Create(params)
			require.NoError(t, err)
			require.NotNil(t, candidate)
		})
	}
}

// TestManagerCreatePreservesInitialAccountIdentity verifies genesis accepts
// equal XPub payloads with disjoint scripts and per-account BIP49 schemas.
func TestManagerCreatePreservesInitialAccountIdentity(t *testing.T) {
	t.Parallel()

	// Arrange: Distinct BIP49 keys share a scope with strict and hybrid
	// schemas. Keep the original key for a disjoint Taproot alias, while
	// inferred scopes avoid numbered slots in all three accounts. Omit the
	// first fingerprint and supply zero on its peer to retain both origins.
	key, _ := importAccountTestKey(t, 44)
	otherKey, _ := importAccountTestKey(t, 84)
	upubVersion := binary.BigEndian.AppendUint32(
		nil, uint32(waddrmgr.HDVersionTestNetBIP0049),
	)
	strictKey, err := key.CloneWithVersion(upubVersion)
	require.NoError(t, err)
	hybridKey, err := otherKey.CloneWithVersion(upubVersion)
	require.NoError(t, err)

	fingerprint := MasterFingerprint(0)
	bip49Scope := waddrmgr.KeyScopeBIP0049Plus
	m := testSQLiteManager(t)
	params := managerLifecycleCreateParams("identities")
	params.InitialAccounts = []ImportAccountParams{
		{
			Name:     "first",
			XPub:     strictKey,
			AddrType: waddrmgr.NestedWitnessPubKey,
		},
		{
			Name:                 "second",
			XPub:                 key,
			MasterKeyFingerprint: &fingerprint,
			AddrType:             waddrmgr.TaprootPubKey,
		},
		{
			Name:                 "third",
			XPub:                 hybridKey,
			MasterKeyFingerprint: &fingerprint,
			AddrType:             waddrmgr.WitnessPubKey,
		},
	}

	// Act: Create the shell through Manager admission with all three accounts.
	w, err := m.Create(params)

	// Assert: Creation keeps every account and its effective branch schema;
	// a reused scope must not replace requested types or collapse omitted
	// origin metadata into a supplied-zero fingerprint.
	require.NoError(t, err)
	accounts, err := w.ListAccounts(t.Context())
	require.NoError(t, err)
	require.Len(t, accounts, len(params.InitialAccounts))

	strict, err := w.GetAccount(t.Context(), bip49Scope, "first")
	require.NoError(t, err)
	require.Equal(t, waddrmgr.KeyScopeBIP0049AddrSchema, strict.AddrSchema)
	require.Nil(t, strict.MasterKeyFingerprint)

	hybrid, err := w.GetAccount(t.Context(), bip49Scope, "third")
	require.NoError(t, err)
	require.Equal(t, waddrmgr.ScopeAddrMap[bip49Scope], hybrid.AddrSchema)
	require.Equal(t, &fingerprint, hybrid.MasterKeyFingerprint)
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
	chain.On("Notifications").Return((<-chan any)(nil)).Once()
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

// TestManagerCreateLifecycleStartFailureStopsManager preserves startup/cleanup
// errors and releases membership before joining a reader waiting on that lock.
func TestManagerCreateLifecycleStartFailureStopsManager(t *testing.T) {
	t.Parallel()

	// Arrange: Hold the failing birthday read while Create owns admission,
	// so the real reader can consume an event and wait on its membership lock.
	_, deps := createTestWalletWithMocks(t)
	createErr := errors.New("candidate birthday")
	closeErr := errors.New("backend close")
	birthdayEntered := make(chan struct{})
	birthdayRelease := make(chan struct{})
	deps.store.On("GetWallet", mock.Anything, "candidate").Run(
		func(mock.Arguments) {
			close(birthdayEntered)
			<-birthdayRelease
		},
	).Return(nil, createErr).Once()

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
	// Release test gates before fixture Stop, even after failed assertions.
	releaseBirthday := sync.OnceFunc(func() { close(birthdayRelease) })
	releaseClose := sync.OnceFunc(func() { close(release) })

	t.Cleanup(releaseBirthday)
	t.Cleanup(releaseClose)

	client, ok := manager.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)

	notifications := make(chan any, 1)
	client.On("Notifications").Return((<-chan any)(notifications)).Once()

	_, err := manager.Start(t.Context())
	require.NoError(t, err)

	// Carry both results across held cleanup; a failed candidate cannot escape.
	type createOutcome struct {
		wallet *Wallet
		err    error
	}

	created := make(chan createOutcome, 1)
	stopped := make(chan error, 1)

	// Act: Once Create owns admission, give the reader an event before allowing
	// startup to fail. A join under that same lock would deadlock its snapshot.
	go func() {
		w, err := manager.Create(params)
		created <- createOutcome{
			wallet: w,
			err:    err,
		}
	}()

	<-birthdayEntered

	notifications <- chain.BlockConnected{}

	require.Eventually(t, func() bool {
		return len(notifications) == 0
	}, time.Second, time.Millisecond)
	releaseBirthday()

	select {
	case <-closing:
	case <-time.After(5 * time.Second):
		t.Fatal("failed Create did not reach storage cleanup")
	}

	go func() { stopped <- manager.Stop() }()

	// Assert: Neither the candidate nor its primary error escapes before the
	// held cleanup finishes. Returning then requires an unlocked reader join.
	select {
	case result := <-created:
		t.Fatalf("Create returned before cleanup completed: %v", result.err)
	default:
	}

	releaseClose()

	var outcome createOutcome
	select {
	case outcome = <-created:
	case <-time.After(5 * time.Second):
		t.Fatal("failed Create did not release membership and join its reader")
	}

	select {
	case stopErr := <-stopped:
		require.NoError(t, stopErr)
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent Stop did not join terminal cleanup")
	}

	require.Nil(t, outcome.wallet)
	require.ErrorIs(t, outcome.err, createErr)
	require.ErrorIs(t, outcome.err, closeErr)
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

// TestManagerGenRootKey observes destruction of the generated seed without
// destroying the independently derived master returned to its owner.
func TestManagerGenRootKey(t *testing.T) {
	t.Parallel()

	// Arrange: Keep the generator's original allocation observable and derive
	// the expected master before cleanup can erase its input bytes.
	m := testKVDBManager(t)
	seed := fixedTestSeed()
	wantMaster, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)

	// Act: Supply the owned buffer through the production generator signature
	// so the observation concerns the seed Manager receives, not a copy.
	key, err := m.genRootKey(func(length uint8) ([]byte, error) {
		require.Equal(t, uint8(hdkeychain.RecommendedSeedLen), length)

		return seed, nil
	})

	// Assert: The original seed is cleared while the returned master still
	// reproduces the expected private root and supports private derivation.
	require.NoError(t, err)
	require.NotNil(t, key)

	require.Equal(t, make([]byte, len(seed)), seed)
	require.Equal(t, wantMaster.String(), key.String())
	require.True(t, key.IsPrivate())
	_, err = key.Derive(hdkeychain.HardenedKeyStart)
	require.NoError(t, err)
}

// TestManagerCreateBoundsGenesisSecrets verifies successful creation destroys
// Manager-derived roots while preserving usable caller seeds and XPrvs.
func TestManagerCreateBoundsGenesisSecrets(t *testing.T) {
	t.Parallel()

	for name, tc := range genesisCreateCases(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Capture the live root at the existing backend boundary
			// and return mock-backed data with the required startup reads.
			params := tc.params
			params.Name = testWalletName
			params.PrivatePassphrase = []byte("private")
			_, deps := createTestWalletWithMocks(t)
			deps.store.On("GetWallet", mock.Anything, params.Name).
				Return(&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil).
				Once()
			deps.store.On("ListAccounts", mock.Anything,
				db.ListAccountsQuery{WalletID: 1}).
				Return([]db.AccountInfo{}, nil).Once()
			deps.store.On("DeleteExpiredLeases", mock.Anything, uint32(1)).
				Return(nil).Once()
			deps.vault.On("Lock").Return().Once()

			var observedRoot *hdkeychain.ExtendedKey

			backend := &managerBackendMock{}
			backend.On("create", mock.Anything, params, mock.Anything).
				Return(&walletData{
					id:    1,
					name:  params.Name,
					store: deps.store,
					vault: deps.vault,
				}, nil).Run(func(args mock.Arguments) {
				var ok bool
				observedRoot, ok = args.Get(2).(*hdkeychain.ExtendedKey)
				require.True(t, ok)
				require.True(t, observedRoot.IsPrivate())
			}).Once()
			backend.On("close").Return(nil).Once()
			manager := newManagerLifecycleTest(t, backend)
			manager.started.Store(true)
			chain, ok := manager.config.ChainSource.(*bwmock.Chain)
			require.True(t, ok)
			chain.On("IsCurrent").Return(false).Maybe()

			// Act: Complete public creation, including private runtime startup,
			// before examining the captured preparation root and caller input.
			wallet, err := manager.Create(params)

			// Assert: Derived roots no longer expose key material; borrowed
			// roots and seeds retain their bytes and remain useful to callers.
			require.NoError(t, err)
			require.NotNil(t, wallet)
			require.Equal(t, tc.wantRoot, observedRoot.String())
			require.Equal(t, tc.wantRootPrivate, observedRoot.IsPrivate())
			require.Equal(t, tc.wantSeed, params.Seed)

			// Preserved roots must retain caller identity and support private
			// derivation, beyond matching the case's serialized expectation.
			if tc.wantRootPrivate {
				require.Same(t, params.RootKey, observedRoot)
				_, err := params.RootKey.Derive(
					hdkeychain.HardenedKeyStart,
				)
				require.NoError(t, err)
			}

			// Preserved seed bytes must still reproduce the declared master
			// after public creation has returned.
			if tc.wantSeedMaster != "" {
				master, err := hdkeychain.NewMaster(
					params.Seed, &chainParams,
				)
				require.NoError(t, err)
				require.Equal(t, tc.wantSeedMaster, master.String())
			}
		})
	}
}

// TestManagerCreateBoundsGenesisSecretsOnFailure verifies backend failure
// destroys derived roots while caller material remains unchanged and usable.
func TestManagerCreateBoundsGenesisSecretsOnFailure(t *testing.T) {
	t.Parallel()

	for name, tc := range genesisCreateCases(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Observe a valid root before returning a later creation
			// error; fixture cleanup owns backend expectation verification.
			params := tc.params
			params.Name = testWalletName
			params.PrivatePassphrase = []byte("private")

			var observedRoot *hdkeychain.ExtendedKey

			backend := &managerBackendMock{}
			backend.On("create", mock.Anything, params, mock.Anything).
				Return(nil, errDBMock).Run(func(args mock.Arguments) {
				var ok bool
				observedRoot, ok = args.Get(2).(*hdkeychain.ExtendedKey)
				require.True(t, ok)
				require.True(t, observedRoot.IsPrivate())
			}).Once()
			backend.On("close").Return(nil).Once()
			manager := newManagerLifecycleTest(t, backend)
			manager.started.Store(true)

			// Act: Let the public request return its backend failure before
			// inspecting the original root object and borrowed input bytes.
			wallet, err := manager.Create(params)

			// Assert: Failure preserves the original error and borrowed
			// material, but leaves no usable Manager-derived root or Wallet.
			require.ErrorIs(t, err, errDBMock)
			require.Nil(t, wallet)
			require.Equal(t, tc.wantRoot, observedRoot.String())
			require.Equal(t, tc.wantRootPrivate, observedRoot.IsPrivate())
			require.Equal(t, tc.wantSeed, params.Seed)

			// Preserved roots must retain caller identity and support private
			// derivation after the backend error has unwound preparation.
			if tc.wantRootPrivate {
				require.Same(t, params.RootKey, observedRoot)
				_, err := params.RootKey.Derive(
					hdkeychain.HardenedKeyStart,
				)
				require.NoError(t, err)
			}

			// Preserved seed bytes must still reproduce the declared master
			// even when no Wallet was returned.
			if tc.wantSeedMaster != "" {
				master, err := hdkeychain.NewMaster(
					params.Seed, &chainParams,
				)
				require.NoError(t, err)
				require.Equal(t, tc.wantSeedMaster, master.String())
			}
		})
	}
}

// genesisCreateCase declares the post-return secret outcomes independently
// of the inputs so each public-creation test can assert ownership directly.
type genesisCreateCase struct {
	params          CreateWalletParams
	wantRoot        string
	wantRootPrivate bool
	wantSeed        []byte
	wantSeedMaster  string
}

// genesisCreateCases shares deterministic inputs and expected ownership
// outcomes while leaving mock expectations and assertions in each test.
func genesisCreateCases(t *testing.T) map[string]genesisCreateCase {
	t.Helper()

	// Each test receives its own imported root; subtests share no mutable
	// signing material across separate public creation outcomes.
	root, err := hdkeychain.NewMaster(fixedTestSeed(), &chainParams)
	require.NoError(t, err)

	return map[string]genesisCreateCase{
		"generated seed": {
			params: CreateWalletParams{
				Mode: ModeGenSeed,
			},
			wantRoot:        "zeroed extended key",
			wantRootPrivate: false,
			wantSeed:        nil,
			wantSeedMaster:  "",
		},
		"imported seed": {
			params: CreateWalletParams{
				Mode: ModeImportSeed,
				Seed: fixedTestSeed(),
			},
			wantRoot:        "zeroed extended key",
			wantRootPrivate: false,
			wantSeed:        fixedTestSeed(),
			wantSeedMaster:  root.String(),
		},
		"imported XPrv": {
			params: CreateWalletParams{
				Mode:    ModeImportExtKey,
				RootKey: root,
			},
			wantRoot:        root.String(),
			wantRootPrivate: true,
			wantSeed:        nil,
			wantSeedMaster:  "",
		},
	}
}

// TestManagerCreateBoundsGenesisSecretsOnPanic verifies that preparation
// unwinding destroys the owned root even when backend creation panics.
func TestManagerCreateBoundsGenesisSecretsOnPanic(t *testing.T) {
	t.Parallel()

	// Arrange: Capture the valid generated root immediately before a backend
	// panic, without creating runtime resources that would obscure cleanup.
	params := CreateWalletParams{
		Name:              testWalletName,
		Mode:              ModeGenSeed,
		PrivatePassphrase: []byte("private"),
	}

	var observedRoot *hdkeychain.ExtendedKey

	backend := &managerBackendMock{}
	backend.On("create", mock.Anything, params, mock.Anything).
		Return(nil, nil).Run(func(args mock.Arguments) {
		var ok bool
		observedRoot, ok = args.Get(2).(*hdkeychain.ExtendedKey)
		require.True(t, ok)
		require.True(t, observedRoot.IsPrivate())
		panic(errDBMock)
	}).Once()
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	manager.started.Store(true)

	// Act: Recover around the public call so assertions observe the original
	// key only after Manager's deferred cleanup has finished unwinding.
	require.PanicsWithValue(t, errDBMock, func() {
		_, _ = manager.Create(params)
	})

	// Assert: The captured master no longer exposes private material even
	// though preparation did not return through an ordinary error path.
	require.NotNil(t, observedRoot)
	require.False(t, observedRoot.IsPrivate())
	require.Equal(t, "zeroed extended key", observedRoot.String())
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

// TestManagerKVDBRejectsSecondCreate verifies cached names and other aliases
// share the duplicate identity without replacing the original Wallet.
func TestManagerKVDBRejectsSecondCreate(t *testing.T) {
	t.Parallel()

	// Arrange: Occupy the database so the same-name cache and the legacy
	// single-wallet guard can reject their respective duplicate requests.
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

	// Act: Request both the cached name and a different legacy alias.
	for _, name := range []string{params.Name, "second"} {
		replacement := params
		replacement.Name = name
		duplicate, err := m.Create(replacement)

		// Assert: Each alias reports the public duplicate identity without
		// returning another Wallet or replacing the published pointer.
		require.ErrorIs(t, err, ErrWalletExists)
		require.Nil(t, duplicate)
		require.Same(t, first, m.wallets[params.Name])
	}
}

// TestManagerKVDBCreateMissingNameAfterReopen verifies an unnamed startup
// entry cannot hide the caller's missing-name validation error.
func TestManagerKVDBCreateMissingNameAfterReopen(t *testing.T) {
	t.Parallel()

	// Arrange: Use the fixture's public passphrase across reopen so startup
	// installs the existing Wallet under its unnamed legacy cache key.
	dbPath := testKVDBPath(t)
	m := testKVDBManagerAt(t, dbPath)
	params := managerLifecycleCreateParams("existing")
	params.PubPassphrase = []byte(InsecurePubPassphrase)
	_, err := m.Create(params)
	require.NoError(t, err)
	require.NoError(t, m.Stop())
	m = testKVDBManagerAt(t, dbPath)

	// Act: Request creation without a name while the unnamed entry is cached.
	duplicate, err := m.Create(CreateWalletParams{})

	// Assert: Validation keeps its public identity instead of misclassifying
	// the absent name as a duplicate of the startup entry.
	require.ErrorIs(t, err, ErrMissingParam)
	require.Nil(t, duplicate)
}

// TestManagerCreateRejectsActiveDuplicate verifies an occupied active name
// prevents a second Store create and keeps the original Wallet usable.
func TestManagerCreateRejectsActiveDuplicate(t *testing.T) {
	t.Parallel()

	// Arrange: Permit exactly one durable create and its ordinary startup;
	// fixture cleanup verifies that a duplicate never consumes another call.
	params := managerLifecycleCreateParams("active-wallet")
	store := &walletmock.Store{}
	store.On("CreateWallet", mock.Anything,
		mock.AnythingOfType("db.CreateWalletParams")).Return(&db.WalletInfo{
		ID:          1,
		Name:        params.Name,
		IsWatchOnly: true,
	}, nil).Once()
	store.On("GetWallet", mock.Anything, params.Name).
		Return(&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil).Once()
	store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 1,
	}).Return([]db.AccountInfo{}, nil).Once()
	store.On("DeleteExpiredLeases", mock.Anything, uint32(1)).Return(nil).Once()
	m := testSQLManager(t, store)
	first, err := m.Create(params)
	require.NoError(t, err)

	// Act: Ask for the same active name with replacement credentials.
	params.PrivatePassphrase = []byte("replacement-private")
	duplicate, err := m.Create(params)

	// Assert: The public duplicate identity returns no candidate, leaves the
	// original pointer published, and permits a public call on that Wallet.
	require.ErrorIs(t, err, ErrWalletExists)
	require.Nil(t, duplicate)
	require.Same(t, first, m.wallets[params.Name])
	require.NoError(t, first.Lock(t.Context()))
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

// TestManagerCreateImportsDeclaredAccount verifies pre-start SQL imports use
// the same declared scope/schema and encoded account number as public imports.
func TestManagerCreateImportsDeclaredAccount(t *testing.T) {
	t.Parallel()

	// Arrange: use generic XPub version bytes with lnd's custom witness scope,
	// requesting SQL chain exclusion through the same pre-start import input.
	m := testSQLiteManager(t)
	key, _ := importAccountTestKey(t, 44)
	scope := waddrmgr.KeyScope{Purpose: 1017, Coin: 0}
	schema := waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084]
	fingerprint := MasterFingerprint(0)
	params := managerLifecycleCreateParams("declared-initial")
	params.InitialAccounts = []ImportAccountParams{
		{
			MasterKeyFingerprint: &fingerprint,
			Name:                 testAccountName,
			XPub:                 key,
			Scope:                &scope,
			AddrSchema:           &schema,
			NoChainSync:          true,
		},
	}

	// Act: create the shell with its initial imported account before startup,
	// then inspect the returned account through the started public interface.
	w, err := m.Create(params)
	require.NoError(t, err)
	info, err := w.GetAccount(t.Context(), scope, testAccountName)

	// Assert: initial import retains declared identity and a present-zero
	// fingerprint, effective witness schema and persisted SQL chain exclusion.
	require.NoError(t, err)
	require.True(t, info.IsImported)
	require.True(t, info.NoChainSync)
	require.Equal(t, AccountNumber(0), *info.AccountNumber)
	require.Equal(t, scope, info.KeyScope)
	require.Equal(t, schema, info.AddrSchema)
	require.Equal(t, MasterFingerprint(0), *info.MasterKeyFingerprint)
}

// TestManagerCreateImportsDeclaredKVDBAccount verifies initial kvdb imports
// use the same custom scope, schema and known number as live imports.
func TestManagerCreateImportsDeclaredKVDBAccount(t *testing.T) {
	t.Parallel()

	// Arrange: a generic account XPub declares lnd's custom key-family scope.
	// Its explicit witness schema supplies the missing canonical scope default.
	m := testKVDBManager(t)
	key, _ := importAccountTestKey(t, 84)
	scope := waddrmgr.KeyScope{Purpose: 1017, Coin: 0}
	schema := waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084]
	fingerprint := MasterFingerprint(0)
	params := managerLifecycleCreateParams("kvdb-initial")
	params.InitialAccounts = []ImportAccountParams{
		{
			MasterKeyFingerprint: &fingerprint,
			Name:                 testAccountName,
			XPub:                 key,
			Scope:                &scope,
			AddrSchema:           &schema,
		},
	}

	// Act: create and start the Wallet with its declared import before startup.
	w, err := m.Create(params)
	require.NoError(t, err)
	info, err := w.GetAccount(t.Context(), scope, testAccountName)

	// Assert: declaration metadata survives Manager preflight and native kvdb
	// persistence, including account zero and its caller-supplied fingerprint.
	require.NoError(t, err)
	require.True(t, info.IsImported)
	require.Equal(t, AccountNumber(0), *info.AccountNumber)
	require.Equal(t, scope, info.KeyScope)
	require.Equal(t, schema, info.AddrSchema)
	require.Equal(t, MasterFingerprint(0), *info.MasterKeyFingerprint)
}

// TestChainSyncerWatchAddresses verifies ownership precedes tip-based
// activation, including a retry after its native subscription fails.
func TestChainSyncerWatchAddresses(t *testing.T) {
	t.Parallel()

	// Arrange: The exact native arguments must activate routing inside
	// the call, before either its causal failure or successful retry.
	addr, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)
	script, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	tx.AddTxOut(&wire.TxOut{PkScript: script})
	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	require.NoError(t, err)

	addrs := []address.Address{addr}
	wallets := []*Wallet{{id: 1}}
	failure := errors.New("subscription failed")

	client := createTestChain(t)
	client.On("WatchAddrsFromTip", mock.Anything, mock.Anything).Unset()

	s := newChainSyncer(client, &chainParams)

	var received []TxEntries

	callback := func(mock.Arguments) {
		events := s.routeChainEvent(
			chain.RelevantTx{TxRecord: rec}, wallets,
		)
		received = append(received, events[1].matches)
	}
	client.On("WatchAddrsFromTip", t.Context(), addrs).Run(callback).
		Return(failure).Once()
	client.On("WatchAddrsFromTip", t.Context(), addrs).Run(callback).
		Return(nil).Once()

	// Act: Repeat the identical producer request after native failure.
	firstErr := s.watchAddresses(t.Context(), 1, addrs)
	retryErr := s.watchAddresses(t.Context(), 1, addrs)

	// Assert: Wrapped errors retain identity; both activations already
	// have one recipient, and fixture cleanup verifies the exact calls.
	require.ErrorIs(t, firstErr, failure)
	require.NoError(t, retryErr)
	require.Len(t, received, 2)

	for _, matches := range received {
		require.Len(t, matches, 1)
		require.Same(t, rec, matches[0].Rec)
	}
}

// TestChainSyncerWatchOutpoints verifies ownership precedes spent-output
// activation, including a retry after its native subscription fails.
func TestChainSyncerWatchOutpoints(t *testing.T) {
	t.Parallel()

	// Arrange: The exact native arguments must activate routing inside
	// the call, before either its causal failure or successful retry.
	point := wire.OutPoint{Index: 7}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&point, nil, nil))
	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	require.NoError(t, err)

	points := []*wire.OutPoint{&point}
	wallets := []*Wallet{{id: 1}}
	failure := errors.New("subscription failed")

	client := createTestChain(t)
	client.On("NotifySpent", mock.Anything).Unset()

	s := newChainSyncer(client, &chainParams)

	var received []TxEntries

	callback := func(mock.Arguments) {
		events := s.routeChainEvent(
			chain.RelevantTx{TxRecord: rec}, wallets,
		)
		received = append(received, events[1].matches)
	}
	client.On("NotifySpent", points).Run(callback).
		Return(failure).Once()
	client.On("NotifySpent", points).Run(callback).
		Return(nil).Once()

	// Act: Repeat the identical producer request after native failure.
	firstErr := s.watchOutpoints(t.Context(), 1, points)
	retryErr := s.watchOutpoints(t.Context(), 1, points)

	// Assert: Wrapped errors retain identity; both activations already
	// have one recipient, and fixture cleanup verifies the exact calls.
	require.ErrorIs(t, firstErr, failure)
	require.NoError(t, retryErr)
	require.Len(t, received, 2)

	for _, matches := range received {
		require.Len(t, matches, 1)
		require.Same(t, rec, matches[0].Rec)
	}
}

// TestChainSyncerNotifyReceived verifies ownership precedes publication
// activation, including a retry after its native subscription fails.
func TestChainSyncerNotifyReceived(t *testing.T) {
	t.Parallel()

	// Arrange: An accepted publication retains native registration even
	// after shutdown cancels the lifetime that its caller supplies.
	addr, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)
	script, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	tx.AddTxOut(&wire.TxOut{PkScript: script})
	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	require.NoError(t, err)

	addrs := []address.Address{addr}
	wallets := []*Wallet{{id: 1}}
	failure := errors.New("subscription failed")

	client := createTestChain(t)

	s := newChainSyncer(client, &chainParams)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var received []TxEntries

	callback := func(mock.Arguments) {
		events := s.routeChainEvent(
			chain.RelevantTx{TxRecord: rec}, wallets,
		)
		received = append(received, events[1].matches)
	}
	client.On("NotifyReceived", addrs).Run(callback).
		Return(failure).Once()
	client.On("NotifyReceived", addrs).Run(callback).
		Return(nil).Once()

	// Act: Register and retry despite the already-canceled lifetime.
	firstErr := s.notifyReceived(ctx, 1, addrs)
	retryErr := s.notifyReceived(ctx, 1, addrs)

	// Assert: Cancellation cannot replace the native result; both calls
	// find one recipient. Fixture cleanup verifies exact activation.
	require.ErrorIs(t, firstErr, failure)
	require.NoError(t, retryErr)
	require.Len(t, received, 2)

	for _, matches := range received {
		require.Len(t, matches, 1)
		require.Same(t, rec, matches[0].Rec)
	}
}

// TestChainSyncerRouting checks shared watches and input-only spends before
// any Wallet has recovered or stored their funding transaction.
func TestChainSyncerRouting(t *testing.T) {
	t.Parallel()

	// Arrange: Two Wallets share an address; a third watches nothing. An
	// input-address spend arrives before recovery learns its funding output.
	// A later parent has duplicate outputs to check recipient deduplication.
	client := createTestChain(t)
	client.On("WatchAddrsFromTip", mock.Anything, mock.Anything).Unset()
	client.On("WatchAddrsFromTip", mock.Anything, mock.Anything).
		Return(nil).Twice()

	s := newChainSyncer(client, &chainParams)

	root, err := hdkeychain.NewMaster(fixedTestSeed(), &chainParams)
	require.NoError(t, err)
	pubKey, err := root.ECPubKey()
	require.NoError(t, err)
	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	script, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	for _, id := range []uint32{1, 2} {
		require.NoError(
			t, s.watchAddresses(
				t.Context(), id, []address.Address{addr},
			),
		)
	}

	// The unrelated output must remain the only source of credit metadata;
	// the watched address belongs solely to the unknown input's witness.
	otherAddr, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)
	otherScript, err := txscript.PayToAddrScript(otherAddr)
	require.NoError(t, err)

	unknownSpend := wire.NewMsgTx(2)
	unknownSpend.AddTxIn(
		wire.NewTxIn(
			&wire.OutPoint{Index: 1}, nil, wire.TxWitness{
				// Native validation owns signature checking; routing needs
				// the public key to recover the spent output's address.
				[]byte{}, pubKey.SerializeCompressed(),
			},
		),
	)
	unknownSpend.AddTxOut(&wire.TxOut{PkScript: otherScript})
	unknownRec, err := wtxmgr.NewTxRecordFromMsgTx(unknownSpend, time.Now())
	require.NoError(t, err)

	originalSpend := unknownSpend.Copy()

	parent := wire.NewMsgTx(2)
	parent.AddTxOut(&wire.TxOut{PkScript: script})
	parent.AddTxOut(&wire.TxOut{PkScript: script})
	parentRec, err := wtxmgr.NewTxRecordFromMsgTx(parent, time.Now())
	require.NoError(t, err)

	child := wire.NewMsgTx(2)
	child.AddTxIn(
		wire.NewTxIn(
			&wire.OutPoint{
				Hash: parentRec.Hash,
			}, nil, nil,
		),
	)
	childRec, err := wtxmgr.NewTxRecordFromMsgTx(child, time.Now())
	require.NoError(t, err)

	wallets := []*Wallet{{id: 1}, {id: 2}, {id: 3}}
	block := chain.FilteredBlockConnected{
		Block:       &wtxmgr.BlockMeta{},
		RelevantTxs: []*wtxmgr.TxRecord{parentRec, childRec},
	}

	original := parent.Copy()

	// Act: Route the input-address-only spend before learning any outpoint,
	// then the parent/child block and a later known-outpoint notification.
	unknown := s.routeChainEvent(
		chain.RelevantTx{TxRecord: unknownRec}, wallets,
	)
	events := s.routeChainEvent(block, wallets)
	spend := s.routeChainEvent(chain.RelevantTx{TxRecord: childRec}, wallets)

	// Assert: Both watched Wallets receive the early spend once, without
	// turning its input address into output credit metadata. Existing ordered
	// descendant routing and empty progress retain their original payloads.
	require.Len(t, unknown, 2)
	require.NotContains(t, unknown, uint32(3))
	require.Equal(t, originalSpend, unknownSpend)
	require.Len(t, events, len(wallets))

	for _, id := range []uint32{1, 2} {
		require.Len(t, unknown[id].matches, 1)
		match := unknown[id].matches[0]
		require.Same(t, unknownRec, match.Rec)
		require.Len(t, match.Entries, 1)
		require.Equal(t, otherAddr, match.Entries[0].Address)
		require.Zero(t, match.Entries[0].Credit.Index)
		require.Len(t, events[id].matches, 2)
		require.Equal(
			t, []*wtxmgr.TxRecord{parentRec, childRec},
			[]*wtxmgr.TxRecord{
				events[id].matches[0].Rec, events[id].matches[1].Rec,
			},
		)
		require.Len(t, spend[id].matches, 1)
	}

	require.Empty(t, events[3].matches)
	require.NotContains(t, spend, uint32(3))
	require.Equal(t, block, events[1].notification)
	require.Equal(t, original, parent)
}

// TestChainSyncerProgressRouting preserves ordinary control handlers and
// delivers empty filtered blocks to every Wallet for checkpoint progress.
func TestChainSyncerProgressRouting(t *testing.T) {
	t.Parallel()

	// Arrange: Header-only events must remain catch-up wakeups, disconnects
	// keep rollback handling, and actual empty filtered blocks carry progress.
	tests := []struct {
		name         string
		notification any
	}{
		{
			name:         "header",
			notification: chain.BlockConnected{},
		},
		{
			name:         "disconnect",
			notification: chain.BlockDisconnected{},
		},
		{
			name: "empty filtered block",
			notification: chain.FilteredBlockConnected{
				Block: &wtxmgr.BlockMeta{},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: No watches are needed for block/control recipients.
			s := newChainSyncer(createTestChain(t), &chainParams)

			wallets := []*Wallet{{id: 1}, {id: 2}}

			// Act: Route the original payload through normal membership.
			events := s.routeChainEvent(test.notification, wallets)

			// Assert: Every Wallet gets the original type and metadata
			// without invented transaction matches or header checkpoints.
			require.Len(t, events, len(wallets))

			for _, event := range events {
				require.Equal(t, test.notification, event.notification)
				require.Empty(t, event.matches)
			}
		})
	}
}

// TestManagerChainSourceClosed verifies a lost required stream tears down both
// real Wallet workers before closing their shared database, without self-join.
func TestManagerChainSourceClosed(t *testing.T) {
	t.Parallel()

	// Arrange: Keep both processors waiting for backend sync. Their normal
	// cleanup locks each vault before the single backend close expectation.
	data := make([]*walletData, 0, 2)
	for i, name := range []string{"first", "second"} {
		_, deps := createTestWalletWithMocks(t)
		id := uint32(i + 1)

		deps.store.On("GetWallet", mock.Anything, name).Return(
			&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil,
		).Once()
		deps.store.On(
			"ListAccounts", mock.Anything, db.ListAccountsQuery{
				WalletID: id,
			},
		).Return([]db.AccountInfo{}, nil).Once()
		deps.store.On("DeleteExpiredLeases", mock.Anything, id).
			Return(nil).Once()
		deps.vault.On("Lock").Return().Once()
		data = append(
			data, &walletData{
				id:    id,
				name:  name,
				store: deps.store,
				vault: deps.vault,
			},
		)
	}

	closed := make(chan struct{})
	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Return(data, nil).Once()
	backend.On("close").Run(
		func(mock.Arguments) {
			close(closed)
		},
	).Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	client, ok := manager.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)

	notifications := make(chan any)
	client.On("Notifications").Return((<-chan any)(notifications)).Once()
	client.On("IsCurrent").Return(false).Maybe()

	wallets, err := manager.Start(t.Context())
	require.NoError(t, err)

	// Act: Lose the one stream while both Wallets are running.
	close(notifications)

	// Assert: Automatic teardown finishes without an external Stop rescuing
	// it; retained Wallets are inert and later Stop is an idempotent no-op.
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("closed source did not stop Manager")
	}

	for _, w := range wallets {
		require.ErrorIs(t, w.lifetimeCtx.Err(), context.Canceled)
		require.Equal(
			t, lifecycleStopped, lifecycle(w.state.lifecycle.Load()),
		)
	}

	require.NoError(t, manager.Stop())
}

// TestManagerChainEventOrder proves source order and bounded asynchronous
// admission while an uncancelled Wallet deliberately stops draining its inbox.
func TestManagerChainEventOrder(t *testing.T) {
	t.Parallel()

	// Arrange: A data-only recipient isolates admission from Store processing.
	// Three headers expose the capacity-one bound without extra worker queues.
	client := createTestChain(t)
	notifications := make(chan any, 3)

	client.On("Notifications").Unset()
	client.On("Notifications").Return((<-chan any)(notifications)).Once()

	w := &Wallet{
		id:             1,
		lifetimeCtx:    t.Context(),
		chainEventChan: make(chan chainEvent, 1),
	}

	// This routing-only fixture has no Store/Wallet workers to stop. Join
	// its sole reader explicitly after canceling the Manager-owned lifetime.
	lifetimeCtx, cancel := context.WithCancel(context.Background())

	manager := &Manager{
		wallets:     map[string]*Wallet{"first": w},
		chainSyncer: newChainSyncer(client, &chainParams),
		lifetimeCtx: lifetimeCtx,
		cancel:      cancel,
	}
	defer func() {
		manager.cancel()
		manager.wg.Wait()
	}()

	for height := int32(1); height <= 3; height++ {
		notifications <- chain.BlockConnected{
			Block: wtxmgr.Block{Height: height},
		}
	}

	// Act: Enroll and launch the one reader, then wait until the second
	// delivery blocks behind the first; it cannot consume the third event.
	manager.wg.Add(1)

	go manager.startChainSyncer()

	require.Eventually(
		t, func() bool {
			return len(notifications) == 1 && len(w.chainEventChan) == 1
		}, time.Second, time.Millisecond,
	)

	// Assert: Releasing capacity admits each unchanged header in FIFO order.
	// The first acceptance did not wait for Wallet persistence or processing.
	for height := int32(1); height <= 3; height++ {
		select {
		case event := <-w.chainEventChan:
			header, ok := event.notification.(chain.BlockConnected)
			require.True(t, ok)
			require.Equal(t, height, header.Height)
		case <-time.After(time.Second):
			t.Fatal("reader failed to resume after mailbox drain")
		}
	}
}

// TestManagerChainEventMembership verifies snapshots include a newly published
// Wallet without retaining the Manager lock during mailbox delivery.
func TestManagerChainEventMembership(t *testing.T) {
	t.Parallel()

	// Arrange: Only the first Wallet is published for the initial snapshot.
	first := &Wallet{
		id:             1,
		lifetimeCtx:    t.Context(),
		chainEventChan: make(chan chainEvent, 1),
	}
	second := &Wallet{
		id:             2,
		lifetimeCtx:    t.Context(),
		chainEventChan: make(chan chainEvent, 1),
	}

	manager := &Manager{
		wallets:     map[string]*Wallet{"first": first},
		chainSyncer: newChainSyncer(createTestChain(t), &chainParams),
	}

	// Act: Publish under the existing membership lock between two events.
	require.NoError(
		t, manager.dispatchChainEvent(
			t.Context(), chain.BlockConnected{},
		),
	)
	manager.Lock()
	manager.wallets["second"] = second
	manager.Unlock()
	<-first.chainEventChan
	require.NoError(
		t, manager.dispatchChainEvent(
			t.Context(), chain.ClientConnected{},
		),
	)

	// Assert: Both current members receive the next control event unchanged.
	require.IsType(
		t, chain.ClientConnected{}, (<-first.chainEventChan).notification,
	)
	require.IsType(
		t, chain.ClientConnected{}, (<-second.chainEventChan).notification,
	)
}

// TestManagerChainEventBlockedStop verifies terminal cancellation releases a
// reader blocked on a real Wallet whose asynchronous initialization is pending.
func TestManagerChainEventBlockedStop(t *testing.T) {
	t.Parallel()

	// Arrange: Hold the backend call itself, since an initialization wait now
	// services its mailbox. A second header still forces delivery to block.
	client := createTestChain(t)
	entered, release := make(chan struct{}), make(chan struct{})

	client.On("IsCurrent").Unset()
	client.On("IsCurrent").Run(func(mock.Arguments) {
		close(entered)
		<-release
	}).Return(false).Once()

	notifications := make(chan any, 2)

	client.On("Notifications").Unset()
	client.On("Notifications").Return((<-chan any)(notifications)).Once()
	manager := testSQLiteManagerWithChain(t, client)

	// Release a held dependency before fixture Stop, even if a prerequisite
	// fails. The backend call is existing blocking I/O, not another worker.
	releaseBackend := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseBackend)

	w, err := manager.Create(sqliteCreateParams(t))
	require.NoError(t, err)

	<-entered

	notifications <- chain.BlockConnected{}

	notifications <- chain.BlockConnected{}

	require.Eventually(
		t, func() bool {
			return len(notifications) == 0 && len(w.chainEventChan) == 1
		}, time.Second, time.Millisecond,
	)

	// Act: Stop while reader delivery has no available mailbox capacity.
	stopped := make(chan error, 1)
	go func() {
		stopped <- manager.Stop()
	}()

	<-w.lifetimeCtx.Done()
	releaseBackend()

	// Assert: Stop joins both reader and Wallet rather than waiting for
	// initialization to become ready or closing Store underneath either one.
	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("full mailbox blocked terminal Stop")
	}

	require.ErrorIs(t, w.lifetimeCtx.Err(), context.Canceled)
}

// TestManagerChainCanceledSourceRejectsCreate rejects terminal admission after
// Stop cancels its lifetime, before it obtains the lock to close storage.
func TestManagerChainCanceledSourceRejectsCreate(t *testing.T) {
	t.Parallel()

	// Arrange: Reproduce the terminal source lifetime while backend remains
	// open and started remains true. No create/storage expectation is allowed.
	backend := &managerBackendMock{}
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	manager.started.Store(true)
	manager.cancel()

	// Act: Try creation before the ordinary cleanup owner closes the Store.
	w, err := manager.Create(CreateWalletParams{Name: "late"})

	// Assert: The terminal source rejects this call before validation or
	// backend preparation; fixture cleanup alone owns the one Store close.
	require.ErrorIs(t, err, ErrManagerStopped)
	require.Nil(t, w)
}

// TestManagerRollbackKvdbAheadOfTip reproduces mined notifications arriving
// before the sync stamp and requires immediate, readable replacement history.
func TestManagerRollbackKvdbAheadOfTip(t *testing.T) {
	t.Parallel()

	// Arrange real stores while syncing, with an owned credit persisted by a
	// mined notification that does not advance the earlier complete sync tip.
	source := newTestChain(t, true)
	source.On("TestMempoolAccept", mock.Anything, float64(0)).
		Return(nil, chain.ErrTxAlreadyInMempool).Maybe()
	m, err := NewManager(t.Context(), ManagerConfig{
		Backend: DBBackendKVDB, DataSource: testKVDBPath(t),
		ChainParams: chainParams, ChainSource: source,
		KVDBPubPassphrase: []byte(InsecurePubPassphrase),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Stop()) })
	_, err = m.Start(t.Context())
	require.NoError(t, err)

	params := managerLifecycleCreateParams(testWalletName)
	params.PubPassphrase = []byte(InsecurePubPassphrase)
	w, err := m.Create(params)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		info, readErr := w.Info(t.Context())
		return readErr == nil && info.Synced
	}, 5*time.Second, time.Millisecond)

	backend, ok := m.backend.(*kvdbManagerBackend)
	require.True(t, ok)
	s, ok := w.sync.(*syncer)
	require.True(t, ok)

	mgr, conn := backend.addressMgr, backend.db

	s.state.Store(uint32(syncStateSyncing))

	stamp := waddrmgr.BlockStamp{
		Height:    1,
		Hash:      chainhash.Hash{1},
		Timestamp: time.Unix(1, 0).UTC(),
	}
	err = walletdb.Update(conn, func(tx walletdb.ReadWriteTx) error {
		return mgr.SetSyncedTo(tx.ReadWriteBucket(waddrmgrNamespaceKey), &stamp)
	})
	require.NoError(t, err)

	old := reorgBlock(2)
	replacement := old
	replacement.Hash = chainhash.Hash{22}
	oldTx, newTx := reorgRecord(t, 80), reorgRecord(t, 81)

	// The configured source must supply the canonical observation. After
	// it, a lower source tip keeps background catch-up idle, so recovery
	// and stale replay must preserve history before any rescan can help.
	source.On("GetBestBlock").Unset()
	source.On("GetBestBlock").Return(&replacement.Hash, int32(2), nil).Once()
	source.On("GetBestBlock").Return(chainParams.GenesisHash, int32(0), nil).
		Maybe()
	source.On("GetBlockHash", int64(1)).Return(&stamp.Hash, nil).Once()
	source.On("GetBlockHash", int64(2)).Return(&replacement.Hash, nil).Once()
	require.NoError(t, s.processChainEvent(t.Context(), chainEvent{
		notification: chain.RelevantTx{
			TxRecord: oldTx,
			Block:    &old,
		},
		matches: liveMatches(oldTx),
	}))

	err = walletdb.Update(conn, func(tx walletdb.ReadWriteTx) error {
		return s.txStore.AddCredit(
			tx.ReadWriteBucket(wtxmgrNamespaceKey), oldTx, &old, 0, false,
		)
	})
	require.NoError(t, err)
	require.Equal(t, stamp, mgr.SyncedTo())

	// Act on the disconnect while the manager is still below the orphan.
	require.NoError(t, m.dispatchChainEvent(
		t.Context(), chain.BlockDisconnected(old),
	))

	// Assert the orphan and its credit are already unmined before any
	// replacement or later rescan; its earlier full sync stamp is unchanged.
	orphan, err := s.store.GetTxDetail(t.Context(), db.GetTxDetailQuery{
		WalletID: 0,
		Txid:     oldTx.Hash,
	})
	require.NoError(t, err)
	require.Nil(t, orphan.Block)
	require.Len(t, orphan.OwnedOutputs, 1)
	require.Equal(t, stamp, mgr.SyncedTo())

	// Act by accepting the replacement and replaying a delayed old detach.
	// The stored replacement identity must make that replay harmless.
	require.NoError(t, s.processChainEvent(t.Context(), chainEvent{
		notification: chain.FilteredBlockConnected{
			Block:       &replacement,
			RelevantTxs: []*wtxmgr.TxRecord{newTx},
		},
		matches: liveMatches(newTx),
	}))
	require.NoError(t, m.dispatchChainEvent(
		t.Context(), chain.BlockDisconnected(old),
	))

	// Assert one complete history query resolves the replacement, while the
	// old transaction remains in the unmined pool with its credit intact.
	history, err := s.store.ListTxns(
		t.Context(), db.ListTxnsQuery{EndHeight: 2},
	)
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.Equal(t, newTx.Hash, history[0].Hash)
	require.Equal(t, replacement.Hash, history[0].Block.Hash)
	orphan, err = s.store.GetTxDetail(t.Context(), db.GetTxDetailQuery{
		Txid: oldTx.Hash,
	})
	require.NoError(t, err)
	require.Nil(t, orphan.Block)
	require.Len(t, orphan.OwnedOutputs, 1)
}
