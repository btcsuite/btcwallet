package wallet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"iter"
	"sync"
	"testing"
	"testing/synctest"
	"time"

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
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newChainEventTestWallet reuses the joined request-loop fixture for dispatcher
// contract tests that supply processor outcomes through direct channels.
func newChainEventTestWallet(t *testing.T, name string,
	id uint32) *Wallet {

	t.Helper()

	w, deps := createTestWalletWithMocks(t)
	w.cfg.Name = name
	w.id = id
	startLoadedWalletForTest(t, w)
	deps.vault.On("Lock").Return().Once()

	return w
}

// TestManagerChainEventRejectsDisconnect prevents connected fanout
// from reaching the legacy per-Wallet rollback handler.
func TestManagerChainEventRejectsDisconnect(t *testing.T) {
	t.Parallel()

	// Arrange: A strict registered processor and Store permit no event or
	// rollback call; only normal fixture shutdown may touch the Vault.
	w := newChainEventTestWallet(t, "first", 1)
	manager := testSQLManager(t, &walletmock.Store{})
	manager.wallets[w.cfg.Name] = w

	// Act: Submit a disconnect to the connected-event entry point.
	err := manager.dispatchChainEvent(
		t.Context(), chain.BlockDisconnected{},
	)

	// Assert: Rejection is local validation and does not stop the Manager or
	// transfer ownership of the disconnect to any processor.
	require.ErrorIs(t, err, db.ErrInvalidParam)
	require.True(t, manager.started.Load())
}

// TestManagerChainEventOrder verifies asynchronous acceptance, bounded
// backpressure and identical FIFO delivery without processing acknowledgments.
func TestManagerChainEventOrder(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		// Arrange: Capacity-one mailboxes let the first dispatch complete
		// while both processors are held. A slow peer then bounds delivery.
		first := newChainEventTestWallet(t, "first", 1)
		second := newChainEventTestWallet(t, "second", 2)
		manager := testSQLManager(t, &walletmock.Store{})
		manager.wallets[first.cfg.Name] = first
		manager.wallets[second.cfg.Name] = second
		firstEvents := make(chan any, 1)
		secondEvents := make(chan any, 1)
		first.chainEventChan = firstEvents
		second.chainEventChan = secondEvents

		block := &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Height: 1},
		}
		filtered := chain.FilteredBlockConnected{
			Block: &wtxmgr.BlockMeta{Block: wtxmgr.Block{Height: 2}},
		}
		events := []any{
			chain.BlockConnected(*block), filtered,
			chain.RelevantTx{TxRecord: &wtxmgr.TxRecord{}},
		}
		want := []any{
			chain.FilteredBlockConnected{Block: block},
			filtered, events[2],
		}
		results := make(chan error, len(events))

		// Act: One ordered caller queues all three events. No recipient
		// reports completion; reads alone release bounded backpressure.
		go func() {
			for _, event := range events {
				results <- manager.dispatchChainEvent(t.Context(), event)
			}
		}()

		// Assert: Acceptance precedes consumption, but the next dispatch
		// waits for the slower mailbox. Both recipients retain source order.
		require.NoError(t, <-results)

		for i := range events {
			require.Equal(t, want[i], <-firstEvents)
			synctest.Wait()
			require.Empty(t, results)
			require.Equal(t, want[i], <-secondEvents)

			if i+1 < len(events) {
				require.NoError(t, <-results)
			}
		}
	})
}

// chainEventWalletData supplies real private startup and sync-worker reads at
// height zero. Expected maintenance counts make readiness deterministic rather
// than leaving an unsynced fixture unable to receive chain delivery.
func chainEventWalletData(t *testing.T, name string, id uint32,
	events int) (*walletData, *mockWalletDeps) {

	t.Helper()

	_, deps := createTestWalletWithMocks(t)
	deps.store.On("GetWallet", mock.Anything, name).Return(
		&db.WalletInfo{
			BirthdayBlock: &db.Block{},
			SyncedTo:      &db.Block{},
		}, nil,
	).Times(3 + events)
	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: id,
	}).Return([]db.AccountInfo(nil), nil).Once()
	deps.store.On("DeleteExpiredLeases", mock.Anything, id).Return(nil).Once()
	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID:      id,
		SkipBalance:   true,
		ChainSyncOnly: true,
	}).Return([]db.AccountInfo(nil), nil).Once()
	expectImportedScanAddressPage(
		deps.store, id, page.Result[db.AddressInfo, uint32]{},
	)
	deps.store.On("ListOutputsToWatch", mock.Anything, id).
		Return([]db.UtxoInfo(nil), nil).Once()
	deps.store.On("ListTxns", mock.Anything, mock.Anything).
		Return([]db.TxInfo(nil), nil).Times(1 + events)
	deps.vault.On("Lock").Return().Once()

	return &walletData{
		id:          id,
		name:        name,
		store:       deps.store,
		vault:       deps.vault,
		isWatchOnly: true,
	}, deps
}

// expectChainEventSource supplies only existing worker initialization and
// maintenance calls. A readiness token marks every actual notification wait;
// the caller's existing fixture remains the sole mock-verification owner.
func expectChainEventSource(backend *bwmock.Chain, wallets, waits int,
	ready chan<- struct{}, source <-chan any) {

	for range wallets {
		backend.On("IsCurrent").Return(true).Once()
		backend.On("WatchAddrsFromTip", mock.Anything, mock.Anything).
			Return(nil).Once()
		backend.On("NotifyBlocks").Return(nil).Once()
	}

	for range waits {
		backend.On("GetBestBlock").Return(
			&chainhash.Hash{}, int32(0), nil,
		).Once()
		backend.On("Notifications").Run(func(mock.Arguments) {
			ready <- struct{}{}
		}).Return(source).Once()
	}
}

// TestManagerChainEventRegistration fixes startup and Create membership at the
// same admission boundary without replaying an older event to the new Wallet.
func TestManagerChainEventRegistration(t *testing.T) {
	t.Parallel()

	// Arrange: Start the complete durable pair on real workers, then
	// prepare a third Wallet for Create. Each worker reaches receipt.
	first, firstDeps := chainEventWalletData(t, "first", 1, 2)
	second, secondDeps := chainEventWalletData(t, "second", 2, 2)
	third, thirdDeps := chainEventWalletData(t, "third", 3, 1)
	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).
		Return([]*walletData{first, second}, nil).Once()

	params := managerLifecycleCreateParams("third")
	backend.On("create", mock.Anything, params, mock.Anything).
		Return(third, nil).Once()
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	manager.config.Backend = DBBackendSQLite
	source, ok := manager.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)

	ready := make(chan struct{}, 8)
	expectChainEventSource(source, 3, 8, ready, nil)

	addr := mustNewPubKeyAddr(t, &Wallet{cfg: Config{
		ChainParams: &chainParams,
	}})
	script := mustPayToAddrScript(addr)
	tx := wire.NewMsgTx(1)
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: script})
	record, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Unix(1, 0))
	require.NoError(t, err)

	event := chain.RelevantTx{TxRecord: record}

	processors := []struct {
		store  *walletmock.Store
		id     uint32
		events int
	}{
		{
			store:  firstDeps.store,
			id:     1,
			events: 2,
		},
		{
			store:  secondDeps.store,
			id:     2,
			events: 2,
		},
		{
			store:  thirdDeps.store,
			id:     3,
			events: 1,
		},
	}
	for _, processor := range processors {
		for range processor.events {
			// Match a real credit so the held write below remains an
			// processing boundary after unrelated events are skipped.
			processor.store.On(
				"ResolveOwnedAddresses", mock.Anything,
				matchResolveOwnedAddressesQuery(processor.id, script),
			).Return(ownedAddrsResult(script), nil).Once()
			processor.store.On("GetTx", mock.Anything, db.GetTxQuery{
				WalletID: processor.id,
				Txid:     record.Hash,
			}).Return(nil, db.ErrTxNotFound).Once()
		}
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	firstDeps.store.On("ApplyTxBatch", mock.Anything, mock.Anything).
		Run(func(mock.Arguments) {
			close(entered)
			<-release
		}).Return(nil).Once()
	firstDeps.store.On("ApplyTxBatch", mock.Anything, mock.Anything).
		Return(nil).Once()
	secondDeps.store.On("ApplyTxBatch", mock.Anything, mock.Anything).
		Return(nil).Twice()
	thirdDeps.store.On("ApplyTxBatch", mock.Anything, mock.Anything).
		Return(nil).Once()

	loaded, err := manager.Start(t.Context())
	require.NoError(t, err)
	require.Len(t, loaded, 2)
	<-ready
	<-ready

	// Act: Hold an admitted event while Create publishes another Wallet.
	// The new pointer belongs only to the next event's admission snapshot.
	delivered := make(chan error, 1)
	go func() {
		delivered <- manager.dispatchChainEvent(t.Context(), event)
	}()

	<-entered

	type createResult struct {
		wallet *Wallet
		err    error
	}

	created := make(chan createResult, 1)
	go func() {
		w, createErr := manager.Create(params)
		created <- createResult{
			wallet: w,
			err:    createErr,
		}
	}()

	result := <-created
	require.NoError(t, result.err)
	require.NoError(t, <-delivered)
	close(release)

	for range 3 {
		<-ready
	}

	err = manager.dispatchChainEvent(t.Context(), event)

	for range 3 {
		<-ready
	}

	// Assert: Startup contributes both durable Wallets, Create
	// contributes only to the later fanout, and exact Store calls
	// prove that no old delivery reached the new processor.
	require.Equal(t, uint32(3), result.wallet.ID())
	require.NoError(t, err)
}

// TestManagerChainEventWalletRelevance prevents shared records from
// leaking into another Wallet's persisted history or transaction subscription.
func TestManagerChainEventWalletRelevance(t *testing.T) {
	t.Parallel()

	// Arrange: Run two real SQLite Wallets against a genesis-only backend.
	// Explicit notification-wait tokens keep delivery on the existing workers;
	// the first Wallet alone derives the receiving script used by this block.
	manager, source, recipient := newLiveWatchManager(t)
	ready := make(chan struct{}, 8)

	source.On("IsCurrent").Unset()
	source.On("IsCurrent").Return(true).Twice()
	source.On("NotifyBlocks").Return(nil).Twice()
	source.On("WatchAddrsFromTip", mock.Anything, mock.Anything).
		Return(nil).Times(3)
	source.On("Notifications").Run(func(mock.Arguments) {
		ready <- struct{}{}
	}).Return((<-chan any)(nil)).Times(8)

	params := sqliteCreateParams(t)
	params.Name = "unrelated"
	unrelated, err := manager.Create(params)
	require.NoError(t, err)

	wallets := []*Wallet{recipient, unrelated}
	recv, err := recipient.NewAddress(t.Context(), NewAccountSelectorByName(
		waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountName,
	), false)
	require.NoError(t, err)
	script, err := txscript.PayToAddrScript(recv.Addr)
	require.NoError(t, err)

	funding := subscriptionTx(script, 87)
	funding.AddTxOut(&wire.TxOut{Value: 1000, PkScript: script})

	child := subscriptionTx([]byte{txscript.OP_TRUE}, 88)
	child.TxIn[0].PreviousOutPoint = wire.OutPoint{Hash: funding.TxHash()}
	spend := subscriptionTx([]byte{txscript.OP_TRUE}, 89)
	spend.TxIn[0].PreviousOutPoint = wire.OutPoint{
		Hash: funding.TxHash(), Index: 1,
	}

	// The existing post-event maintenance rebroadcasts only the relevant
	// unmined spend. Report it already known so this adds no publication write
	// or extra observation to the shared-event regression.
	source.On("TestMempoolAccept", mock.MatchedBy(
		func(txns []*wire.MsgTx) bool {
			return len(txns) == 1 && txns[0].TxHash() == spend.TxHash()
		},
	), float64(0)).Return(nil, chain.ErrTxAlreadyInMempool).Twice()

	records := make([]*wtxmgr.TxRecord, 0, 3)

	originalRecords := make([]wtxmgr.TxRecord, 0, 3)
	for _, tx := range []*wire.MsgTx{funding, child, spend} {
		record, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Unix(1, 0))
		require.NoError(t, err)

		records = append(records, record)

		// Copy mutable transaction data before any Wallet sees the record.
		original := *record
		original.MsgTx = *record.MsgTx.Copy()
		original.SerializedTx = bytes.Clone(record.SerializedTx)
		originalRecords = append(originalRecords, original)
	}

	block := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: chainhash.Hash{87}, Height: 1},
		Time:  time.Unix(1, 0),
	}

	// Keep block identity as well as transaction payloads immutable.
	originalBlock := block

	events, cancel, err := wallets[0].SubscribeTxns(t.Context())
	require.NoError(t, err)

	defer cancel()

	unrelatedEvents, cancelUnrelated, err := wallets[1].SubscribeTxns(
		t.Context(),
	)
	require.NoError(t, err)

	defer cancelUnrelated()

	<-ready
	<-ready

	// Act: Queue a payment with its debit-only same-block child in one
	// shared block, then submit an unmined spend of its other owned output.
	// Queue both before waiting so matching must see the preceding commit.
	blockErr := manager.dispatchChainEvent(t.Context(),
		chain.FilteredBlockConnected{
			Block:       &block,
			RelevantTxs: records[:2],
		},
	)

	spendErr := manager.dispatchChainEvent(t.Context(), chain.RelevantTx{
		TxRecord: records[2],
	})

	for range 4 {
		<-ready
	}

	// Header-only progress also uses the atomic block path, with no matching
	// transaction and no new subscriber observation in either Wallet.
	empty := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: chainhash.Hash{88}, Height: 2},
		Time:  time.Unix(2, 0),
	}
	headerErr := manager.dispatchChainEvent(
		t.Context(), chain.BlockConnected(empty),
	)

	<-ready
	<-ready

	// Assert: Public history and observations contain all three relevant
	// transactions only in the recipient. The unmatched Wallet advances its
	// atomic checkpoint without a transaction row or a notification.
	require.NoError(t, blockErr)
	require.NoError(t, spendErr)
	require.NoError(t, headerErr)
	require.Equal(t, originalBlock, block)

	for i, record := range records {
		require.Equal(t, originalRecords[i], *record)

		_, err := wallets[0].GetTx(t.Context(), record.Hash)
		require.NoError(t, err)
		_, err = wallets[1].GetTx(t.Context(), record.Hash)
		require.ErrorIs(t, err, ErrTxNotFound)

		select {
		case event := <-events:
			require.Equal(t, record.Hash, event.Detail.Hash)
		default:
			t.Fatal("recipient lost a committed transaction observation")
		}
	}

	history, err := wallets[0].ListTxns(t.Context(), 0, -1)
	require.NoError(t, err)
	require.Len(t, history, 3)
	history, err = wallets[1].ListTxns(t.Context(), 0, -1)
	require.NoError(t, err)
	require.Empty(t, history)

	for _, w := range wallets {
		info, err := w.Info(t.Context())
		require.NoError(t, err)
		require.Equal(t, empty.Height, info.SyncedTo.Height)
		require.Equal(t, empty.Hash, info.SyncedTo.Hash)
	}

	select {
	case event := <-unrelatedEvents:
		t.Fatalf("unrelated Wallet received transaction observation: %v", event)
	default:
	}
}

// TestManagerChainEventBlockedStop proves that shutdown joins a busy worker
// before Store closure and later chain events are rejected.
func TestManagerChainEventBlockedStop(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		// Arrange: Hold an existing worker in an accepted rewind so chain
		// delivery fills its mailbox. Neither processor consumes queued work;
		// the rewind remains held even after cancellation.
		first := newChainEventTestWallet(t, "first", 1)
		second, deps := createTestWalletWithMocks(t)
		second.cfg.Name = "second"
		second.id = 2
		secondEvents := make(chan any, 1)
		second.chainEventChan = secondEvents
		s := newSyncer(
			second.cfg, nil, nil, second, second.store, second.id, secondEvents,
		)
		second.sync = s
		second.state = newWalletState(s)
		s.state.Store(uint32(syncStateSynced))
		deps.vault.On("Lock").Return().Once()
		deps.chain.On("Notifications").Return((<-chan any)(nil)).Once()
		deps.store.On("GetWallet", mock.Anything, "second").Return(
			&db.WalletInfo{SyncedTo: &db.Block{Height: 10}}, nil,
		).Once()
		fork := waddrmgr.BlockStamp{
			Hash:      chainhash.Hash{5},
			Height:    5,
			Timestamp: time.Unix(5, 0),
		}
		entered := make(chan struct{})
		draining := make(chan struct{})
		release := make(chan struct{})
		deps.store.On("RewindWallet", mock.Anything,
			matchRewindWalletParams(second.id, fork),
		).Run(func(args mock.Arguments) {
			close(entered)
			ctx, ok := args.Get(0).(context.Context)
			if !ok {
				panic("rewind has no context")
			}
			<-ctx.Done()
			close(draining)
			<-release
		}).Return(context.Canceled).Once()
		startLoadedWalletForTest(t, second)
		require.NoError(t, s.requestScan(t.Context(), &scanReq{
			typ:        scanTypeRewind,
			startBlock: fork,
		}))

		workerResult := make(chan error, 1)
		second.wg.Go(func() {
			workerResult <- s.waitForEvent(second.lifetimeCtx)
		})
		<-entered

		backend := &managerBackendMock{}
		backend.On("listWallets", mock.Anything).
			Return([]*walletData{}, nil).Once()

		storeClosed := make(chan struct{})
		backend.On("close").Run(func(mock.Arguments) {
			close(storeClosed)
		}).Return(nil).Once()
		manager := newManagerLifecycleTest(t, backend)
		manager.config.Backend = DBBackendSQLite
		_, err := manager.Start(t.Context())
		require.NoError(t, err)

		manager.wallets[first.cfg.Name] = first
		manager.wallets[second.cfg.Name] = second
		// Even an aborted assertion must release owned Store work before the
		// existing fixture attempts its Manager/Wallet joins.
		releaseWork := sync.OnceFunc(func() { close(release) })
		t.Cleanup(releaseWork)

		event := chain.RelevantTx{TxRecord: &wtxmgr.TxRecord{}}
		firstEvents := make(chan any, 1)
		first.chainEventChan = firstEvents
		// Fill both mailboxes while the accepted rewind owns its worker.
		require.NoError(t, manager.dispatchChainEvent(t.Context(), event))

		// Act: Wait until delivery is blocked on the busy worker, then Stop.
		// synctest observes channel waits without assuming which Wallet was
		// visited first or introducing a concurrent dispatch caller.
		delivered := make(chan error, 1)
		stopped := make(chan error, 1)

		go func() {
			delivered <- manager.dispatchChainEvent(t.Context(), event)
		}()

		synctest.Wait()

		go func() { stopped <- manager.Stop() }()

		<-draining

		// Assert: Cancellation releases delivery independently of processing.
		// Stop and Store closure still wait for the held worker to join.
		select {
		case <-storeClosed:
			t.Fatal("Store closes before accepted worker joins")
		default:
		}

		require.ErrorIs(t, <-delivered, ErrManagerStopped)
		require.Empty(t, stopped)
		releaseWork()
		require.NoError(t, <-stopped)
		require.ErrorIs(t, <-workerResult, context.Canceled)
		<-storeClosed

		// Only after this operation settles does the single caller submit
		// another event; terminal admission must reject without Store work.
		err = manager.dispatchChainEvent(t.Context(), event)
		require.ErrorIs(t, err, ErrStateForbidden)
	})
}

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
