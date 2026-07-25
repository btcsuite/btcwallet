package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

var errRPCInStoreCallback = errors.New("chain RPC called in Store callback")

// callbackGuardStore tracks when a Store callback is active so the chain mock
// can reject transaction-bound RPC calls.
type callbackGuardStore struct {
	// Store delegates transaction execution while callbacks are tracked.
	walletstore.Store

	active atomic.Int32
}

// View tracks the lifetime of a read callback.
func (s *callbackGuardStore) View(ctx context.Context,
	body func(walletstore.ReadTx) error, reset func()) error {

	return s.Store.View(ctx, func(tx walletstore.ReadTx) error {
		s.active.Add(1)
		defer s.active.Add(-1)
		return body(tx)
	}, reset)
}

// Update tracks the lifetime of a replayable write callback.
func (s *callbackGuardStore) Update(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	return s.Store.Update(ctx, func(tx walletstore.ReadWriteTx) error {
		s.active.Add(1)
		defer s.active.Add(-1)
		return body(tx)
	}, reset)
}

// UpdateOnce tracks the lifetime of a one-shot write callback.
func (s *callbackGuardStore) UpdateOnce(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	return s.Store.UpdateOnce(ctx, func(tx walletstore.ReadWriteTx) error {
		s.active.Add(1)
		defer s.active.Add(-1)
		return body(tx)
	}, reset)
}

// failUpdateStore injects one rollback after a Store plan body completes.
type failUpdateStore struct {
	// Store delegates transactions not selected for rollback injection.
	walletstore.Store

	err      error
	failNext bool
}

// UpdateOnce rolls back the selected plan after all writes have been staged.
func (s *failUpdateStore) UpdateOnce(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	if !s.failNext {
		return s.Store.UpdateOnce(ctx, body, reset)
	}
	s.failNext = false

	return s.Store.UpdateOnce(ctx, func(tx walletstore.ReadWriteTx) error {
		if err := body(tx); err != nil {
			return err
		}

		return s.err
	}, reset)
}

// rpcBlocker pauses one or more mock RPCs until the test releases them.
type rpcBlocker struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

// newRPCBlocker creates an unreleased RPC blocker.
func newRPCBlocker() *rpcBlocker {
	return &rpcBlocker{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

// wait announces the blocked RPC and waits for release.
func (b *rpcBlocker) wait() {
	b.once.Do(func() {
		close(b.started)
	})
	<-b.release
}

// syncTestChain builds a valid in-memory header chain rooted at genesis.
func syncTestChain(params *chaincfg.Params, count int32) (
	map[int64]chainhash.Hash, map[chainhash.Hash]wire.BlockHeader) {

	hashes := make(map[int64]chainhash.Hash, count+1)
	headers := make(map[chainhash.Hash]wire.BlockHeader, count+1)
	genesisHash := params.GenesisBlock.BlockHash()
	hashes[0] = genesisHash
	headers[genesisHash] = params.GenesisBlock.Header

	previous := genesisHash
	for height := int32(1); height <= count; height++ {
		header := wire.BlockHeader{
			Version:   1,
			PrevBlock: previous,
			Timestamp: params.GenesisBlock.Header.Timestamp.Add(
				time.Duration(height) * time.Minute,
			),
			Nonce: uint32(height),
		}
		hash := header.BlockHash()
		hashes[int64(height)] = hash
		headers[hash] = header
		previous = hash
	}

	return hashes, headers
}

// newGuardedChain returns a chain mock that rejects every guarded RPC while a
// Store callback is active.
func newGuardedChain(guard *callbackGuardStore, hashes map[int64]chainhash.Hash,
	headers map[chainhash.Hash]wire.BlockHeader) *mockChainClient {

	client := &mockChainClient{}
	client.rpcGuard = func() error {
		if guard.active.Load() != 0 {
			return errRPCInStoreCallback
		}
		return nil
	}
	client.getBlockHashAt = func(height int64) (*chainhash.Hash, error) {
		hash, ok := hashes[height]
		if !ok {
			return nil, fmt.Errorf("block %d not found", height)
		}
		return &hash, nil
	}
	client.getBlockHeaderFunc = func(hash *chainhash.Hash) (
		*wire.BlockHeader, error) {

		header, ok := headers[*hash]
		if !ok {
			return nil, fmt.Errorf("header %v not found", hash)
		}
		return &header, nil
	}

	return client
}

// newSyncStoreWallet creates a SQLite Store wallet and installs callback and
// RPC guards around it.
func newSyncStoreWallet(t *testing.T, recoveryWindow uint32) (
	*validationFixture, *callbackGuardStore, *mockChainClient,
	map[int64]chainhash.Hash, map[chainhash.Hash]wire.BlockHeader) {

	t.Helper()
	params := &chaincfg.TestNet3Params
	seed := bytes.Repeat([]byte{0x41}, hdkeychain.RecommendedSeedLen)
	fixture := newValidationFixtureForParams(
		t, "sqlite", "sync-transactions", params, recoveryWindow,
		func(loader *Loader) (*Wallet, error) {
			return loader.CreateNewWallet(
				[]byte("public"), []byte("private"), seed,
				params.GenesisBlock.Header.Timestamp,
			)
		},
	)
	t.Cleanup(fixture.close)

	guard := &callbackGuardStore{Store: fixture.wallet.store}
	fixture.wallet.store = guard
	hashes, headers := syncTestChain(params, 2)
	client := newGuardedChain(guard, hashes, headers)
	client.getBestBlockHash = ptrHash(hashes[2])
	client.getBestBlockHeight = 2
	fixture.wallet.chainClient = client

	return fixture, guard, client, hashes, headers
}

// ptrHash returns a pointer to a copied hash.
func ptrHash(hash chainhash.Hash) *chainhash.Hash {
	return &hash
}

// requireUnrelatedWrite verifies that SQLite is writable while an RPC is
// blocked, then releases the RPC regardless of the assertion result.
func requireUnrelatedWrite(t *testing.T, store walletstore.Store,
	blocker *rpcBlocker) {

	t.Helper()
	writeErr := make(chan error, 1)
	go func() {
		writeErr <- store.UpdateOnce(
			t.Context(), func(tx walletstore.ReadWriteTx) error {
				return tx.Addr().SetBirthday(time.Unix(1_700_000_001, 0))
			}, nil,
		)
	}()

	var err error
	completed := false
	select {
	case err = <-writeErr:
		completed = true
	case <-time.After(2 * time.Second):
	}
	close(blocker.release)
	require.True(t, completed, "unrelated SQLite write blocked behind RPC")
	require.NoError(t, err)
}

// TestStoreRPCPlanningDoesNotBlockSQLiteWrites proves the three expensive RPC
// phases execute without retaining a SQLite transaction.
func TestStoreRPCPlanningDoesNotBlockSQLiteWrites(t *testing.T) {
	t.Run("FilterBlocks", func(t *testing.T) {
		fixture, _, client, hashes, _ := newSyncStoreWallet(t, 1)
		wallet := fixture.wallet
		client.getBestBlockHash = ptrHash(hashes[1])
		client.getBestBlockHeight = 1
		blocker := newRPCBlocker()
		client.filterBlocksFunc = func(*chain.FilterBlocksRequest) (
			*chain.FilterBlocksResponse, error) {

			blocker.wait()
			return nil, nil
		}

		birthday := waddrmgr.BlockStamp{
			Hash:      hashes[0],
			Height:    0,
			Timestamp: fixture.params.GenesisBlock.Header.Timestamp,
		}
		recoveryErr := make(chan error, 1)
		go func() {
			recoveryErr <- wallet.recovery(client, &birthday)
		}()
		<-blocker.started
		requireUnrelatedWrite(t, wallet.store, blocker)
		require.NoError(t, <-recoveryErr)
	})

	t.Run("GetBlockHeader", func(t *testing.T) {
		fixture, _, client, hashes, headers := newSyncStoreWallet(t, 0)
		wallet := fixture.wallet
		block := wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Hash: hashes[1], Height: 1},
			Time:  headers[hashes[1]].Timestamp,
		}
		require.NoError(t, wallet.store.UpdateOnce(
			t.Context(), func(tx walletstore.ReadWriteTx) error {
				return wallet.connectBlockFromStore(tx, block)
			}, nil,
		))
		wallet.SetChainSynced(true)

		blocker := newRPCBlocker()
		client.getBlockHeaderFunc = func(hash *chainhash.Hash) (
			*wire.BlockHeader, error) {

			blocker.wait()
			header := headers[*hash]
			return &header, nil
		}
		disconnectResult := make(chan error, 1)
		go func() {
			_, err := wallet.disconnectBlockFromStore(client, block)
			disconnectResult <- err
		}()
		<-blocker.started
		requireUnrelatedWrite(t, wallet.store, blocker)
		require.NoError(t, <-disconnectResult)
	})

	t.Run("catch-up hash collection", func(t *testing.T) {
		fixture, _, client, hashes, _ := newSyncStoreWallet(t, 0)
		wallet := fixture.wallet
		blocker := newRPCBlocker()
		client.getBlockHashAt = func(height int64) (*chainhash.Hash, error) {
			if height == 1 {
				blocker.wait()
			}
			hash := hashes[height]
			return &hash, nil
		}

		catchUpErr := make(chan error, 1)
		go func() {
			catchUpErr <- wallet.catchUpHashes(
				client, 2, ptrHash(hashes[2]),
			)
		}()
		<-blocker.started
		requireUnrelatedWrite(t, wallet.store, blocker)
		require.NoError(t, <-catchUpErr)
	})
}

// TestStoreCatchUpRejectsStaleStartingTip verifies a plan cannot overwrite a
// concurrent durable tip change.
func TestStoreCatchUpRejectsStaleStartingTip(t *testing.T) {
	fixture, _, client, hashes, headers := newSyncStoreWallet(t, 0)
	wallet := fixture.wallet
	blocker := newRPCBlocker()
	client.getBlockHeaderFunc = func(hash *chainhash.Hash) (
		*wire.BlockHeader, error) {

		if *hash == hashes[1] {
			blocker.wait()
		}
		header := headers[*hash]
		return &header, nil
	}

	catchUpErr := make(chan error, 1)
	go func() {
		catchUpErr <- wallet.catchUpHashes(client, 2, ptrHash(hashes[2]))
	}()
	<-blocker.started
	alternate := waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{0xaa},
		Height:    1,
		Timestamp: time.Unix(1_700_000_010, 0),
	}
	require.NoError(t, wallet.store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			return wallet.Manager.SetSyncedToFromStore(tx.Addr(), &alternate)
		}, nil,
	))
	close(blocker.release)

	err := <-catchUpErr
	var stale *StorePlanStaleError
	require.ErrorAs(t, err, &stale)
	require.Equal(t, alternate.Hash, wallet.Manager.SyncedTo().Hash)
}

// TestCatchUpFailureDoesNotFinishRescan verifies a failed catch-up neither
// forwards completion nor marks the wallet chain-synced.
func TestCatchUpFailureDoesNotFinishRescan(t *testing.T) {
	fixture, _, client, hashes, _ := newSyncStoreWallet(t, 0)
	wallet := fixture.wallet
	rpcErr := errors.New("catch-up hash failure")
	called := make(chan struct{})
	client.getBlockHashAt = func(int64) (*chainhash.Hash, error) {
		close(called)
		return nil, rpcErr
	}
	client.notifications = make(chan interface{}, 1)
	wallet.rescanNotifications = make(chan interface{}, 1)
	wallet.chainClient = client

	wallet.wg.Add(1)
	go wallet.handleChainNotifications()
	client.notifications <- &chain.RescanFinished{
		Hash:   ptrHash(hashes[1]),
		Height: 1,
	}
	<-called
	close(client.notifications)
	wallet.Stop()
	wallet.WaitForShutdown()

	require.False(t, wallet.ChainSynced())
	select {
	case notification := <-wallet.rescanNotifications:
		t.Fatalf("unexpected rescan completion: %T", notification)
	default:
	}
}

// TestDisconnectNoOpDoesNotNotify verifies a future disconnect cannot create a
// detached-block notification.
func TestDisconnectNoOpDoesNotNotify(t *testing.T) {
	fixture, _, client, hashes, headers := newSyncStoreWallet(t, 0)
	wallet := fixture.wallet
	wallet.SetChainSynced(true)
	subscriber := wallet.NtfnServer.TransactionNotifications()
	defer subscriber.Done()

	block := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: hashes[1], Height: 1},
		Time:  headers[hashes[1]].Timestamp,
	}
	require.NoError(t, wallet.processBlockDisconnected(client, block))

	wallet.NtfnServer.mu.Lock()
	defer wallet.NtfnServer.mu.Unlock()
	require.Nil(t, wallet.NtfnServer.currentTxNtfn)
}

// TestRecoveryWriteFailureKeepsStateAtomic verifies a failed apply persists no
// addresses, transactions, stamps, or cloned recovery-state advancement.
func TestRecoveryWriteFailureKeepsStateAtomic(t *testing.T) {
	fixture, guard, client, hashes, headers := newSyncStoreWallet(t, 1)
	wallet := fixture.wallet
	writeErr := errors.New("recovery write failure")
	wallet.store = &failUpdateStore{
		Store:    guard,
		err:      writeErr,
		failNext: true,
	}

	var (
		recoveredAddrScript []byte
		relevantHash        chainhash.Hash
	)
	client.filterBlocksFunc = func(request *chain.FilterBlocksRequest) (
		*chain.FilterBlocksResponse, error) {

		scopedIndex := waddrmgr.ScopedIndex{
			Scope: waddrmgr.KeyScopeBIP0084,
			Index: 0,
		}
		addr := request.ExternalAddrs[scopedIndex]
		recoveredAddrScript = append(
			[]byte(nil), addr.ScriptAddress()...,
		)
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}
		transaction := wire.NewMsgTx(2)
		transaction.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
			Hash: chainhash.Hash{0x51},
		}})
		transaction.AddTxOut(wire.NewTxOut(50_000, pkScript))
		relevantHash = transaction.TxHash()

		return &chain.FilterBlocksResponse{
			BatchIndex: 0,
			BlockMeta:  request.Blocks[0],
			FoundExternalAddrs: map[waddrmgr.KeyScope]map[uint32]struct{}{
				waddrmgr.KeyScopeBIP0084: {0: {}},
			},
			FoundOutPoints: map[wire.OutPoint]address.Address{},
			RelevantTxns:   []*wire.MsgTx{transaction},
		}, nil
	}

	manager := NewRecoveryManager(1, 1, fixture.params)
	batch := []wtxmgr.BlockMeta{{
		Block: wtxmgr.Block{Hash: hashes[1], Height: 1},
		Time:  headers[hashes[1]].Timestamp,
	}}
	blocks := []*waddrmgr.BlockStamp{{
		Hash:      hashes[1],
		Height:    1,
		Timestamp: headers[hashes[1]].Timestamp,
	}}
	scopedMgrs := make(map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager)
	for _, scopedMgr := range wallet.Manager.ActiveScopedKeyManagers() {
		scopedMgrs[scopedMgr.Scope()] = scopedMgr
	}

	err := wallet.recoverStoreBatch(
		client, manager, batch, blocks, scopedMgrs,
	)
	require.ErrorIs(t, err, writeErr)
	require.Zero(t, manager.State().StateForScope(
		waddrmgr.KeyScopeBIP0084,
	).ExternalBranch.NextUnfound())

	require.NoError(t, guard.View(t.Context(), func(tx walletstore.ReadTx) error {
		state, err := tx.Addr().SyncState()
		require.NoError(t, err)
		require.Zero(t, state.SyncedTo.Height)
		account, err := tx.Addr().Account(
			waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
		)
		require.NoError(t, err)
		require.Zero(t, account.NextExternalIndex)
		_, err = tx.Addr().Address(
			waddrmgr.KeyScopeBIP0084, recoveredAddrScript,
		)
		require.True(t, waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound))
		details, err := tx.Tx().TxDetails(&relevantHash)
		require.NoError(t, err)
		require.Nil(t, details)
		return nil
	}, nil))
}

// TestRecoveryRejectsStaleAccountIndexes verifies address allocation between
// planning and apply cannot be overwritten by a recovery batch.
func TestRecoveryRejectsStaleAccountIndexes(t *testing.T) {
	fixture, _, client, hashes, headers := newSyncStoreWallet(t, 1)
	wallet := fixture.wallet
	client.filterBlocksFunc = func(*chain.FilterBlocksRequest) (
		*chain.FilterBlocksResponse, error) {

		return nil, nil
	}

	manager := NewRecoveryManager(1, 1, fixture.params)
	batch := []wtxmgr.BlockMeta{{
		Block: wtxmgr.Block{Hash: hashes[1], Height: 1},
		Time:  headers[hashes[1]].Timestamp,
	}}
	blocks := []*waddrmgr.BlockStamp{{
		Hash:      hashes[1],
		Height:    1,
		Timestamp: headers[hashes[1]].Timestamp,
	}}
	scopedMgrs := make(map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager)
	for _, scopedMgr := range wallet.Manager.ActiveScopedKeyManagers() {
		scopedMgrs[scopedMgr.Scope()] = scopedMgr
	}
	plan, err := wallet.prepareRecoveryStorePlan(
		client, manager.State(), batch, blocks, scopedMgrs,
	)
	require.NoError(t, err)

	_, err = wallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	err = wallet.applyRecoveryStorePlan(plan)
	var stale *StorePlanStaleError
	require.ErrorAs(t, err, &stale)
	require.Zero(t, wallet.Manager.SyncedTo().Height)
}

// TestCatchUpReconcilesDurableAmbiguity verifies an acknowledged failure does
// not replay hash RPCs after the exact terminal tip proves the plan committed.
func TestCatchUpReconcilesDurableAmbiguity(t *testing.T) {
	fixture, guard, client, hashes, _ := newSyncStoreWallet(t, 0)
	wallet := fixture.wallet
	var hashCalls atomic.Int32
	originalHash := client.getBlockHashAt
	client.getBlockHashAt = func(height int64) (*chainhash.Hash, error) {
		hashCalls.Add(1)
		return originalHash(height)
	}
	wallet.store = &ambiguousCommitStore{
		Store:                   guard,
		ambiguousNextUpdateOnce: true,
	}

	require.NoError(t, wallet.catchUpHashes(
		client, 2, ptrHash(hashes[2]),
	))
	require.EqualValues(t, 2, hashCalls.Load())
	require.Equal(t, hashes[2], wallet.Manager.SyncedTo().Hash)
}
