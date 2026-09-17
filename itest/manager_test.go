//go:build itest

package itest

import (
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// testManagerStartConcurrent verifies that every supported Manager backend
// admits one concurrent Start and rejects the others without rebuilding it.
func testManagerStartConcurrent(h *bwtest.HarnessTest) {
	// Arrange. The setup Manager creates durable state, then stops so the test
	// Manager opens the same backend with no runtime Wallets.
	firstParams := h.TestWalletParams()
	firstParams.Name += "-z"
	setupManager := h.NewWalletManager()
	loaded, err := setupManager.Start(h.Context())
	require.NoError(h, err, "failed to start setup manager")
	require.Empty(h, loaded, "empty store loaded wallets")

	firstWallet, err := setupManager.Create(firstParams)
	require.NoError(h, err, "failed to create wallet")

	expectedIDs := []uint32{firstWallet.ID()}

	// Legacy kvdb has a documented one-Wallet limit. SQL backends create a
	// second Wallet with a lexically earlier name but a later durable ID.
	if *dbBackend != "kvdb" {
		secondParams := h.TestWalletParams()
		secondParams.Name += "-a"
		secondWallet, err := setupManager.Create(secondParams)
		require.NoError(h, err, "failed to create second wallet")

		expectedIDs = append(expectedIDs, secondWallet.ID())
	}

	require.NoError(h, setupManager.Stop(), "failed to stop manager")
	require.True(
		h, h.ReleaseManager(setupManager),
		"failed to release setup manager",
	)

	manager := h.NewWalletManager()

	// Multiple callers contend for startup. The exact number is not
	// significant as long as it is greater than one.
	const numCallers = 8

	type result struct {
		// wallets is the exact ordered runtime set returned to one caller.
		wallets []*wallet.Wallet

		// err is the Start result returned with wallets.
		err error
	}

	results := make(chan result, numCallers)
	start := make(chan struct{})

	var ready sync.WaitGroup

	ready.Add(numCallers)

	for range numCallers {
		go func() {
			ready.Done()
			<-start

			wallets, err := manager.Start(h.Context())
			results <- result{
				wallets: wallets,
				err:     err,
			}
		}()
	}

	// Act. Release every caller into the empty Manager cache together.
	ready.Wait()
	close(start)

	var installed []*wallet.Wallet
	for range numCallers {
		result := <-results
		if result.err != nil {
			require.ErrorIs(h, result.err, wallet.ErrStateForbidden)
			require.Nil(h, result.wallets)

			continue
		}

		require.Nil(h, installed, "more than one Start succeeded")
		installed = result.wallets
	}

	require.Len(h, installed, len(expectedIDs),
		"unexpected startup wallet count")

	for i, w := range installed {
		require.Equal(h, expectedIDs[i], w.ID(),
			"wallets not returned in durable ID order")
		h.RegisterWallet(manager, w)
	}
}

// testCreateWallet verifies a wallet can be created, started, and synced.
func testCreateWallet(h *bwtest.HarnessTest) {
	// This is a manager-focused test, so drive the Manager API directly
	// rather than the harness's CreateEmptyWallet convenience helper.
	params := h.TestWalletParams()
	manager := h.NewWalletManager()
	loaded, err := manager.Start(h.Context())
	require.NoError(h, err, "failed to start wallet manager")
	require.Empty(h, loaded, "empty store loaded wallets")

	w, err := manager.Create(params)
	require.NoError(h, err, "failed to create wallet")
	h.RegisterWallet(manager, w)

	// Wait for the wallet to catch up to the existing tip before mining new
	// blocks.
	h.AssertWalletSynced(w)

	// Mine a few blocks and require the wallet catches up.
	h.MineBlocks(5)
}

// testManagerCreateDuplicate verifies that both a live wallet cache entry and
// a completed wallet in the durable store reject a duplicate creation.
func testManagerCreateDuplicate(h *bwtest.HarnessTest) {
	params := h.TestWalletParams()

	manager := h.NewWalletManager()
	loaded, err := manager.Start(h.Context())
	require.NoError(h, err, "failed to start wallet manager")
	require.Empty(h, loaded, "empty store loaded wallets")

	w, err := manager.Create(params)
	require.NoError(h, err, "failed to create wallet")
	h.RegisterWallet(manager, w)

	duplicate, err := manager.Create(params)

	require.Error(h, err, "duplicate create not rejected by live wallet cache")
	require.Nil(h, duplicate, "duplicate create returned a wallet")

	// Stop the aggregate, then open a new Manager over the durable store.
	require.NoError(h, manager.Stop(), "failed to stop manager")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")
	require.True(h, h.ReleaseManager(manager), "failed to release manager")
	manager = h.NewWalletManager()
	loaded, err = manager.Start(h.Context())
	require.NoError(h, err, "failed to start replacement manager")
	require.Len(h, loaded, 1, "replacement manager lost durable wallet")
	h.RegisterWallet(manager, loaded[0])

	// A fresh manager must reject creation over the completed durable wallet.
	duplicate, err = manager.Create(params)
	require.Error(h, err, "duplicate create not rejected against durable store")
	require.Nil(h, duplicate, "duplicate create returned a wallet")
}

// testManagerStartReopen verifies durable startup and birthday metadata while
// preserving lifecycle ownership.
func testManagerStartReopen(h *bwtest.HarnessTest) {
	params := h.TestWalletParams()

	// Keep the effective birthday five days ahead of the chain after the
	// wallet's two-day safety margin. With every candidate too early, one real
	// mined block guarantees birthday reconstruction selects a different block.
	params.Birthday = time.Now().Add(7 * 24 * time.Hour)

	manager := h.NewWalletManager()
	loaded, err := manager.Start(h.Context())
	require.NoError(h, err, "failed to start wallet manager")
	require.Empty(h, loaded, "empty store loaded wallets")

	w, err := manager.Create(params)
	require.NoError(h, err, "failed to create wallet")
	h.RegisterWallet(manager, w)

	firstInfo, err := w.Info(h.Context())
	require.NoError(h, err, "failed to query initial wallet info")

	birthdayBlock := firstInfo.BirthdayBlock
	require.NotEqual(
		h, waddrmgr.BlockStamp{}, birthdayBlock,
		"initial wallet did not initialize its birthday block",
	)

	// Mine through the real chain while the original wallet is active; the
	// harness waits for the wallet to synchronize to the new tip.
	h.MineBlocks(1)

	require.NoError(h, manager.Stop(), "failed to stop manager")
	_, err = w.Info(h.Context())
	require.ErrorIs(h, err, wallet.ErrWalletStopped,
		"stopped wallet accepted maintained access")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")
	require.True(h, h.ReleaseManager(manager), "failed to release manager")
	manager = h.NewWalletManager()
	loaded, err = manager.Start(h.Context())
	require.NoError(h, err, "failed to reload wallet")
	require.Len(h, loaded, 1, "unexpected reloaded wallet count")
	reloaded := loaded[0]
	h.RegisterWallet(manager, reloaded)

	require.NotSame(h, w, reloaded, "reload returned the torn-down instance")
	reloadedInfo, err := reloaded.Info(h.Context())
	require.NoError(h, err, "failed to query reloaded wallet info")
	require.Equal(
		h, birthdayBlock.Height, reloadedInfo.BirthdayBlock.Height,
		"reloaded wallet restored a different birthday block height",
	)
	require.Equal(
		h, birthdayBlock.Hash, reloadedInfo.BirthdayBlock.Hash,
		"reloaded wallet restored a different birthday block hash",
	)
	require.True(
		h, birthdayBlock.Timestamp.Equal(reloadedInfo.BirthdayBlock.Timestamp),
		"reloaded wallet restored the same birthday instant "+
			"with different timestamp location metadata",
	)
}

// testManagerCreateWatchOnly verifies that a watch-only wallet is created,
// starts, syncs like a spendable wallet, and stays watch-only across a reload
// from the durable store.
//
// The wallet is rootless: that is the one watch-only shape every backend can
// represent, and its keyspace arrives later as account-level xpub imports.
func testManagerCreateWatchOnly(h *bwtest.HarnessTest) {
	params := h.TestWalletParams()
	params.Mode = wallet.ModeShell
	params.WatchOnly = true

	manager := h.NewWalletManager()
	loaded, err := manager.Start(h.Context())
	require.NoError(h, err, "failed to start wallet manager")
	require.Empty(h, loaded, "empty store loaded wallets")

	w, err := manager.Create(params)
	require.NoError(h, err, "failed to create watch-only wallet")
	h.RegisterWallet(manager, w)

	h.AssertWalletSynced(w)

	require.True(h, w.IsWatchOnly(), "created wallet is not watch-only")

	// A watch-only wallet tracks the chain like any other wallet.
	h.MineBlocks(1)

	// Stop the aggregate, then reload from the durable store with a fresh
	// Manager.
	require.NoError(h, manager.Stop(), "failed to stop manager")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")
	require.True(h, h.ReleaseManager(manager), "failed to release manager")

	manager = h.NewWalletManager()
	loaded, err = manager.Start(h.Context())
	require.NoError(h, err, "failed to reload watch-only wallet")
	require.Len(h, loaded, 1, "unexpected reloaded wallet count")
	reloaded := loaded[0]
	h.RegisterWallet(manager, reloaded)

	require.True(
		h, reloaded.IsWatchOnly(),
		"reloaded wallet lost its watch-only state",
	)
}

// testManagerLiveWatchReplay proves a fresh client restores both persisted
// address and outpoint watches for payments and external mempool spends.
func testManagerLiveWatchReplay(h *bwtest.HarnessTest) {
	if _, ok := h.ChainClient.(*chain.NeutrinoClient); ok {
		h.Skip("SPV does not deliver mempool transactions")
	}

	// Arrange: Persist an unused address and a funded output so reopening
	// must restore both kinds of watch from the store.
	manager := h.NewWalletManager()

	_, err := manager.Start(h.Context())
	require.NoError(h, err, "failed to start manager")

	w, err := manager.Create(h.TestWalletParams())
	require.NoError(h, err, "failed to create wallet")
	h.RegisterWallet(manager, w)

	addr := h.NewWalletAddressOfType(w, waddrmgr.WitnessPubKey)

	// A key-path witness cannot reconstruct the receiving address, so
	// bitcoind must match this spend through its persisted outpoint watch.
	funding := h.FundWalletOfType(w, waddrmgr.TaprootPubKey, oneBTC)

	// Discard the source as well as the Manager: retained in-memory filters
	// would let this test pass without restoring persisted watches.
	require.NoError(h, manager.Stop(), "failed to stop initial manager")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")
	require.True(h, h.ReleaseManager(manager), "failed to release manager")
	h.ChainClient.Stop()

	client, cleanup, err := h.Backend.NewChainClient(h.Context())
	require.NoError(h, err, "failed to create fresh chain client")
	h.Cleanup(cleanup)
	h.ChainClient = client

	manager = h.NewWalletManager()
	wallets, err := manager.Start(h.Context())
	require.NoError(h, err, "failed to reopen manager")
	require.Len(h, wallets, 1, "unexpected reopened wallet count")

	w = wallets[0]
	h.RegisterWallet(manager, w)
	h.AssertWalletSynced(w)
	h.UnlockWallet(w)

	// Keep outputs external as well, so only the outpoint watch can deliver
	// this spend. Sign locally, but broadcast outside the Wallet.
	external, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), h.NetParams(),
	)
	require.NoError(h, err, "failed to construct external address")

	script, err := txscript.PayToAddrScript(external)
	require.NoError(h, err, "failed to construct external script")

	tx := h.SignSpend(w, bwtest.SpendFixture{
		Inputs: funding.WalletOutpoints,
		Outputs: []wire.TxOut{
			{
				Value:    oneBTC - spendFee,
				PkScript: script,
			},
		},
	})

	paymentScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to construct payment script")

	// Act: Pay the persisted address and broadcast the external spend after
	// reopening. Neither transaction can be discovered by a mined block yet.
	payment := h.SendOutput(&wire.TxOut{
		Value:    oneBTC,
		PkScript: paymentScript,
	}, bwtest.MinerFeeRate)

	_, err = h.ChainClient.SendRawTransaction(tx, false)
	require.NoError(h, err, "failed to broadcast external spend")

	// Assert: Wait for asynchronous live delivery, then inspect the public
	// transaction state to prove both restored watches work before mining.
	err = wait.NoError(func() error {
		_, err := w.GetTx(h.Context(), *payment)
		return err
	}, pollTimeout)
	require.NoError(h, err, "persisted address missed unmined payment")

	received, err := w.GetTx(h.Context(), *payment)
	require.NoError(h, err, "failed to read received payment")
	require.Nil(h, received.Block, "payment was already confirmed")

	err = wait.NoError(func() error {
		_, err := w.GetTx(h.Context(), tx.TxHash())
		return err
	}, pollTimeout)
	require.NoError(h, err, "persisted outpoint missed unmined spend")

	spent, err := w.GetTx(h.Context(), tx.TxHash())
	require.NoError(h, err, "failed to read external spend")
	require.Nil(h, spent.Block, "spend was already confirmed")
	require.Negative(h, spent.Value, "external spend did not debit wallet")

	// Empty the shared miner's mempool so later cases start without these
	// transactions; confirmation behavior is covered by transaction tests.
	h.MineBlocksAndAssertNumTxns(1, 2)
}

// testManagerNeutrinoWatchReplay verifies that a fresh SPV notification client
// retains persisted address watches when processing new confirmed payments.
func testManagerNeutrinoWatchReplay(h *bwtest.HarnessTest) {
	if _, ok := h.ChainClient.(*chain.NeutrinoClient); !ok {
		h.Skip("requires the SPV notification rescan")
	}

	// Arrange: Persist an unused address, then discard both consumers so
	// the reopened wallet cannot inherit an in-memory notification filter.
	manager := h.NewWalletManager()
	_, err := manager.Start(h.Context())
	require.NoError(h, err, "failed to start manager")

	w, err := manager.Create(h.TestWalletParams())
	require.NoError(h, err, "failed to create wallet")
	h.RegisterWallet(manager, w)

	addr := h.NewWalletAddressOfType(w, waddrmgr.WitnessPubKey)

	require.NoError(h, manager.Stop(), "failed to stop initial manager")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")
	require.True(h, h.ReleaseManager(manager), "failed to release manager")
	h.ChainClient.Stop()

	client, cleanup, err := h.Backend.NewChainClient(h.Context())
	require.NoError(h, err, "failed to create fresh chain client")
	h.Cleanup(cleanup)
	h.ChainClient = client

	manager = h.NewWalletManager()
	wallets, err := manager.Start(h.Context())
	require.NoError(h, err, "failed to reopen manager")
	require.Len(h, wallets, 1, "unexpected reopened wallet count")

	w = wallets[0]
	h.RegisterWallet(manager, w)
	h.AssertWalletSynced(w)

	// Join notification delivery for a new empty block as well as wallet
	// catch-up. Otherwise queued historical events could let catch-up find
	// the later payment and hide an empty notification filter.
	h.MineBlocks(1)
	tip, _ := h.GetBestBlock()
	source, ok := client.(*chain.NeutrinoClient)
	require.True(h, ok, "replacement client is not Neutrino")

	err = wait.NoError(func() error {
		stamp, err := source.BlockStamp()
		if err != nil {
			return err
		}

		if stamp.Hash != *tip {
			return fmt.Errorf("notification tip %v, want %v",
				stamp.Hash, tip)
		}

		return nil
	}, pollTimeout)
	require.NoError(h, err, "notification rescan missed preparation block")

	script, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to construct payment script")

	// Act: Confirm a payment to the persisted address while the wallet is
	// already at the tip and relies on its normal block notification path.
	payment := h.SendOutput(&wire.TxOut{
		Value:    oneBTC,
		PkScript: script,
	}, bwtest.MinerFeeRate)
	h.MineBlockWithTx(h.AssertTxInMempool(*payment))

	// Assert: Mining joined wallet synchronization, so the confirmed payment
	// must already be visible; retrying this read could mask a skipped block.
	got, err := w.GetTx(h.Context(), *payment)
	require.NoError(h, err, "persisted address missed confirmed payment")
	require.NotNil(h, got.Block, "payment was not recorded as confirmed")
}
