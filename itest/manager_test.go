//go:build itest

package itest

import (
	"sync"
	"time"

	"github.com/btcsuite/btcwallet/bwtest"
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
	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

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
	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

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
	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

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
	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

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
