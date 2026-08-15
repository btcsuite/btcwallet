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

// testManagerLoadConcurrent verifies that every supported Manager backend gives
// concurrent cold Loads one exact runtime Wallet pointer.
func testManagerLoadConcurrent(h *bwtest.HarnessTest) {
	// Arrange. The setup Manager creates durable state, then closes so the
	// test Manager opens the same backend with an empty runtime cache. Using
	// two Managers is required to exercise a true cold Load on kvdb as well
	// as SQL.
	cfg, params := h.TestWalletConfig()
	setupManager := h.NewWalletManager()

	created, err := setupManager.Create(cfg, params)
	require.NoError(h, err, "failed to create wallet")
	require.NoError(h, created.Stop(h.Context()), "failed to stop wallet")
	require.NoError(h, setupManager.Close(), "failed to close setup manager")
	require.True(
		h, h.ReleaseManager(setupManager),
		"failed to release setup manager",
	)

	manager := h.NewWalletManager()

	// Multiple callers contend for cold assembly. The exact number is not
	// significant as long as it is greater than one.
	const numCallers = 8

	type result struct {
		// wallet is the exact runtime returned to one caller.
		wallet *wallet.Wallet

		// err is the Load result returned with wallet.
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

			w, err := manager.Load(cfg)
			results <- result{wallet: w, err: err}
		}()
	}

	// Act. Release every caller into the empty Manager cache together.
	ready.Wait()
	close(start)

	// Assert. One caller assembles the runtime and every other caller returns
	// that exact installed pointer.
	first := <-results
	require.NoError(h, first.err, "failed to load wallet")
	installed := first.wallet
	h.RegisterWallet(installed)

	for range numCallers - 1 {
		result := <-results
		require.NoError(h, result.err, "failed to load wallet")
		require.Same(h, installed, result.wallet, "load rebuilt wallet")
	}
}

// testCreateWallet verifies a wallet can be created, started, and synced.
func testCreateWallet(h *bwtest.HarnessTest) {
	// This is a manager-focused test, so drive the Manager API directly
	// rather than the harness's CreateEmptyWallet convenience helper.
	cfg, params := h.TestWalletConfig()
	manager := h.NewWalletManager()

	w, err := manager.Create(cfg, params)
	require.NoError(h, err, "failed to create wallet")

	// Register before Start so teardown owns the wallet even if Start fails.
	// The harness stops every registered wallet and then closes every
	// Manager. Do not add another Stop cleanup here; it would only stop the
	// wallet early and duplicate the harness-owned teardown.
	h.RegisterWallet(w)

	err = w.Start(h.Context())
	require.NoError(h, err, "failed to start wallet")

	// Wait for the wallet to catch up to the existing tip before mining new
	// blocks.
	h.AssertWalletSynced(w)

	// Mine a few blocks and require the wallet catches up.
	h.MineBlocks(5)
}

// testManagerCreateDuplicate verifies that both a live wallet cache entry and
// a completed wallet in the durable store reject a duplicate creation.
func testManagerCreateDuplicate(h *bwtest.HarnessTest) {
	cfg, params := h.TestWalletConfig()

	manager := h.NewWalletManager()
	w, err := manager.Create(cfg, params)
	require.NoError(h, err, "failed to create wallet")
	h.RegisterWallet(w)

	err = w.Start(h.Context())
	require.NoError(h, err, "failed to start wallet")

	// Creating a duplicate while the original is still cached must fail before
	// the manager consults the durable store.
	duplicate, err := manager.Create(cfg, params)
	require.Error(h, err, "duplicate create not rejected by live wallet cache")
	require.Nil(h, duplicate, "duplicate create returned a wallet")

	// Keep both resources registered until shutdown succeeds, then open a new
	// Manager over the durable store.
	require.NoError(h, w.Stop(h.Context()), "failed to stop wallet")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")
	require.NoError(h, manager.Close(), "failed to close wallet manager")
	require.True(h, h.ReleaseManager(manager), "failed to release manager")
	manager = h.NewWalletManager()

	// A fresh manager must reject creation over the completed durable wallet.
	duplicate, err = manager.Create(cfg, params)
	require.Error(h, err, "duplicate create not rejected against durable store")
	require.Nil(h, duplicate, "duplicate create returned a wallet")
}

// testManagerLoadReload verifies Manager cache identity, durable reload, and
// birthday metadata while preserving lifecycle ownership.
func testManagerLoadReload(h *bwtest.HarnessTest) {
	cfg, params := h.TestWalletConfig()

	// Keep the effective birthday five days ahead of the chain after the
	// wallet's two-day safety margin. With every candidate too early, one real
	// mined block guarantees birthday reconstruction selects a different block.
	params.Birthday = time.Now().Add(7 * 24 * time.Hour)

	manager := h.NewWalletManager()
	w, err := manager.Create(cfg, params)
	require.NoError(h, err, "failed to create wallet")
	h.RegisterWallet(w)

	err = w.Start(h.Context())
	require.NoError(h, err, "failed to start wallet")

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

	// Loading an already-loaded wallet returns the same live instance
	// without rebuilding.
	wCached, err := manager.Load(cfg)
	require.NoError(h, err, "failed to load cached wallet")
	require.Same(h, w, wCached, "load of cached wallet rebuilt the instance")

	// Keep both resources registered until shutdown succeeds, then reload from
	// their durable state with a fresh Manager.
	require.NoError(h, w.Stop(h.Context()), "failed to stop wallet")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")
	require.NoError(h, manager.Close(), "failed to close wallet manager")
	require.True(h, h.ReleaseManager(manager), "failed to release manager")
	manager = h.NewWalletManager()

	// Reload a fresh instance from the same durable store.
	reloaded, err := manager.Load(cfg)
	require.NoError(h, err, "failed to reload wallet")
	h.RegisterWallet(reloaded)
	require.NotSame(h, w, reloaded, "reload returned the torn-down instance")

	err = reloaded.Start(h.Context())
	require.NoError(h, err, "failed to start reloaded wallet")

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

// testManagerLoadMissing verifies that loading a wallet that was never created
// fails rather than silently returning an empty wallet.
func testManagerLoadMissing(h *bwtest.HarnessTest) {
	// Arrange a manager whose durable store has never contained the named
	// wallet from the standard test configuration.
	cfg, _ := h.TestWalletConfig()
	manager := h.NewWalletManager()

	// Act by asking the manager to load the never-created wallet.
	w, err := manager.Load(cfg)

	// Assert that the public missing-wallet contract is returned without a
	// partially assembled wallet.
	require.ErrorIs(h, err, wallet.ErrWalletNotFound,
		"load of never-created wallet should report wallet not found")
	require.Nil(h, w, "load of never-created wallet should return no wallet")
}

// testManagerCreateWatchOnly verifies that a watch-only wallet is created,
// starts, syncs like a spendable wallet, and stays watch-only across a reload
// from the durable store.
//
// The wallet is rootless: that is the one watch-only shape every backend can
// represent, and its keyspace arrives later as account-level xpub imports.
func testManagerCreateWatchOnly(h *bwtest.HarnessTest) {
	cfg, params := h.TestWalletConfig()
	params.Mode = wallet.ModeShell
	params.WatchOnly = true

	manager := h.NewWalletManager()
	w, err := manager.Create(cfg, params)
	require.NoError(h, err, "failed to create watch-only wallet")
	h.RegisterWallet(w)

	require.NoError(h, w.Start(h.Context()), "failed to start wallet")
	h.AssertWalletSynced(w)

	require.True(h, w.IsWatchOnly(), "created wallet is not watch-only")

	// A watch-only wallet tracks the chain like any other wallet.
	h.MineBlocks(1)

	// Keep both resources registered until shutdown succeeds, then reload from
	// the durable store with a fresh Manager.
	require.NoError(h, w.Stop(h.Context()), "failed to stop wallet")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")
	require.NoError(h, manager.Close(), "failed to close wallet manager")
	require.True(h, h.ReleaseManager(manager), "failed to release manager")

	manager = h.NewWalletManager()
	reloaded, err := manager.Load(cfg)
	require.NoError(h, err, "failed to reload watch-only wallet")
	h.RegisterWallet(reloaded)

	require.NoError(
		h, reloaded.Start(h.Context()), "failed to start reloaded wallet",
	)
	require.True(
		h, reloaded.IsWatchOnly(),
		"reloaded wallet lost its watch-only state",
	)
}
