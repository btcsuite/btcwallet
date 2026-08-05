//go:build itest

package itest

import (
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/stretchr/testify/require"
)

// testCreateWallet verifies a wallet can be created, started, and synced.
func testCreateWallet(h *bwtest.HarnessTest) {
	h.Helper()

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
	h.Helper()

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

// testManagerLoadMissing verifies that loading a wallet that was never created
// fails rather than silently returning an empty wallet.
func testManagerLoadMissing(h *bwtest.HarnessTest) {
	h.Helper()

	cfg, _ := h.TestWalletConfig()

	manager := h.NewWalletManager()
	_, err := manager.Load(cfg)
	require.Error(h, err, "load of never-created wallet should fail")
}
