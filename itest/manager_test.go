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

	// Mine a few blocks and require the wallet catches up.
	h.MineBlocks(5)
}
