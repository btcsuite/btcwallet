//go:build itest

package itest

import (
	"context"
	"time"

	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// testCreateWallet verifies a wallet can be created, started, and synced.
func testCreateWallet(h *bwtest.HarnessTest) {
	h.Helper()

	// Create a wallet using the Manager API.
	cfg := wallet.Config{
		DB:                      h.WalletDB,
		Chain:                   h.ChainClient,
		ChainParams:             h.NetParams(),
		RecoveryWindow:          20,
		WalletSyncRetryInterval: 500 * time.Millisecond,
		Name:                    "testwallet",
		PubPassphrase:           []byte("public"),
	}

	manager := wallet.NewManager()
	params := wallet.CreateWalletParams{
		Mode:              wallet.ModeGenSeed,
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now().Add(-1 * time.Hour),
	}

	w, err := manager.Create(cfg, params)
	require.NoError(h, err, "failed to create wallet")

	err = w.Start(h.Context())
	require.NoError(h, err, "failed to start wallet")
	h.Cleanup(func() {
		// We use a background context here because h.Context() might be
		// cancelled already.
		require.NoError(h, w.Stop(context.Background()), "failed to stop wallet")
	})

	// Register the wallet so harness helpers can assert global invariants.
	h.RegisterWallet(w)

	// Mine a few blocks and require the wallet catches up.
	h.MineBlocks(5)
}
