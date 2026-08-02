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

	// Create a wallet using the Manager API. The Manager owns the database
	// selected by the -db flag; the wallet config carries no backend.
	cfg := wallet.Config{
		Chain:                   h.ChainClient,
		ChainParams:             h.NetParams(),
		RecoveryWindow:          20,
		WalletSyncRetryInterval: 500 * time.Millisecond,
		Name:                    "testwallet",
		PubPassphrase:           []byte("public"),
	}

	manager := h.NewWalletManager()
	params := wallet.CreateWalletParams{
		Mode:              wallet.ModeGenSeed,
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now().Add(-1 * time.Hour),
	}

	w, err := manager.Create(cfg, params)
	require.NoError(h, err, "failed to create wallet")

	// Register so harness-level assertions can see this wallet.
	h.RegisterWallet(w)

	// Temporary, until #1292 owns teardown through the registries: stop this
	// wallet directly. Registered after the Manager's Close and run first,
	// since testing.Cleanup is LIFO.
	h.Cleanup(func() {
		_ = w.Stop(context.Background())
	})

	err = w.Start(h.Context())
	require.NoError(h, err, "failed to start wallet")

	// Mine a few blocks and require the wallet catches up.
	h.MineBlocks(5)
}
