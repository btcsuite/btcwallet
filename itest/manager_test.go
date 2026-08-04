//go:build itest

package itest

import (
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
