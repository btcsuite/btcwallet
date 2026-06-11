package bwtest

import (
	"context"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

const (
	// defaultPubPass is the standard public passphrase used by test wallets.
	defaultPubPass = "public"

	// defaultPrivPass is the standard private passphrase used by test wallets.
	defaultPrivPass = "private"

	// defaultWalletRecoveryWindow keeps enough look-ahead addresses for test
	// cases that derive multiple addresses while scanning historical blocks.
	defaultWalletRecoveryWindow = 20

	// defaultWalletSyncRetryInterval controls how often wallet sync retries
	// when the chain backend is temporarily unavailable during startup.
	defaultWalletSyncRetryInterval = 500 * time.Millisecond
)

// CreateEmptyWallet creates, starts, and registers a new wallet instance.
//
// This is intended for non-manager integration tests that want a ready-to-use
// wallet without repeating boilerplate.
func (h *HarnessTest) CreateEmptyWallet() *wallet.Wallet {
	h.Helper()

	name := "itest-" + strings.ReplaceAll(h.Name(), "/", "_")

	cfg := wallet.Config{
		// Use the subtest-scoped DB path and chain client prepared by the
		// harness.
		DB: wallet.DBConfig{
			KVDB: wallet.KVDBConfig{
				DBPath: h.WalletDBPath,
			},
		},
		Chain: h.ChainClient,

		// Keep network and startup behavior deterministic across tests.
		ChainParams:             h.NetParams(),
		RecoveryWindow:          defaultWalletRecoveryWindow,
		WalletSyncRetryInterval: defaultWalletSyncRetryInterval,

		// Use a unique wallet name per test to avoid collisions in logs.
		Name:          name,
		PubPassphrase: []byte(defaultPubPass),
	}

	params := wallet.CreateWalletParams{
		// Generate a fresh seed for each test wallet.
		Mode:              wallet.ModeGenSeed,
		PubPassphrase:     []byte(defaultPubPass),
		PrivatePassphrase: []byte(defaultPrivPass),

		// Use an old birthday to ensure the wallet can discover historical
		// blocks when used in tests that pre-mine chain state.
		Birthday: time.Now().Add(-1 * time.Hour),
	}

	manager := wallet.NewManager()
	w, err := manager.Create(cfg, params)
	require.NoError(h, err, "failed to create wallet")

	err = w.Start(h.Context())
	require.NoError(h, err, "failed to start wallet")

	h.Cleanup(func() {
		// We use a background context here because the test context might be
		// canceled by the time cleanup runs.
		_ = w.Stop(context.Background())
	})

	// Register the wallet so harness helpers can assert global invariants.
	h.RegisterWallet(w)

	return w
}

// CreateFundedWallet creates an empty wallet and funds it with 10 BTC.
//
// This is intended for future integration tests that need spendable funds.
func (h *HarnessTest) CreateFundedWallet() *wallet.Wallet {
	h.Helper()

	w := h.CreateEmptyWallet()

	err := w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(defaultPrivPass),
	})
	require.NoError(h, err, "failed to unlock wallet")

	addr, err := w.NewAddress(
		h.Context(), waddrmgr.DefaultAccountName,
		waddrmgr.WitnessPubKey, false,
	)
	require.NoError(h, err, "failed to create address")

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create pkscript")

	const tenBTC = 10 * btcutil.SatoshiPerBitcoin

	output := &wire.TxOut{Value: int64(tenBTC), PkScript: pkScript}

	// Use a minimal fee rate for regtest.
	h.SendOutput(output, btcutil.Amount(1))

	// Confirm and wait for sync.
	h.MineBlocks(1)
	h.AssertWalletSynced(w)

	return w
}

func init() {
	// Use fast scrypt options for tests to avoid CPU exhaustion and
	// timeouts, especially when running with -race.
	waddrmgr.DefaultScryptOptions = waddrmgr.FastScryptOptions
}
