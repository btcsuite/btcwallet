package bwtest

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

const (
	// defaultPubPass is the standard public passphrase used by test wallets.
	defaultPubPass = "public"

	// TestWalletPrivatePassphrase is the standard private passphrase used by
	// harness test wallets.
	TestWalletPrivatePassphrase = "private"

	// defaultWalletRecoveryWindow keeps enough look-ahead addresses for test
	// cases that derive multiple addresses while scanning historical blocks.
	defaultWalletRecoveryWindow = 20

	// defaultWalletSyncRetryInterval controls how often wallet sync retries
	// when the chain backend is temporarily unavailable during startup.
	defaultWalletSyncRetryInterval = 500 * time.Millisecond
)

// TestWalletConfig builds the standard Config and CreateWalletParams for a
// harness test wallet. Callers retain ownership of the wallet lifecycle.
func (h *HarnessTest) TestWalletConfig() (wallet.Config,
	wallet.CreateWalletParams) {

	h.Helper()

	cfg := wallet.Config{
		// The chain client is prepared by the harness; the database is
		// owned by the Manager built below.
		Chain:       h.ChainClient,
		ChainParams: h.NetParams(),

		// Keep network and startup behavior deterministic across tests.
		RecoveryWindow:          defaultWalletRecoveryWindow,
		WalletSyncRetryInterval: defaultWalletSyncRetryInterval,

		// Use a unique wallet name per test to avoid collisions in logs.
		Name:          "itest-" + strings.ReplaceAll(h.Name(), "/", "_"),
		PubPassphrase: []byte(defaultPubPass),
	}

	params := wallet.CreateWalletParams{
		// Generate a fresh seed for each test wallet.
		Mode:              wallet.ModeGenSeed,
		PubPassphrase:     []byte(defaultPubPass),
		PrivatePassphrase: []byte(TestWalletPrivatePassphrase),

		// Use an old birthday to ensure the wallet can discover historical
		// blocks when used in tests that pre-mine chain state.
		Birthday: time.Now().Add(-1 * time.Hour),
	}

	return cfg, params
}

// CreateEmptyWallet creates, starts, and registers a new wallet instance.
//
// This is intended for non-manager integration tests that want a ready-to-use
// wallet without repeating boilerplate.
func (h *HarnessTest) CreateEmptyWallet() *wallet.Wallet {
	h.Helper()

	cfg, params := h.TestWalletConfig()

	manager := h.NewWalletManager()
	w, err := manager.Create(cfg, params)
	require.NoError(h, err, "failed to create wallet")

	// Register before Start, and only register: teardownWallets is the single
	// cleanup owner. Registering after Start would leave a wallet whose Start
	// failed unregistered, and a second direct Stop callback here would stop a
	// successful one twice, out of order with the Manager close.
	h.RegisterWallet(w)

	err = w.Start(h.Context())
	require.NoError(h, err, "failed to start wallet")

	return w
}

// CreateFundedWallet creates an empty wallet and funds it with 10 BTC.
func (h *HarnessTest) CreateFundedWallet() *wallet.Wallet {
	h.Helper()

	w := h.CreateEmptyWallet()

	const tenBTC = 10 * btcutil.SatoshiPerBitcoin

	h.FundWallet(w, tenBTC)

	return w
}

// fundingAddrType is the address type FundWallet derives funding addresses
// for.
const fundingAddrType = waddrmgr.WitnessPubKey

// UnlockWallet unlocks the wallet if it is locked, and is a no-op otherwise.
//
// Unlock is not idempotent: the key vault rejects a second Unlock on an
// already-unlocked wallet, so the state is checked first. Timeout -1 disables
// auto-lock, keeping assertions from racing against a re-lock.
func (h *HarnessTest) UnlockWallet(w *wallet.Wallet) {
	h.Helper()

	info, err := w.Info(h.Context())
	require.NoError(h, err, "failed to query wallet info")

	if !info.Locked {
		return
	}

	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(TestWalletPrivatePassphrase),
		Timeout:    -1,
	})
	require.NoError(h, err, "failed to unlock wallet")
}

// NewWalletAddress derives a fresh receive address from the wallet's default
// account, ensuring the account exists first.
func (h *HarnessTest) NewWalletAddress(w *wallet.Wallet) address.Address {
	h.Helper()

	scope, err := fundingAddrType.KeyScope()
	require.NoError(h, err, "failed to resolve funding address scope")

	h.ensureAccount(w, scope, waddrmgr.DefaultAccountName)

	addr, err := w.NewAddress(
		h.Context(), waddrmgr.DefaultAccountName, fundingAddrType, false,
	)
	require.NoError(h, err, "failed to create address")

	return addr
}

// FundWallet pays one output per amount to fresh wallet addresses in a single
// miner transaction, confirms it, and returns the wallet outpoints in the
// order of the amounts argument.
func (h *HarnessTest) FundWallet(w *wallet.Wallet,
	amounts ...btcutil.Amount) []wire.OutPoint {

	h.Helper()

	outputs := make([]*wire.TxOut, 0, len(amounts))
	for _, amount := range amounts {
		addr := h.NewWalletAddress(w)

		pkScript, err := txscript.PayToAddrScript(addr)
		require.NoError(h, err, "failed to create pkscript")

		outputs = append(outputs, &wire.TxOut{
			Value:    int64(amount),
			PkScript: pkScript,
		})
	}

	txid := h.SendOutputs(outputs, MinerFeeRate)

	// Confirm the funding transaction and wait for every registered wallet
	// to sync the mined block.
	tx := h.AssertTxInMempool(*txid)
	h.MineBlockWithTx(tx)

	// Locate each wallet output's index within the funding transaction so
	// callers receive ready-to-use outpoints in the order of the amounts
	// argument.
	outpoints := make([]wire.OutPoint, 0, len(outputs))
	for _, output := range outputs {
		index := -1

		for i, txOut := range tx.TxOut {
			if bytes.Equal(txOut.PkScript, output.PkScript) {
				index = i

				break
			}
		}

		require.NotEqual(h, -1, index,
			"funding output missing from transaction")

		outpoints = append(outpoints, wire.OutPoint{
			Hash:  *txid,
			Index: uint32(index), //nolint:gosec
		})
	}

	h.AssertUtxosVisible(w, outpoints...)

	return outpoints
}

// AssertUtxosVisible polls until the wallet's GetUtxo query can observe every
// outpoint.
func (h *HarnessTest) AssertUtxosVisible(w *wallet.Wallet,
	outpoints ...wire.OutPoint) {

	h.Helper()

	err := wait.NoError(func() error {
		for _, op := range outpoints {
			_, err := w.GetUtxo(h.Context(), op)
			if err != nil {
				return fmt.Errorf("utxo %v not visible: %w",
					op, err)
			}
		}

		return nil
	}, defaultTestTimeout)
	require.NoError(h, err, "timeout waiting for utxos to be visible")
}

// AssertUtxoConfirmations polls until the wallet reports the outpoint with the
// expected number of confirmations.
func (h *HarnessTest) AssertUtxoConfirmations(w *wallet.Wallet,
	op wire.OutPoint, confs int32) {

	h.Helper()

	err := wait.NoError(func() error {
		utxo, err := w.GetUtxo(h.Context(), op)
		if err != nil {
			return fmt.Errorf("utxo %v not visible: %w", op, err)
		}

		if utxo.Confirmations != confs {
			return fmt.Errorf("utxo %v: want %d confirmations, "+
				"got %d", op, confs, utxo.Confirmations)
		}

		return nil
	}, defaultTestTimeout)
	require.NoError(h, err, "timeout waiting for utxo confirmations")
}

// ensureAccount makes sure an account exists for the given key scope, creating
// it when the backend did not seed it at wallet creation.
func (h *HarnessTest) ensureAccount(w *wallet.Wallet,
	scope waddrmgr.KeyScope, name string) {

	h.Helper()

	accounts, err := w.ListAccountsByScope(h.Context(), scope)
	require.NoError(h, err, "failed to list accounts for scope %v", scope)

	for i := range accounts {
		if accounts[i].AccountName == name {
			return
		}
	}

	info, err := w.Info(h.Context())
	require.NoError(h, err, "failed to query wallet info")

	if info.Locked {
		h.UnlockWallet(w)
		defer func() {
			require.NoError(h, w.Lock(h.Context()),
				"failed to restore locked wallet state")
		}()
	}

	_, err = w.NewAccount(h.Context(), scope, name)
	require.NoError(h, err, "failed to create account %q", name)
}

// init uses fast scrypt options for tests to avoid CPU exhaustion and timeouts,
// especially when running with -race.
func init() {
	waddrmgr.DefaultScryptOptions = waddrmgr.FastScryptOptions
}
