package bwtest

import (
	"bytes"
	"strings"
	"time"

	"github.com/btcsuite/btcd/address/v2"
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

// WalletFixture describes the wallet a test case needs. It is the harness's
// parameterized wallet preparation request, so a component test states what it
// needs instead of growing its own creation, funding and lock policy.
type WalletFixture struct {
	// AddrType is the address type funding is paid to. A test that selects
	// those coins derives its key scope from this same value with
	// KeyScope(), so the funded scope has a single authority.
	//
	// This field is always honored, including its zero value, PubKeyHash.
	AddrType waddrmgr.AddressType

	// Amounts funds the wallet with one confirmed output per amount, in
	// the order given. Funding needs a running wallet, so it cannot be
	// combined with Unstarted.
	Amounts []btcutil.Amount

	// Unlocked unlocks the wallet once it has started.
	Unlocked bool

	// Unstarted returns the wallet before Start, for cases asserting
	// behavior that is only observable while the wallet is not running.
	Unstarted bool
}

// NewWallet creates, registers and prepares a wallet as the fixture describes,
// returning it alongside the outpoints funding produced, in the order of the
// requested amounts.
//
// The returned wallet is not a synchronization boundary. Funding and address
// derivation are both wallet side effects, so a case that reads wallet state
// must cross AssertWalletSynced after its own last funding or derivation, not
// merely after this call.
func (h *HarnessTest) NewWallet(fixture WalletFixture) (*wallet.Wallet,
	[]wire.OutPoint) {

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

	if fixture.Unstarted {
		require.Empty(
			h, fixture.Amounts, "funding needs a started wallet",
		)

		return w, nil
	}

	err = w.Start(h.Context())
	require.NoError(h, err, "failed to start wallet")

	if fixture.Unlocked {
		h.UnlockWallet(w)
	}

	if len(fixture.Amounts) == 0 {
		return w, nil
	}

	return w, h.FundWalletOfType(w, fixture.AddrType, fixture.Amounts...)
}

// CreateEmptyWallet creates, starts, and registers a new wallet instance.
//
// This is intended for non-manager integration tests that want a ready-to-use
// wallet without repeating boilerplate.
func (h *HarnessTest) CreateEmptyWallet() *wallet.Wallet {
	h.Helper()

	w, _ := h.NewWallet(WalletFixture{AddrType: fundingAddrType})

	return w
}

// CreateFundedWallet creates an empty wallet and funds it with 10 BTC.
func (h *HarnessTest) CreateFundedWallet() *wallet.Wallet {
	h.Helper()

	const tenBTC = 10 * btcutil.SatoshiPerBitcoin

	w, _ := h.NewWallet(WalletFixture{
		AddrType: fundingAddrType,
		Amounts:  []btcutil.Amount{tenBTC},
	})

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

// NewWalletAddress derives a fresh receive address of the default funding
// type from the wallet's default account, ensuring the account exists first.
func (h *HarnessTest) NewWalletAddress(w *wallet.Wallet) address.Address {
	h.Helper()

	return h.NewWalletAddressOfType(w, fundingAddrType)
}

// NewWalletAddressOfType derives a fresh receive address of the requested type
// from the wallet's default account in that type's key scope, ensuring the
// account exists first.
//
// Callers that need funds under a particular key scope must use this instead
// of NewWalletAddress, because the wallet resolves accounts per scope: coins
// held under one scope's default account are invisible to selection from
// another.
func (h *HarnessTest) NewWalletAddressOfType(w *wallet.Wallet,
	addrType waddrmgr.AddressType) address.Address {

	h.Helper()

	scope, err := addrType.KeyScope()
	require.NoError(h, err, "failed to resolve address scope")

	h.ensureAccount(w, scope, waddrmgr.DefaultAccountName)

	addr, err := w.NewAddress(
		h.Context(), waddrmgr.DefaultAccountName, addrType, false,
	)
	require.NoError(h, err, "failed to create address")

	return addr
}

// FundWallet pays one output per amount to fresh wallet addresses of the
// default funding type in a single miner transaction, confirms it, and returns
// the wallet outpoints in the order of the amounts argument.
func (h *HarnessTest) FundWallet(w *wallet.Wallet,
	amounts ...btcutil.Amount) []wire.OutPoint {

	h.Helper()

	return h.FundWalletOfType(w, fundingAddrType, amounts...)
}

// FundWalletOfType pays one output per amount to fresh wallet addresses of the
// requested address type in a single miner transaction, confirms it, and
// returns the wallet outpoints in the order of the amounts argument.
func (h *HarnessTest) FundWalletOfType(w *wallet.Wallet,
	addrType waddrmgr.AddressType,
	amounts ...btcutil.Amount) []wire.OutPoint {

	h.Helper()

	outputs := make([]*wire.TxOut, 0, len(amounts))
	for _, amount := range amounts {
		addr := h.NewWalletAddressOfType(w, addrType)

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

	return outpoints
}

// ForeignOutpoint returns an outpoint of the funding transaction that the
// funded wallet does not own.
//
// Funding pays one output per requested amount plus a single change output
// back to the miner, so exactly one index in the transaction's first
// len(funded)+1 outputs is not wallet-owned. That output exists on chain and is
// spendable by the miner, which makes it the fixture's foreign coin.
func (h *HarnessTest) ForeignOutpoint(funded []wire.OutPoint) wire.OutPoint {
	h.Helper()

	require.NotEmpty(h, funded, "no funded outpoints")

	owned := make(map[uint32]struct{}, len(funded))
	for _, outpoint := range funded {
		owned[outpoint.Index] = struct{}{}
	}

	for index := range len(funded) + 1 {
		//nolint:gosec // A funding transaction's output count is small.
		outputIndex := uint32(index)

		if _, ok := owned[outputIndex]; ok {
			continue
		}

		return wire.OutPoint{
			Hash:  funded[0].Hash,
			Index: outputIndex,
		}
	}

	h.Fatalf("funding transaction has no foreign output")

	return wire.OutPoint{}
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
