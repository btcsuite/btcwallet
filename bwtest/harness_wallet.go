package bwtest

import (
	"bytes"
	"strings"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/psbt/v2"
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

	// WatchOnly creates a rootless watch-only shell wallet when
	// InitialAccounts is empty.
	WatchOnly bool

	// InitialAccounts seeds a watch-only shell wallet with the provided
	// accounts. A nil or empty slice creates no accounts, and a non-empty
	// slice implies WatchOnly.
	InitialAccounts []wallet.WatchOnlyAccount

	// Unlocked unlocks the wallet once it has started.
	Unlocked bool

	// Unstarted returns the wallet before Start, for cases asserting
	// behavior that is only observable while the wallet is not running.
	Unstarted bool
}

// NewWallet creates, registers and prepares a wallet as the fixture describes,
// returning it alongside what its funding transaction created.
//
// A funded fixture returns after the funding block's synchronization check,
// which mining performs for every registered wallet, so its coins are readable
// without a further check; deriving an address afterwards does not need one
// either. An unfunded fixture mines nothing and so provides no such boundary.
func (h *HarnessTest) NewWallet(fixture WalletFixture) (*wallet.Wallet,
	WalletFunding) {

	h.Helper()

	cfg, params := h.TestWalletConfig()
	if fixture.WatchOnly || len(fixture.InitialAccounts) != 0 {
		params.Mode, params.WatchOnly = wallet.ModeShell, true
		params.InitialAccounts = fixture.InitialAccounts
	}

	manager := h.NewWalletManager()
	w, err := manager.Create(cfg, params)
	require.NoError(h, err, "failed to create wallet")

	// Register before Start, and only register: teardownWallets is the single
	// cleanup owner. Registering after Start would leave a wallet whose Start
	// failed unregistered, and a second direct Stop callback here would stop a
	// successful one twice, out of order with the Manager close.
	h.registerWallet(manager, w, &cfg)

	if fixture.Unstarted {
		require.Empty(
			h, fixture.Amounts, "funding needs a started wallet",
		)

		return w, WalletFunding{}
	}

	err = w.Start(h.Context())
	require.NoError(h, err, "failed to start wallet")

	if fixture.Unlocked {
		h.UnlockWallet(w)
	}

	if len(fixture.Amounts) == 0 {
		return w, WalletFunding{}
	}

	return w, h.FundWalletOfType(w, fixture.AddrType, fixture.Amounts...)
}

// ReloadWallet consumes current after shutting it down and returns a fresh
// registered, started, and locked replacement loaded from the same store.
// The current wallet must be the Manager's only registered wallet because
// reload closes and replaces that Manager. Callers must use the returned wallet
// for any later reload.
func (h *HarnessTest) ReloadWallet(current *wallet.Wallet) *wallet.Wallet {
	h.Helper()

	require.NotNil(h, current, "cannot reload nil wallet")

	h.mu.Lock()

	var (
		manager           *wallet.Manager
		reloadConfig      *wallet.Config
		registeredWallets int
	)

	for candidate, registration := range h.wallets {
		config, ok := registration[current]
		if !ok {
			continue
		}

		manager = candidate
		reloadConfig = config
		registeredWallets = len(registration)

		break
	}

	h.mu.Unlock()

	require.NotNil(h, manager, "wallet is not registered with this harness")
	require.NotNil(h, reloadConfig, "wallet is not reloadable")
	require.Equal(
		h, 1, registeredWallets,
		"wallet manager has sibling registered wallets",
	)

	cfg := *reloadConfig

	ctx := h.Context()
	require.NoError(
		h, current.Stop(ctx), "failed to stop wallet before reload",
	)
	require.True(
		h, h.DeregisterWallet(current), "failed to deregister wallet",
	)
	require.NoError(
		h, manager.Close(), "failed to close wallet manager",
	)
	require.True(
		h, h.ReleaseManager(manager), "failed to release wallet manager",
	)

	manager = h.NewWalletManager()
	w, err := manager.Load(cfg)
	require.NoError(h, err, "failed to reload wallet")
	require.NotSame(h, current, w, "reload returned the original wallet")

	h.registerWallet(manager, w, &cfg)
	require.NoError(h, w.Start(ctx), "failed to start reloaded wallet")

	return w
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

// WalletFunding describes the funding transaction and the outputs it created.
//
// A fixture that funded nothing returns the zero value, whose Tx and Block are
// nil. Only a caller that asked for amounts may dereference them.
type WalletFunding struct {
	// Tx is the funding transaction itself. It is reported because the
	// wallet did not author it: its inputs are the miner's, so a case
	// asserting how the wallet reports a received transaction cannot
	// reconstruct it from what it asked for.
	//
	// Nil when the fixture funded nothing.
	Tx *wire.MsgTx

	// Block is the block that confirmed Tx, and BlockHeight is that
	// block's height. Together they are the chain facts a case needs to
	// state where the funding transaction landed.
	//
	// Block is nil, and BlockHeight zero, when the fixture funded nothing.
	Block       *wire.MsgBlock
	BlockHeight int32

	// WalletOutpoints are the outputs the funded wallet owns, in the order
	// of the amounts that were requested.
	WalletOutpoints []wire.OutPoint

	// ForeignOutpoints are the transaction's remaining outputs, which
	// exist on chain but belong to the miner rather than to the funded
	// wallet. Funding pays its own change here, so there is normally one.
	ForeignOutpoints []wire.OutPoint
}

// FundWallet pays one output per amount to fresh wallet addresses of the
// default funding type in a single miner transaction, confirms it, and returns
// what the funding transaction created.
func (h *HarnessTest) FundWallet(w *wallet.Wallet,
	amounts ...btcutil.Amount) WalletFunding {

	h.Helper()

	return h.FundWalletOfType(w, fundingAddrType, amounts...)
}

// FundWalletOfType pays one output per amount to fresh wallet addresses of the
// requested address type in a single miner transaction, confirms it, and
// returns what the funding transaction created.
//
// The transaction's outputs are classified here, where the transaction itself
// is known, so no caller has to infer which of them the wallet owns.
func (h *HarnessTest) FundWalletOfType(w *wallet.Wallet,
	addrType waddrmgr.AddressType,
	amounts ...btcutil.Amount) WalletFunding {

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
	block := h.MineBlockWithTx(tx)

	// The block just mined is the tip, so its height is the chain's.
	_, blockHeight := h.GetBestBlock()

	// Locate each wallet output's index within the funding transaction so
	// callers receive ready-to-use outpoints in the order of the amounts
	// argument.
	owned := make(map[uint32]struct{}, len(outputs))
	funding := WalletFunding{
		Tx:              tx,
		Block:           block,
		BlockHeight:     blockHeight,
		WalletOutpoints: make([]wire.OutPoint, 0, len(outputs)),
	}

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

		outputIndex := uint32(index) //nolint:gosec
		owned[outputIndex] = struct{}{}

		funding.WalletOutpoints = append(
			funding.WalletOutpoints, wire.OutPoint{
				Hash:  *txid,
				Index: outputIndex,
			},
		)
	}

	// Whatever the transaction pays elsewhere belongs to the miner, and is
	// reported as it stands rather than assumed to exist.
	for i := range tx.TxOut {
		outputIndex := uint32(i) //nolint:gosec
		if _, ok := owned[outputIndex]; ok {
			continue
		}

		funding.ForeignOutpoints = append(
			funding.ForeignOutpoints, wire.OutPoint{
				Hash:  *txid,
				Index: outputIndex,
			},
		)
	}

	return funding
}

// DustThreshold returns the smallest amount an output paying pkScript may
// carry without the network refusing it as dust. Any amount below it is dust.
//
// The limit depends on the output's script, so it is taken from the relay
// policy rather than written down as a number that would silently drift from
// it. The policy states dust as the comparison
// value*1000/threshold < relayFee, which first holds at the threshold itself,
// so the threshold is the smallest amount that clears it at the default relay
// fee. A case paying a different relay fee cannot use this.
//
// The script is assumed spendable, which is what paying a wallet address
// produces. An unspendable script is dust at any amount and has no threshold.
func (h *HarnessTest) DustThreshold(pkScript []byte) btcutil.Amount {
	h.Helper()

	output := wire.TxOut{PkScript: pkScript}

	return btcutil.Amount(mempool.GetDustThreshold(&output))
}

// spendTxVersion is the transaction version SignSpend authors. Version 2 is
// the standard version both supported chain backends relay.
const spendTxVersion = 2

// SpendFixture describes a transaction the harness authors from a wallet's own
// coins and signs with the wallet's keys.
type SpendFixture struct {
	// Inputs are the wallet-owned coins the transaction spends.
	Inputs []wire.OutPoint

	// Outputs are the transaction's outputs. No change output is added, so
	// whatever the outputs leave behind is paid as the fee.
	Outputs []wire.TxOut
}

// SignSpend returns a signed transaction spending the wallet coins the fixture
// names.
//
// The inputs and outputs are used exactly as given, in the order given. Unlike
// CreateTransaction this applies no coin selection, no change and no output
// policy, which is what lets a case author a transaction the network is
// required to reject. The wallet must be started, synced and unlocked.
func (h *HarnessTest) SignSpend(w *wallet.Wallet,
	fixture SpendFixture) *wire.MsgTx {

	h.Helper()

	inputs := make([]*wire.OutPoint, len(fixture.Inputs))
	sequences := make([]uint32, len(fixture.Inputs))

	for i := range fixture.Inputs {
		inputs[i] = &fixture.Inputs[i]

		// Every input is final. No case needs replaceability, and a
		// transaction that signals it changes how a backend judges a
		// conflict with an unconfirmed transaction. A case that wants
		// replacement should add the knob then, rather than inherit it
		// from a zero value.
		sequences[i] = wire.MaxTxInSequenceNum
	}

	// psbt.New keeps the output pointers it is given, so the returned
	// transaction would otherwise share its outputs with the caller's
	// fixture, and mutating the fixture would alter an already-signed
	// transaction. Hand it copies instead.
	outputs := make([]*wire.TxOut, len(fixture.Outputs))
	for i := range fixture.Outputs {
		output := fixture.Outputs[i]
		outputs[i] = &output
	}

	packet, err := psbt.New(inputs, outputs, spendTxVersion, 0, sequences)
	require.NoError(h, err, "failed to create psbt")

	// The wallet supplies each input's previous output and derivation path
	// from its own records, so the fixture only has to name the outpoints.
	// Unknown inputs are an error rather than a silently unsigned input,
	// which would surface later as an opaque finalization failure.
	packet, err = w.DecorateInputs(h.Context(), packet, false)
	require.NoError(h, err, "failed to decorate psbt inputs")

	// FinalizePsbt signs the wallet-owned inputs on its way to building the
	// final witnesses, so a separate SignPsbt call would add nothing.
	err = w.FinalizePsbt(h.Context(), packet)
	require.NoError(h, err, "failed to finalize psbt")

	tx, err := psbt.Extract(packet)
	require.NoError(h, err, "failed to extract signed transaction")

	return tx
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
