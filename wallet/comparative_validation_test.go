package wallet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	dbsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	storesqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

type validationFixture struct {
	t          *testing.T
	backend    string
	dir        string
	dbPath     string
	walletName string
	params     *chaincfg.Params
	recovery   uint32
	conn       *sql.DB
	loader     *Loader
	wallet     *Wallet
}

type validationLifecycleDigest struct {
	// WrongPrivatePassphrase records the private passphrase error.
	WrongPrivatePassphrase string `json:"wrong_private_passphrase"`
	// WrongPublicPassphrase records the public passphrase error.
	WrongPublicPassphrase string `json:"wrong_public_passphrase"`
	// ExtendedKeyRestart records whether extended keys survive restart.
	ExtendedKeyRestart bool `json:"extended_key_restart"`
	// WatchOnlyRestart records whether watch-only state survives restart.
	WatchOnlyRestart bool `json:"watch_only_restart"`
	// WatchOnlyUnlock records the watch-only unlock result.
	WatchOnlyUnlock string `json:"watch_only_unlock"`
	// BirthdayUnix records the wallet birthday as a Unix timestamp.
	BirthdayUnix int64 `json:"birthday_unix"`
	// Scopes records the wallet's key scopes.
	Scopes []string `json:"scopes"`
	// Accounts records the wallet's accounts.
	Accounts []string `json:"accounts"`
	// Addresses records the wallet's addresses.
	Addresses []string `json:"addresses"`
	// AddressTypes records the wallet's address types.
	AddressTypes []string `json:"address_types"`
}

type validationTxCheckpoint struct {
	// Name identifies the checkpoint.
	Name string `json:"name"`
	// Balance records the wallet balance at the checkpoint.
	Balance int64 `json:"balance"`
	// Unspent records the unspent outputs at the checkpoint.
	Unspent []string `json:"unspent"`
	// Leases records the leased output count at the checkpoint.
	Leases int `json:"leases"`
	// TxHeight records the transaction height at the checkpoint.
	TxHeight int32 `json:"tx_height"`
	// Label records the transaction label at the checkpoint.
	Label string `json:"label"`
	// AddressUsed records whether the address is marked used.
	AddressUsed bool `json:"address_used"`
	// SyncedHeight records the wallet sync height at the checkpoint.
	SyncedHeight int32 `json:"synced_height"`
}

type validationFundingDigest struct {
	// DryRunStatus records the dry-run funding result.
	DryRunStatus string `json:"dry_run_status"`
	// DryRunInputs records the number of dry-run inputs.
	DryRunInputs int `json:"dry_run_inputs"`
	// DryRunSigned records whether the dry-run transaction was signed.
	DryRunSigned bool `json:"dry_run_signed"`
	// ExplicitP2WPKHStatus records the explicit P2WPKH funding result.
	ExplicitP2WPKHStatus string `json:"explicit_p2wpkh_status"`
	// ExplicitP2WPKHValid records whether the P2WPKH spend is valid.
	ExplicitP2WPKHValid bool `json:"explicit_p2wpkh_valid"`
	// ExplicitP2TRStatus records the explicit P2TR funding result.
	ExplicitP2TRStatus string `json:"explicit_p2tr_status"`
	// ExplicitP2TRValid records whether the P2TR spend is valid.
	ExplicitP2TRValid bool `json:"explicit_p2tr_valid"`
	// ImportedSigningStatus records the imported-key signing result.
	ImportedSigningStatus string `json:"imported_signing_status"`
	// ImportedSigningValid records whether the imported-key spend is valid.
	ImportedSigningValid bool `json:"imported_signing_valid"`
	// FundPsbtStatus records the PSBT funding result.
	FundPsbtStatus string `json:"fund_psbt_status"`
	// DecorateInputsStatus records the PSBT input decoration result.
	DecorateInputsStatus string `json:"decorate_inputs_status"`
	// FinalizePsbtStatus records the PSBT finalization result.
	FinalizePsbtStatus string `json:"finalize_psbt_status"`
	// PsbtValid records whether the finalized PSBT is valid.
	PsbtValid bool `json:"psbt_valid"`
	// PsbtChangeType records the PSBT change output type.
	PsbtChangeType string `json:"psbt_change_type"`
	// CallerInputMetadata records whether caller input metadata is retained.
	CallerInputMetadata bool `json:"caller_input_metadata"`
	// CallerOutputMetadata records whether caller output metadata is retained.
	CallerOutputMetadata bool `json:"caller_output_metadata"`
	// BIP69Outputs records whether outputs follow BIP 69 ordering.
	BIP69Outputs bool `json:"bip69_outputs"`
}

type validationSemanticDigest struct {
	// Lifecycle records lifecycle validation results.
	Lifecycle validationLifecycleDigest `json:"lifecycle"`
	// Transaction records transaction checkpoints.
	Transaction []validationTxCheckpoint `json:"transaction"`
	// Funding records funding validation results.
	Funding validationFundingDigest `json:"funding"`
}

type validationResult struct {
	// Semantic records backend-independent validation results.
	Semantic validationSemanticDigest `json:"semantic"`
	// RuntimeKVSidecar records whether a runtime KV sidecar exists.
	RuntimeKVSidecar bool `json:"runtime_kv_sidecar"`
}

type validationBTCDDigest struct {
	// RecoveryBalance records the recovered wallet balance.
	RecoveryBalance int64 `json:"recovery_balance"`
	// RecoveryBeyondLookahead records recovery beyond the lookahead window.
	RecoveryBeyondLookahead bool `json:"recovery_beyond_lookahead"`
	// RestartBalance records the wallet balance after restart.
	RestartBalance int64 `json:"restart_balance"`
	// AdditionalBalance records the balance after additional funding.
	AdditionalBalance int64 `json:"additional_balance"`
	// SpendCreated records whether the spend was created.
	SpendCreated bool `json:"spend_created"`
	// SpendConfirmed records whether the spend was confirmed.
	SpendConfirmed bool `json:"spend_confirmed"`
	// ReorgUnconfirmed records whether the reorg unconfirmed the spend.
	ReorgUnconfirmed bool `json:"reorg_unconfirmed"`
	// ReplacementConfirmed records whether the replacement was confirmed.
	ReplacementConfirmed bool `json:"replacement_confirmed"`
}

// TestComparativeValidationGates1To4 records equivalent KV and Store-backed
// SQLite behavior at compact Gate 1-4 checkpoints.
func TestComparativeValidationGates1To4(t *testing.T) {
	seed := bytes.Repeat([]byte{0x2a}, hdkeychain.RecommendedSeedLen)
	results := make(map[string]validationResult)

	for _, backend := range []string{"kv", "sqlite"} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			results[backend] = runValidationScenario(t, backend, seed)
		})
	}

	require.Equal(t, results["kv"].Semantic, results["sqlite"].Semantic)
	require.True(t, results["kv"].RuntimeKVSidecar)
	require.False(t, results["sqlite"].RuntimeKVSidecar)
}

// TestComparativeValidationRealBTCD exercises recovery and a reorg across
// restart against one real btcd regtest fixture.
func TestComparativeValidationRealBTCD(t *testing.T) {
	if os.Getenv("BTCWALLET_REAL_BTCD") != "1" {
		t.Skip("set BTCWALLET_REAL_BTCD=1 to run the real btcd fixture")
	}

	params := &chaincfg.RegressionNetParams
	miner, err := rpctest.New(params, nil, nil, "")
	require.NoError(t, err)
	require.NoError(t, miner.SetUp(true, 8))
	t.Cleanup(func() {
		require.NoError(t, miner.TearDown())
	})

	results := make(map[string]validationBTCDDigest)
	for index, backend := range []string{"kv", "sqlite"} {
		backend := backend
		index := index
		t.Run(backend, func(t *testing.T) {
			seed := bytes.Repeat(
				[]byte{byte(0x31 + index)},
				hdkeychain.RecommendedSeedLen,
			)
			results[backend] = runValidationBTCDScenario(
				t, miner, backend, seed,
			)
		})
	}

	require.Equal(t, results["kv"], results["sqlite"])
	require.True(t, results["kv"].RecoveryBeyondLookahead)
}

// runValidationBTCDScenario runs one backend through real recovery, restart,
// spend, and reorg transitions.
func runValidationBTCDScenario(t *testing.T, miner *rpctest.Harness,
	backend string, seed []byte) validationBTCDDigest {

	t.Helper()

	params := &chaincfg.RegressionNetParams
	recoveryAddresses := make([]address.Address, 0, 2)
	for _, index := range []uint32{0, 1, 2} {
		recoveryAddresses = append(recoveryAddresses,
			validationDerivedAddress(t, seed, params, index))
	}

	outputs := make([]*wire.TxOut, 0, len(recoveryAddresses))
	for _, addr := range recoveryAddresses {
		script, err := txscript.PayToAddrScript(addr)
		require.NoError(t, err)
		outputs = append(outputs, wire.NewTxOut(100_000, script))
	}
	// Recovering beyond the initial lookahead requires a later block. A new
	// horizon cannot discover another address in a block already filtered.
	_, err := miner.SendOutputs(outputs[:2], 1_000)
	require.NoError(t, err)
	_, err = miner.Client.Generate(1)
	require.NoError(t, err)
	_, err = miner.SendOutputs(outputs[2:], 1_000)
	require.NoError(t, err)
	_, err = miner.Client.Generate(1)
	require.NoError(t, err)

	fixture := newValidationFixtureForParams(
		t, backend, "real-btcd", params, 2,
		func(loader *Loader) (*Wallet, error) {
			return loader.CreateNewWallet(
				[]byte("public"), []byte("private"), seed,
				params.GenesisBlock.Header.Timestamp,
			)
		},
	)
	defer fixture.close()
	wallet := fixture.wallet
	require.NoError(t, wallet.Unlock([]byte("private"), nil))
	validationStartRPC(t, miner, wallet, params)

	digest := validationBTCDDigest{}
	balance, err := wallet.CalculateBalance(1)
	require.NoError(t, err)
	digest.RecoveryBalance = int64(balance)
	digest.RecoveryBeyondLookahead = balance == 300_000

	allocated, err := wallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	fixture.restart([]byte("public"), []byte("private"))
	wallet = fixture.wallet
	wallet.chainClient = nil
	validationStartRPC(t, miner, wallet, params)
	require.Eventually(t, func() bool {
		balance, err := wallet.CalculateBalance(1)
		digest.RestartBalance = int64(balance)

		return err == nil && int64(balance) == digest.RecoveryBalance &&
			wallet.ChainSynced()
	}, 30*time.Second, 100*time.Millisecond)

	allocatedScript, err := txscript.PayToAddrScript(allocated)
	require.NoError(t, err)
	_, err = miner.SendOutputs(
		[]*wire.TxOut{wire.NewTxOut(300_000, allocatedScript)}, 1_000,
	)
	require.NoError(t, err)
	_, err = miner.Client.Generate(1)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		balance, err := wallet.CalculateBalance(1)
		digest.AdditionalBalance = int64(balance)

		return err == nil && int64(balance) ==
			digest.RecoveryBalance+300_000
	}, 30*time.Second, 100*time.Millisecond)

	destination, err := miner.NewAddress()
	require.NoError(t, err)
	destinationScript, err := txscript.PayToAddrScript(destination)
	require.NoError(t, err)
	authored, err := wallet.CreateSimpleTx(
		&waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
		[]*wire.TxOut{wire.NewTxOut(100_000, destinationScript)}, 1,
		1_000, CoinSelectionLargest, false,
	)
	digest.SpendCreated = err == nil
	require.NoError(t, err)
	require.NoError(t, wallet.PublishTransaction(
		authored.Tx, "comparative real spend",
	))
	spendHash := authored.Tx.TxHash()
	blocks, err := miner.Client.Generate(1)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Eventually(t, func() bool {
		tx, err := wallet.GetTransaction(spendHash)
		digest.SpendConfirmed = err == nil && tx.Height >= 0

		return digest.SpendConfirmed
	}, 30*time.Second, 100*time.Millisecond)

	fixture.restart([]byte("public"), []byte("private"))
	wallet = fixture.wallet
	wallet.chainClient = nil
	validationStartRPC(t, miner, wallet, params)
	require.NoError(t, miner.Client.InvalidateBlock(blocks[0]))
	require.Eventually(t, func() bool {
		tx, err := wallet.GetTransaction(spendHash)
		digest.ReorgUnconfirmed = err == nil && tx.Height == -1

		return digest.ReorgUnconfirmed
	}, 30*time.Second, 100*time.Millisecond)

	_, err = miner.Client.Generate(1)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		tx, err := wallet.GetTransaction(spendHash)
		digest.ReplacementConfirmed = err == nil && tx.Height >= 0

		return digest.ReplacementConfirmed
	}, 30*time.Second, 100*time.Millisecond)

	payload, err := json.Marshal(digest)
	require.NoError(t, err)
	sum := sha256.Sum256(payload)
	t.Logf("BTCD_SEMANTIC_DIGEST backend=%s sha256=%x json=%s", backend,
		sum, payload)

	return digest
}

// validationDerivedAddress derives one BIP84 external address from a seed.
func validationDerivedAddress(t *testing.T, seed []byte,
	params *chaincfg.Params, index uint32) address.Address {

	t.Helper()

	key, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)
	defer key.Zero()
	for _, child := range []uint32{
		waddrmgr.KeyScopeBIP0084.Purpose + hdkeychain.HardenedKeyStart,
		waddrmgr.KeyScopeBIP0084.Coin + hdkeychain.HardenedKeyStart,
		hdkeychain.HardenedKeyStart, 0, index,
	} {
		key, err = key.DeriveNonStandard(child)
		require.NoError(t, err)
	}
	pubKey, err := key.ECPubKey()
	require.NoError(t, err)
	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), params,
	)
	require.NoError(t, err)

	return addr
}

// validationStartRPC attaches a wallet to a fresh client for the test miner.
func validationStartRPC(t *testing.T, miner *rpctest.Harness, wallet *Wallet,
	params *chaincfg.Params) {

	t.Helper()

	rpcConfig := miner.RPCConfig()
	client, err := chain.NewRPCClientWithConfig(&chain.RPCClientConfig{
		Conn:              &rpcConfig,
		Chain:             params,
		ReconnectAttempts: 3,
	})
	require.NoError(t, err)
	require.NoError(t, client.Start(t.Context()))
	wallet.SynchronizeRPC(client)

	_, bestHeight, err := miner.Client.GetBestBlock()
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return wallet.ChainSynced() &&
			wallet.Manager.SyncedTo().Height == bestHeight
	}, 30*time.Second, 100*time.Millisecond)
}

// runValidationScenario executes the shared semantic scenario for one backend.
func runValidationScenario(t *testing.T, backend string,
	seed []byte) validationResult {

	t.Helper()

	variants := validationCreationVariants(t, backend, seed)
	birthday := time.Unix(1_700_000_000, 0)
	fixture := newValidationFixture(
		t, backend, "comparative", func(loader *Loader) (*Wallet, error) {
			return loader.CreateNewWallet(
				[]byte("public-pass"), []byte("private-pass"), seed,
				birthday,
			)
		},
	)
	defer fixture.close()

	wallet := fixture.wallet
	wallet.chainClient = &mockChainClient{}
	wallet.Lock()
	require.Eventually(t, wallet.Locked, time.Second, 10*time.Millisecond)
	wrongPrivate := validationError(wallet.Unlock([]byte("wrong"), nil))
	require.NoError(t, wallet.Unlock([]byte("private-pass"), nil))

	account, err := wallet.NextAccount(
		waddrmgr.KeyScopeBIP0084, "secondary",
	)
	require.NoError(t, err)
	require.NoError(t, wallet.RenameAccount(
		waddrmgr.KeyScopeBIP0084, account, "renamed",
	))

	customScope := waddrmgr.KeyScope{Purpose: 1_017, Coin: 1}
	customSchema := waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.WitnessPubKey,
		InternalAddrType: waddrmgr.TaprootPubKey,
	}
	_, err = wallet.AddScopeManager(customScope, customSchema)
	require.NoError(t, err)

	addresses := make(map[waddrmgr.KeyScope]address.Address)
	var addressTypes []string
	for _, scope := range append(
		append([]waddrmgr.KeyScope{}, waddrmgr.DefaultKeyScopes...),
		customScope,
	) {
		scopeAccount := uint32(waddrmgr.DefaultAccountNum)
		if scope == waddrmgr.KeyScopeBIP0084 {
			scopeAccount = account
		}

		external, err := wallet.NewAddress(scopeAccount, scope)
		require.NoError(t, err)
		addresses[scope] = external
		managed, err := wallet.AddressInfo(external)
		require.NoError(t, err)
		addressTypes = append(addressTypes, fmt.Sprint(managed.AddrType()))

		internal, err := wallet.NewChangeAddress(scopeAccount, scope)
		require.NoError(t, err)
		managed, err = wallet.AddressInfo(internal)
		require.NoError(t, err)
		addressTypes = append(addressTypes, fmt.Sprint(managed.AddrType()))
	}

	privateKey, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x03}, 32))
	wif, err := btcutil.NewWIF(privateKey, &chaincfg.TestNet3Params, true)
	require.NoError(t, err)
	importBlock := &waddrmgr.BlockStamp{
		Hash:      *chaincfg.TestNet3Params.GenesisHash,
		Height:    0,
		Timestamp: chaincfg.TestNet3Params.GenesisBlock.Header.Timestamp,
	}
	require.NoError(t, wallet.store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			return wallet.Manager.SetBirthdayBlockFromStore(
				tx.Addr(), *importBlock, false,
			)
		}, nil,
	))
	importedString, err := wallet.ImportPrivateKey(
		waddrmgr.KeyScopeBIP0044, wif, importBlock, false,
	)
	require.NoError(t, err)
	importedAddress, err := address.DecodeAddress(
		importedString, &chaincfg.TestNet3Params,
	)
	require.NoError(t, err)

	publicKey, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x04}, 32))
	require.NoError(t, wallet.ImportPublicKey(
		publicKey.PubKey(), waddrmgr.TaprootPubKey,
	))
	_, err = wallet.ImportP2SHRedeemScript([]byte{txscript.OP_TRUE})
	require.NoError(t, err)

	require.NoError(t, wallet.ChangePassphrases(
		[]byte("public-pass"), []byte("new-public-pass"),
		[]byte("private-pass"), []byte("new-private-pass"),
	))
	fixture.unload()
	if fixture.backend == "sqlite" {
		fixture.openSQLite()
	}

	wrongLoader := fixture.newLoader()
	_, err = wrongLoader.OpenExistingWallet([]byte("public-pass"), false)
	wrongPublic := validationError(err)
	fixture.restart([]byte("new-public-pass"), []byte("new-private-pass"))
	wallet = fixture.wallet

	lifecycle := validationLifecycleDigest{
		WrongPrivatePassphrase: wrongPrivate,
		WrongPublicPassphrase:  wrongPublic,
		ExtendedKeyRestart:     variants.ExtendedKeyRestart,
		WatchOnlyRestart:       variants.WatchOnlyRestart,
		WatchOnlyUnlock:        variants.WatchOnlyUnlock,
		BirthdayUnix:           wallet.Manager.Birthday().Unix(),
		AddressTypes:           addressTypes,
	}
	for _, manager := range wallet.Manager.ActiveScopedKeyManagers() {
		lifecycle.Scopes = append(
			lifecycle.Scopes, manager.Scope().String(),
		)
	}
	sort.Strings(lifecycle.Scopes)
	for _, scope := range []waddrmgr.KeyScope{
		waddrmgr.KeyScopeBIP0044, waddrmgr.KeyScopeBIP0084, customScope,
	} {
		result, err := wallet.Accounts(scope)
		require.NoError(t, err)
		for _, item := range result.Accounts {
			lifecycle.Accounts = append(lifecycle.Accounts, fmt.Sprintf(
				"%s:%d:%s:%d:%d", scope, item.AccountNumber,
				item.AccountName, item.ExternalKeyCount,
				item.InternalKeyCount,
			))
		}
	}
	sort.Strings(lifecycle.Accounts)
	lifecycle.Addresses, err = wallet.SortedActivePaymentAddresses()
	require.NoError(t, err)
	sort.Strings(lifecycle.AddressTypes)

	fundingTx := wire.NewMsgTx(2)
	fundingTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{0x10}, Index: 1,
	}})
	fundingScripts := make([][]byte, 0, 3)
	for _, addr := range []address.Address{
		addresses[waddrmgr.KeyScopeBIP0084],
		addresses[waddrmgr.KeyScopeBIP0086], importedAddress,
	} {
		script, err := txscript.PayToAddrScript(addr)
		require.NoError(t, err)
		fundingScripts = append(fundingScripts, script)
	}
	for index, amount := range []int64{1_000_000, 2_000_000, 300_000} {
		fundingTx.AddTxOut(wire.NewTxOut(amount, fundingScripts[index]))
	}
	funding, err := wtxmgr.NewTxRecordFromMsgTx(
		fundingTx, time.Unix(1_700_000_100, 0),
	)
	require.NoError(t, err)
	require.NoError(t, wallet.store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			return wallet.addRelevantTxFromStore(tx, funding, nil)
		}, nil,
	))
	require.NoError(t, wallet.LabelTransaction(
		funding.Hash, "comparative funding", false,
	))

	outpoint84 := wire.OutPoint{Hash: funding.Hash, Index: 0}
	outpoint86 := wire.OutPoint{Hash: funding.Hash, Index: 1}
	importedOutpoint := wire.OutPoint{Hash: funding.Hash, Index: 2}
	lockID := wtxmgr.LockID{0x20}
	_, err = wallet.LeaseOutput(lockID, outpoint84, time.Hour)
	require.NoError(t, err)

	checkpoints := []validationTxCheckpoint{
		validationTransactionCheckpoint(
			t, wallet, "unconfirmed_leased", funding.Hash,
			waddrmgr.KeyScopeBIP0084,
			addresses[waddrmgr.KeyScopeBIP0084],
		),
	}
	fixture.restart([]byte("new-public-pass"), []byte("new-private-pass"))
	wallet = fixture.wallet
	checkpoints = append(checkpoints, validationTransactionCheckpoint(
		t, wallet, "lease_restart", funding.Hash,
		waddrmgr.KeyScopeBIP0084,
		addresses[waddrmgr.KeyScopeBIP0084],
	))
	require.NoError(t, wallet.ReleaseOutput(lockID, outpoint84))

	block := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: chainhash.Hash{0x21}, Height: 1},
		Time:  time.Unix(1_700_000_200, 0),
	}
	require.NoError(t, wallet.store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			if err := wallet.addRelevantTxFromStore(
				tx, funding, &block,
			); err != nil {

				return err
			}

			return wallet.connectBlockFromStore(tx, block)
		}, nil,
	))
	wallet.chainClient = &mockChainClient{getBestBlockHeight: 1}
	checkpoints = append(checkpoints, validationTransactionCheckpoint(
		t, wallet, "confirmed", funding.Hash,
		waddrmgr.KeyScopeBIP0084,
		addresses[waddrmgr.KeyScopeBIP0084],
	))

	fixture.restart([]byte("new-public-pass"), []byte("new-private-pass"))
	wallet = fixture.wallet
	wallet.chainClient = &mockChainClient{
		getBlockHeader: &chaincfg.TestNet3Params.GenesisBlock.Header,
	}
	wallet.SetChainSynced(true)
	rewound, err := wallet.disconnectBlockFromStore(wallet.chainClient, block)
	require.NoError(t, err)
	require.True(t, rewound)
	checkpoints = append(checkpoints, validationTransactionCheckpoint(
		t, wallet, "reorg_after_restart", funding.Hash,
		waddrmgr.KeyScopeBIP0084,
		addresses[waddrmgr.KeyScopeBIP0084],
	))

	fundingDigest := validationFundingScenario(
		t, wallet, outpoint84, outpoint86, importedOutpoint,
		fundingScripts, account,
	)
	result := validationResult{
		Semantic: validationSemanticDigest{
			Lifecycle:   lifecycle,
			Transaction: checkpoints,
			Funding:     fundingDigest,
		},
	}
	_, statErr := os.Stat(filepath.Join(fixture.dir, WalletDBName))
	result.RuntimeKVSidecar = statErr == nil

	payload, err := json.Marshal(result.Semantic)
	require.NoError(t, err)
	digest := sha256.Sum256(payload)
	t.Logf("SEMANTIC_DIGEST backend=%s sha256=%x json=%s", backend,
		digest, payload)
	t.Logf("SETUP_OBSERVATION backend=%s runtime_kv_sidecar=%t", backend,
		result.RuntimeKVSidecar)

	return result
}

// validationCreationVariants checks extended-key and watch-only restart paths.
func validationCreationVariants(t *testing.T, backend string,
	seed []byte) validationLifecycleDigest {

	t.Helper()

	rootKey, err := hdkeychain.NewMaster(seed, &chaincfg.TestNet3Params)
	require.NoError(t, err)
	extended := newValidationFixture(
		t, backend, "extended", func(loader *Loader) (*Wallet, error) {
			return loader.CreateNewWalletExtendedKey(
				[]byte("public"), []byte("private"), rootKey,
				time.Unix(1_700_000_000, 0),
			)
		},
	)
	extended.wallet.chainClient = &mockChainClient{}
	require.NoError(t, extended.wallet.Unlock([]byte("private"), nil))
	extendedAddress, err := extended.wallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	extended.restart([]byte("public"), []byte("private"))
	haveExtended, err := extended.wallet.HaveAddress(extendedAddress)
	require.NoError(t, err)
	extended.close()
	rootKey.Zero()

	watchOnly := newValidationFixture(
		t, backend, "watch-only", func(loader *Loader) (*Wallet, error) {
			return loader.CreateNewWatchingOnlyWallet(
				[]byte("public"), time.Unix(1_700_000_000, 0),
			)
		},
	)
	unlockStatus := validationError(
		watchOnly.wallet.Unlock([]byte("private"), nil),
	)
	watchOnly.restart([]byte("public"), nil)
	watchOnlyRestart := watchOnly.wallet.Manager.WatchOnly()
	watchOnly.close()

	return validationLifecycleDigest{
		ExtendedKeyRestart: haveExtended,
		WatchOnlyRestart:   watchOnlyRestart,
		WatchOnlyUnlock:    unlockStatus,
	}
}

// newValidationFixture creates one test wallet using the selected backend.
func newValidationFixture(t *testing.T, backend, walletName string,
	create func(*Loader) (*Wallet, error)) *validationFixture {

	t.Helper()
	return newValidationFixtureForParams(
		t, backend, walletName, &chaincfg.TestNet3Params, 0, create,
	)
}

// newValidationFixtureForParams creates a wallet with explicit chain and
// recovery settings.
func newValidationFixtureForParams(t *testing.T, backend, walletName string,
	params *chaincfg.Params, recovery uint32,
	create func(*Loader) (*Wallet, error)) *validationFixture {

	t.Helper()

	dir := t.TempDir()
	fixture := &validationFixture{
		t:          t,
		backend:    backend,
		dir:        dir,
		dbPath:     filepath.Join(dir, "wallet.sqlite"),
		walletName: walletName,
		params:     params,
		recovery:   recovery,
	}
	if backend == "sqlite" {
		fixture.openSQLite()
	}
	fixture.loader = fixture.newLoader()
	wallet, err := create(fixture.loader)
	require.NoError(t, err)
	fixture.wallet = wallet

	return fixture
}

// newLoader constructs a fresh loader over the fixture's durable backend.
func (f *validationFixture) newLoader() *Loader {
	f.t.Helper()

	if f.backend == "kv" {
		return NewLoader(
			f.params, f.dir, true, DefaultDBTimeout, f.recovery,
		)
	}

	store := dbsqlite.NewNamedStore(f.conn, f.walletName)
	loader, err := NewLoaderWithStore(f.params, f.recovery, store)
	require.NoError(f.t, err)

	return loader
}

// openSQLite opens and migrates the fixture's SQLite database.
func (f *validationFixture) openSQLite() {
	f.t.Helper()

	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: f.dbPath,
	})
	require.NoError(f.t, err)
	require.NoError(f.t, storesqlite.ApplyMigrations(conn))
	f.conn = conn
}

// unload stops the wallet and closes externally owned SQLite connections.
func (f *validationFixture) unload() {
	f.t.Helper()

	if f.loader != nil {
		if _, loaded := f.loader.LoadedWallet(); loaded {
			require.NoError(f.t, f.loader.UnloadWallet())
		}
	}
	f.wallet = nil
	f.loader = nil
	if f.conn != nil {
		require.NoError(f.t, f.conn.Close())
		f.conn = nil
	}
}

// restart closes and reopens the backend before unlocking the wallet.
func (f *validationFixture) restart(pubPass, privPass []byte) {
	f.t.Helper()

	f.unload()
	if f.backend == "sqlite" {
		f.openSQLite()
	}
	f.loader = f.newLoader()
	wallet, err := f.loader.OpenExistingWallet(pubPass, false)
	require.NoError(f.t, err)
	wallet.chainClient = &mockChainClient{}
	if privPass != nil {
		require.NoError(f.t, wallet.Unlock(privPass, nil))
	}
	f.wallet = wallet
}

// close releases any resources still held by the fixture.
func (f *validationFixture) close() {
	f.t.Helper()
	f.unload()
}

// validationTransactionCheckpoint captures backend-neutral wallet state.
func validationTransactionCheckpoint(t *testing.T, wallet *Wallet, name string,
	hash chainhash.Hash, usedScope waddrmgr.KeyScope,
	usedAddress address.Address) validationTxCheckpoint {

	t.Helper()

	balance, err := wallet.CalculateBalance(0)
	require.NoError(t, err)
	unspent, err := wallet.ListUnspent(0, 1_000_000, "")
	require.NoError(t, err)
	leases, err := wallet.ListLeasedOutputs()
	require.NoError(t, err)
	tx, err := wallet.GetTransaction(hash)
	require.NoError(t, err)
	var addressUsed bool
	err = wallet.store.View(
		t.Context(), func(tx walletstore.ReadTx) error {
			state, err := tx.Addr().Address(
				usedScope, usedAddress.ScriptAddress(),
			)
			if err != nil {
				return err
			}
			addressUsed = state.Used

			return nil
		}, func() {
			addressUsed = false
		},
	)
	require.NoError(t, err)

	digest := validationTxCheckpoint{
		Name:         name,
		Balance:      int64(balance),
		Leases:       len(leases),
		TxHeight:     tx.Height,
		Label:        tx.Summary.Label,
		AddressUsed:  addressUsed,
		SyncedHeight: wallet.Manager.SyncedTo().Height,
	}
	for _, output := range unspent {
		digest.Unspent = append(digest.Unspent, fmt.Sprintf(
			"%d:%d:%s", output.Vout,
			btcutil.Amount(output.Amount*btcutil.SatoshiPerBitcoin),
			output.ScriptPubKey,
		))
	}
	sort.Strings(digest.Unspent)

	return digest
}

// validationFundingScenario records transaction creation, signing, and PSBT
// behavior without publishing any authored transaction.
func validationFundingScenario(t *testing.T, wallet *Wallet,
	outpoint84, outpoint86, importedOutpoint wire.OutPoint,
	fundingScripts [][]byte, p2wpkhAccount uint32) validationFundingDigest {

	t.Helper()

	destination, err := address.NewAddressWitnessPubKeyHash(
		bytes.Repeat([]byte{0x05}, 20), &chaincfg.TestNet3Params,
	)
	require.NoError(t, err)
	destinationScript, err := txscript.PayToAddrScript(destination)
	require.NoError(t, err)

	digest := validationFundingDigest{}
	dryRun, err := wallet.CreateSimpleTx(
		&waddrmgr.KeyScopeBIP0084, p2wpkhAccount,
		[]*wire.TxOut{wire.NewTxOut(100_000, destinationScript)}, 0,
		1_000, CoinSelectionLargest, true,
		WithCustomSelectUtxos([]wire.OutPoint{outpoint84}),
	)
	digest.DryRunStatus = validationError(err)
	if dryRun != nil {
		digest.DryRunInputs = len(dryRun.Tx.TxIn)
		digest.DryRunSigned = transactionSigned(dryRun.Tx)
	}

	p2wpkh, err := wallet.CreateSimpleTx(
		&waddrmgr.KeyScopeBIP0084, p2wpkhAccount,
		[]*wire.TxOut{wire.NewTxOut(100_000, destinationScript)}, 0,
		1_000, CoinSelectionLargest, false,
		WithCustomSelectUtxos([]wire.OutPoint{outpoint84}),
	)
	digest.ExplicitP2WPKHStatus = validationError(err)
	if p2wpkh != nil {
		digest.ExplicitP2WPKHValid = validateMsgTx(
			p2wpkh.Tx, p2wpkh.PrevScripts, p2wpkh.PrevInputValues,
		) == nil
	}

	p2tr, err := wallet.CreateSimpleTx(
		&waddrmgr.KeyScopeBIP0086, waddrmgr.DefaultAccountNum,
		[]*wire.TxOut{wire.NewTxOut(100_000, destinationScript)}, 0,
		1_000, CoinSelectionLargest, false,
		WithCustomSelectUtxos([]wire.OutPoint{outpoint86}),
	)
	digest.ExplicitP2TRStatus = validationError(err)
	if p2tr != nil {
		digest.ExplicitP2TRValid = validateMsgTx(
			p2tr.Tx, p2tr.PrevScripts, p2tr.PrevInputValues,
		) == nil
	}

	importedSpend := wire.NewMsgTx(2)
	importedSpend.AddTxIn(&wire.TxIn{PreviousOutPoint: importedOutpoint})
	importedSpend.AddTxOut(wire.NewTxOut(250_000, destinationScript))
	signErrors, err := wallet.SignTransaction(
		importedSpend, txscript.SigHashAll, nil, nil, nil,
	)
	digest.ImportedSigningStatus = validationError(err)
	if err == nil && len(signErrors) == 0 {
		digest.ImportedSigningValid = validateMsgTx(
			importedSpend, [][]byte{fundingScripts[2]},
			[]btcutil.Amount{300_000},
		) == nil
	}

	inputMetadata := &psbt.Unknown{Key: []byte{0xfc, 0x01}, Value: []byte{1}}
	outputMetadata := &psbt.Unknown{Key: []byte{0xfc, 0x02}, Value: []byte{2}}
	packet := &psbt.Packet{
		UnsignedTx: &wire.MsgTx{
			Version: 2,
			TxIn:    []*wire.TxIn{{PreviousOutPoint: outpoint84}},
			TxOut: []*wire.TxOut{
				wire.NewTxOut(100_000, destinationScript),
			},
		},
		Inputs:  []psbt.PInput{{Unknowns: []*psbt.Unknown{inputMetadata}}},
		Outputs: []psbt.POutput{{Unknowns: []*psbt.Unknown{outputMetadata}}},
	}
	changeIndex, err := wallet.FundPsbt(
		packet, &waddrmgr.KeyScopeBIP0084, 0,
		p2wpkhAccount, 1_000, CoinSelectionLargest,
	)
	digest.FundPsbtStatus = validationError(err)
	if err == nil {
		digest.CallerInputMetadata = packetHasUnknown(
			packet.Inputs[0].Unknowns, inputMetadata,
		)
		digest.CallerOutputMetadata = packetOutputHasUnknown(
			packet.Outputs, outputMetadata,
		)
		digest.BIP69Outputs = validationOutputsSorted(packet.UnsignedTx.TxOut)
		if changeIndex >= 0 {
			digest.PsbtChangeType = validationScriptType(
				packet.UnsignedTx.TxOut[changeIndex].PkScript,
			)
		}

		err = wallet.DecorateInputs(packet, true)
		digest.DecorateInputsStatus = validationError(err)
		if err == nil {
			err = wallet.FinalizePsbt(
				&waddrmgr.KeyScopeBIP0084,
				p2wpkhAccount, packet,
			)
			digest.FinalizePsbtStatus = validationError(err)
			if err == nil {
				finalTx, extractErr := psbt.Extract(packet)
				if extractErr == nil {
					digest.PsbtValid = validateMsgTx(
						finalTx, [][]byte{fundingScripts[0]},
						[]btcutil.Amount{1_000_000},
					) == nil
				}
			}
		}
	}

	return digest
}

// validationError reduces errors to stable semantic categories.
func validationError(err error) string {
	switch {
	case err == nil:
		return "ok"

	case waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase):
		return "wrong passphrase"

	case waddrmgr.IsError(err, waddrmgr.ErrWatchingOnly):
		return "watching only"

	default:
		return err.Error()
	}
}

// transactionSigned reports whether any transaction input contains a script.
func transactionSigned(tx *wire.MsgTx) bool {
	for _, input := range tx.TxIn {
		if len(input.SignatureScript) > 0 || len(input.Witness) > 0 {
			return true
		}
	}

	return false
}

// packetHasUnknown reports whether one PSBT unknown field remains present.
func packetHasUnknown(unknowns []*psbt.Unknown, want *psbt.Unknown) bool {
	for _, unknown := range unknowns {
		if bytes.Equal(unknown.Key, want.Key) &&
			bytes.Equal(unknown.Value, want.Value) {

			return true
		}
	}

	return false
}

// packetOutputHasUnknown searches all PSBT outputs for one unknown field.
func packetOutputHasUnknown(outputs []psbt.POutput, want *psbt.Unknown) bool {
	for _, output := range outputs {
		if packetHasUnknown(output.Unknowns, want) {
			return true
		}
	}

	return false
}

// validationOutputsSorted reports whether outputs use BIP69 value/script order.
func validationOutputsSorted(outputs []*wire.TxOut) bool {
	for index := 1; index < len(outputs); index++ {
		previous := outputs[index-1]
		current := outputs[index]
		if previous.Value > current.Value {
			return false
		}
		if previous.Value == current.Value &&
			bytes.Compare(previous.PkScript, current.PkScript) > 0 {

			return false
		}
	}

	return true
}

// validationScriptType returns a stable name for a standard output script.
func validationScriptType(script []byte) string {
	switch {
	case txscript.IsPayToPubKeyHash(script):
		return "p2pkh"

	case txscript.IsPayToScriptHash(script):
		return "p2sh"

	case txscript.IsPayToWitnessPubKeyHash(script):
		return "p2wpkh"

	case txscript.IsPayToTaproot(script):
		return "p2tr"

	default:
		return "other"
	}
}
