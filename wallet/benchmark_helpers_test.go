package wallet

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

var errAccountNotFound = errors.New("account not found")

// growthFunc defines how a benchmark parameter should scale with iteration
// index. It takes an iteration index i (0-based) and returns the parameter
// value for that iteration. This allows flexible configuration of benchmark
// data sizes with different growth patterns (linear, exponential, logarithmic,
// etc.).
type growthFunc func(i int) int

// constantGrowth returns a constant value regardless of iteration.
//
// Use when: The parameter is a control variable not under test and should
// remain fixed across all iterations.
//
// Example: accountGrowth when testing transaction complexity (not account
// scaling).
//
// Note: Ideal for CI as it produces predictable, stable results for regression
// detection.
//
// Result: 5, 5, 5, 5, 5...
func constantGrowth(i int) int {
	return 5
}

// linearGrowth scales the parameter value linearly with arithmetic progression.
//
// Use when: Testing gradual scaling behavior, O(n) or O(n²) algorithms, or
// when detailed granularity is needed across a moderate range.
//
// Example: Transaction I/O counts, address counts, or database record counts
// where you want to see how performance degrades proportionally.
//
// Note: Safe for CI when used with limited range (e.g., i = 0..9 yields 5..50)
// for regression detection. Avoid for O(log n) algorithms as x grows linearly
// while y grows logarithmically, making regressions harder to detect.
//
// Result: 5, 10, 15, 20, 25, 30, 35...
func linearGrowth(i int) int {
	return 5 + (i * 5)
}

// exponentialGrowth scales the parameter value exponentially (powers of 2).
//
// Use when: Stress testing scalability limits, testing concurrency levels, or
// quickly covering a wide range from small to large values. Works well for
// algorithms with O(log n) complexity as it creates a linear relationship when
// plotted (e.g., y = log₂(x) when x grows exponentially, y grows linearly).
//
// Example: Concurrent worker counts, cache sizes, or finding performance
// breaking points.
//
// Note: Avoid running in CI due to large values and long execution times. Use
// for local performance analysis only.
//
// Result: 1, 2, 4, 8, 16, 32, 64, 128, 256...
func exponentialGrowth(i int) int {
	return 1 << i
}

// mapRange maps fn over indices [start..end] (inclusive) and returns the
// results. This provides functional-style array generation for benchmarks.
//
//nolint:unparam // Different benchmarks may intentionally use different values
func mapRange(start, end int, fn growthFunc) []int {
	result := make([]int, end-start+1)
	for i := range result {
		result[i] = fn(start + i)
	}

	return result
}

// decimalWidth returns the number of characters in the decimal representation
// of given value.
func decimalWidth(value int) int {
	return len(strconv.Itoa(value))
}

// benchmarkWalletConfig holds configuration for benchmark wallet setup.
type benchmarkWalletConfig struct {
	// scopes is the key scopes to create accounts in.
	scopes []waddrmgr.KeyScope

	// numAccounts is the number of accounts to create.
	numAccounts int

	// numWalletTxs is the number of wallet transactions to create.
	numWalletTxs int

	// numAddresses is the number of addresses to create.
	numAddresses int

	// numTxInputs is the number of inputs per transaction. If 0, defaults
	// to 1 input per transaction.
	numTxInputs int

	// numTxOutputs is the number of outputs per transaction. If 0,
	// defaults to 1 output per transaction.
	numTxOutputs int
}

// benchmarkWallet holds a wallet and its created wallet transactions.
type benchmarkWallet struct {
	*Wallet

	// confirmedTxs contains confirmed wallet transactions created during
	// benchmark setup. These are spending transactions with both debits
	// (inputs) and credits (outputs) that have been mined in blocks.
	confirmedTxs []*wire.MsgTx

	// unconfirmedTxs contains unconfirmed wallet transactions created
	// during benchmark setup. These are spending transactions with both
	// debits (inputs) and credits (outputs) that are in the mempool.
	unconfirmedTxs []*wire.MsgTx
}

// setupBenchmarkWallet creates a wallet with test data based on the provided
// configuration. It distributes accounts evenly across the specified scopes
// and returns the wallet along with the outpoints of all created UTXOs. If
// config.miner is provided, the wallet is connected to the btcd node via RPC.
func setupBenchmarkWallet(tb testing.TB,
	cfg benchmarkWalletConfig) *benchmarkWallet {

	tb.Helper()

	// Since testWallet requires a *testing.T, we can't pass the benchmark's
	// *testing.B. Instead, we create a setup *testing.T and manually fail
	// the benchmark if the setup fails.
	setupT := &testing.T{}
	w := testWallet(setupT)
	require.False(tb, setupT.Failed(), "testWallet setup failed")

	addresses := createTestAccounts(
		tb, w, cfg.scopes, cfg.numAccounts, cfg.numAddresses,
	)

	var txsResult *testWalletTxsResult
	if cfg.numWalletTxs > 0 {
		txsResult = createTestWalletTxs(
			tb, w, addresses, cfg.numWalletTxs, cfg.numTxInputs,
			cfg.numTxOutputs,
		)
	} else {
		// Return empty result if no transactions requested.
		txsResult = &testWalletTxsResult{
			confirmed:   []*wire.MsgTx{},
			unconfirmed: []*wire.MsgTx{},
		}
	}

	return &benchmarkWallet{
		Wallet:         w,
		confirmedTxs:   txsResult.confirmed,
		unconfirmedTxs: txsResult.unconfirmed,
	}
}

// setSyncedToHeight updates the wallet's synced block height. This is useful
// for benchmark tests to ensure confirmation calculations work correctly.
func setSyncedToHeight(tb testing.TB, w *Wallet, height int32,
	hash chainhash.Hash) {

	tb.Helper()

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		return w.addrStore.SetSyncedTo(addrmgrNs, &waddrmgr.BlockStamp{
			Height: height,
			Hash:   hash,
		})
	})
	require.NoError(tb, err, "failed to set synced height to %d", height)
}

// createTestAccounts creates test accounts across the specified key scopes
// and returns all generated addresses.
func createTestAccounts(tb testing.TB, w *Wallet, scopes []waddrmgr.KeyScope,
	numAccounts, numAddresses int) []waddrmgr.ManagedAddress {

	tb.Helper()

	var allAddresses []waddrmgr.ManagedAddress

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		// Distribute accounts across the specified key scopes.
		accountsPerScope := numAccounts / len(scopes)
		remainder := numAccounts % len(scopes)

		for i, scope := range scopes {
			scopeAccounts := accountsPerScope
			if i < remainder {
				// Distribute remainder accounts.
				scopeAccounts++
			}

			err := createAccountsInScope(
				w, tx, scope, scopeAccounts, numAddresses,
				i*accountsPerScope, &allAddresses,
			)
			if err != nil {
				return err
			}
		}

		return nil
	})

	require.NoError(tb, err, "failed to create test accounts: %v", err)

	return allAddresses
}

// createAccountsInScope creates accounts within a specific scope with unique
// naming across scopes.
func createAccountsInScope(w *Wallet, tx walletdb.ReadWriteTx,
	scope waddrmgr.KeyScope, numAccounts, numAddresses, offset int,
	allAddresses *[]waddrmgr.ManagedAddress) error {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return err
	}

	addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

	for i := range numAccounts {
		name := fmt.Sprintf("bench-scope-%d-%d-account-%d",
			scope.Purpose, scope.Coin, offset+i)

		account, err := manager.NewAccount(addrmgrNs, name)
		if err != nil {
			return err
		}

		addrs, err := manager.NextExternalAddresses(
			addrmgrNs, account, uint32(numAddresses),
		)
		if err != nil {
			return err
		}

		*allAddresses = append(*allAddresses, addrs...)
	}

	return nil
}

// testWalletTxsResult holds the result of creating test wallet transactions.
type testWalletTxsResult struct {
	// confirmed contains confirmed spending transactions.
	confirmed []*wire.MsgTx

	// unconfirmed contains unconfirmed spending transactions.
	unconfirmed []*wire.MsgTx

	// highestBlockMeta is the metadata for the highest block containing
	// confirmed transactions.
	highestBlockMeta wtxmgr.BlockMeta
}

// createTestWalletTxs creates diverse test wallet transactions with both
// confirmed and unconfirmed transaction history. The goal is diversity for more
// comprehensive benchmark testing. The function creates four passes of
// transactions:
//  1. Initial confirmed UTXOs for confirmed spending txs (credits only)
//  2. Confirmed spending transactions (debits + credits, mined in blocks)
//  3. Initial confirmed UTXOs for unconfirmed spending txs (credits only)
//  4. Unconfirmed spending transactions (debits + credits, unmined/mempool)
//
// Each set of spending transactions uses separate UTXOs to avoid double-spend
// conflicts. numInputs and numOutputs control transaction complexity. Returns
// both confirmed and unconfirmed spending transactions.
func createTestWalletTxs(tb testing.TB, w *Wallet,
	addresses []waddrmgr.ManagedAddress, numTxs,
	numInputs, numOutputs int) *testWalletTxsResult {

	tb.Helper()

	var (
		txsConfirmed     []*wire.MsgTx
		txsUnconfirmed   []*wire.MsgTx
		highestBlockMeta wtxmgr.BlockMeta
	)

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		msgTx := TstTx.MsgTx()

		var (
			initialCreditsConfirmed []*wire.MsgTx
			prevOutpointsConfirmed  []wire.OutPoint
		)

		var (
			baseBlockHeight int32 = 1
			mined                 = true
		)

		// First pass: Create initial UTXOs (credits only, no debits).
		initialCreditsConfirmed, highestBlockMeta = createTxBatch(
			tb, w, txmgrNs, addrmgrNs, addresses, numTxs,
			msgTx.Version, baseBlockHeight, 200000, nil, 0,
			numOutputs, mined,
		)

		prevOutpointsConfirmed = txsToOutpoints(
			initialCreditsConfirmed,
		)

		// Second pass: Create confirmed spending transactions
		baseBlockHeight = highestBlockMeta.Height + 1
		txsConfirmed, highestBlockMeta = createTxBatch(
			tb, w, txmgrNs, addrmgrNs, addresses, numTxs,
			msgTx.Version, baseBlockHeight, 100000,
			prevOutpointsConfirmed, numInputs, numOutputs, mined,
		)

		// Third pass: Create initial UTXOs for unconfirmed spending
		// txs.
		baseBlockHeight = highestBlockMeta.Height + 1
		initialCreditsConfirmed, highestBlockMeta = createTxBatch(
			tb, w, txmgrNs, addrmgrNs, addresses, numTxs,
			msgTx.Version, baseBlockHeight, 200000, nil, 0,
			numOutputs, mined,
		)

		prevOutpointsConfirmed = txsToOutpoints(initialCreditsConfirmed)

		// Fourth pass: Create unconfirmed spending transactions.
		baseBlockHeight = -1
		mined = false
		txsUnconfirmed, _ = createTxBatch(
			tb, w, txmgrNs, addrmgrNs, addresses, numTxs,
			msgTx.Version, baseBlockHeight, 110000,
			prevOutpointsConfirmed, numInputs, numOutputs, mined,
		)

		return nil
	})

	require.NoError(tb, err, "failed to create test wallet txs: %v", err)

	// Sync wallet to the highest block containing confirmed transactions.
	setSyncedToHeight(
		tb, w, highestBlockMeta.Height,
		highestBlockMeta.Hash,
	)

	return &testWalletTxsResult{
		confirmed:        txsConfirmed,
		unconfirmed:      txsUnconfirmed,
		highestBlockMeta: highestBlockMeta,
	}
}

// txsToOutpoints converts all transaction outputs to outpoints. For X txs with
// Y outputs per tx outputs, returns X*Y outpoints.
func txsToOutpoints(txs []*wire.MsgTx) []wire.OutPoint {
	var outpoints []wire.OutPoint
	for _, tx := range txs {
		txHash := tx.TxHash()
		for j := range tx.TxOut {
			outpoints = append(
				outpoints, wire.OutPoint{
					Hash:  txHash,
					Index: uint32(j),
				},
			)
		}
	}

	return outpoints
}

// createTxBatch is a helper that creates a batch of transactions.
// If prevOutpoints is nil, creates receiving transactions (credits only).
// If prevOutpoints is provided, creates spending transactions
// (debits + credits). If mined is true, each transaction is placed in its own
// block (blockHeight + i). If mined is false, transactions are unmined
// (unconfirmed). numInputs and numOutputs control transaction complexity; if 0,
// defaults to 1 input and 1 output per transaction. Returns the created
// transactions and the block metadata for the highest block (only meaningful if
// mined is true).
func createTxBatch(tb testing.TB, w *Wallet, txmgrNs,
	addrmgrNs walletdb.ReadWriteBucket, addresses []waddrmgr.ManagedAddress,
	count int, txVersion int32, startBlockHeight int32, baseAmount int64,
	prevOutpoints []wire.OutPoint, numInputs, numOutputs int,
	mined bool) ([]*wire.MsgTx, wtxmgr.BlockMeta) {

	tb.Helper()

	// Default to 1 input and 1 output if not specified.
	if numInputs == 0 {
		numInputs = 1
	}

	if numOutputs == 0 {
		numOutputs = 1
	}

	var (
		transactions  []*wire.MsgTx
		lastBlockMeta wtxmgr.BlockMeta
	)

	for i := 0; i < count && i < len(addresses); i++ {
		var blockMeta *wtxmgr.BlockMeta
		if mined {
			// Each transaction goes in its own block with unique
			// hash.
			blockHash := chainhash.Hash{}
			blockHash[0] = byte(startBlockHeight + int32(i))
			blockHash[1] = byte((startBlockHeight + int32(i)) >> 8)

			blockMeta = &wtxmgr.BlockMeta{
				Block: wtxmgr.Block{
					Hash:   blockHash,
					Height: startBlockHeight + int32(i),
				},
				Time: time.Now(),
			}
			lastBlockMeta = *blockMeta
		}

		tx := buildTxForBatch(
			tb, addresses, txVersion, i, baseAmount,
			prevOutpoints, numInputs, numOutputs,
		)

		rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
		require.NoError(tb, err)

		err = w.txStore.InsertTx(txmgrNs, rec, blockMeta)
		require.NoError(tb, err)

		// Add credits for all outputs belonging to our wallet.
		for j := range numOutputs {
			err = w.txStore.AddCredit(
				txmgrNs, rec, blockMeta, uint32(j), false,
			)
			require.NoError(tb, err)
		}

		// Mark all addresses as used.
		for j := range numOutputs {
			addr := addresses[(i+j)%len(addresses)]
			err = w.addrStore.MarkUsed(addrmgrNs, addr.Address())
			require.NoError(tb, err)
		}

		transactions = append(transactions, tx)
	}

	return transactions, lastBlockMeta
}

// buildTxForBatch creates a single transaction with the specified inputs and
// outputs.
func buildTxForBatch(tb testing.TB, addresses []waddrmgr.ManagedAddress,
	txVersion int32, i int, baseAmount int64, prevOutpoints []wire.OutPoint,
	numInputs, numOutputs int) *wire.MsgTx {

	tb.Helper()

	tx := wire.NewMsgTx(txVersion)

	// Add multiple outputs to our wallet (creates credits).
	for j := range numOutputs {
		addr := addresses[(i+j)%len(addresses)]
		pkScript, err := txscript.PayToAddrScript(addr.Address())
		require.NoError(tb, err)

		// Add random jitter based on timestamp to ensure unique
		// transaction hashes across benchmark runs, preventing
		// duplicate transaction errors when the same test data is
		// created multiple times. This is necessary for
		// representative benchmarking.
		randomJitter := time.Now().UnixNano() % 1000
		amount := btcutil.Amount(
			baseAmount + int64(i*1000+j*100) + randomJitter,
		)
		txOut := wire.NewTxOut(int64(amount), pkScript)
		tx.AddTxOut(txOut)
	}

	// Add multiple inputs - either external or from our wallet.
	for j := range numInputs {
		outpointIdx := i*numInputs + j
		if prevOutpoints != nil && outpointIdx < len(prevOutpoints) {
			// Spend from our previous UTXO (creates debit).
			txIn := wire.NewTxIn(
				&prevOutpoints[outpointIdx], nil, nil,
			)
			tx.AddTxIn(txIn)
		} else {
			// External input (no debit). Needed for tx to be
			// syntactically valid.
			prevHash := chainhash.Hash{}
			prevHash[0] = byte(i)
			prevHash[1] = byte(j)
			txIn := wire.NewTxIn(
				wire.NewOutPoint(&prevHash, uint32(j)), nil,
				nil,
			)
			tx.AddTxIn(txIn)
		}
	}

	return tx
}

// generateAccountName generates a consistent account name and number for
// benchmarking based on the given number of accounts and scopes. It returns
// the first account name and number in the last scope, which provides a good
// heuristic case for evaluating search performance.
func generateAccountName(numAccounts int,
	scopes []waddrmgr.KeyScope) (string, uint32) {

	accountsPerScope := numAccounts / len(scopes)

	lastScopeIndex := len(scopes) - 1
	lastScope := scopes[lastScopeIndex]
	lastScopeOffset := lastScopeIndex * accountsPerScope

	accountName := fmt.Sprintf("bench-scope-%d-%d-account-%d",
		lastScope.Purpose, lastScope.Coin, lastScopeOffset)

	// Account numbers start from 1, not 0. Account 0 is reserved for
	// "default".
	accountNumber := uint32(lastScopeOffset + 1)

	return accountName, accountNumber
}

// generateTestExtendedKey generates a test extended public key for benchmarking
// ImportAccount operations. It uses a deterministic seed based on the
// seed index to ensure consistent and unique results across benchmark runs.
func generateTestExtendedKey(tb testing.TB,
	seedIndex int) (*hdkeychain.ExtendedKey, uint32, waddrmgr.AddressType) {

	tb.Helper()

	// Use a simple deterministic seed based on seed index.
	seed := make([]byte, 32)
	for j := range seed {
		seed[j] = byte(seedIndex + j)
	}

	// Create master key from seed.
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.TestNet3Params)
	require.NoError(tb, err)

	// Derive account key for BIP0084 (m/84'/1'/seedIndex').
	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 84)
	require.NoError(tb, err)

	coin, err := purpose.Derive(hdkeychain.HardenedKeyStart + 1)
	require.NoError(tb, err)

	account, err := coin.Derive(
		hdkeychain.HardenedKeyStart + uint32(seedIndex),
	)
	require.NoError(tb, err)

	accountPubKey, err := account.Neuter()
	require.NoError(tb, err)

	return accountPubKey, uint32(seedIndex), waddrmgr.WitnessPubKey
}

// getMedianTestAddress returns a median address from a median account for
// benchmarking purposes.
func getTestAddress(tb testing.TB, w *Wallet, numAccounts int) btcutil.Address {
	tb.Helper()

	medianAccount := uint32(numAccounts / 2)
	addresses, err := w.AccountAddresses(medianAccount)
	require.NoError(tb, err)

	return addresses[len(addresses)/2]
}

// markAddressAsUsed marks an address as used in the wallet database. This is
// useful for making benchmark iterations idempotent.
func markAddressAsUsed(b *testing.B, w *Wallet, addr btcutil.Address) {
	b.Helper()

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		manager, err := w.addrStore.FetchScopedKeyManager(
			waddrmgr.KeyScopeBIP0044,
		)
		if err != nil {
			return err
		}

		return manager.MarkUsed(addrmgrNs, addr)
	})
	require.NoError(b, err)
}

// getTestUtxoOutpoint returns a median UTXO outpoint from the provided list
// for benchmarking purposes. It returns the outpoint from the middle of the
// list to provide a representative test case.
func getTestUtxoOutpoint(outpoints []wire.OutPoint) wire.OutPoint {
	medianIndex := len(outpoints) / 2
	return outpoints[medianIndex]
}

// generateTestTapscript generates a test tapscript for benchmarking purposes.
// It creates a simple script that checks a signature against the provided
// public key, wraps it in a tap leaf, and returns a complete Tapscript
// structure ready for import.
func generateTestTapscript(tb testing.TB,
	pubKey *btcec.PublicKey) waddrmgr.Tapscript {

	tb.Helper()

	script, err := txscript.NewScriptBuilder().
		AddData(pubKey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(tb, err)

	leaf := txscript.NewTapLeaf(txscript.BaseLeafVersion, script)

	return waddrmgr.Tapscript{
		Type: waddrmgr.TapscriptTypeFullTree,
		ControlBlock: &txscript.ControlBlock{
			InternalKey: pubKey,
		},
		Leaves: []txscript.TapLeaf{leaf},
	}
}

// generateTestTxOut generates a test TxOut for benchmarking purposes.
// It creates a TxOut with the provided address as the PkScript.
func generateTestTxOut(tb testing.TB, addr btcutil.Address) wire.TxOut {
	tb.Helper()

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(tb, err)

	return wire.TxOut{
		Value:    1e8,
		PkScript: pkScript,
	}
}

// leaseAllOutputs leases all outputs in the wallet with unique lock IDs. This
// is used to set up benchmarks for ListLeasedOutputs where we want to maximize
// the N+1 query impact when comparing the new vs deprecated ListLeasedOutputs
// APIs.
func leaseAllOutputs(tb testing.TB, w *Wallet, outpoints []wire.OutPoint,
	duration time.Duration) {

	tb.Helper()

	for i, outpoint := range outpoints {
		lockID := wtxmgr.LockID{byte(i)}
		_, err := w.LeaseOutput(
			tb.Context(), lockID, outpoint, duration,
		)
		require.NoError(tb, err, "failed to lease output %v", outpoint)
	}
}

// listAccountsDeprecated wraps the deprecated Accounts API to satisfy the same
// contract as ListAccounts by calling Accounts API across all active key scopes
// and aggregating the results.
func listAccountsDeprecated(w *Wallet) (*AccountsResult, error) {
	var (
		allAccounts      []AccountResult
		finalBlockHash   chainhash.Hash
		finalBlockHeight int32
		scopeManagers    = w.addrStore.ActiveScopedKeyManagers()
	)

	for _, scopeMgr := range scopeManagers {
		scope := scopeMgr.Scope()

		result, err := w.Accounts(scope)
		if err != nil {
			return nil, err
		}

		allAccounts = append(allAccounts, result.Accounts...)

		finalBlockHash = result.CurrentBlockHash
		finalBlockHeight = result.CurrentBlockHeight
	}

	return &AccountsResult{
		Accounts:           allAccounts,
		CurrentBlockHash:   finalBlockHash,
		CurrentBlockHeight: finalBlockHeight,
	}, nil
}

// listAccountsByNameDeprecated wraps the deprecated Accounts API to satisfy the
// same contract as ListAccountsByName by calling Accounts API across all active
// key scopes, filtering by account name, and aggregating the results.
func listAccountsByNameDeprecated(w *Wallet,
	name string) (*AccountsResult, error) {

	var (
		matchingAccounts []AccountResult
		finalBlockHash   chainhash.Hash
		finalBlockHeight int32
		scopeManagers    = w.addrStore.ActiveScopedKeyManagers()
	)

	for _, scopeMgr := range scopeManagers {
		scope := scopeMgr.Scope()

		result, err := w.Accounts(scope)
		if err != nil {
			return nil, err
		}

		// Filter accounts by name from this scope's results.
		for _, account := range result.Accounts {
			if account.AccountName == name {
				matchingAccounts = append(
					matchingAccounts, account,
				)
			}
		}

		finalBlockHash = result.CurrentBlockHash
		finalBlockHeight = result.CurrentBlockHeight
	}

	return &AccountsResult{
		Accounts:           matchingAccounts,
		CurrentBlockHash:   finalBlockHash,
		CurrentBlockHeight: finalBlockHeight,
	}, nil
}

// getAccountDeprecated wraps the deprecated Accounts API to satisfy the same
// contract as GetAccount by calling Accounts API across all active key scopes
// and filtering by account name.
func getAccountDeprecated(w *Wallet, scope waddrmgr.KeyScope,
	accountName string) (*AccountResult, error) {

	result, err := w.Accounts(scope)
	if err != nil {
		return nil, err
	}

	for _, account := range result.Accounts {
		if account.AccountName == accountName {
			return &account, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", errAccountNotFound, accountName)
}

// getBalanceDeprecated wraps the deprecated Accounts API to satisfy the same
// contract as GetBalance by calling Accounts API across all active key scopes
// and filtering by account name.
func getBalanceDeprecated(w *Wallet, scope waddrmgr.KeyScope,
	accountName string, _ int32) (btcutil.Amount, error) {

	result, err := w.Accounts(scope)
	if err != nil {
		return 0, err
	}

	for _, account := range result.Accounts {
		if account.AccountName == accountName {
			// The deprecated Accounts API doesn't support
			// confirmation filtering. It always returns total
			// balance.
			return account.TotalBalance, nil
		}
	}

	return 0, fmt.Errorf("%w: %s", errAccountNotFound, accountName)
}

// listAddressesDeprecated wraps the deprecated AccountAddresses and
// TotalReceivedForAddr APIs to satisfy the same contract as ListAddresses by
// calling the old APIs and aggregating the results with balances.
func listAddressesDeprecated(w *Wallet,
	accountID uint32) ([]AddressProperty, error) {

	addresses, err := w.AccountAddresses(accountID)
	if err != nil {
		return nil, err
	}

	allProperties := make([]AddressProperty, 0, len(addresses))

	for _, addr := range addresses {
		balance, err := w.TotalReceivedForAddr(addr, 0)
		if err != nil {
			return nil, err
		}

		allProperties = append(allProperties, AddressProperty{
			Address: addr,
			Balance: balance,
		})
	}

	return allProperties, nil
}

// getUtxoDeprecated wraps the deprecated FetchOutpointInfo API to satisfy the
// same contract as GetUtxo by calling FetchOutpointInfo and performing
// additional lookups to construct a complete Utxo struct. This demonstrates
// the inefficiency of the old API which returns raw data requiring the caller
// to perform multiple additional lookups.
func getUtxoDeprecated(w *Wallet, prevOut wire.OutPoint) (*Utxo, error) {
	_, txOut, confs, err := w.FetchOutpointInfo(&prevOut)
	if err != nil {
		return nil, err
	}

	// Additional lookup 1: Extract address from pkScript.
	addr := extractAddrFromPKScript(txOut.PkScript, w.chainParams)
	if addr == nil {
		return nil, ErrNotMine
	}

	// Additional lookup 2: Get address details (spendability, account,
	// address type) from the address manager.
	var (
		spendable bool
		account   string
		addrType  waddrmgr.AddressType
	)

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		spendable, account, addrType = w.addrStore.AddressDetails(
			addrmgrNs, addr,
		)

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Additional lookup 3: Check if the output is locked.
	locked := w.LockedOutpoint(prevOut)

	return &Utxo{
		OutPoint:      prevOut,
		Amount:        btcutil.Amount(txOut.Value),
		PkScript:      txOut.PkScript,
		Confirmations: int32(confs),
		Spendable:     spendable,
		Address:       addr,
		Account:       account,
		AddressType:   addrType,
		Locked:        locked,
	}, nil
}
