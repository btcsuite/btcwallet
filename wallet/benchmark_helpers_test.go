package wallet

import (
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// growthFunc defines how a benchmark parameter should scale with iteration
// index. It takes an iteration index i (0-based) and returns the parameter
// value for that iteration. This allows flexible configuration of benchmark
// data sizes with different growth patterns (linear, exponential, logarithmic,
// etc.).
type growthFunc func(i int) int

// linearGrowth scales the parameter value linearly.
func linearGrowth(i int) int {
	return 5 + (i * 5)
}

// exponentialGrowth scales the parameter value exponentially.
func exponentialGrowth(i int) int {
	return 1 << i
}

// benchmarkDataSize represents different test data sizes for stress testing.
type benchmarkDataSize struct {
	// numAccounts is the number of accounts to create.
	numAccounts int

	// numUTXOs is the number of UTXOs to create.
	numUTXOs int

	// maxAccounts is the maximum number of accounts in the benchmark
	// series.
	maxAccounts int

	// maxUTXOs is the maximum number of UTXOs in the benchmark series.
	maxUTXOs int
}

// name returns a dynamically generated benchmark name based on accounts and
// UTXOs. Uses dynamic padding based on maximum values for proper sorting in
// visualization tools. If numUTXOs is 0, it's omitted from the name.
func (b benchmarkDataSize) name() string {
	accountDigits := len(fmt.Sprintf("%d", b.maxAccounts))

	if b.numUTXOs == 0 {
		return fmt.Sprintf("%0*d-Accounts", accountDigits,
			b.numAccounts)
	}

	utxoDigits := len(fmt.Sprintf("%d", b.maxUTXOs))

	return fmt.Sprintf("%0*d-Accounts-%0*d-UTXOs",
		accountDigits, b.numAccounts, utxoDigits, b.numUTXOs)
}

// benchmarkConfig holds configuration for benchmark wallet setup.
type benchmarkConfig struct {
	// accountGrowth is the function to use to grow the number of accounts.
	accountGrowth growthFunc

	// utxoGrowth is the function to use to grow the number of UTXOs.
	utxoGrowth growthFunc

	// maxIterations is the maximum number of iterations to run.
	maxIterations int

	// startIndex is the index to start the benchmark at.
	startIndex int
}

// generateBenchmarkSizes creates benchmark data sizes programmatically.
func generateBenchmarkSizes(config benchmarkConfig) []benchmarkDataSize {
	var sizes []benchmarkDataSize

	// Calculate maximum values for proper padding.
	maxAccounts := config.accountGrowth(config.maxIterations)
	maxUTXOs := config.utxoGrowth(config.maxIterations)

	for i := config.startIndex; i <= config.maxIterations; i++ {
		sizes = append(sizes, benchmarkDataSize{
			numAccounts: config.accountGrowth(i),
			numUTXOs:    config.utxoGrowth(i),
			maxAccounts: maxAccounts,
			maxUTXOs:    maxUTXOs,
		})
	}

	return sizes
}

// benchmarkWalletConfig holds configuration for benchmark wallet setup.
type benchmarkWalletConfig struct {
	// scopes is the key scopes to create accounts in.
	scopes []waddrmgr.KeyScope

	// numAccounts is the number of accounts to create.
	numAccounts int

	// numUTXOs is the number of UTXOs to create.
	numUTXOs int

	// skipUTXOs skips UTXO creation for account-only benchmarks.
	skipUTXOs bool
}

// setupBenchmarkWallet creates a wallet with test data based on the provided
// configuration. It distributes accounts evenly across the specified scopes.
func setupBenchmarkWallet(t testing.TB, config benchmarkWalletConfig) *Wallet {
	t.Helper()

	// Since testWallet requires a *testing.T, we can't pass the benchmark's
	// *testing.B. Instead, we create a dummy *testing.T and manually fail
	// the benchmark if the setup fails.
	dummyT := &testing.T{}
	w, cleanup := testWallet(dummyT)
	t.Cleanup(cleanup)
	require.False(t, dummyT.Failed(), "testWallet setup failed")

	addresses := createTestAccounts(t, w, config.scopes, config.numAccounts)

	if !config.skipUTXOs && config.numUTXOs > 0 {
		createTestUTXOs(t, w, addresses, config.numUTXOs)
	}

	return w
}

// createTestAccounts creates test accounts across the specified key scopes
// and returns all generated addresses.
func createTestAccounts(t testing.TB, w *Wallet, scopes []waddrmgr.KeyScope,
	numAccounts int) []waddrmgr.ManagedAddress {

	t.Helper()

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

			if err := createAccountsInScope(
				w, tx, scope, scopeAccounts, i*accountsPerScope,
				&allAddresses,
			); err != nil {
				return err
			}
		}
		return nil
	})

	require.NoError(t, err, "failed to create test accounts: %v", err)

	return allAddresses
}

// createAccountsInScope creates accounts within a specific scope with unique
// naming across scopes.
func createAccountsInScope(w *Wallet, tx walletdb.ReadWriteTx,
	scope waddrmgr.KeyScope, numAccounts, offset int,
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
			addrmgrNs, account, 5,
		)
		if err != nil {
			return err
		}

		*allAddresses = append(*allAddresses, addrs...)
	}

	return nil
}

// createTestUTXOs creates the specified number of test UTXOs using the provided
// addresses for benchmark data setup.
func createTestUTXOs(t testing.TB, w *Wallet,
	addresses []waddrmgr.ManagedAddress, numUTXOs int) {

	t.Helper()

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		msgTx := TstTx.MsgTx()

		for i := 0; i < numUTXOs && i < len(addresses); i++ {
			newMsgTx := wire.NewMsgTx(msgTx.Version)
			addr := addresses[i%len(addresses)]

			pkScript, err := txscript.PayToAddrScript(
				addr.Address(),
			)
			if err != nil {
				return err
			}

			// Add a dummy tx output to make it valid.
			amount := btcutil.Amount(100000 + i*1000)
			txOut := wire.NewTxOut(int64(amount), pkScript)
			newMsgTx.AddTxOut(txOut)

			// Add a dummy tx input to make it valid.
			prevHash := chainhash.Hash{}
			prevHash[0] = byte(i)
			txIn := wire.NewTxIn(
				wire.NewOutPoint(&prevHash, 0), nil, nil,
			)
			newMsgTx.AddTxIn(txIn)

			rec, err := wtxmgr.NewTxRecordFromMsgTx(
				newMsgTx, time.Now(),
			)
			if err != nil {
				return err
			}

			blockMeta := &wtxmgr.BlockMeta{
				Block: wtxmgr.Block{
					Hash:   chainhash.Hash{},
					Height: 1,
				},
				Time: time.Now(),
			}

			err = w.txStore.InsertTx(txmgrNs, rec, blockMeta)
			if err != nil {
				return err
			}

			// Mark the output as unspent.
			if err = w.txStore.AddCredit(
				txmgrNs, rec, blockMeta, 0, false,
			); err != nil {
				return err
			}
		}

		return nil
	})

	require.NoError(t, err, "failed to create test UTXOs: %v", err)
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
