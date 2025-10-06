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
func constantGrowth(i int) int {
	return 5
}

// linearGrowth scales the parameter value linearly.
func linearGrowth(i int) int {
	return 5 + (i * 5)
}

// exponentialGrowth scales the parameter value exponentially.
func exponentialGrowth(i int) int {
	return 1 << i
}

// benchmarkDataSize represents the test data size for a single benchmark
// iteration.
type benchmarkDataSize struct {
	// numAccounts is the number of accounts to create.
	numAccounts int

	// numUTXOs is the number of UTXOs to create.
	numUTXOs int

	// numAddresses is the number of addresses to create.
	numAddresses int
}

// benchmarkNamingInfo holds metadata for generating benchmark names.
type benchmarkNamingInfo struct {
	// maxAccounts is the maximum number of accounts in the benchmark
	// series. That would helpful in determining the dynamic padding for the
	// account digits
	maxAccounts int

	// maxUTXOs is the maximum number of UTXOs in the benchmark series. That
	// would helpful in determining the dynamic padding for the UTXO digits.
	maxUTXOs int

	// maxAddresses is the maximum number of addresses in the benchmark
	// series. That would helpful in determining the dynamic padding for the
	// address digits.
	maxAddresses int
}

// name returns a dynamically generated benchmark name based on accounts,
// UTXOs, and addresses. Uses dynamic padding based on maximum values for
// proper sorting in visualization tools.
func (b benchmarkDataSize) name(namingInfo benchmarkNamingInfo) string {
	accountDigits := len(strconv.Itoa(namingInfo.maxAccounts))

	name := fmt.Sprintf("%0*d-Accounts", accountDigits, b.numAccounts)

	if b.numAddresses > 0 {
		addressDigits := len(strconv.Itoa(namingInfo.maxAddresses))
		name += fmt.Sprintf("-%0*d-Addresses", addressDigits,
			b.numAddresses)
	}

	if b.numUTXOs > 0 {
		utxoDigits := len(strconv.Itoa(namingInfo.maxUTXOs))
		name += fmt.Sprintf("-%0*d-UTXOs", utxoDigits, b.numUTXOs)
	}

	return name
}

// benchmarkConfig holds configuration for benchmark wallet setup.
type benchmarkConfig struct {
	// accountGrowth is the function to use to grow the number of accounts.
	accountGrowth growthFunc

	// utxoGrowth is the function to use to grow the number of UTXOs.
	utxoGrowth growthFunc

	// addressGrowth is the function to use to grow the number of addresses.
	addressGrowth growthFunc

	// maxIterations is the maximum number of iterations to run.
	maxIterations int

	// startIndex is the index to start the benchmark at.
	startIndex int
}

// generateBenchmarkSizes creates benchmark data sizes programmatically.
func generateBenchmarkSizes(
	config benchmarkConfig) ([]benchmarkDataSize, benchmarkNamingInfo) {

	var sizes []benchmarkDataSize

	// Calculate maximum values for proper padding.
	maxAccounts := config.accountGrowth(config.maxIterations)
	maxUTXOs := config.utxoGrowth(config.maxIterations)
	maxAddresses := config.addressGrowth(config.maxIterations)

	namingInfo := benchmarkNamingInfo{
		maxAccounts:  maxAccounts,
		maxUTXOs:     maxUTXOs,
		maxAddresses: maxAddresses,
	}

	for i := config.startIndex; i <= config.maxIterations; i++ {
		sizes = append(sizes, benchmarkDataSize{
			numAccounts:  config.accountGrowth(i),
			numUTXOs:     config.utxoGrowth(i),
			numAddresses: config.addressGrowth(i),
		})
	}

	return sizes, namingInfo
}

// benchmarkWalletConfig holds configuration for benchmark wallet setup.
type benchmarkWalletConfig struct {
	// scopes is the key scopes to create accounts in.
	scopes []waddrmgr.KeyScope

	// numAccounts is the number of accounts to create.
	numAccounts int

	// numUTXOs is the number of UTXOs to create.
	numUTXOs int

	// numAddresses is the number of addresses to create.
	numAddresses int
}

// setupBenchmarkWallet creates a wallet with test data based on the provided
// configuration. It distributes accounts evenly across the specified scopes.
func setupBenchmarkWallet(tb testing.TB, config benchmarkWalletConfig) *Wallet {
	tb.Helper()

	// Since testWallet requires a *testing.T, we can't pass the benchmark's
	// *testing.B. Instead, we create a setup *testing.T and manually fail
	// the benchmark if the setup fails.
	setupT := &testing.T{}
	w := testWallet(setupT)
	require.False(tb, setupT.Failed(), "testWallet setup failed")

	addresses := createTestAccounts(
		tb, w, config.scopes, config.numAccounts,
		config.numAddresses,
	)

	createTestUTXOs(tb, w, addresses, config.numUTXOs)

	return w
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

// createTestUTXOs creates the specified number of test UTXOs using the provided
// addresses for benchmark data setup.
func createTestUTXOs(tb testing.TB, w *Wallet,
	addresses []waddrmgr.ManagedAddress, numUTXOs int) {

	tb.Helper()

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
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
			err = w.txStore.AddCredit(
				txmgrNs, rec, blockMeta, 0, false,
			)
			if err != nil {
				return err
			}

			err = w.addrStore.MarkUsed(
				addrmgrNs, addr.Address(),
			)
			if err != nil {
				return err
			}
		}

		return nil
	})

	require.NoError(tb, err, "failed to create test UTXOs: %v", err)
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
