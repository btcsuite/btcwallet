// Copyright (c) 2016 The decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
package rpctest

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	//"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrrpcclient"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/rpc/legacyrpc"
	"github.com/decred/dcrwallet/wallet"
)

type rpcTestCase func(r *Harness, t *testing.T)

var rpcTestCases = []rpcTestCase{
	testGetNewAddress,
	testValidateAddress,
	testWalletPassphrase,
	testGetBalance,
	testListAccounts,
	testListUnspent,
	testSendToAddress,
	testSendFrom,
	testSendMany,
	testListTransactions,
	testGetSetRelayFee,
	testGetSetTicketFee,
	testPurchaseTickets,
}

// Not all tests need their own harness. Indicate here which get a dedicaed
// harness, and use a map from function name to assigned harness.
var primaryHarness *Harness
var harnesses = make(map[string]*Harness)
var needOwnHarness = map[string]bool{
	"testGetNewAddress":    false,
	"testValidateAddress":  false,
	"testWalletPassphrase": false,
	"testGetBalance":       false,
	"testListAccounts":     false,
	"testListUnspent":      false,
	"testSendToAddress":    false,
	"testSendFrom":         false,
	"testListTransactions": true,
	"testGetSetRelayFee":   false,
	"testGetSetTicketFee":  false,
	"testPurchaseTickets":  false,
}

// Get function name from module name
var funcInModulePath = regexp.MustCompile(`^.*\.(.*)$`)

// Get the name of a calling function
func thisFuncName() string {
	fnName := "unknown"
	// PC of caller
	if pc, _, _, ok := runtime.Caller(1); ok {
		fnName = funcInModulePath.ReplaceAllString(runtime.FuncForPC(pc).Name(), "$1")
	}

	return fnName
}

// Get the name of a function type
func funcName(tc rpcTestCase) string {
	fncName := runtime.FuncForPC(reflect.ValueOf(tc).Pointer()).Name()
	return funcInModulePath.ReplaceAllString(fncName, "$1")
}

// TestMain manages the test harnesses and runs the tests instead of go test
// running the tests directly.
func TestMain(m *testing.M) {
	ntfnHandlersNode := dcrrpcclient.NotificationHandlers{
		OnBlockConnected: func(hash *chainhash.Hash, height int32,
			time time.Time, vb uint16) {
			// if height > 41 {
			// 	fmt.Printf("New block connected, at height: %v\n", height)
			// }
		},
	}

	// Create the primary/shared harness
	fmt.Println("Generating primary test harness")
	var err error
	primaryHarness, err = NewHarness(&chaincfg.SimNetParams, &ntfnHandlersNode, nil)
	if err != nil {
		fmt.Println("Unable to create primary harness: ", err)
		os.Exit(1)
	}

	// Initialize the primary mining node with a chain of length 41,
	// providing 25 mature coinbases to allow spending from for testing
	// purposes (CoinbaseMaturity=16 for simnet).
	if err = primaryHarness.SetUp(true, 25); err != nil {
		fmt.Println("Unable to setup test chain: ", err)
		err = primaryHarness.TearDown()
		os.Exit(1)
	}

	// Make a new harness for each test that needs one
	for _, tc := range rpcTestCases {
		tcName := funcName(tc)
		harness := primaryHarness
		if need, ok := needOwnHarness[tcName]; ok && need {
			fmt.Println("Generating own harness for", tcName)
			harness, err = NewHarness(&chaincfg.SimNetParams, nil, nil)
			if err != nil {
				fmt.Println("Unable to create harness: ", err)
				os.Exit(1)
			}

			if err = harness.SetUp(true, 25); err != nil {
				fmt.Println("Unable to setup test chain: ", err)
				err = harness.TearDown()
				os.Exit(1)
			}
		}
		harnesses[tcName] = harness
	}

	// Run the tests
	exitCode := m.Run()

	// Clean up the primary harness created above. This includes removing
	// all temporary directories, and shutting down any created processes.
	if err := primaryHarness.TearDown(); err != nil {
		fmt.Println("Unable to teardown test chain: ", err)
		os.Exit(1)
	}

	for _, h := range harnesses {
		if h.IsUp() {
			if err := h.TearDown(); err != nil {
				fmt.Println("Unable to teardown test chain: ", err)
				os.Exit(1)
			}
		}
	}

	os.Exit(exitCode)
}

func TestRpcServer(t *testing.T) {
	for _, testCase := range rpcTestCases {
		testName := funcName(testCase)
		// fmt.Printf("Starting test %s\n", testName)
		testCase(harnesses[testName], t)
	}
}

func testGetNewAddress(r *Harness, t *testing.T) {
	// Wallet RPC client
	wcl := r.WalletRPC

	// Get a new address from "default" account
	addr, err := wcl.GetNewAddress("default")
	if err != nil {
		t.Fatal(err)
	}

	// Verify that address is for current network
	if !addr.IsForNet(r.ActiveNet) {
		t.Fatalf("Address not for active network (%s)", r.ActiveNet.Name)
	}

	// ValidateAddress
	validRes, err := wcl.ValidateAddress(addr)
	if err != nil {
		t.Fatalf("Unable to validate address %s: %v", addr, err)
	}
	if !validRes.IsValid {
		t.Fatalf("Address not valid: %s", addr)
	}

	// Create new account
	accountName := "newAddressTest"
	err = r.WalletRPC.CreateNewAccount(accountName)
	if err != nil {
		t.Fatal(err)
	}

	// Get a new address from new "newAddressTest" account
	addrA, err := r.WalletRPC.GetNewAddress(accountName)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that address is for current network
	if !addrA.IsForNet(r.ActiveNet) {
		t.Fatalf("Address not for active network (%s)", r.ActiveNet.Name)
	}

	validRes, err = wcl.ValidateAddress(addrA)
	if err != nil {
		t.Fatalf("Unable to validate address %s: %v", addrA, err)
	}
	if !validRes.IsValid {
		t.Fatalf("Address not valid: %s", addr)
	}

	// Verbose - Get a new address from "default" account
	// addr, err := wcl.GetNewAddress
	// if err != nil {
	// 	t.Fatal(err)
	// }

	for i := 0; i < 100; i++ {
		addr, err = wcl.GetNewAddress("default")
		if err != nil {
			t.Fatal(err)
		}

		validRes, err = wcl.ValidateAddress(addr)
		if err != nil {
			t.Fatalf("Unable to validate address %s: %v", addr, err)
		}
		if !validRes.IsValid {
			t.Fatalf("Address not valid: %s", addr)
		}
	}
}

func testValidateAddress(r *Harness, t *testing.T) {
	// Wallet RPC client
	wcl := r.WalletRPC

	accounts := []string{"default", "testValidateAddress"}

	for _, acct := range accounts {
		// Create a non-default account
		if strings.Compare("default", acct) != 0 &&
			strings.Compare("imported", acct) != 0 {
			err := r.WalletRPC.CreateNewAccount(acct)
			if err != nil {
				t.Fatalf("Unable to create account %s: %v", acct, err)
			}
		}

		// Get a new address from current account
		addr, err := wcl.GetNewAddress(acct)
		if err != nil {
			t.Fatal(err)
		}

		// Verify that address is for current network
		if !addr.IsForNet(r.ActiveNet) {
			t.Fatalf("Address not for active network (%s)", r.ActiveNet.Name)
		}

		// ValidateAddress
		addrStr := addr.String()
		validRes, err := wcl.ValidateAddress(addr)
		if err != nil {
			t.Fatalf("Unable to validate address %s: %v", addrStr, err)
		}
		if !validRes.IsValid {
			t.Fatalf("Address not valid: %s", addrStr)
		}
		if !validRes.IsMine {
			t.Fatalf("Address incorrectly identified as NOT mine: %s", addrStr)
		}
		if validRes.IsScript {
			t.Fatalf("Address incorrectly identified as script: %s", addrStr)
		}

		// Address is "mine", so we can check account
		if strings.Compare(acct, validRes.Account) != 0 {
			t.Fatalf("Address %s reported as not from \"%s\" account",
				addrStr, acct)
		}

		// Decode address
		_, err = dcrutil.DecodeAddress(addrStr, r.ActiveNet)
		if err != nil {
			t.Fatalf("Unable to decode address %s: %v", addr.String(), err)
		}

		// Try to validate an address that is not owned by wallet
		otherAddress, err := dcrutil.DecodeNetworkAddress("SsqvxBX8MZC5iiKCgBscwt69jg4u4hHhDKU")
		if err != nil {
			t.Fatalf("Unable to decode address %v: %v", otherAddress, err)
		}
		validRes, err = wcl.ValidateAddress(otherAddress)
		if err != nil {
			t.Fatalf("Unable to validate address %s with secondary wallet: %v",
				addrStr, err)
		}
		if !validRes.IsValid {
			t.Fatalf("Address not valid: %s", addrStr)
		}
		if validRes.IsMine {
			t.Fatalf("Address incorrectly identified as mine: %s", addrStr)
		}
		if validRes.IsScript {
			t.Fatalf("Address incorrectly identified as script: %s", addrStr)
		}

	}

	// Validate simnet dev subsidy address
	devSubAddrStr := chaincfg.SimNetParams.OrganizationAddress // "ScuQxvveKGfpG1ypt6u27F99Anf7EW3cqhq"
	DevAddr, err := dcrutil.DecodeAddress(devSubAddrStr, &chaincfg.SimNetParams)
	if err != nil {
		t.Fatalf("Unable to decode address %s: %v", devSubAddrStr, err)
	}

	validRes, err := wcl.ValidateAddress(DevAddr)
	if err != nil {
		t.Fatalf("Unable to validate address %s: ", devSubAddrStr)
	}
	if !validRes.IsValid {
		t.Fatalf("Address not valid: %s", devSubAddrStr)
	}
	if validRes.IsMine {
		t.Fatalf("Address incorrectly identified as mine: %s", devSubAddrStr)
	}
	// for ismine==false, nothing else to test

}

func testWalletPassphrase(r *Harness, t *testing.T) {
	// Wallet RPC client
	wcl := r.WalletRPC

	// Remember to leave the wallet unlocked for any subsequent tests
	defaultWalletPassphrase := "password"
	defer wcl.WalletPassphrase(defaultWalletPassphrase, 0)

	// Lock the wallet since test wallet is unlocked by default
	err := wcl.WalletLock()
	if err != nil {
		t.Fatal("Unable to lock wallet.")
	}

	// Check that wallet is locked
	walletInfo, err := wcl.WalletInfo()
	if err != nil {
		t.Fatal("walletinfo failed.")
	}
	if walletInfo.Unlocked {
		t.Fatal("WalletLock failed to lock the wallet")
	}

	// Try incorrect password
	err = wcl.WalletPassphrase("Wrong Password", 0)
	// Check for "-14: invalid passphrase for master private key"
	if err != nil && err.(*dcrjson.RPCError).Code !=
		dcrjson.ErrRPCWalletPassphraseIncorrect {
		// dcrjson.ErrWalletPassphraseIncorrect.Code
		t.Fatalf("WalletPassphrase with INCORRECT passphrase exited with: %v",
			err)
	}

	// Check that wallet is still locked
	walletInfo, err = wcl.WalletInfo()
	if err != nil {
		t.Fatal("walletinfo failed.")
	}
	if walletInfo.Unlocked {
		t.Fatal("WalletPassphrase unlocked the wallet with the wrong passphrase")
	}

	// Verify that a restricted operation like createnewaccount fails
	accountName := "cannotCreateThisAccount"
	err = wcl.CreateNewAccount(accountName)
	if err == nil {
		t.Fatal("createnewaccount succeeded on a locked wallet.")
	}
	// dcrjson.ErrRPCWalletUnlockNeeded
	if !strings.HasPrefix(err.Error(),
		strconv.Itoa(int(legacyrpc.ErrWalletUnlockNeeded.Code))) {
		t.Fatalf("createnewaccount returned error (%v) instead of %v",
			err, legacyrpc.ErrWalletUnlockNeeded.Code)
	}

	// Unlock with correct passphrase
	err = wcl.WalletPassphrase(defaultWalletPassphrase, 0)
	if err != nil {
		t.Fatalf("WalletPassphrase failed: %v", err)
	}

	// Check that wallet is now ulocked
	walletInfo, err = wcl.WalletInfo()
	if err != nil {
		t.Fatal("walletinfo failed.")
	}
	if !walletInfo.Unlocked {
		t.Fatal("WalletPassphrase failed to unlock the wallet with the correct passphrase")
	}

	// Check for ErrRPCWalletAlreadyUnlocked
	err = wcl.WalletPassphrase(defaultWalletPassphrase, 0)
	// Check for "-17: Wallet is already unlocked"
	if err != nil && err.(*dcrjson.RPCError).Code !=
		dcrjson.ErrRPCWalletAlreadyUnlocked {
		t.Fatalf("WalletPassphrase failed: %v", err)
	}

	// Re-lock wallet
	err = wcl.WalletLock()
	if err != nil {
		t.Fatal("Unable to lock wallet.")
	}

	// Unlock with timeout
	timeOut := int64(10)
	err = wcl.WalletPassphrase(defaultWalletPassphrase, timeOut)
	if err != nil {
		t.Fatalf("WalletPassphrase failed: %v", err)
	}

	// Check that wallet is now unlocked
	walletInfo, err = wcl.WalletInfo()
	if err != nil {
		t.Fatal("walletinfo failed.")
	}
	if !walletInfo.Unlocked {
		t.Fatal("WalletPassphrase failed to unlock the wallet with the correct passphrase")
	}

	time.Sleep(time.Duration(timeOut+2) * time.Second)

	// Check that wallet is now locked
	walletInfo, err = wcl.WalletInfo()
	if err != nil {
		t.Fatal("walletinfo failed.")
	}
	if walletInfo.Unlocked {
		t.Fatal("Wallet still unlocked after timeout")
	}

	// TODO: Watching-only error?
}

func testGetBalance(r *Harness, t *testing.T) {
	// Wallet RPC client
	wcl := r.WalletRPC

	accountName := "getBalanceTest"
	err := wcl.CreateNewAccount(accountName)
	if err != nil {
		t.Fatal(err)
	}

	// Grab a fresh address from the test account
	addr, err := r.WalletRPC.GetNewAddress(accountName)
	if err != nil {
		t.Fatal(err)
	}

	// Check invalid balance type
	balance, err := wcl.GetBalanceMinConfType(accountName, 0, "invalidBalanceType")
	// -4: unknown balance type 'invalidBalanceType', please use spendable, locked, all, or fullscan
	if err == nil {
		t.Fatalf("GetBalanceMinConfType failed to return non-nil error for invalid balance type: %v\n"+
			"balance: %v", err, balance)
	}

	// Check invalid account name
	balance, err = wcl.GetBalanceMinConfType("invalid account", 0, "spendable")
	// -4: account name 'invalid account' not found
	if err == nil {
		t.Fatalf("GetBalanceMinConfType failed to return non-nil error for invalid account name: %v", err)
	}

	// Check invalid minconf
	balance, err = wcl.GetBalanceMinConfType("default", -1, "spendable")
	if err == nil {
		t.Logf("GetBalanceMinConfType failed to return non-nil error for invalid minconf (-1)")
		// TODO: I think this is a bug in Store.balanceFullScan (tx.go), where
		// the check is minConf == 0 instead of minConf < 1
	}

	// Exercise all valid balance types
	balanceTypes := []string{"all", "spendable", "locked", "fullscan"}

	// Check initial balances, including "*" case
	initBalancesAllAccts := getBalances("*", balanceTypes, 0, t, wcl)
	initBalancesDefaultAcct := getBalances("default", balanceTypes, 0, t, wcl)
	initBalancesTestingAcct := getBalances(accountName, balanceTypes, 0, t, wcl)

	// For individual accounts (not "*"), spendable is fullscan
	if initBalancesDefaultAcct["spendable"] != initBalancesDefaultAcct["fullscan"] {
		t.Fatalf("For individual account, fullscan should equal spendable. %v != %v",
			initBalancesDefaultAcct["spendable"], initBalancesDefaultAcct["fullscan"])
	}

	// Send from default to test account
	sendAmount := dcrutil.Amount(700000000)
	wcl.SendFromMinConf("default", addr, sendAmount, 1)

	// After send, but before new block check mempool (minconf=0) balances
	postSendBalancesAllAccts := getBalances("*", balanceTypes, 0, t, wcl)
	postSendBalancesDefaultAcct := getBalances("default", balanceTypes, 0, t, wcl)
	postSendBalancesTestingAcct := getBalances(accountName, balanceTypes, 0, t, wcl)

	// Fees prevent easy exact comparison
	if initBalancesDefaultAcct["spendable"] <= postSendBalancesDefaultAcct["spendable"] {
		t.Fatalf("spendable balance of sending account not decreased: %v <= %v",
			initBalancesDefaultAcct["spendable"],
			postSendBalancesDefaultAcct["spendable"])
	}

	if sendAmount != (postSendBalancesTestingAcct["spendable"] - initBalancesTestingAcct["spendable"]) {
		t.Fatalf("spendable balance of receiving account not increased: %v >= %v",
			initBalancesTestingAcct["spendable"],
			postSendBalancesTestingAcct["spendable"])
	}

	// Make sure "*" account balance has decreased (fees)
	if postSendBalancesAllAccts["spendable"] >= initBalancesAllAccts["spendable"] {
		t.Fatalf("Total balanance over all accounts not decreased after send.")
	}

	// Test vanilla GetBalance()
	amtGetBalance, err := wcl.GetBalance("default")
	if err != nil {
		t.Fatal(err)
	}

	// For GetBalance(), default minconf=1, default balance type is spendable.
	// Check spendable balance of "default" account with minconf=1
	amtGetBalanceMinConf1TypeSpendable, err := wcl.GetBalanceMinConfType("default", 1, "spendable")
	if err != nil {
		t.Fatalf("GetBalanceMinConfType failed: %v", err)
	}

	if amtGetBalance != amtGetBalanceMinConf1TypeSpendable {
		t.Fatalf(`Balance from GetBalance("default") does not equal amount `+
			`from GetBalanceMinConfType: %v != %v`, amtGetBalance,
			amtGetBalanceMinConf1TypeSpendable)
	}

	// Verify minconf=1 balances of receiving account before/after new block
	// Before, getbalance minconf=1
	amtTestMinconf1BeforeBlock, err := wcl.GetBalanceMinConfType(accountName, 1, "spendable")
	if err != nil {
		t.Fatalf("GetBalanceMinConfType failed: %v", err)
	}

	// Mine 2 new blocks to validate tx
	newBestBlock(r, t)
	newBestBlock(r, t)

	// After, getbalance minconf=1
	amtTestMinconf1AfterBlock, err := wcl.GetBalanceMinConfType(accountName, 1, "spendable")
	if err != nil {
		t.Fatalf("GetBalanceMinConfType failed: %v", err)
	}

	// Verify that balance (minconf=1) has increased
	if sendAmount != (amtTestMinconf1AfterBlock - amtTestMinconf1BeforeBlock) {
		t.Fatalf(`Balance (minconf=1) not increased after new block: %v - %v != %v`,
			amtTestMinconf1AfterBlock, amtTestMinconf1BeforeBlock, sendAmount)
	}
}

func testListAccounts(r *Harness, t *testing.T) {
	// Wallet RPC client
	wcl := r.WalletRPC

	// Create a new account and verify that we can see it
	listBeforeCreateAccount, err := wcl.ListAccounts()
	if err != nil {
		t.Fatal("Failed to create new account ", err)
	}

	// New account
	accountName := "listaccountsTestAcct"
	err = wcl.CreateNewAccount(accountName)
	if err != nil {
		t.Fatal(err)
	}

	// Account list after creating new
	accountsBalancesDefault1, err := wcl.ListAccounts()
	if err != nil {
		t.Fatal(err)
	}

	// Verify that new account is in the list, with zero balance
	foundNewAcct := false
	for acct, amt := range accountsBalancesDefault1 {
		if _, ok := listBeforeCreateAccount[acct]; !ok {
			// Found new account.  Now check name and balance
			if amt != 0 {
				t.Fatalf("New account (%v) found with non-zero balance: %v",
					acct, amt)
			}
			if accountName == acct {
				foundNewAcct = true
				break
			}
			t.Fatalf("Found new account, %v; Expected %v", acct, accountName)
		}
	}
	if !foundNewAcct {
		t.Fatalf("Failed to find newly created account, %v.", accountName)
	}

	// Grab a fresh address from the test account
	addr, err := r.WalletRPC.GetNewAddress(accountName)
	if err != nil {
		t.Fatal(err)
	}

	// For ListAccountsCmd: MinConf *int `jsonrpcdefault:"1"`
	// Let's test that ListAccounts() is equivalent to explicit minconf=1
	accountsBalancesMinconf1, err := wcl.ListAccountsMinConf(1)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(accountsBalancesDefault1, accountsBalancesMinconf1) {
		t.Fatal("ListAccounts() returned different result from ListAccountsMinConf(1): ",
			accountsBalancesDefault1, accountsBalancesMinconf1)
	}

	// Get accounts with minconf=0 pre-send
	accountsBalancesMinconf0PreSend, err := wcl.ListAccountsMinConf(0)
	if err != nil {
		t.Fatal(err)
	}

	// Get balance of test account prior to a send
	acctBalancePreSend := accountsBalancesMinconf0PreSend[accountName]

	// Send from default to test account
	sendAmount := dcrutil.Amount(700000000)
	wcl.SendFromMinConf("default", addr, sendAmount, 1)

	// Get accounts with minconf=0 post-send
	accountsBalancesMinconf0PostSend, err := wcl.ListAccountsMinConf(0)
	if err != nil {
		t.Fatal(err)
	}

	// Get balance of test account prior to a send
	acctBalancePostSend := accountsBalancesMinconf0PostSend[accountName]

	// Check if reported balances match expectations
	if sendAmount != (acctBalancePostSend - acctBalancePreSend) {
		t.Fatalf("Test account balance not changed by expected amount after send: "+
			"%v -%v != %v", acctBalancePostSend, acctBalancePreSend, sendAmount)
	}

	// Verify minconf>0 works: list, mine, list

	// List BEFORE mining a block
	accountsBalancesMinconf1PostSend, err := wcl.ListAccountsMinConf(1)
	if err != nil {
		t.Fatal(err)
	}

	// Get balance of test account prior to a send
	acctBalanceMin1PostSend := accountsBalancesMinconf1PostSend[accountName]

	// Mine 2 new blocks to validate tx
	newBestBlock(r, t)
	newBestBlock(r, t)

	// List AFTER mining a block
	accountsBalancesMinconf1PostMine, err := wcl.ListAccountsMinConf(1)
	if err != nil {
		t.Fatal(err)
	}

	// Get balance of test account prior to a send
	acctBalanceMin1PostMine := accountsBalancesMinconf1PostMine[accountName]

	// Check if reported balances match expectations
	if sendAmount != (acctBalanceMin1PostMine - acctBalanceMin1PostSend) {
		t.Fatalf("Test account balance (minconf=1) not changed by expected "+
			"amount after new block: %v - %v != %v", acctBalanceMin1PostMine,
			acctBalanceMin1PostSend, sendAmount)
	}

	// Note that ListAccounts uses Store.balanceFullScan to handle a UTXO scan
	// for each specific account. We can compare against GetBalanceMinConfType.
	// Also, I think there is the same bug that allows negative minconf values,
	// but does not handle unconfirmed outputs the same way as minconf=0.

	GetBalancePostSend, err := wcl.GetBalanceMinConf(accountName, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Note that BFBalanceSpendable is used with GetBalanceMinConf (not Type),
	// which uses BFBalanceFullScan when a single account is specified.
	// Recall thet fullscan is used by listaccounts.

	if GetBalancePostSend != acctBalancePostSend {
		t.Fatalf("Balance for default account from GetBalanceMinConf does not "+
			"match balance from ListAccounts: %v != %v", GetBalancePostSend,
			acctBalancePostSend)
	}

	// Mine 2 blocks to validate the tx and clean up UTXO set
	newBestBlock(r, t)
	newBestBlock(r, t)
}

func testListUnspent(r *Harness, t *testing.T) {
	// Wallet RPC client
	wcl := r.WalletRPC

	// New account
	accountName := "listUnspentTestAcct"
	err := wcl.CreateNewAccount(accountName)
	if err != nil {
		t.Fatal(err)
	}

	// Grab an address from the test account
	addr, err := wcl.GetNewAddress(accountName)
	if err != nil {
		t.Fatal(err)
	}

	// UTXOs before send
	list, err := wcl.ListUnspent()
	if err != nil {
		t.Fatalf("failed to get utxos")
	}
	utxosBeforeSend := make(map[string]float64)
	for _, utxo := range list {
		// Get a OutPoint string in the form of hash:index
		outpointStr, err := getOutPointString(&utxo)
		if err != nil {
			t.Fatal(err)
		}
		// if utxo.Spendable ...
		utxosBeforeSend[outpointStr] = utxo.Amount
	}

	// Check Min/Maxconf arguments
	defaultMaxConf := 9999999

	listMin1MaxBig, err := wcl.ListUnspentMinMax(1, defaultMaxConf)
	if err != nil {
		t.Fatalf("failed to get utxos")
	}
	if !reflect.DeepEqual(list, listMin1MaxBig) {
		t.Fatal("Outputs from ListUnspent() and ListUnspentMinMax() do not match.")
	}

	// Grab an address from known unspents to test the filter
	refOut := list[0]
	PkScript, err := hex.DecodeString(refOut.ScriptPubKey)
	if err != nil {
		t.Fatalf("Failed to decode ScriptPubKey into PkScript.")
	}
	// The Address field is broken, including only one address, so don't use it
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		txscript.DefaultScriptVersion, PkScript, r.ActiveNet)
	if err != nil {
		t.Fatal("Failed to extract addresses from PkScript.")
	}
	// This may be helpful to debug ListUnspentResult Address field
	//t.Log(addrs)

	// List with all of the above address
	listAddressesKnown, err := wcl.ListUnspentMinMaxAddresses(1, defaultMaxConf, addrs)
	if err != nil {
		t.Fatalf("Failed to get utxos with addresses argument.")
	}

	// Check that there is at least one output for the input addresses
	// TODO: Better check?
	if len(listAddressesKnown) == 0 {
		t.Fatalf("Failed to find expected UTXOs with addresses.")
	}

	// Make sure each found output's txid:vout is in original list
	var foundTxID = false
	for _, listRes := range listAddressesKnown {
		// Get a OutPoint string in the form of hash:index
		outpointStr, err := getOutPointString(&listRes)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := utxosBeforeSend[outpointStr]; !ok {
			t.Fatalf("Failed to find TxID")
		}
		// Also verify that the txid of the reference output is in the list
		if listRes.TxID == refOut.TxID {
			foundTxID = true
		}
	}
	if !foundTxID {
		t.Fatal("Original TxID not found in list by addresses.")
	}

	// SendFromMinConf to addr
	amountToSend := dcrutil.Amount(700000000)
	txid, err := wcl.SendFromMinConf("default", addr, amountToSend, 0)
	if err != nil {
		t.Fatalf("sendfromminconf failed: %v", err)
	}

	newBestBlock(r, t)
	time.Sleep(2 * time.Second)
	// TODO: why is above necessary for GetRawTransaction to give a tx with
	// sensible MsgTx().TxIn[:].ValueIn values?

	// Get *dcrutil.Tx of send to check the inputs
	rawTx, err := r.Node.GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("getrawtransaction failed: %v", err)
	}

	// Get previous OutPoint of each TxIn for send transaction
	txInIDs := make(map[string]float64)
	for _, txIn := range rawTx.MsgTx().TxIn {
		prevOut := &txIn.PreviousOutPoint
		// Outpoint.String() appends :index to the hash
		txInIDs[prevOut.String()] = dcrutil.Amount(txIn.ValueIn).ToCoin()
	}
	//t.Log("Number of TxIns: ", len(txInIDs))

	// First check to make sure we see these in the UTXO list prior to send,
	// then not in the UTXO list after send.
	for txinID, amt := range txInIDs {
		if _, ok := utxosBeforeSend[txinID]; !ok {
			t.Fatalf("Failed to find txid %v (%v DCR) in list of UTXOs",
				txinID, amt)
		}
		// TODO: Is there a useful value/amount check?
	}

	// Validate the send Tx with 2 new blocks
	newBestBlock(r, t)
	newBestBlock(r, t)

	// Make sure these txInIDS are not in the new UTXO set
	time.Sleep(4 * time.Second)
	list, err = wcl.ListUnspent()
	if err != nil {
		t.Fatalf("Failed to get UTXOs")
	}
	for _, utxo := range list {
		// Get a OutPoint string in the form of hash:index
		outpointStr, err := getOutPointString(&utxo)
		if err != nil {
			t.Fatal(err)
		}
		if amt, ok := txInIDs[outpointStr]; ok {
			t.Fatalf("Found PreviousOutPoint of send still in UTXO set: %v, "+
				"%v DCR", outpointStr, amt)
		}
	}
}

func testSendToAddress(r *Harness, t *testing.T) {
	// Wallet RPC client
	wcl := r.WalletRPC

	// Grab a fresh address from the wallet.
	addr, err := wcl.GetNewAddress("default")
	if err != nil {
		t.Fatal(err)
	}

	// Check spendable balance of default account
	_, err = wcl.GetBalanceMinConfType("default", 1, "spendable")
	if err != nil {
		t.Fatalf("GetBalanceMinConfType failed: %v", err)
	}

	// SendToAddress
	txid, err := wcl.SendToAddress(addr, 1000000)
	if err != nil {
		t.Fatalf("SendToAddress failed: %v", err)
	}

	// Generate a single block, in which the transaction the wallet created
	// should be found.
	_, block, _ := newBestBlock(r, t)

	if len(block.Transactions()) <= 1 {
		t.Fatalf("expected transaction not included in block")
	}
	// Confirm that the expected tx was mined into the block.
	minedTx := block.Transactions()[1]
	txSha := minedTx.Sha()
	if !bytes.Equal(txid[:], txSha.Bytes()[:]) {
		t.Fatalf("txid's don't match, %v vs %v", txSha, txid)
	}

	// We should now check to confirm that the utxo that wallet used to create
	// that sendfrom was properly marked as spent and removed from utxo set.

	// Try this a different way, without another ListUnspent call.  Use
	// GetTxOut to tell if the outpoint is spent.

	// The spending transaction has to be off the tip block for the previous
	// outpoint to be spent, out of the UTXO set. Generate another block.
	_, err = r.GenerateBlock(block.MsgBlock().Header.Height)
	if err != nil {
		t.Fatal(err)
	}

	// Check each PreviousOutPoint for the sending tx.
	time.Sleep(2 * time.Second)
	// Get the sending Tx
	Tx, err := wcl.GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("Unable to get raw transaction %v: %v", txid, err)
	}
	// txid is rawTx.MsgTx().TxIn[0].PreviousOutPoint.Hash

	// Check all inputs
	for ii, txIn := range Tx.MsgTx().TxIn {
		prevOut := &txIn.PreviousOutPoint
		t.Logf("Checking previous outpoint %v, %v", ii, prevOut.String())

		// If a txout is spent (not in the UTXO set) GetTxOutResult will be nil
		res, _ := wcl.GetTxOut(&prevOut.Hash, prevOut.Index, false)
		if res != nil {
			t.Fatalf("Transaction output %v still unspent.", ii)
		}
	}
}

func testSendFrom(r *Harness, t *testing.T) {

	accountName := "sendFromTest"
	err := r.WalletRPC.CreateNewAccount(accountName)
	if err != nil {
		t.Fatal(err)
	}

	// Grab a fresh address from the wallet.
	addr, err := r.WalletRPC.GetNewAddress(accountName)
	if err != nil {
		t.Fatal(err)
	}

	amountToSend := dcrutil.Amount(1000000)
	// Check spendable balance of default account
	defaultBalanceBeforeSend, err := r.WalletRPC.GetBalanceMinConfType("default", 0, "all")
	if err != nil {
		t.Fatalf("getbalanceminconftype failed: %v", err)
	}

	// Get utxo list before send
	list, err := r.WalletRPC.ListUnspent()
	if err != nil {
		t.Fatalf("failed to get utxos")
	}
	utxosBeforeSend := make(map[string]float64)
	for _, utxo := range list {
		// Get a OutPoint string in the form of hash:index
		outpointStr, err := getOutPointString(&utxo)
		if err != nil {
			t.Fatal(err)
		}
		// if utxo.Spendable ...
		utxosBeforeSend[outpointStr] = utxo.Amount
	}

	// SendFromMinConf 1000 to addr
	txid, err := r.WalletRPC.SendFromMinConf("default", addr, amountToSend, 0)
	if err != nil {
		t.Fatalf("sendfromminconf failed: %v", err)
	}

	// Check spendable balance of default account
	defaultBalanceAfterSendNoBlock, err := r.WalletRPC.GetBalanceMinConfType("default", 0, "all")
	if err != nil {
		t.Fatalf("getbalanceminconftype failed: %v", err)
	}

	// Check balance of sendfrom account
	sendFromBalanceAfterSendNoBlock, err := r.WalletRPC.GetBalanceMinConfType(accountName, 0, "all")
	if err != nil {
		t.Fatalf("getbalanceminconftype failed: %v", err)
	}
	if sendFromBalanceAfterSendNoBlock != amountToSend {
		t.Fatalf("balance for %s account incorrect:  want %v got %v",
			accountName, amountToSend, sendFromBalanceAfterSendNoBlock)
	}

	// Generate a single block, the transaction the wallet created should
	// be found in this block.
	_, block, _ := newBestBlock(r, t)

	// Check to make sure the transaction that was sent was included in the block
	if len(block.Transactions()) <= 1 {
		t.Fatalf("expected transaction not included in block")
	}
	minedTx := block.Transactions()[1]
	txSha := minedTx.Sha()
	if !bytes.Equal(txid[:], txSha.Bytes()[:]) {
		t.Fatalf("txid's don't match, %v vs. %v (actual vs. expected)",
			txSha, txid)
	}

	// Generate another block, since it takes 2 blocks to validate a tx
	newBestBlock(r, t)

	// Get rawTx of sent txid so we can calculate the fee that was used
	time.Sleep(2 * time.Second)
	rawTx, err := r.WalletRPC.GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("getrawtransaction failed: %v", err)
	}

	var totalSpent int64
	for _, txIn := range rawTx.MsgTx().TxIn {
		totalSpent += txIn.ValueIn
	}

	var totalSent int64
	for _, txOut := range rawTx.MsgTx().TxOut {
		totalSent += txOut.Value
	}

	fee := dcrutil.Amount(totalSpent - totalSent)

	// Calculate the expected balance for the default account after the tx was sent
	expectedBalance := defaultBalanceBeforeSend - (amountToSend + fee)

	if expectedBalance != defaultBalanceAfterSendNoBlock {
		t.Fatalf("balance for %s account incorrect: want %v got %v", "default",
			expectedBalance, defaultBalanceAfterSendNoBlock)
	}

	time.Sleep(8 * time.Second)
	// Check balance of sendfrom account
	sendFromBalanceAfterSend1Block, err := r.WalletRPC.GetBalanceMinConfType(accountName, 1, "all")
	if err != nil {
		t.Fatalf("getbalanceminconftype failed: %v", err)
	}

	if sendFromBalanceAfterSend1Block != amountToSend {
		t.Fatalf("balance for %s account incorrect:  want %v got %v",
			accountName, amountToSend, sendFromBalanceAfterSend1Block)
	}

	// We have confirmed that the expected tx was mined into the block.
	// We should now check to confirm that the utxo that wallet used to create
	// that sendfrom was properly marked to spent and removed from utxo set.
	list, err = r.WalletRPC.ListUnspent()
	if err != nil {
		t.Fatal("Failed to get utxos")
	}
	for _, utxo := range list {
		if utxo.TxID == rawTx.MsgTx().TxIn[0].PreviousOutPoint.Hash.String() {
			t.Fatal("Found a utxo that should have been marked spent:", utxo.TxID)
		}
	}
}

func testSendMany(r *Harness, t *testing.T) {
	// Wallet RPC client
	wcl := r.WalletRPC

	// Create 2 accounts to receive funds
	accountNames := []string{"sendManyTestA", "sendManyTestB"}
	amountsToSend := []dcrutil.Amount{700000000, 1400000000}
	addresses := []dcrutil.Address{}

	var err error
	for _, acct := range accountNames {
		err = wcl.CreateNewAccount(acct)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Grab new addresses from the wallet, under each account.
	// Set corresponding amount to send to each address.
	addressAmounts := make(map[dcrutil.Address]dcrutil.Amount)
	//var totalAmountToSend dcrutil.Amount
	totalAmountToSend := dcrutil.Amount(0)

	for i, acct := range accountNames {
		addr, err := wcl.GetNewAddress(acct)
		if err != nil {
			t.Fatal(err)
		}

		// Set the amounts to send to each address
		addresses = append(addresses, addr)
		addressAmounts[addr] = amountsToSend[i]
		totalAmountToSend += amountsToSend[i]
	}

	// Check spendable balance of default account
	defaultBalanceBeforeSend, err := wcl.GetBalanceMinConfType("default", 0, "all")
	if err != nil {
		t.Fatalf("getbalanceminconftype failed: %v", err)
	}

	// SendMany to two addresses
	txid, err := wcl.SendMany("default", addressAmounts)
	if err != nil {
		t.Fatalf("sendmany failed: %v", err)
	}

	time.Sleep(2 * time.Second)
	// Check spendable balance of default account
	defaultBalanceAfterSendUnmined, err := r.WalletRPC.GetBalanceMinConfType("default", 0, "all")
	if err != nil {
		t.Fatalf("getbalanceminconftype failed: %v", err)
	}

	// Check balance of each receiving account
	for i, acct := range accountNames {
		bal, err := r.WalletRPC.GetBalanceMinConfType(acct, 0, "all")
		if err != nil {
			t.Fatalf("getbalanceminconftype failed: %v", err)
		}
		addr := addresses[i]
		if bal != addressAmounts[addr] {
			t.Fatalf("Balance for %s account incorrect:  want %v got %v",
				acct, addressAmounts[addr], bal)
		}
	}

	// Get rawTx of sent txid so we can calculate the fee that was used
	rawTx, err := r.Node.GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("getrawtransaction failed: %v", err)
	}
	fee := getWireMsgTxFee(rawTx)
	t.Log("Raw TX before mining block: ", rawTx, " Fee: ", fee)

	_, block, _ := newBestBlock(r, t)

	rawTx, err = r.Node.GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("getrawtransaction failed: %v", err)
	}
	fee = getWireMsgTxFee(rawTx)
	t.Log("Raw TX after mining block: ", rawTx, " Fee: ", fee)

	// Calculate the expected balance for the default account after the tx was sent
	expectedBalance := defaultBalanceBeforeSend - (totalAmountToSend + fee)

	if expectedBalance != defaultBalanceAfterSendUnmined {
		t.Fatalf("Balance for %s account (sender) incorrect: want %v got %v",
			"default", expectedBalance, defaultBalanceAfterSendUnmined)
	}

	// Generate a single block, the transaction the wallet created should
	// be found in this block.
	//_, block, _ := newBestBlock(r, t)

	// Check to make sure the transaction that was sent was included in the block
	if !includesTx(txid, block, r, t) {
		t.Fatalf("Expected transaction not included in block")
	}

	// Validate
	newBestBlock(r, t)

	// Check balance after confirmations
	for i, acct := range accountNames {
		balanceAcctValidated, err := wcl.GetBalanceMinConfType(acct, 1, "all")
		if err != nil {
			t.Fatalf("getbalanceminconftype failed: %v", err)
		}

		addr := addresses[i]
		if balanceAcctValidated != addressAmounts[addr] {
			t.Fatalf("Balance for %s account incorrect:  want %v got %v",
				acct, addressAmounts[addr], balanceAcctValidated)
		}
	}

	// Check all inputs
	for ii, txIn := range rawTx.MsgTx().TxIn {
		prevOut := &txIn.PreviousOutPoint
		//t.Logf("Checking previous outpoint %v, %v", ii, prevOut.String())

		// If a txout is spent (not in the UTXO set) GetTxOutResult will be nil
		res, _ := wcl.GetTxOut(&prevOut.Hash, prevOut.Index, false)
		if res != nil {
			t.Fatalf("Transaction output %v still unspent.", ii)
		}
	}
}

func testListTransactions(r *Harness, t *testing.T) {
	// Wallet RPC client
	wcl := r.WalletRPC

	// List latest transaction
	txList1, err := wcl.ListTransactionsCount("*", 1)
	if err != nil {
		t.Fatal("ListTransactionsCount failed:", err)
	}

	// Verify that only one returned (a PoW coinbase since this is a fresh
	// harness with only blocks generated and no other transactions).
	if len(txList1) != 1 {
		t.Fatalf("Transaction list not len=1: %d", len(txList1))
	}

	// Verify paid to miningAddr
	if txList1[0].Address != r.miningAddr.String() {
		t.Fatalf("Unexpected address in latest transaction: %v",
			txList1[0].Address)
	}

	// Verify that it is a coinbase
	if !txList1[0].Generated {
		t.Fatal("Latest transaction output not a coinbase output.")
	}

	// Not "generate" category until mature
	if txList1[0].Category != "immature" {
		t.Fatalf("Latest transaction not immature. Category: %v",
			txList1[0].Category)
	}

	// Verify blockhash is non-nil and valid
	hash, err := chainhash.NewHashFromStr(txList1[0].BlockHash)
	if err != nil {
		t.Fatal("Blockhash not valid")
	}
	_, err = wcl.GetBlock(hash)
	if err != nil {
		t.Fatal("Blockhash does not refer to valid block")
	}

	// "regular" not "stake" txtype
	if *txList1[0].TxType != dcrjson.LTTTRegular {
		t.Fatal(`txtype not "regular".`)
	}

	// ListUnspent only shows validated (confirmations>=2) coinbase tx, so the
	// first result should have 2 confirmations.
	if txList1[0].Confirmations != 2 {
		t.Fatalf("Latest coinbase tx listed has %v confirmations, expected 2.",
			txList1[0].Confirmations)
	}

	// Check txid
	txid, err := chainhash.NewHashFromStr(txList1[0].TxID)
	if err != nil {
		t.Fatal("Invalid Txid: ", err)
	}

	rawTx, err := wcl.GetRawTransaction(txid)
	if err != nil {
		t.Fatal("Invalid Txid: ", err)
	}

	// Use Vout from listtransaction to index []TxOut from getrawtransaction.
	if len(rawTx.MsgTx().TxOut) <= int(txList1[0].Vout) {
		t.Fatal("Too few vouts.")
	}
	txOut := rawTx.MsgTx().TxOut[txList1[0].Vout]
	voutAmt := dcrutil.Amount(txOut.Value).ToCoin()
	// Verify amounts agree
	if txList1[0].Amount != voutAmt {
		t.Fatalf("Listed amount %v does not match expected vout amount %v",
			txList1[0].Amount, voutAmt)
	}

	// Test number of transactions (count).  With only coinbase in this harness,
	// length of result slice should be equal to number requested.
	txList2, err := wcl.ListTransactionsCount("*", 2)
	if err != nil {
		t.Fatal("ListTransactionsCount failed:", err)
	}

	// With only coinbase transactions, there will only be one result per tx
	if len(txList2) != 2 {
		t.Fatalf("Expected 2 transactions, got %v", len(txList2))
	}

	// List all transactions
	txListAllInit, err := wcl.ListTransactionsCount("*", 9999999)
	if err != nil {
		t.Fatal("ListTransactionsCount failed:", err)
	}
	initNumTx := len(txListAllInit)

	// Send within wallet, and check for both send and receive parts of tx.
	accountName := "listTransactionsTest"
	if wcl.CreateNewAccount(accountName) != nil {
		t.Fatal("Failed to create account for listtransactions test")
	}

	addr, err := wcl.GetNewAddress(accountName)
	if err != nil {
		t.Fatal("Failed to get new address.")
	}

	sendAmount := dcrutil.Amount(240000000)
	txHash, err := wcl.SendFromMinConf("default", addr, sendAmount, 6)
	if err != nil {
		t.Fatal("Failed to send:", err)
	}

	// Number of results should be +3 now
	txListAll, err := wcl.ListTransactionsCount("*", 9999999)
	if err != nil {
		t.Fatal("ListTransactionsCount failed:", err)
	}
	// Expect 3 more results in the list: a receive for the owned address in
	// the amount sent, a send in the amount sent, and the a send from the
	// original outpoint for the mined coins.
	expectedAdditional := 3
	if len(txListAll) != initNumTx+expectedAdditional {
		t.Fatalf("Expected %v listtransactions results, got %v", initNumTx+expectedAdditional,
			len(txListAll))
	}

	// The top of the list should be one send and one receive.  The coinbase
	// spend should be lower in the list.
	var sendResult, recvResult dcrjson.ListTransactionsResult
	if txListAll[0].Category == txListAll[1].Category {
		t.Fatal("Expected one send and one receive, got two", txListAll[0].Category)
	}
	// Use a map since order doesn't matter, and keys are not duplicate
	rxtxResults := map[string]dcrjson.ListTransactionsResult{
		txListAll[0].Category: txListAll[0],
		txListAll[1].Category: txListAll[1],
	}
	var ok bool
	if sendResult, ok = rxtxResults["send"]; !ok {
		t.Fatal("Expected send transaction not found.")
	}
	if recvResult, ok = rxtxResults["receive"]; !ok {
		t.Fatal("Expected receive transaction not found.")
	}

	// Verify send result amount
	if sendResult.Amount != -sendAmount.ToCoin() {
		t.Fatalf("Listed send tx amount incorrect. Expected %v, got %v",
			-sendAmount.ToCoin(), sendResult.Amount)
	}

	// Verify send result fee
	if sendResult.Fee == nil {
		t.Fatal("Fee in send tx result is nil.")
	}

	// Now that there's a new Tx on top, skip back to previoius transaction
	// using from=1
	txList1New, err := wcl.ListTransactionsCountFrom("*", 1, 1)
	if err != nil {
		t.Fatal("Failed to listtransactions:", err)
	}

	// Should be equal to earlier result with implicit from=0
	if !reflect.DeepEqual(txList1, txList1New) {
		t.Fatal("Listtransaction results not equal.")
	}

	// Get rawTx of sent txid so we can calculate the fee that was used
	newBestBlock(r, t) // or getrawtransaction is wrong
	rawTx, err = r.Node.GetRawTransaction(txHash)
	if err != nil {
		t.Fatalf("getrawtransaction failed: %v", err)
	}

	expectedFee := getWireMsgTxFee(rawTx).ToCoin()
	gotFee := -*sendResult.Fee
	if gotFee != expectedFee {
		t.Fatalf("Expected fee %v, got %v", expectedFee, gotFee)
	}

	// Verify receive results amount
	if recvResult.Amount != sendAmount.ToCoin() {
		t.Fatalf("Listed send tx amount incorrect. Expected %v, got %v",
			sendAmount.ToCoin(), recvResult.Amount)
	}

	// Verify TxID in both send and receive results
	txstr := txHash.String()
	if sendResult.TxID != txstr {
		t.Fatalf("TxID in send tx result was %v, expected %v.",
			sendResult.TxID, txstr)
	}
	if recvResult.TxID != txstr {
		t.Fatalf("TxID in receive tx result was %v, expected %v.",
			recvResult.TxID, txstr)
	}

	// Should only accept "*" account
	_, err = wcl.ListTransactions("default")
	if err == nil {
		t.Fatal(`Listtransactions should only work on "*" account. "default" succeeded.`)
	}

	txList0, err := wcl.ListTransactionsCount("*", 0)
	if err != nil {
		t.Fatal("listtransactions failed:", err)
	}
	if len(txList0) != 0 {
		t.Fatal("Length of listransactions result not zero:", len(txList0))
	}

	txListAll, err = wcl.ListTransactionsCount("*", 99999999)

	// Create 2 accounts to receive funds
	accountNames := []string{"listTxA", "listTxB"}
	amountsToSend := []dcrutil.Amount{700000000, 1400000000}
	addresses := []dcrutil.Address{}

	for _, acct := range accountNames {
		err := wcl.CreateNewAccount(acct)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Grab new addresses from the wallet, under each account.
	// Set corresponding amount to send to each address.
	addressAmounts := make(map[dcrutil.Address]dcrutil.Amount)
	//var totalAmountToSend dcrutil.Amount
	totalAmountToSend := dcrutil.Amount(0)

	for i, acct := range accountNames {
		addr, err := wcl.GetNewAddress(acct)
		if err != nil {
			t.Fatal(err)
		}

		// Set the amounts to send to each address
		addresses = append(addresses, addr)
		addressAmounts[addr] = amountsToSend[i]
		totalAmountToSend += amountsToSend[i]
	}

	// SendMany to two addresses
	_, err = wcl.SendMany("default", addressAmounts)
	if err != nil {
		t.Fatalf("sendmany failed: %v", err)
	}

	// This should add 5 results: coinbase send, 2 receives, 2 sends
	listSentMany, err := wcl.ListTransactionsCount("*", 99999999)
	if err != nil {
		t.Fatal(`Listtransactions failed.`)
	}
	if len(listSentMany) != len(txListAll)+5 {
		t.Fatalf("Expected %v tx results, got %v", len(txListAll)+5,
			len(listSentMany))
	}
}

func testGetSetRelayFee(r *Harness, t *testing.T) {
	// dcrrpcclient does not have a getwalletfee or any direct method, so we
	// need to use walletinfo to get.  SetTxFee can be used to set.

	// Wallet RPC client
	wcl := r.WalletRPC

	// Increase the ticket fee so these SSTx get mined first
	walletInfo, err := wcl.WalletInfo()
	if err != nil {
		t.Fatal("WalletInfo failed:", err)
	}
	// Save the original fee
	origTxFee, err := dcrutil.NewAmount(walletInfo.TxFee)
	if err != nil {
		t.Fatal("Invalid Amount:", walletInfo.TxFee)
	}
	// Increase fee by 50%
	newTxFeeCoin := walletInfo.TxFee * 1.5
	newTxFee, _ := dcrutil.NewAmount(newTxFeeCoin)
	if err != nil {
		t.Fatal("Invalid Amount:", newTxFeeCoin)
	}

	err = wcl.SetTxFee(newTxFee)
	if err != nil {
		t.Fatal("SetTxFee failed:", err)
	}

	// Check that wallet thinks the fee is as expected
	walletInfo, err = wcl.WalletInfo()
	if err != nil {
		t.Fatal("WalletInfo failed:", err)
	}
	newTxFeeActual, err := dcrutil.NewAmount(walletInfo.TxFee)
	if err != nil {
		t.Fatal("Invalid Amount:", walletInfo.TxFee)
	}
	if newTxFee != newTxFeeActual {
		t.Fatalf("Expected tx fee %v, got %v.", newTxFee, newTxFeeActual)
	}

	// Create a transaction and compute the effective fee
	accountName := "testGetSetRelayFee"
	err = wcl.CreateNewAccount(accountName)
	if err != nil {
		t.Fatal("Failed to create account.")
	}

	// Grab a fresh address from the test account
	addr, err := r.WalletRPC.GetNewAddress(accountName)
	if err != nil {
		t.Fatal(err)
	}

	// SendFromMinConf to addr
	amountToSend := dcrutil.Amount(700000000)
	txid, err := wcl.SendFromMinConf("default", addr, amountToSend, 0)
	if err != nil {
		t.Fatalf("sendfromminconf failed: %v", err)
	}

	newBestBlock(r, t)
	time.Sleep(2 * time.Second)
	// Give the tx a sensible MsgTx().TxIn[:].ValueIn values

	// Compute the fee
	rawTx, err := r.Node.GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("getrawtransaction failed: %v", err)
	}

	fee := getWireMsgTxFee(rawTx)
	feeRate := fee.ToCoin() / float64(rawTx.MsgTx().SerializeSize()) * 1000

	// Ensure actual fee is at least nominal
	t.Logf("Set relay fee: %v, actual: %v", walletInfo.TxFee, feeRate)
	if feeRate < walletInfo.TxFee {
		t.Errorf("Regular tx fee rate difference (actual-set) too high: %v",
			walletInfo.TxFee-feeRate)
	}

	// Negative fee should throw an error
	err = wcl.SetTxFee(dcrutil.Amount(-1))
	if err == nil {
		t.Fatal("SetTxFee accepted negative fee")
	}

	// Set it back
	err = wcl.SetTxFee(origTxFee)
	if err != nil {
		t.Fatal("SetTxFee failed:", err)
	}

	// Validate last tx before we complete
	newBestBlock(r, t)
}

func testGetSetTicketFee(r *Harness, t *testing.T) {
	// dcrrpcclient does not have a getticketee or any direct method, so we
	// need to use walletinfo to get.  SetTicketFee can be used to set.

	// Wallet RPC client
	wcl := r.WalletRPC

	// Get the current ticket fee
	walletInfo, err := wcl.WalletInfo()
	if err != nil {
		t.Fatal("WalletInfo failed:", err)
	}
	nominalTicketFee := walletInfo.TicketFee
	origTicketFee, err := dcrutil.NewAmount(nominalTicketFee)
	if err != nil {
		t.Fatal("Invalid Amount:", nominalTicketFee)
	}

	// Increase the ticket fee to ensure the SSTx in ths test gets mined
	newTicketFeeCoin := nominalTicketFee * 1.5
	newTicketFee, _ := dcrutil.NewAmount(newTicketFeeCoin)
	if err != nil {
		t.Fatal("Invalid Amount:", newTicketFeeCoin)
	}

	err = wcl.SetTicketFee(newTicketFee)
	if err != nil {
		t.Fatal("SetTicketFee failed:", err)
	}

	// Check that wallet is set to use the new fee
	walletInfo, err = wcl.WalletInfo()
	if err != nil {
		t.Fatal("WalletInfo failed:", err)
	}
	nominalTicketFee = walletInfo.TicketFee
	newTicketFeeActual, err := dcrutil.NewAmount(nominalTicketFee)
	if err != nil {
		t.Fatal("Invalid Amount:", nominalTicketFee)
	}
	if newTicketFee != newTicketFeeActual {
		t.Fatalf("Expected ticket fee %v, got %v.", newTicketFee,
			newTicketFeeActual)
	}

	// Purchase ticket
	minConf, numTicket := 0, 1
	hashes, err := wcl.PurchaseTicket("default", 100000000,
		&minConf, nil, &numTicket, nil, nil, nil)
	if err != nil {
		t.Fatal("Unable to purchase with nil ticketAddr:", err)
	}
	if len(hashes) != 1 {
		t.Fatal("More than one tx hash returned. Expected one.")
	}

	// Need 2 blocks or the vin is incorrect in getrawtransaction
	// Not yet at StakeValidationHeight, so no voting.
	newBestBlock(r, t)
	newBestBlock(r, t)
	time.Sleep(2 * time.Second)

	// Compute the actual fee for the ticket purchase
	rawTx, err := wcl.GetRawTransaction(hashes[0])
	if err != nil {
		t.Fatal("Invalid Txid:", err)
	}

	fee := getWireMsgTxFee(rawTx)
	feeRate := fee.ToCoin() / float64(rawTx.MsgTx().SerializeSize()) * 1000

	// Ensure actual fee is at least nominal
	t.Logf("Set ticket fee: %v, actual: %v", nominalTicketFee, feeRate)
	if feeRate < nominalTicketFee {
		t.Errorf("Ticket fee rate difference (actual-set) too high: %v",
			nominalTicketFee-feeRate)
	}

	// Negative fee should throw and error
	err = wcl.SetTicketFee(dcrutil.Amount(-1))
	if err == nil {
		t.Fatal("SetTicketFee accepted negative fee")
	}

	// Set it back
	err = wcl.SetTicketFee(origTicketFee)
	if err != nil {
		t.Fatal("SetTicketFee failed:", err)
	}

	// Validate last tx before we complete
	newBestBlock(r, t)
}

func testPurchaseTickets(r *Harness, t *testing.T) {
	// Wallet.purchaseTicket() in wallet/createtx.go

	// Wallet RPC client
	wcl := r.WalletRPC

	// Grab a fresh address from the wallet.
	addr, err := wcl.GetNewAddress("default")
	if err != nil {
		t.Fatal(err)
	}

	// Set various variables for the test
	minConf := 0
	expiry := 0

	// Test nil ticketAddress
	oneTix := 1
	hashes, err := wcl.PurchaseTicket("default", 100000000,
		&minConf, nil, &oneTix, nil, nil, &expiry)
	if err != nil {
		t.Fatal("Unable to purchase with nil ticketAddr:", err)
	}
	if len(hashes) != 1 {
		t.Fatal("More than one tx hash returned purchasing single ticket.")
	}
	_, err = wcl.GetRawTransaction(hashes[0])
	if err != nil {
		t.Fatal("Invalid Txid:", err)
	}

	// test numTickets == nil
	hashes, err = wcl.PurchaseTicket("default", 100000000,
		&minConf, nil, nil, nil, nil, &expiry)
	if err != nil {
		t.Fatal("Unable to purchase with nil numTickets:", err)
	}
	if len(hashes) != 1 {
		t.Fatal("More than one tx hash returned. Expected one.")
	}
	_, err = wcl.GetRawTransaction(hashes[0])
	if err != nil {
		t.Fatal("Invalid Txid:", err)
	}

	// Get current blockheight to make sure chain is at the desiredHeight
	curBlockHeight, _, _ := getBestBlock(r, t)

	// Test expiry - earliest is next height + 1
	// invalid
	expiry = int(curBlockHeight)
	_, err = wcl.PurchaseTicket("default", 100000000,
		&minConf, nil, nil, nil, nil, &expiry)
	if err == nil {
		t.Fatal("Invalid expiry used to purchase tickets")
	}
	// invalid
	expiry = int(curBlockHeight) + 1
	_, err = wcl.PurchaseTicket("default", 100000000,
		&minConf, nil, nil, nil, nil, &expiry)
	if err == nil {
		t.Fatal("Invalid expiry used to purchase tickets")
	}

	// valid expiry
	expiry = int(curBlockHeight) + 2
	hashes, err = wcl.PurchaseTicket("default", 100000000,
		&minConf, nil, nil, nil, nil, &expiry)
	if err != nil {
		t.Fatal("Unable to purchase tickets:", err)
	}
	if len(hashes) != 1 {
		t.Fatal("More than one tx hash returned. Expected one.")
	}
	ticketWithExpiry := hashes[0]
	_, err = wcl.GetRawTransaction(ticketWithExpiry)
	if err != nil {
		t.Fatal("Invalid Txid:", err)
	}

	// Now purchase 2 blocks worth of tickets to be mined before the above
	// ticket with an expiry 2 blocks away.

	// Increase the ticket fee so these SSTx get mined first
	walletInfo, _ := wcl.WalletInfo()
	origTicketFee, _ := dcrutil.NewAmount(walletInfo.TicketFee)
	newTicketFee, _ := dcrutil.NewAmount(walletInfo.TicketFee * 1.5)

	wcl.SetTicketFee(newTicketFee)

	expiry = 0
	numTicket := 2 * int(chaincfg.SimNetParams.MaxFreshStakePerBlock)
	_, err = r.WalletRPC.PurchaseTicket("default", 100000000,
		&minConf, addr, &numTicket, nil, nil, &expiry)
	if err != nil {
		t.Fatal("Unable to purchase tickets:", err)
	}

	wcl.SetTicketFee(origTicketFee)

	// Check for the ticket
	_, err = wcl.GetTransaction(ticketWithExpiry)
	if err != nil {
		t.Fatal("Ticket not found:", err)
	}

	// Mine 2 blocks, should include the higher fee tickets with no expiry
	curBlockHeight, _, _ = newBlockAt(curBlockHeight, r, t)
	curBlockHeight, _, _ = newBlockAt(curBlockHeight, r, t)

	// Ticket with expiry set should now be expired (unmined and removed from
	// mempool)
	// ticketsWithoutExired, err := wcl.GetTickets(true)
	// for _, ticket := range ticketsWithoutExired {
	// 	if ticket == ticketWithExpiry {
	// 		t.Fatal("Expired ticket found:", ticketWithExpiry)
	// 	}
	// }
	// An unmined and expired tx should have been removed/pruned
	//tx, err := wcl.GetRawTransaction(ticketWithExpiry)
	txRawVerbose, err := wcl.GetRawTransactionVerbose(ticketWithExpiry)
	if err == nil {
		t.Fatalf("Found transaction that should be expired (blockHeight %v): %v",
			txRawVerbose.BlockHeight, err)
	}

	// NOTE: ticket maturity = 16 (spendable at 17), stakeenabled height = 144
	// Must have tickets purchased before block 128
	//ticketMaturity := chaincfg.SimNetParams.TicketMaturity
	//stakeValidationHeight := chaincfg.SimNetParams.StakeValidationHeight

	// Keep generating blocks until desiredHeight is achieved
	desiredHeight := uint32(150)
	expiry = 0
	numTicket = 1
	for curBlockHeight < desiredHeight {
		_, err = r.WalletRPC.PurchaseTicket("default", 100000000,
			&minConf, addr, &numTicket, nil, nil, &expiry)

		// allow ErrSStxPriceExceedsSpendLimit
		if err != nil && wallet.ErrSStxPriceExceedsSpendLimit.Error() !=
			err.(*dcrjson.RPCError).Message {
			t.Fatal(err)
		}
		curBlockHeight, _, _ = newBlockAtQuick(curBlockHeight, r, t)
		time.Sleep(600 * time.Millisecond)
	}

	// TODO: test pool fees

	// Validate last tx
	newBestBlock(r, t)
}

///////////////////////////////////////////////////////////////////////////////
// Helper functions

func newBlockAt(currentHeight uint32, r *Harness,
	t *testing.T) (uint32, *dcrutil.Block, []*chainhash.Hash) {
	height, block, blockHashes := newBlockAtQuick(currentHeight, r, t)

	time.Sleep(1500 * time.Millisecond)

	return height, block, blockHashes
}

func newBlockAtQuick(currentHeight uint32, r *Harness,
	t *testing.T) (uint32, *dcrutil.Block, []*chainhash.Hash) {

	blockHashes, err := r.GenerateBlock(currentHeight)
	if err != nil {
		t.Fatalf("Unable to generate single block: %v", err)
	}

	block, err := r.Node.GetBlock(blockHashes[0])
	if err != nil {
		t.Fatalf("Unable to get block: %v", err)
	}

	height := block.MsgBlock().Header.Height

	return height, block, blockHashes
}

func getBestBlock(r *Harness, t *testing.T) (uint32, *dcrutil.Block, *chainhash.Hash) {
	bestBlockHash, err := r.Node.GetBestBlockHash()
	if err != nil {
		t.Fatalf("Unable to get best block hash: %v", err)
	}
	bestBlock, err := r.Node.GetBlock(bestBlockHash)
	if err != nil {
		t.Fatalf("Unable to get block: %v", err)
	}
	curBlockHeight := bestBlock.MsgBlock().Header.Height

	return curBlockHeight, bestBlock, bestBlockHash
}

func newBestBlock(r *Harness,
	t *testing.T) (uint32, *dcrutil.Block, []*chainhash.Hash) {
	height, _, _ := getBestBlock(r, t)
	height, block, blockHash := newBlockAt(height, r, t)
	return height, block, blockHash
}

func getBalances(account string, balanceTypes []string, minConf int,
	t *testing.T, wcl *dcrrpcclient.Client) map[string]dcrutil.Amount {

	balances := make(map[string]dcrutil.Amount)

	for _, balType := range balanceTypes {

		balance, err := wcl.GetBalanceMinConfType(account, 0, balType)
		if err != nil {
			t.Fatalf("getbalanceminconftype failed: %v", err)
		}
		balances[balType] = balance
	}

	return balances
}

// includesTx checks if a block contains a transaction hash
func includesTx(txHash *chainhash.Hash, block *dcrutil.Block,
	r *Harness, t *testing.T) bool {

	if len(block.Transactions()) <= 1 {
		return false
	}

	blockTxs := block.Transactions()

	for _, minedTx := range blockTxs {
		txSha := minedTx.Sha()
		if bytes.Equal(txHash[:], txSha.Bytes()[:]) {
			return true
		}
	}

	return false
}

// getWireMsgTxFee computes the effective absolute fee from a Tx as the amount
// spent minus sent.
func getWireMsgTxFee(tx *dcrutil.Tx) dcrutil.Amount {
	var totalSpent int64
	for _, txIn := range tx.MsgTx().TxIn {
		totalSpent += txIn.ValueIn
	}

	var totalSent int64
	for _, txOut := range tx.MsgTx().TxOut {
		totalSent += txOut.Value
	}

	return dcrutil.Amount(totalSpent - totalSent)
}

// getOutPointString uses OutPoint.String() to combine the tx hash with vout
// index from a ListUnspentResult.
func getOutPointString(utxo *dcrjson.ListUnspentResult) (string, error) {
	txhash, err := chainhash.NewHashFromStr(utxo.TxID)
	if err != nil {
		return "", err
	}
	return wire.NewOutPoint(txhash, utxo.Vout, utxo.Tree).String(), nil
}
