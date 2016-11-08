// Copyright (c) 2016 The decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
package rpctest

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/blockchain"
	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrrpcclient"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/rpc/legacyrpc"
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
	testGetTickets,
	testPurchaseTickets,
	testGetSetTicketMaxPrice,
	testGetSetBalanceToMaintain,
	testGetStakeInfo,
	testWalletInfo,
}

// Not all tests need their own harness. Indicate here which get a dedicaed
// harness, and use a map from function name to assigned harness.
var primaryHarness *Harness
var harnesses = make(map[string]*Harness)
var needOwnHarness = map[string]bool{
	"testGetNewAddress":           false,
	"testValidateAddress":         false,
	"testWalletPassphrase":        false,
	"testGetBalance":              false,
	"testListAccounts":            false,
	"testListUnspent":             false,
	"testSendToAddress":           false,
	"testSendFrom":                false,
	"testListTransactions":        true,
	"testGetSetRelayFee":          false,
	"testGetSetTicketFee":         false,
	"testPurchaseTickets":         false,
	"testGetTickets":              false,
	"testGetSetTicketMaxPrice":    false,
	"testGetSetBalanceToMaintain": false,
	"testGetStakeInfo":            true,
	"testWalletInfo":              false,
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
	// For timing of block generation, create an OnBlockConnected notification
	ntfnHandlersNode := dcrrpcclient.NotificationHandlers{
		OnBlockConnected: func(blockHeader []byte, transactions [][]byte) {},
	}

	var gracefulExit = func(code int) {
		if err := primaryHarness.TearDown(); err != nil {
			fmt.Println("Unable to teardown test chain: ", err)
			code = 1
		}

		for _, h := range harnesses {
			if h.IsUp() {
				if err := h.TearDown(); err != nil {
					fmt.Println("Unable to teardown test chain: ", err)
					code = 1
				}
			}
		}

		os.Exit(code)
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
				gracefulExit(1)
			}

			if err = harness.SetUp(true, 25); err != nil {
				fmt.Println("Unable to setup test chain: ", err)
				err = harness.TearDown()
				gracefulExit(1)
			}
		}
		harnesses[tcName] = harness
	}

	// Run the tests
	exitCode := m.Run()

	// Clean up the primary harness created above. This includes removing
	// all temporary directories, and shutting down any created processes.
	gracefulExit(exitCode)
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
	devSubPkScript := chaincfg.SimNetParams.OrganizationPkScript // "ScuQxvveKGfpG1ypt6u27F99Anf7EW3cqhq"
	devSubPkScrVer := chaincfg.SimNetParams.OrganizationPkScriptVersion
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		devSubPkScrVer, devSubPkScript, r.ActiveNet)
	if err != nil {
		t.Fatal("Failed to extract addresses from PkScript:", err)
	}
	devSubAddrStr := addrs[0].String()

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
	defer func() {
		if err := wcl.WalletPassphrase(defaultWalletPassphrase, 0); err != nil {
			t.Fatal("Unable to unlock wallet:", err)
		}
	}()

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
	timeOut := int64(6)
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
	_, err = wcl.GetBalanceMinConfType("invalid account", 0, "spendable")
	// -4: account name 'invalid account' not found
	if err == nil {
		t.Fatalf("GetBalanceMinConfType failed to return non-nil error for invalid account name: %v", err)
	}

	// Check invalid minconf
	_, err = wcl.GetBalanceMinConfType("default", -1, "spendable")
	if err == nil {
		t.Logf("GetBalanceMinConfType failed to return non-nil error for invalid minconf (-1)")
		// TODO: This is a bug in Store.balanceFullScan (tx.go), where the check
		// is minConf == 0 instead of minConf < 1
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
	if _, err = wcl.SendFromMinConf("default", addr, sendAmount, 1); err != nil {
		t.Fatal("SendFromMinConf failed.", err)
	}

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
	if _, err = wcl.SendFromMinConf("default", addr, sendAmount, 1); err != nil {
		t.Fatal("SendFromMinConf failed.", err)
	}

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
		t.Fatal("Failed to extract addresses from PkScript:", err)
	}

	// List with all of the above address
	listAddressesKnown, err := wcl.ListUnspentMinMaxAddresses(1, defaultMaxConf, addrs)
	if err != nil {
		t.Fatalf("Failed to get utxos with addresses argument.")
	}

	// Check that there is at least one output for the input addresses
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
	time.Sleep(1 * time.Second)
	// New block is necessary for GetRawTransaction to give a tx with sensible
	// MsgTx().TxIn[:].ValueIn values.

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

	// First check to make sure we see these in the UTXO list prior to send,
	// then not in the UTXO list after send.
	for txinID, amt := range txInIDs {
		if _, ok := utxosBeforeSend[txinID]; !ok {
			t.Fatalf("Failed to find txid %v (%v DCR) in list of UTXOs",
				txinID, amt)
		}
	}

	// Validate the send Tx with 2 new blocks
	newBestBlock(r, t)
	newBestBlock(r, t)

	// Make sure these txInIDS are not in the new UTXO set
	time.Sleep(2 * time.Second)
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
	// that sendfrom was properly marked as spent and removed from utxo set. Use
	// GetTxOut to tell if the outpoint is spent.
	//
	// The spending transaction has to be off the tip block for the previous
	// outpoint to be spent, out of the UTXO set. Generate another block.
	_, err = r.GenerateBlock(block.MsgBlock().Header.Height)
	if err != nil {
		t.Fatal(err)
	}

	// Check each PreviousOutPoint for the sending tx.
	time.Sleep(1 * time.Second)
	// Get the sending Tx
	rawTx, err := wcl.GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("Unable to get raw transaction %v: %v", txid, err)
	}
	// txid is rawTx.MsgTx().TxIn[0].PreviousOutPoint.Hash

	// Check all inputs
	for i, txIn := range rawTx.MsgTx().TxIn {
		prevOut := &txIn.PreviousOutPoint
		t.Logf("Checking previous outpoint %v, %v", i, prevOut.String())

		// If a txout is spent (not in the UTXO set) GetTxOutResult will be nil
		res, err := wcl.GetTxOut(&prevOut.Hash, prevOut.Index, false)
		if err != nil {
			t.Fatal("GetTxOut failure:", err)
		}
		if res != nil {
			t.Fatalf("Transaction output %v still unspent.", i)
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
	time.Sleep(1 * time.Second)
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

	// Get the sending Tx
	rawTx, err = r.WalletRPC.GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("Unable to get raw transaction %v: %v", txid, err)
	}

	// Check all inputs
	for i, txIn := range rawTx.MsgTx().TxIn {
		prevOut := &txIn.PreviousOutPoint

		// If a txout is spent (not in the UTXO set) GetTxOutResult will be nil
		res, err := r.WalletRPC.GetTxOut(&prevOut.Hash, prevOut.Index, false)
		if err != nil {
			t.Fatal("GetTxOut failure:", err)
		}
		if res != nil {
			t.Fatalf("Transaction output %v still unspent.", i)
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

	time.Sleep(250 * time.Millisecond)
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

	// Generate a single block, the transaction the wallet created should be
	// found in this block.
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
	for i, txIn := range rawTx.MsgTx().TxIn {
		prevOut := &txIn.PreviousOutPoint

		// If a txout is spent (not in the UTXO set) GetTxOutResult will be nil
		res, err := wcl.GetTxOut(&prevOut.Hash, prevOut.Index, false)
		if err != nil {
			t.Fatal("GetTxOut failure:", err)
		}
		if res != nil {
			t.Fatalf("Transaction output %v still unspent.", i)
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

	// ListUnspent only shows validated (confirmations>=1) coinbase tx, so the
	// first result should have 2 confirmations.
	if txList1[0].Confirmations != 1 {
		t.Fatalf("Latest coinbase tx listed has %v confirmations, expected 1.",
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

	for i, acct := range accountNames {
		addr, err := wcl.GetNewAddress(acct)
		if err != nil {
			t.Fatal(err)
		}

		// Set the amounts to send to each address
		addresses = append(addresses, addr)
		addressAmounts[addr] = amountsToSend[i]
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
		t.Fatalf("Invalid Amount %f. %v", walletInfo.TxFee, err)
	}
	// Increase fee by 50%
	newTxFeeCoin := walletInfo.TxFee * 1.5
	newTxFee, err := dcrutil.NewAmount(newTxFeeCoin)
	if err != nil {
		t.Fatalf("Invalid Amount %f. %v", newTxFeeCoin, err)
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
		t.Fatalf("Invalid Amount %f. %v", walletInfo.TxFee, err)
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
	newTicketFee, err := dcrutil.NewAmount(newTicketFeeCoin)
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
		t.Fatalf("Invalid Amount %f. %v", nominalTicketFee, err)
	}
	if newTicketFee != newTicketFeeActual {
		t.Fatalf("Expected ticket fee %v, got %v.", newTicketFee,
			newTicketFeeActual)
	}

	// Purchase ticket
	minConf, numTickets := 0, 1
	priceLimit, err := dcrutil.NewAmount(2 * mustGetStakeDiffNext(r, t))
	if err != nil {
		t.Fatal("Invalid Amount. ", err)
	}
	hashes, err := wcl.PurchaseTicket("default", priceLimit,
		&minConf, nil, &numTickets, nil, nil, nil)
	if err != nil {
		t.Fatal("Unable to purchase ticket:", err)
	}
	if len(hashes) != numTickets {
		t.Fatalf("Number of returned hashes does not equal expected."+
			"got %v, want %v", len(hashes), numTickets)
	}

	// Need 2 blocks or the vin is incorrect in getrawtransaction
	// Not yet at StakeValidationHeight, so no voting.
	newBestBlock(r, t)
	newBestBlock(r, t)

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

func testGetTickets(r *Harness, t *testing.T) {
	// Wallet.purchaseTicket() in wallet/createtx.go

	// Wallet RPC client
	wcl := r.WalletRPC

	// Initial number of mature (live) tickets
	ticketHashes, err := wcl.GetTickets(false)
	if err != nil {
		t.Fatal("GetTickets failed:", err)
	}
	numTicketsInitLive := len(ticketHashes)

	// Initial number of immature (not live) and unconfirmed (unmined) tickets
	ticketHashes, err = wcl.GetTickets(true)
	if err != nil {
		t.Fatal("GetTickets failed:", err)
	}

	numTicketsInit := len(ticketHashes)

	// Purchase a full blocks worth of tickets
	minConf, numTicketsPurchased := 1, int(chaincfg.SimNetParams.MaxFreshStakePerBlock)
	priceLimit, err := dcrutil.NewAmount(2 * mustGetStakeDiffNext(r, t))
	if err != nil {
		t.Fatal("Invalid Amount. ", err)
	}
	hashes, err := wcl.PurchaseTicket("default", priceLimit,
		&minConf, nil, &numTicketsPurchased, nil, nil, nil)
	if err != nil {
		t.Fatal("Unable to purchase tickets:", err)
	}
	if len(hashes) != numTicketsPurchased {
		t.Fatalf("Expected %v ticket hashes, got %v.", numTicketsPurchased,
			len(hashes))
	}

	// Verify GetTickets(true) sees these unconfirmed SSTx
	ticketHashes, err = wcl.GetTickets(true)
	if err != nil {
		t.Fatal("GetTickets failed:", err)
	}

	if numTicketsInit+numTicketsPurchased != len(ticketHashes) {
		t.Fatal("GetTickets(true) did not include unmined tickets")
	}

	// Compare GetTickets(includeImmature = false) before the purchase with
	// GetTickets(includeImmature = true) after the purchase. This tests that
	// the former does exclude unconfirmed tickets, which we now have following
	// the above purchase.
	if len(ticketHashes) <= numTicketsInitLive {
		t.Fatalf("Number of live tickets (%d) not less than total tickets (%d).",
			numTicketsInitLive, len(ticketHashes))
	}

	// Mine the split tx and THEN stake submission itself
	newBestBlock(r, t)
	_, block, _ := newBestBlock(r, t)

	// Verify stake submissions were mined
	for _, hash := range hashes {
		if !includesStakeTx(hash, block, r, t) {
			t.Errorf("SSTx expected, not found in block %v.", block.Height())
		}
	}

	// Verify each SSTx hash
	for _, hash := range ticketHashes {
		tx, err := wcl.GetRawTransaction(hash)
		if err != nil {
			t.Fatalf("Invalid transaction %v: %v", tx, err)
		}

		// Ensure result is a SSTx
		isSSTx, err := stake.IsSStx(tx.MsgTx())
		if err != nil {
			t.Fatal("IsSSTx failed:", err)
		}

		if !isSSTx {
			t.Log(blockchain.DebugMsgTxString(tx.MsgTx()))
			t.Fatal("Ticket hash is not for a SSTx.")
		}
	}
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
	priceLimit, err := dcrutil.NewAmount(2 * mustGetStakeDiffNext(r, t))
	if err != nil {
		t.Fatal("Invalid Amount.", err)
	}

	// Test nil ticketAddress
	oneTix := 1
	hashes, err := wcl.PurchaseTicket("default", priceLimit,
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
	hashes, err = wcl.PurchaseTicket("default", priceLimit,
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
	curBlockHeight := getBestBlockHeight(r, t)

	// Test expiry - earliest is next height + 1
	// invalid
	expiry = int(curBlockHeight)
	_, err = wcl.PurchaseTicket("default", priceLimit,
		&minConf, nil, nil, nil, nil, &expiry)
	if err == nil {
		t.Fatal("Invalid expiry used to purchase tickets")
	}
	// invalid
	expiry = int(curBlockHeight) + 1
	_, err = wcl.PurchaseTicket("default", priceLimit,
		&minConf, nil, nil, nil, nil, &expiry)
	if err == nil {
		t.Fatal("Invalid expiry used to purchase tickets")
	}

	// valid expiry
	expiry = int(curBlockHeight) + 2
	hashes, err = wcl.PurchaseTicket("default", priceLimit,
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
	walletInfo, err := wcl.WalletInfo()
	if err != nil {
		t.Fatal("WalletInfo failed.", err)
	}
	origTicketFee, err := dcrutil.NewAmount(walletInfo.TicketFee)
	if err != nil {
		t.Fatalf("Invalid Amount %f. %v", walletInfo.TicketFee, err)
	}
	newTicketFee, err := dcrutil.NewAmount(walletInfo.TicketFee * 1.5)
	if err != nil {
		t.Fatalf("Invalid Amount %f. %v", walletInfo.TicketFee, err)
	}

	if err = wcl.SetTicketFee(newTicketFee); err != nil {
		t.Fatalf("SetTicketFee failed for Amount %v: %v", newTicketFee, err)
	}

	expiry = 0
	numTicket := 2 * int(chaincfg.SimNetParams.MaxFreshStakePerBlock)
	_, err = r.WalletRPC.PurchaseTicket("default", priceLimit,
		&minConf, addr, &numTicket, nil, nil, &expiry)
	if err != nil {
		t.Fatal("Unable to purchase tickets:", err)
	}

	if err = wcl.SetTicketFee(origTicketFee); err != nil {
		t.Fatalf("SetTicketFee failed for Amount %v: %v", origTicketFee, err)
	}

	// Check for the ticket
	_, err = wcl.GetTransaction(ticketWithExpiry)
	if err != nil {
		t.Fatal("Ticket not found:", err)
	}

	// Mine 2 blocks, should include the higher fee tickets with no expiry
	curBlockHeight, _, _ = newBlockAt(curBlockHeight, r, t)
	curBlockHeight, _, _ = newBlockAt(curBlockHeight, r, t)

	// Ticket with expiry set should now be expired (unmined and removed from
	// mempool).  An unmined and expired tx should have been removed/pruned
	txRawVerbose, err := wcl.GetRawTransactionVerbose(ticketWithExpiry)
	if err == nil {
		t.Fatalf("Found transaction that should be expired (height %v): %v",
			txRawVerbose.BlockHeight, err)
	}

	// Test too low price
	lowPrice := dcrutil.Amount(1)
	hashes, err = wcl.PurchaseTicket("default", lowPrice,
		&minConf, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatalf("PurchaseTicket succeeded with limit of %f, but diff was %f.",
			lowPrice.ToCoin(), mustGetStakeDiff(r, t))
	}
	if len(hashes) > 0 {
		t.Fatal("At least one tickets hash returned. Expected none.")
	}

	// NOTE: ticket maturity = 16 (spendable at 17), stakeenabled height = 144
	// Must have tickets purchased before block 128

	// Keep generating blocks until desiredHeight is achieved
	desiredHeight := uint32(150)
	numTicket = int(chaincfg.SimNetParams.MaxFreshStakePerBlock)
	for curBlockHeight < desiredHeight {
		priceLimit, err = dcrutil.NewAmount(2 * mustGetStakeDiffNext(r, t))
		if err != nil {
			t.Fatal("Invalid Amount.", err)
		}
		_, err = r.WalletRPC.PurchaseTicket("default", priceLimit,
			&minConf, addr, &numTicket, nil, nil, nil)

		// Do not allow even ErrSStxPriceExceedsSpendLimit since price is set
		if err != nil {
			t.Fatal("Failed to purchase tickets:", err)
		}
		curBlockHeight, _, _ = newBlockAtQuick(curBlockHeight, r, t)
		time.Sleep(100 * time.Millisecond)
	}

	// Validate last tx
	newBestBlock(r, t)

	// TODO: test pool fees

}

func testGetSetTicketMaxPrice(r *Harness, t *testing.T) {
	// Wallet RPC client
	wcl := r.WalletRPC

	var err error

	height := getBestBlockHeight(r, t)
	heightForVoting := uint32(chaincfg.SimNetParams.StakeValidationHeight)
	if height < heightForVoting {
		advanceToHeight(r, t, heightForVoting)
	}

	// Increase the ticket fee so SSTx in this test get mined first. Or we could
	// do this test in a fresh harness...
	walletInfo, err := wcl.WalletInfo()
	if err != nil {
		t.Fatal("WalletInfo failed.", err)
	}
	origTicketFee, err := dcrutil.NewAmount(walletInfo.TicketFee)
	if err != nil {
		t.Fatalf("Invalid Amount %f. %v", walletInfo.TicketFee, err)
	}
	newTicketFee, err := dcrutil.NewAmount(walletInfo.TicketFee * 1.5)
	if err != nil {
		t.Fatalf("Invalid Amount %f. %v", walletInfo.TicketFee*1.5, err)
	}

	if err = wcl.SetTicketFee(newTicketFee); err != nil {
		t.Fatal("SetTicketFee failed:", err)
	}
	// Drop the balance to maintain so tickets will be purchased. If balance to
	// too low for this test, it should be preceeded by more block subsidy.
	if err = wcl.SetBalanceToMaintain(10); err != nil {
		t.Fatal("SetBalanceToMaintain failed:", err)
	}

	// Get current ticket max price via WalletInfo
	walletInfoResult, err := wcl.WalletInfo()
	if err != nil {
		t.Fatal("WalletInfo failed:", err)
	}
	maxPriceInit := walletInfoResult.TicketMaxPrice

	// Get the current stake difficulty to know how low we need to set the
	// wallet's max ticket price so that it should not purchase tickets.
	advanceToNewWindow(r, t)
	stakeDiff := mustGetStakeDiffNext(r, t)

	// Count tickets before enabling auto-purchasing
	ticketHashes, err := wcl.GetTickets(true)
	if err != nil {
		t.Fatal("GetTickets failed:", err)
	}
	ticketHashMap := make(map[chainhash.Hash]bool)
	for _, tx := range ticketHashes {
		ticketHashMap[*tx] = true
	}

	// Too low
	lowTicketMaxPrice := stakeDiff / 2

	// Set ticket price to lower than current stake difficulty
	if err = wcl.SetTicketMaxPrice(lowTicketMaxPrice); err != nil {
		t.Fatal("SetTicketMaxPrice failed:", err)
	}

	// Verify set price
	walletInfoResult, err = wcl.WalletInfo()
	if err != nil {
		t.Fatal("WalletInfo failed:", err)
	}
	if lowTicketMaxPrice != walletInfoResult.TicketMaxPrice {
		t.Fatalf("Set ticket max price failed.")
	}

	// Enable stake mining so tickets get automatically purchased
	if err = wcl.SetGenerate(true, 0); err != nil {
		t.Fatal("SetGenerate failed:", err)
	}

	newBestBlock(r, t)
	// SSTx would be happening now with high enough price
	time.Sleep(1 * time.Second)
	newBestBlock(r, t)

	// Check for new tickets after enabling auto-purchasing, but with low price
	ticketHashes, err = wcl.GetTickets(true)
	if err != nil {
		t.Fatal("GetTickets failed:", err)
	}
	for _, tx := range ticketHashes {
		if !ticketHashMap[*tx] {
			t.Fatalf("Tickets were purchased at %f while max price was %f",
				stakeDiff, lowTicketMaxPrice)
		}
	}

	// Just high enough (max == diff + eps)
	adequateTicketMaxPrice := math.Nextafter(stakeDiff, stakeDiff+1)
	if err = wcl.SetTicketMaxPrice(adequateTicketMaxPrice); err != nil {
		t.Fatal("SetTicketMaxPrice failed:", err)
	}

	newBestBlock(r, t)
	// SSTx would be happening now with high enough price
	time.Sleep(1 * time.Second)
	newBestBlock(r, t)

	// Check for new tickets after enabling auto-purchasing, but with low price
	ticketHashes, err = wcl.GetTickets(true)
	if err != nil {
		t.Fatal("GetTickets failed:", err)
	}
	newTickets := false
	for _, tx := range ticketHashes {
		if !ticketHashMap[*tx] {
			newTickets = true
			break
		}
	}
	if !newTickets {
		t.Fatalf("Tickets were NOT purchased at %f, but max price was %f",
			stakeDiff, adequateTicketMaxPrice)
	}

	// Double.  Plenty high.
	adequateTicketMaxPrice = stakeDiff * 2

	newBestBlock(r, t)
	// SSTx would be happening now with high enough price
	time.Sleep(1 * time.Second)

	// One should be enough for the test, but buy more to keep the chain alive
	numBlocksToStakeMine := 4
	for i := 0; i < 4; i++ {
		newBestBlock(r, t)
	}

	// Check for new tickets after enabling auto-purchasing, but with low price
	ticketHashes, err = wcl.GetTickets(true)
	if err != nil {
		t.Fatal("GetTickets failed:", err)
	}
	newTickets = false
	numTicketsPurchased := 0
	for _, tx := range ticketHashes {
		if !ticketHashMap[*tx] {
			numTicketsPurchased++
			newTickets = true
		}
	}
	t.Logf("Number of tickets auto-purchased over %d blocks: %d",
		numBlocksToStakeMine, numTicketsPurchased)
	if !newTickets {
		t.Fatalf("Tickets were NOT purchased at %f, but max price was %f",
			stakeDiff, adequateTicketMaxPrice)
	}

	// reset ticket fee and max price
	if err = wcl.SetTicketFee(origTicketFee); err != nil {
		t.Fatalf("SetTicketFee failed for Amount %v. %v", origTicketFee, err)
	}
	err = wcl.SetTicketMaxPrice(maxPriceInit)
	if err != nil {
		t.Fatal("SetTicketMaxPrice failed:", err)
	}

	// Disable automatic ticket purchasing
	if !walletInfoResult.StakeMining {
		if err = wcl.SetGenerate(false, 0); err != nil {
			t.Fatal("SetGenerate failed:", err)
		}
	}
}

func testGetSetBalanceToMaintain(r *Harness, t *testing.T) {
	// Wallet RPC client
	wcl := r.WalletRPC

	var err error

	height := getBestBlockHeight(r, t)
	heightForVoting := uint32(chaincfg.SimNetParams.StakeValidationHeight)
	if height < heightForVoting {
		advanceToHeight(r, t, heightForVoting)
	}

	// Increase the ticket fee so SSTx in this test get mined first. Or we could
	// do this test in a fresh harness...
	walletInfo, err := wcl.WalletInfo()
	if err != nil {
		t.Fatal("WalletInfo failed.", err)
	}
	origTicketFee, err := dcrutil.NewAmount(walletInfo.TicketFee)
	if err != nil {
		t.Fatalf("Invalid Amount %f. %v", walletInfo.TicketFee, err)
	}
	newTicketFee, err := dcrutil.NewAmount(walletInfo.TicketFee * 1.5)
	if err != nil {
		t.Fatalf("Invalid Amount %f. %v", walletInfo.TicketFee*1.5, err)
	}

	if err = wcl.SetTicketFee(newTicketFee); err != nil {
		t.Fatal("SetTicketFee failed:", err)
	}

	// Push BTM over spendable balance + at least 20 full block rewards
	spendable, err := wcl.GetBalance("default")
	if err != nil {
		t.Fatal(err)
	}

	newBTM := spendable + 20*dcrutil.Amount(chaincfg.SimNetParams.BaseSubsidy)
	if err = wcl.SetBalanceToMaintain(newBTM.ToCoin()); err != nil {
		t.Fatal("SetBalanceToMaintain failed:", err)
	}

	// Verify the set BTM
	walletInfoResult, err := wcl.WalletInfo()
	if err != nil {
		t.Fatal("WalletInfo failed:", err)
	}

	if walletInfoResult.BalanceToMaintain != newBTM.ToCoin() {
		t.Fatalf("Balance to maintain set incorrectly.")
	}

	// Advance to new price window, but don't purchase tickets in this period
	maxPriceInit := walletInfo.TicketMaxPrice
	if err = wcl.SetTicketMaxPrice(0); err != nil {
		t.Fatal("SetTicketMaxPrice(0) failed.", err)
	}

	advanceToNewWindow(r, t)
	// Now next != current stake difficulty

	// Index before enabling auto-purchasing
	ticketHashes, err := wcl.GetTickets(true)
	if err != nil {
		t.Fatal("GetTickets failed:", err)
	}
	ticketHashMap := make(map[chainhash.Hash]bool)
	for _, tx := range ticketHashes {
		ticketHashMap[*tx] = true
	}

	// Get the current stake difficulty to know how low we need to set the
	// wallet's max ticket price so that it should NOT purchase tickets.
	stakeDiff := mustGetStakeDiffNext(r, t)

	// Set ticket price to higher than current stake difficulty
	if err = wcl.SetTicketMaxPrice(stakeDiff * 2); err != nil {
		t.Fatal("SetTicketMaxPrice failed:", err)
	}

	// Enable stake mining so tickets get automatically purchased
	if err = wcl.SetGenerate(true, 0); err != nil {
		// TODO: This will "error" because of rejected TX (already have votes
		// that get resent). Verify if this should even be an error.
		//t.Fatal("SetGenerate failed:", err)
	}

	newBestBlock(r, t)
	// SSTx would be happening now with high enough price and low enough BTM
	time.Sleep(1 * time.Second)
	newBestBlock(r, t)

	// Check for new tickets after enabling auto-purchasing, but with high BTM
	ticketHashes, err = wcl.GetTickets(true)
	if err != nil {
		t.Fatal("GetTickets failed:", err)
	}
	for _, tx := range ticketHashes {
		if !ticketHashMap[*tx] {
			t.Fatalf("Tickets were purchased with %v spendable balance; "+
				"balance to maintain %v", spendable.ToCoin(),
				walletInfoResult.BalanceToMaintain)
		}
	}

	// Drop BTM under spendable balance by cost of at least 3 blocks worth of
	// max fresh stake
	spendable, err = wcl.GetBalance("default")
	if err != nil {
		t.Fatal(err)
	}

	newBTMCoin := spendable.ToCoin() -
		stakeDiff*3*float64(chaincfg.SimNetParams.MaxFreshStakePerBlock)
	if err = wcl.SetBalanceToMaintain(newBTMCoin); err != nil {
		t.Fatal("SetBalanceToMaintain failed:", err)
	}

	newBestBlock(r, t)
	// SSTx would be happening now with high enough price
	time.Sleep(1 * time.Second)
	newBestBlock(r, t)

	// Check for new tickets with low enough BTM and high enough max price
	ticketHashes, err = wcl.GetTickets(true)
	if err != nil {
		t.Fatal("GetTickets failed:", err)
	}
	newTickets := false
	for _, tx := range ticketHashes {
		if !ticketHashMap[*tx] {
			newTickets = true
			break
		}
	}
	if !newTickets {
		t.Fatalf("Tickets were NOT purchased with %v spendable; BTM = %v",
			spendable.ToCoin(), newBTMCoin)
	}

	// reset ticket fee and max price
	if err = wcl.SetTicketFee(origTicketFee); err != nil {
		t.Fatalf("SetTicketFee failed for Amount %v. %v", origTicketFee, err)
	}
	if err = wcl.SetTicketMaxPrice(maxPriceInit); err != nil {
		t.Fatal("SetTicketMaxPrice failed:", err)
	}

	// Disable automatical tickets purchasing
	if !walletInfoResult.StakeMining {
		if err = wcl.SetGenerate(false, 0); err != nil {
			t.Fatal("SetGenerate failed:", err)
		}
	}

	// Test too high amount for SetBalanceToMaintain
	tooHighAmt := dcrutil.Amount(dcrutil.MaxAmount + 100).ToCoin()
	expectedErr := legacyrpc.ErrNeedBelowMaxAmount
	err = wcl.SetBalanceToMaintain(tooHighAmt)
	if !strings.Contains(err.Error(), expectedErr.Error()) {
		t.Fatalf("SetBalanceToMaintain failed to return \"%v\" for too high amount: %v",
			expectedErr, err)
	}

	// Test below 0 for SetBalanceToMaintain
	tooLowAmt := -1.0
	expectedErr = legacyrpc.ErrNeedPositiveAmount
	err = wcl.SetBalanceToMaintain(tooLowAmt)
	if !strings.Contains(err.Error(), expectedErr.Error()) {
		t.Fatalf("SetBalanceToMaintain failed to return \"%v\" for negative amount: %v",
			expectedErr, err)
	}

	// Test invalid Amount to ensure it's checking error from NewAmount
	err = wcl.SetBalanceToMaintain(math.NaN())
	if err == nil {
		t.Fatalf("SetBalanceToMaintain failed to return non-nil error for invalid amount.")
	}
}

// testGetStakeInfo gets a FRESH harness
func testGetStakeInfo(r *Harness, t *testing.T) {
	// Wallet RPC client
	wcl := r.WalletRPC

	// Compare stake difficulty from getstakeinfo with getstakeinfo
	sdiff, err := wcl.GetStakeDifficulty()
	if err != nil {
		t.Fatal("GetStakeDifficulty failed: ", err)
	}

	stakeinfo, err := wcl.GetStakeInfo()
	if err != nil {
		t.Fatal("GetStakeInfo failed: ", err)
	}
	// Ensure we are starting with a fresh harness
	if stakeinfo.AllMempoolTix != 0 || stakeinfo.Immature != 0 ||
		stakeinfo.Live != 0 {
		t.Fatalf("GetStakeInfo reported active tickets. Expected 0, got:\n"+
			"%d/%d/%d (allmempooltix/immature/live)",
			stakeinfo.AllMempoolTix, stakeinfo.Immature, stakeinfo.Live)
	}
	// At the expected block height
	height, block, _ := getBestBlock(r, t)
	if stakeinfo.BlockHeight != int64(height) {
		t.Fatalf("Block height reported by GetStakeInfo incorrect. Expected %d, got %d.",
			height, stakeinfo.BlockHeight)
	}
	poolSize := block.MsgBlock().Header.PoolSize
	if stakeinfo.PoolSize != poolSize {
		t.Fatalf("Reported pool size incorrect. Expected %d, got %d.",
			poolSize, stakeinfo.PoolSize)
	}

	// Ticket fate values should also be zero
	if stakeinfo.Voted != 0 || stakeinfo.Missed != 0 ||
		stakeinfo.Revoked != 0 {
		t.Fatalf("GetStakeInfo reported spent tickets:\n"+
			"%d/%d/%d (voted/missed/revoked/pct. missed)", stakeinfo.Voted,
			stakeinfo.Missed, stakeinfo.Revoked)
	}
	if stakeinfo.ProportionLive != 0 {
		t.Fatalf("ProportionLive incorrect. Expected %f, got %f.", 0.0,
			stakeinfo.ProportionLive)
	}
	if stakeinfo.ProportionMissed != 0 {
		t.Fatalf("ProportionMissed incorrect. Expected %f, got %f.", 0.0,
			stakeinfo.ProportionMissed)
	}

	// Verify getstakeinfo.difficulty == getstakedifficulty
	if sdiff.CurrentStakeDifficulty != stakeinfo.Difficulty {
		t.Fatalf("Stake difficulty mismatch: %f vs %f (getstakedifficulty, getstakeinfo)",
			sdiff.CurrentStakeDifficulty, stakeinfo.Difficulty)
	}

	// Buy tickets to check that they shows up in ownmempooltix/allmempooltix
	minConf := 1
	priceLimit, err := dcrutil.NewAmount(2 * mustGetStakeDiffNext(r, t))
	if err != nil {
		t.Fatal("Invalid Amount.", err)
	}
	numTickets := int(chaincfg.SimNetParams.MaxFreshStakePerBlock)
	tickets, err := r.WalletRPC.PurchaseTicket("default", priceLimit,
		&minConf, nil, &numTickets, nil, nil, nil)
	if err != nil {
		t.Fatal("Failed to purchase tickets:", err)
	}

	// Before mining a block allmempooltix and ownmempooltix should be equal to
	// the number of tickets just purchesed in this fresh harness
	stakeinfo = mustGetStakeInfo(wcl, t)
	if stakeinfo.AllMempoolTix != uint32(numTickets) {
		t.Fatalf("getstakeinfo AllMempoolTix mismatch: %d vs %d",
			stakeinfo.AllMempoolTix, numTickets)
	}
	if stakeinfo.AllMempoolTix != stakeinfo.OwnMempoolTix {
		t.Fatalf("getstakeinfo AllMempoolTix/OwnMempoolTix mismatch: %d vs %d",
			stakeinfo.AllMempoolTix, stakeinfo.OwnMempoolTix)
	}

	// Mine the split tx, which creates the correctly-sized outpoints for the
	// actual SSTx
	newBestBlock(r, t)
	// Mine SSTx
	newBestBlock(r, t)

	// Compute the height at which these tickets mature
	ticketsTx, err := wcl.GetRawTransactionVerbose(tickets[0])
	if err != nil {
		t.Fatalf("Unable to gettransaction for ticket.")
	}
	maturityHeight := ticketsTx.BlockHeight + int64(chaincfg.SimNetParams.TicketMaturity)

	// After mining tickets, immature should be the number of tickets
	stakeinfo = mustGetStakeInfo(wcl, t)
	if stakeinfo.Immature != uint32(numTickets) {
		t.Fatalf("Tickets not reported as immature (got %d, expected %d)",
			stakeinfo.Immature, numTickets)
	}
	// mempool tickets should be zero
	if stakeinfo.OwnMempoolTix != 0 {
		t.Fatalf("Tickets reported in mempool (got %d, expected %d)",
			stakeinfo.OwnMempoolTix, 0)
	}
	// mempool tickets should be zero
	if stakeinfo.AllMempoolTix != 0 {
		t.Fatalf("Tickets reported in mempool (got %d, expected %d)",
			stakeinfo.AllMempoolTix, 0)
	}

	// Advance to maturity height
	t.Logf("Advancing to maturity height %d for tickets in block %d", maturityHeight,
		ticketsTx.BlockHeight)
	advanceToHeight(r, t, uint32(maturityHeight))
	// NOTE: voting does not begin until TicketValidationHeight

	// mature should be number of tickets now
	stakeinfo = mustGetStakeInfo(wcl, t)
	if stakeinfo.Live != uint32(numTickets) {
		t.Fatalf("Tickets not reported as live (got %d, expected %d)",
			stakeinfo.Live, numTickets)
	}
	// immature tickets should be zero
	if stakeinfo.Immature != 0 {
		t.Fatalf("Tickets reported as immature (got %d, expected %d)",
			stakeinfo.Immature, 0)
	}

	// Buy some more tickets (4 blocks worth) so chain doesn't stall when voting
	// burns through the batch purchased above
	for i := 0; i < 4; i++ {
		priceLimit, err := dcrutil.NewAmount(2 * mustGetStakeDiffNext(r, t))
		if err != nil {
			t.Fatal("Invalid Amount.", err)
		}
		numTickets := int(chaincfg.SimNetParams.MaxFreshStakePerBlock)
		_, err = r.WalletRPC.PurchaseTicket("default", priceLimit,
			&minConf, nil, &numTickets, nil, nil, nil)
		if err != nil {
			t.Fatal("Failed to purchase tickets:", err)
		}

		newBestBlock(r, t)
	}

	// Advance to voting height and votes should happen right away
	votingHeight := chaincfg.SimNetParams.StakeValidationHeight
	advanceToHeight(r, t, uint32(votingHeight))
	time.Sleep(250 * time.Millisecond)

	// voted should be TicketsPerBlock
	stakeinfo = mustGetStakeInfo(wcl, t)
	expectedVotes := chaincfg.SimNetParams.TicketsPerBlock
	if stakeinfo.Voted != uint32(expectedVotes) {
		t.Fatalf("Tickets not reported as voted (got %d, expected %d)",
			stakeinfo.Voted, expectedVotes)
	}

	newBestBlock(r, t)
	// voted should be 2*TicketsPerBlock
	stakeinfo = mustGetStakeInfo(wcl, t)
	expectedVotes = 2 * chaincfg.SimNetParams.TicketsPerBlock
	if stakeinfo.Voted != uint32(expectedVotes) {
		t.Fatalf("Tickets not reported as voted (got %d, expected %d)",
			stakeinfo.Voted, expectedVotes)
	}

	// ProportionLive
	proportionLive := float64(stakeinfo.Live) / float64(stakeinfo.PoolSize)
	if stakeinfo.ProportionLive != proportionLive {
		t.Fatalf("ProportionLive mismatch.  Expected %f, got %f",
			proportionLive, stakeinfo.ProportionLive)
	}

	// ProportionMissed
	proportionMissed := float64(stakeinfo.Missed) /
		(float64(stakeinfo.Voted) + float64(stakeinfo.Missed))
	if stakeinfo.ProportionMissed != proportionMissed {
		t.Fatalf("ProportionMissed mismatch.  Expected %f, got %f",
			proportionMissed, stakeinfo.ProportionMissed)
	}
}

// testWalletInfo
func testWalletInfo(r *Harness, t *testing.T) {
	// Wallet RPC client
	wcl := r.WalletRPC

	// WalletInfo is tested exhaustively in other test, so only do some basic
	// checks here
	walletInfo, err := wcl.WalletInfo()
	if err != nil {
		t.Fatal("walletinfo failed.")
	}
	if !walletInfo.DaemonConnected {
		t.Fatal("WalletInfo indicates that daemon is not connected.")
	}

	// Turn off stake mining
	if err := wcl.SetGenerate(false, 0); err != nil {
		// TODO: This will "error" because of rejected TX (already have votes
		// that get resent). Verify if this should even be an error.
		//t.Fatal("SetGenerate failed:", err)
	}

	walletInfo, err = wcl.WalletInfo()
	if err != nil {
		t.Fatal("walletinfo failed.")
	}
	if walletInfo.StakeMining {
		t.Fatalf("WalletInfo indicades that stake mining is enabled.")
	}

	// Now turn on stake mining
	if err = wcl.SetGenerate(true, 0); err != nil {
		//t.Fatal("SetGenerate failed:", err)
	}

	walletInfo, err = wcl.WalletInfo()
	if err != nil {
		t.Fatal("walletinfo failed.")
	}
	if !walletInfo.StakeMining {
		t.Fatalf("WalletInfo indicades that stake mining is disabled.")
	}
}

///////////////////////////////////////////////////////////////////////////////
// Helper functions

func mustGetStakeInfo(wcl *dcrrpcclient.Client, t *testing.T) *dcrjson.GetStakeInfoResult {
	stakeinfo, err := wcl.GetStakeInfo()
	if err != nil {
		t.Fatal("GetStakeInfo failed: ", err)
	}
	return stakeinfo
}

func mustGetStakeDiff(r *Harness, t *testing.T) float64 {
	stakeDiffResult, err := r.WalletRPC.GetStakeDifficulty()
	if err != nil {
		t.Fatal("GetStakeDifficulty failed:", err)
	}

	return stakeDiffResult.CurrentStakeDifficulty
}

func mustGetStakeDiffNext(r *Harness, t *testing.T) float64 {
	stakeDiffResult, err := r.WalletRPC.GetStakeDifficulty()
	if err != nil {
		t.Fatal("GetStakeDifficulty failed:", err)
	}

	return stakeDiffResult.NextStakeDifficulty
}

// advanceToNewWindow goes to the height where next != current stake difficulty
func advanceToNewWindow(r *Harness, t *testing.T) uint32 {
	// ensure there are many blocks left in this price window
	var blocksLeftInWindow = func(height uint32) int64 {
		// height + 1 is used to land at the height where next != current diff.
		windowIdx := int64(height+1) % chaincfg.SimNetParams.StakeDiffWindowSize
		return chaincfg.SimNetParams.StakeDiffWindowSize - windowIdx
	}
	// Keep generating blocks until a new price window starts, giving us several
	// blocks with the same stake difficulty
	curBlockHeight := getBestBlockHeight(r, t)
	initHeight := curBlockHeight
	for blocksLeftInWindow(curBlockHeight) !=
		chaincfg.SimNetParams.StakeDiffWindowSize {
		curBlockHeight, _, _ = newBlockAtQuick(curBlockHeight, r, t)
		time.Sleep(75 * time.Millisecond)
	}
	t.Logf("Advanced %d blocks to block height %d", curBlockHeight-initHeight,
		curBlockHeight)
	return curBlockHeight
}

func advanceToHeight(r *Harness, t *testing.T, height uint32) {
	curBlockHeight := getBestBlockHeight(r, t)
	initHeight := curBlockHeight

	if curBlockHeight >= height {
		return
	}

	for curBlockHeight != height {
		curBlockHeight, _, _ = newBlockAtQuick(curBlockHeight, r, t)
		time.Sleep(75 * time.Millisecond)
	}
	t.Logf("Advanced %d blocks to block height %d", curBlockHeight-initHeight,
		curBlockHeight)
	return
}

func newBlockAt(currentHeight uint32, r *Harness,
	t *testing.T) (uint32, *dcrutil.Block, []*chainhash.Hash) {
	height, block, blockHashes := newBlockAtQuick(currentHeight, r, t)

	time.Sleep(700 * time.Millisecond)

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

func getBestBlockHeight(r *Harness, t *testing.T) uint32 {
	_, height, err := r.Node.GetBestBlock()
	if err != nil {
		t.Fatalf("Failed to GetBestBlock: %v", err)
	}

	return uint32(height)
}

func newBestBlock(r *Harness,
	t *testing.T) (uint32, *dcrutil.Block, []*chainhash.Hash) {
	height := getBestBlockHeight(r, t)
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
		//if bytes.Equal(txHash[:], txSha.Bytes()[:]) {
		if txHash.IsEqual(txSha) {
			return true
		}
	}

	return false
}

// includesTx checks if a block contains a transaction hash
func includesStakeTx(txHash *chainhash.Hash, block *dcrutil.Block,
	r *Harness, t *testing.T) bool {

	if len(block.STransactions()) <= 1 {
		return false
	}

	blockTxs := block.STransactions()

	for _, minedTx := range blockTxs {
		txSha := minedTx.Sha()
		if txHash.IsEqual(txSha) {
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
