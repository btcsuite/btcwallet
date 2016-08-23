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
	"strconv"
	"strings"
	"testing"
	"time"

	//"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrd/txscript"
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
	testPurchaseTickets,
}

// TODO use a []*Harness instead
var primaryHarness, secondaryHarness *Harness

// TestMain manages the test harness and runs the tests instead of go test
// running the tests directly.
func TestMain(m *testing.M) {
	var err error
	primaryHarness, err = NewHarness(&chaincfg.SimNetParams, nil, nil)
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

	// Secondary harness
	secondaryHarness, err = NewHarness(&chaincfg.SimNetParams, nil, nil)
	if err != nil {
		fmt.Println("Unable to create secondary harness: ", err)
		os.Exit(1)
	}
	if err = secondaryHarness.SetUp(true, 4); err != nil {
		fmt.Println("Unable to setup test chain: ", err)
		err = secondaryHarness.TearDown()
		os.Exit(1)
	}

	// Run the tests
	exitCode := m.Run()

	// Clean up the primary harness created above. This includes removing
	// all temporary directories, and shutting down any created processes.
	if err := primaryHarness.TearDown(); err != nil {
		fmt.Println("Unable to teardown test chain: ", err)
		os.Exit(1)
	}

	if err := secondaryHarness.TearDown(); err != nil {
		fmt.Println("Unable to teardown secondary test chain: ", err)
		os.Exit(1)
	}

	os.Exit(exitCode)
}

func TestRpcServer(t *testing.T) {
	for _, testCase := range rpcTestCases {
		testCase(primaryHarness, t)
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
	// Also validate with non-owner wallet
	wcl2 := secondaryHarness.WalletRPC

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

		// Check ownership from secondary wallet
		validRes, err = wcl2.ValidateAddress(addr)
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
		if utxo.Spendable {
			utxosBeforeSend[utxo.TxID] = utxo.Amount
		}
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
	t.Log(addrs)

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

	// Make sure each found output's txid is in original list (although this is
	// not the same thing as checking if the output is there)
	var foundTxID = false
	for _, listRes := range listAddressesKnown {
		if _, ok := utxosBeforeSend[listRes.TxID]; !ok {
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

	// SendFromMinConf 1000 to addr
	amountToSend := dcrutil.Amount(700000000)
	txid, err := wcl.SendFromMinConf("default", addr, amountToSend, 0)
	if err != nil {
		t.Fatalf("sendfromminconf failed: %v", err)
	}

	time.Sleep(2 * time.Second)
	newBestBlock(r, t)
	// TODO: why is above necessary for GetRawTransaction to give a tx with
	// sensible MsgTx().TxIn[:].ValueIn values?

	// Get *dcrutil.Tx of send to check the inputs
	rawTx, err := r.chainClient.GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("getrawtransaction failed: %v", err)
	}

	// Get previous OutPoint of each TxIn for send transaction
	txInIDs := make(map[string]float64)
	for _, txIn := range rawTx.MsgTx().TxIn {
		prevOut := &txIn.PreviousOutPoint
		txInIDs[prevOut.Hash.String()] = dcrutil.Amount(txIn.ValueIn).ToCoin()
	}
	t.Log("Number of TxIns: ", len(txInIDs))

	// First check to make sure we see these in the UTXO list prior to send,
	// then not in the UTXO list after send.
	for txinID, amt := range txInIDs {
		if _, ok := utxosBeforeSend[txinID]; !ok {
			t.Fatalf("Failed to find txid %v (%v DCR) in list of UTXOs",
				txinID, amt)
		}
		// TODO: Is there a value/amount check?
	}

	// Validate the send Tx with 2 new blocks
	newBestBlock(r, t)
	newBestBlock(r, t)

	// Make sure these txInIDS are not in the new UTXO set
	list, err = wcl.ListUnspent()
	if err != nil {
		t.Fatalf("Failed to get UTXOs")
	}
	for _, utxo := range list {
		if amt, ok := txInIDs[utxo.TxID]; ok {
			t.Fatalf("Found PreviousOutPoint of send still in UTXO set: %v, "+
				"%v DCR", utxo.TxID, amt)
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

	// SendFromMinConf 1000 to addr
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

	// Get the sending Tx
	Tx, err := wcl.GetRawTransaction(txid)
	if err != nil {
		t.Fatal("Unable to get raw transaction for", Tx)
	}
	// txid is rawTx.MsgTx().TxIn[0].PreviousOutPoint.Hash

	// Check all inputs
	for ii, txIn := range Tx.MsgTx().TxIn {
		prevOut := &txIn.PreviousOutPoint
		t.Logf("Checking previous outpoint %v, %v", ii, prevOut.String())

		// If a txout is spent (not in the UTXO set) GetTxOutResult will be nil
		res, _ := wcl.GetTxOut(&prevOut.Hash, prevOut.Index, false)
		if res != nil {
			t.Errorf("Transaction output %v still unspent.", ii)
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
		if utxo.Spendable {
			utxosBeforeSend[utxo.TxID] = utxo.Amount
		}
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
	curBlockHeight, block, _ := newBestBlock(r, t)

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
	_, err = r.GenerateBlock(curBlockHeight)
	if err != nil {
		t.Fatal(err)
	}

	// Get rawTx of sent txid so we can calculate the fee that was used
	rawTx, err := r.chainClient.GetRawTransaction(txid)
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

	time.Sleep(2 * time.Second)
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
		t.Fatalf("failed to get utxos")
	}
	for _, utxo := range list {
		if utxo.TxID == rawTx.MsgTx().TxIn[0].PreviousOutPoint.Hash.String() {
			t.Fatalf("found a utxo that should have been marked spent")
		}
	}
}

func testPurchaseTickets(r *Harness, t *testing.T) {
	// Grab a fresh address from the wallet.
	addr, err := r.WalletRPC.GetNewAddress("default")
	if err != nil {
		t.Fatal(err)
	}
	// Set various variables for the test
	minConf := 0
	numTicket := 20
	expiry := 0
	desiredHeight := uint32(150)

	// Get current blockheight to make sure chain is at the desiredHeight
	curBlockHeight, _, _ := getBestBlock(r, t)

	// Keep generating blocks until desiredHeight is achieved
	for curBlockHeight < desiredHeight {
		_, err = r.WalletRPC.PurchaseTicket("default", 100000000,
			&minConf, addr, &numTicket, nil, nil, &expiry)

		// allow ErrSStxPriceExceedsSpendLimit
		if err != nil && wallet.ErrSStxPriceExceedsSpendLimit.Error() !=
			err.(*dcrjson.RPCError).Message {
			t.Fatal(err)
		}
		curBlockHeight, _, _ = newBlockAt(curBlockHeight, r, t)
	}

	// TODO: test pool fees

}

///////////////////////////////////////////////////////////////////////////////
// Helper functions

func newBlockAt(currentHeight uint32, r *Harness,
	t *testing.T) (uint32, *dcrutil.Block, []*chainhash.Hash) {

	blockHashes, err := r.GenerateBlock(currentHeight)
	if err != nil {
		t.Fatalf("Unable to generate single block: %v", err)
	}

	time.Sleep(2 * time.Second)

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
