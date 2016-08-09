// Copyright (c) 2016 The decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
package rpctest

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrutil"
)

type rpcTestCase func(r *Harness, t *testing.T)

var rpcTestCases = []rpcTestCase{
	testSendFrom,
	testSendToAddress,
	testPurchaseTickets,
}

var primaryHarness *Harness

func TestMain(m *testing.M) {
	var err error
	primaryHarness, err = NewHarness(&chaincfg.SimNetParams, nil, nil)
	if err != nil {
		fmt.Println("unable to create primary harness: ", err)
		os.Exit(1)
	}

	// Initialize the primary mining node with a chain of length 41,
	// providing 25 mature coinbases to allow spending from for testing
	// purposes.
	if err = primaryHarness.SetUp(true, 25); err != nil {
		fmt.Println("unable to setup test chain: ", err)
		err = primaryHarness.TearDown()
		os.Exit(1)
	}

	exitCode := m.Run()

	// Clean up the primary harness created above. This includes removing
	// all temporary directories, and shutting down any created processes.
	if err := primaryHarness.TearDown(); err != nil {
		fmt.Println("unable to teardown test chain: ", err)
		os.Exit(1)
	}

	os.Exit(exitCode)
}

func TestRpcServer(t *testing.T) {
	for _, testCase := range rpcTestCases {
		testCase(primaryHarness, t)
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
		t.Fatalf("balance for %s account incorrect:  want %v got %v", accountName, amountToSend, sendFromBalanceAfterSendNoBlock)
	}

	// Get current blockheight to make sure chain is at the desiredHeight
	bestBlockHash, err := r.Node.GetBestBlockHash()
	if err != nil {
		t.Fatalf("unable to get best block hash: %v", err)
	}
	bestBlock, err := r.Node.GetBlock(bestBlockHash)
	if err != nil {
		t.Fatalf("unable to get block: %v", err)
	}
	curBlockHeight := bestBlock.MsgBlock().Header.Height

	// Generate a single block, the transaction the wallet created should
	// be found in this block.
	blockHashes, err := r.GenerateBlock(curBlockHeight)
	if err != nil {
		t.Fatal(err)
	}
	block, err := r.Node.GetBlock(blockHashes[0])
	if err != nil {
		t.Fatalf("unable to get block: %v", err)
	}
	curBlockHeight = block.MsgBlock().Header.Height

	// Check to make sure the transaction that was sent was included in the block
	if len(block.Transactions()) <= 1 {
		t.Fatalf("expected transaction not included in block")
	}
	minedTx := block.Transactions()[1]
	txSha := minedTx.Sha()
	if !bytes.Equal(txid[:], txSha.Bytes()[:]) {
		t.Fatalf("txid's don't match, %v vs %v", txSha, txid)
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
		t.Fatalf("balance for %s account incorrect: want %v got %v", "default", expectedBalance, defaultBalanceAfterSendNoBlock)
	}

	time.Sleep(10 * time.Second)
	// Check balance of sendfrom account
	sendFromBalanceAfterSend1Block, err := r.WalletRPC.GetBalanceMinConfType(accountName, 1, "all")
	if err != nil {
		t.Fatalf("getbalanceminconftype failed: %v", err)
	}

	if sendFromBalanceAfterSend1Block != amountToSend {
		t.Fatalf("balance for %s account incorrect:  want %v got %v", accountName, amountToSend, sendFromBalanceAfterSend1Block)
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

func testSendToAddress(r *Harness, t *testing.T) {
	// Get current blockheight to make sure chain is at the desiredHeight
	bestBlockHash, err := r.Node.GetBestBlockHash()
	if err != nil {
		t.Fatalf("unable to get best block hash: %v", err)
	}
	bestBlock, err := r.Node.GetBlock(bestBlockHash)
	if err != nil {
		t.Fatalf("unable to get block: %v", err)
	}

	curBlockHeight := bestBlock.MsgBlock().Header.Height

	// Grab a fresh address from the wallet.
	addr, err := r.WalletRPC.GetNewAddress("default")
	if err != nil {
		t.Fatal(err)
	}

	// Check spendable balance of default account
	_, err = r.WalletRPC.GetBalanceMinConfType("default", 1, "spendable")
	if err != nil {
		t.Fatalf("getbalanceminconftype failed: %v", err)
	}

	// SendFromMinConf 1000 to addr
	txid, err := r.WalletRPC.SendToAddress(addr, 1000000)
	if err != nil {
		t.Fatalf("sendtoaddress failed: %v", err)
	}

	// Generate a single block, the transaction the wallet created should
	// be found in this block.
	blockHashes, err := r.GenerateBlock(curBlockHeight)
	if err != nil {
		t.Fatal(err)
	}

	block, err := r.Node.GetBlock(blockHashes[0])
	if err != nil {
		t.Fatalf("unable to get block: %v", err)
	}
	if len(block.Transactions()) <= 1 {
		t.Fatalf("expected transaction not included in block")
	}
	minedTx := block.Transactions()[1]
	txSha := minedTx.Sha()
	if !bytes.Equal(txid[:], txSha.Bytes()[:]) {
		t.Fatalf("txid's don't match, %v vs %v", txSha, txid)
	}

	// We have confirmed that the expected tx was mined into the block.
	// We should now check to confirm that the utxo that wallet used to create
	// that sendfrom was properly marked to spent and removed from utxo set.

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
	bestBlockHash, err := r.Node.GetBestBlockHash()
	if err != nil {
		t.Fatalf("unable to get best block hash: %v", err)
	}
	bestBlock, err := r.Node.GetBlock(bestBlockHash)
	if err != nil {
		t.Fatalf("unable to get block: %v", err)
	}
	curBlockHeight := bestBlock.MsgBlock().Header.Height

	// Keep generating blocks until desiredHeight is achieved
	for curBlockHeight < desiredHeight {
		_, err = r.WalletRPC.PurchaseTicket("default", 100000000,
			&minConf, addr, &numTicket, nil, nil, &expiry)
		if err != nil && err.Error() != "-4: ticket price exceeds spend limit" {
			t.Fatal(err)
		}
		blockHashes, err := r.GenerateBlock(curBlockHeight)
		if err != nil {
			t.Fatalf("unable to generate single block: %v", err)
		}
		block, err := r.Node.GetBlock(blockHashes[0])
		if err != nil {
			t.Fatalf("unable to get block: %v", err)
		}
		curBlockHeight = block.MsgBlock().Header.Height
	}
}
