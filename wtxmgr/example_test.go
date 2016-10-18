// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr_test

import (
	"fmt"

	"github.com/jadeblaquiere/ctcd/chaincfg"
	"github.com/jadeblaquiere/ctcd/chaincfg/chainhash"
	"github.com/jadeblaquiere/ctcd/wire"
	"github.com/jadeblaquiere/ctcwallet/wtxmgr"
)

var (
	// Spends: bogus
	// Outputs: 10 BTC
	exampleTxRecordA *wtxmgr.TxRecord

	// Spends: A:0
	// Outputs: 5 BTC, 5 BTC
	exampleTxRecordB *wtxmgr.TxRecord
)

func init() {
	tx := spendOutput(&chainhash.Hash{}, 0, 10e8)
	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, timeNow())
	if err != nil {
		panic(err)
	}
	exampleTxRecordA = rec

	tx = spendOutput(&exampleTxRecordA.Hash, 0, 5e8, 5e8)
	rec, err = wtxmgr.NewTxRecordFromMsgTx(tx, timeNow())
	if err != nil {
		panic(err)
	}
	exampleTxRecordB = rec
}

var exampleBlock100 = makeBlockMeta(100)

// This example demonstrates reporting the Store balance given an unmined and
// mined transaction given 0, 1, and 6 block confirmations.
func ExampleStore_Balance() {
	s, teardown, err := testStore()
	defer teardown()
	if err != nil {
		fmt.Println(err)
		return
	}

	// Prints balances for 0 block confirmations, 1 confirmation, and 6
	// confirmations.
	printBalances := func(syncHeight int32) {
		zeroConfBal, err := s.Balance(0, syncHeight)
		if err != nil {
			fmt.Println(err)
			return
		}
		oneConfBal, err := s.Balance(1, syncHeight)
		if err != nil {
			fmt.Println(err)
			return
		}
		sixConfBal, err := s.Balance(6, syncHeight)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("%v, %v, %v\n", zeroConfBal, oneConfBal, sixConfBal)
	}

	// Insert a transaction which outputs 10 BTC unmined and mark the output
	// as a credit.
	err = s.InsertTx(exampleTxRecordA, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = s.AddCredit(exampleTxRecordA, nil, 0, false)
	if err != nil {
		fmt.Println(err)
		return
	}
	printBalances(100)

	// Mine the transaction in block 100 and print balances again with a
	// sync height of 100 and 105 blocks.
	err = s.InsertTx(exampleTxRecordA, &exampleBlock100)
	if err != nil {
		fmt.Println(err)
		return
	}
	printBalances(100)
	printBalances(105)

	// Output:
	// 10 BTC, 0 BTC, 0 BTC
	// 10 BTC, 10 BTC, 0 BTC
	// 10 BTC, 10 BTC, 10 BTC
}

func ExampleStore_Rollback() {
	s, teardown, err := testStore()
	defer teardown()
	if err != nil {
		fmt.Println(err)
		return
	}

	// Insert a transaction which outputs 10 BTC in a block at height 100.
	err = s.InsertTx(exampleTxRecordA, &exampleBlock100)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Rollback everything from block 100 onwards.
	err = s.Rollback(100)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Assert that the transaction is now unmined.
	details, err := s.TxDetails(&exampleTxRecordA.Hash)
	if err != nil {
		fmt.Println(err)
		return
	}
	if details == nil {
		fmt.Println("No details found")
		return
	}
	fmt.Println(details.Block.Height)

	// Output:
	// -1
}

func Example_basicUsage() {
	// Open the database.
	db, dbTeardown, err := testDB()
	defer dbTeardown()
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create or open a db namespace for the transaction store.
	ns, err := db.Namespace([]byte("txstore"))
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create (or open) the transaction store in the provided namespace.
	err = wtxmgr.Create(ns)
	if err != nil {
		fmt.Println(err)
		return
	}
	s, err := wtxmgr.Open(ns, &chaincfg.TestNet3Params)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Insert an unmined transaction that outputs 10 BTC to a wallet address
	// at output 0.
	err = s.InsertTx(exampleTxRecordA, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = s.AddCredit(exampleTxRecordA, nil, 0, false)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Insert a second transaction which spends the output, and creates two
	// outputs.  Mark the second one (5 BTC) as wallet change.
	err = s.InsertTx(exampleTxRecordB, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = s.AddCredit(exampleTxRecordB, nil, 1, true)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Mine each transaction in a block at height 100.
	err = s.InsertTx(exampleTxRecordA, &exampleBlock100)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = s.InsertTx(exampleTxRecordB, &exampleBlock100)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Print the one confirmation balance.
	bal, err := s.Balance(1, 100)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(bal)

	// Fetch unspent outputs.
	utxos, err := s.UnspentOutputs()
	if err != nil {
		fmt.Println(err)
	}
	expectedOutPoint := wire.OutPoint{Hash: exampleTxRecordB.Hash, Index: 1}
	for _, utxo := range utxos {
		fmt.Println(utxo.OutPoint == expectedOutPoint)
	}

	// Output:
	// 5 BTC
	// true
}
