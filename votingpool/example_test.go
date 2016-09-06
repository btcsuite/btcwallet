/*
 * Copyright (c) 2014 The btcsuite developers
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package votingpool_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/jadeblaquiere/ctcd/chaincfg"
	"github.com/jadeblaquiere/ctcd/txscript"
	"github.com/jadeblaquiere/ctcutil"
	"github.com/jadeblaquiere/ctcwallet/votingpool"
	"github.com/jadeblaquiere/ctcwallet/waddrmgr"
	"github.com/jadeblaquiere/ctcwallet/walletdb"
	_ "github.com/jadeblaquiere/ctcwallet/walletdb/bdb"
	"github.com/jadeblaquiere/ctcwallet/wtxmgr"
)

var (
	pubPassphrase  = []byte("pubPassphrase")
	privPassphrase = []byte("privPassphrase")
	seed           = bytes.Repeat([]byte{0x2a, 0x64, 0xdf, 0x08}, 8)
	fastScrypt     = &waddrmgr.ScryptOptions{N: 16, R: 8, P: 1}
)

func createWaddrmgr(ns walletdb.Namespace, params *chaincfg.Params) (*waddrmgr.Manager, error) {
	err := waddrmgr.Create(ns, seed, pubPassphrase, privPassphrase, params,
		fastScrypt)
	if err != nil {
		return nil, err
	}
	return waddrmgr.Open(ns, pubPassphrase, params, nil)
}

func ExampleCreate() {
	// Create a new walletdb.DB. See the walletdb docs for instructions on how
	// to do that.
	db, dbTearDown, err := createWalletDB()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer dbTearDown()

	// Create a new walletdb namespace for the address manager.
	mgrNamespace, err := db.Namespace([]byte("waddrmgr"))
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create the address manager.
	mgr, err := createWaddrmgr(mgrNamespace, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create a walletdb namespace for votingpools.
	vpNamespace, err := db.Namespace([]byte("votingpool"))
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create a voting pool.
	_, err = votingpool.Create(vpNamespace, mgr, []byte{0x00})
	if err != nil {
		fmt.Println(err)
		return
	}

	// Output:
	//
}

// This example demonstrates how to create a voting pool with one
// series and get a deposit address for that series.
func Example_depositAddress() {
	// Create the address manager and votingpool DB namespace. See the example
	// for the Create() function for more info on how this is done.
	mgr, vpNamespace, tearDownFunc, err := exampleCreateMgrAndDBNamespace()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer tearDownFunc()

	// Create the voting pool.
	pool, err := votingpool.Create(vpNamespace, mgr, []byte{0x00})
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create a 2-of-3 series.
	seriesID := uint32(1)
	requiredSignatures := uint32(2)
	pubKeys := []string{
		"xpub661MyMwAqRbcFDDrR5jY7LqsRioFDwg3cLjc7tML3RRcfYyhXqqgCH5SqMSQdpQ1Xh8EtVwcfm8psD8zXKPcRaCVSY4GCqbb3aMEs27GitE",
		"xpub661MyMwAqRbcGsxyD8hTmJFtpmwoZhy4NBBVxzvFU8tDXD2ME49A6JjQCYgbpSUpHGP1q4S2S1Pxv2EqTjwfERS5pc9Q2yeLkPFzSgRpjs9",
		"xpub661MyMwAqRbcEbc4uYVXvQQpH9L3YuZLZ1gxCmj59yAhNy33vXxbXadmRpx5YZEupNSqWRrR7PqU6duS2FiVCGEiugBEa5zuEAjsyLJjKCh",
	}
	err = pool.CreateSeries(votingpool.CurrentVersion, seriesID, requiredSignatures, pubKeys)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create a deposit address.
	addr, err := pool.DepositScriptAddress(seriesID, votingpool.Branch(0), votingpool.Index(1))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Generated deposit address:", addr.EncodeAddress())

	// Output:
	// Generated deposit address: 3QTzpc9d3tTbNLJLB7xwt87nWM38boAhAw
}

// This example demonstrates how to empower a series by loading the private
// key for one of the series' public keys.
func Example_empowerSeries() {
	// Create the address manager and votingpool DB namespace. See the example
	// for the Create() function for more info on how this is done.
	mgr, vpNamespace, tearDownFunc, err := exampleCreateMgrAndDBNamespace()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer tearDownFunc()

	// Create a pool and a series. See the DepositAddress example for more info
	// on how this is done.
	pool, seriesID, err := exampleCreatePoolAndSeries(mgr, vpNamespace)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Now empower the series with one of its private keys. Notice that in order
	// to do that we need to unlock the address manager.
	if err := mgr.Unlock(privPassphrase); err != nil {
		fmt.Println(err)
		return
	}
	defer mgr.Lock()
	privKey := "xprv9s21ZrQH143K2j9PK4CXkCu8sgxkpUxCF7p1KVwiV5tdnkeYzJXReUkxz5iB2FUzTXC1L15abCDG4RMxSYT5zhm67uvsnLYxuDhZfoFcB6a"
	err = pool.EmpowerSeries(seriesID, privKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Output:
	//
}

// This example demonstrates how to use the Pool.StartWithdrawal method.
func Example_startWithdrawal() {
	// Create the address manager and votingpool DB namespace. See the example
	// for the Create() function for more info on how this is done.
	mgr, vpNamespace, tearDownFunc, err := exampleCreateMgrAndDBNamespace()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer tearDownFunc()

	// Create a pool and a series. See the DepositAddress example for more info
	// on how this is done.
	pool, seriesID, err := exampleCreatePoolAndSeries(mgr, vpNamespace)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Unlock the manager
	if err := mgr.Unlock(privPassphrase); err != nil {
		fmt.Println(err)
		return
	}
	defer mgr.Lock()

	addr, _ := btcutil.DecodeAddress("1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX", mgr.ChainParams())
	pkScript, _ := txscript.PayToAddrScript(addr)
	requests := []votingpool.OutputRequest{
		votingpool.OutputRequest{
			PkScript:    pkScript,
			Address:     addr,
			Amount:      1e6,
			Server:      "server-id",
			Transaction: 123},
	}
	changeStart, err := pool.ChangeAddress(seriesID, votingpool.Index(0))
	if err != nil {
		fmt.Println(err)
		return
	}
	// This is only needed because we have not used any deposit addresses from
	// the series, and we cannot create a WithdrawalAddress for an unused
	// branch/idx pair.
	if err = pool.EnsureUsedAddr(seriesID, votingpool.Branch(1), votingpool.Index(0)); err != nil {
		fmt.Println(err)
		return
	}
	startAddr, err := pool.WithdrawalAddress(seriesID, votingpool.Branch(1), votingpool.Index(0))
	if err != nil {
		fmt.Println(err)
		return
	}
	lastSeriesID := seriesID
	dustThreshold := btcutil.Amount(1e4)
	currentBlock := int32(19432)
	roundID := uint32(0)
	txstore, tearDownFunc, err := exampleCreateTxStore()
	if err != nil {
		fmt.Println(err)
		return
	}
	_, err = pool.StartWithdrawal(
		roundID, requests, *startAddr, lastSeriesID, *changeStart, txstore, currentBlock,
		dustThreshold)
	if err != nil {
		fmt.Println(err)
	}

	// Output:
	//
}

func createWalletDB() (walletdb.DB, func(), error) {
	dir, err := ioutil.TempDir("", "votingpool_example")
	if err != nil {
		return nil, nil, err
	}
	db, err := walletdb.Create("bdb", filepath.Join(dir, "wallet.db"))
	if err != nil {
		return nil, nil, err
	}
	dbTearDown := func() {
		db.Close()
		os.RemoveAll(dir)
	}
	return db, dbTearDown, nil
}

func exampleCreateMgrAndDBNamespace() (*waddrmgr.Manager, walletdb.Namespace, func(), error) {
	db, dbTearDown, err := createWalletDB()
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a new walletdb namespace for the address manager.
	mgrNamespace, err := db.Namespace([]byte("waddrmgr"))
	if err != nil {
		dbTearDown()
		return nil, nil, nil, err
	}

	// Create the address manager
	mgr, err := createWaddrmgr(mgrNamespace, &chaincfg.MainNetParams)
	if err != nil {
		dbTearDown()
		return nil, nil, nil, err
	}

	tearDownFunc := func() {
		mgr.Close()
		dbTearDown()
	}

	// Create a walletdb namespace for votingpools.
	vpNamespace, err := db.Namespace([]byte("votingpool"))
	if err != nil {
		tearDownFunc()
		return nil, nil, nil, err
	}
	return mgr, vpNamespace, tearDownFunc, nil
}

func exampleCreatePoolAndSeries(mgr *waddrmgr.Manager, vpNamespace walletdb.Namespace) (
	*votingpool.Pool, uint32, error) {
	pool, err := votingpool.Create(vpNamespace, mgr, []byte{0x00})
	if err != nil {
		return nil, 0, err
	}

	// Create a 2-of-3 series.
	seriesID := uint32(1)
	requiredSignatures := uint32(2)
	pubKeys := []string{
		"xpub661MyMwAqRbcFDDrR5jY7LqsRioFDwg3cLjc7tML3RRcfYyhXqqgCH5SqMSQdpQ1Xh8EtVwcfm8psD8zXKPcRaCVSY4GCqbb3aMEs27GitE",
		"xpub661MyMwAqRbcGsxyD8hTmJFtpmwoZhy4NBBVxzvFU8tDXD2ME49A6JjQCYgbpSUpHGP1q4S2S1Pxv2EqTjwfERS5pc9Q2yeLkPFzSgRpjs9",
		"xpub661MyMwAqRbcEbc4uYVXvQQpH9L3YuZLZ1gxCmj59yAhNy33vXxbXadmRpx5YZEupNSqWRrR7PqU6duS2FiVCGEiugBEa5zuEAjsyLJjKCh",
	}
	err = pool.CreateSeries(votingpool.CurrentVersion, seriesID, requiredSignatures, pubKeys)
	if err != nil {
		return nil, 0, err
	}
	err = pool.ActivateSeries(seriesID)
	if err != nil {
		return nil, 0, err
	}
	return pool, seriesID, nil
}

func exampleCreateTxStore() (*wtxmgr.Store, func(), error) {
	dir, err := ioutil.TempDir("", "pool_test_txstore")
	if err != nil {
		return nil, nil, err
	}
	db, err := walletdb.Create("bdb", filepath.Join(dir, "txstore.db"))
	if err != nil {
		return nil, nil, err
	}
	wtxmgrNamespace, err := db.Namespace([]byte("testtxstore"))
	if err != nil {
		return nil, nil, err
	}
	err = wtxmgr.Create(wtxmgrNamespace)
	if err != nil {
		return nil, nil, err
	}
	s, err := wtxmgr.Open(wtxmgrNamespace, &chaincfg.MainNetParams)
	if err != nil {
		return nil, nil, err
	}
	return s, func() { os.RemoveAll(dir) }, nil
}
