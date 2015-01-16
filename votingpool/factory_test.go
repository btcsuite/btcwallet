/*
 * Copyright (c) 2014 Conformal Systems LLC <info@conformal.com>
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

// Helpers to create parameterized objects to use in tests.

package votingpool

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/legacy/txstore"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// seed is the master seed used to create extended keys.
	seed           = bytes.Repeat([]byte{0x2a, 0x64, 0xdf, 0x08}, 8)
	pubPassphrase  = []byte("_DJr{fL4H0O}*-0\n:V1izc)(6BomK")
	privPassphrase = []byte("81lUHXnOMZ@?XXd7O9xyDIWIbXX-lj")
	uniqueCounter  = uint32(0)
	// The block height where all our test inputs are created.
	TstInputsBlock = int32(10)
)

func getUniqueID() uint32 {
	return atomic.AddUint32(&uniqueCounter, 1)
}

// createWithdrawalTx creates a withdrawalTx with the given input and output amounts.
func createWithdrawalTx(t *testing.T, pool *Pool, store *txstore.Store, inputAmounts []int64,
	outputAmounts []int64) *withdrawalTx {
	net := pool.Manager().ChainParams()
	tx := newWithdrawalTx()
	_, credits := TstCreateCredits(t, pool, inputAmounts, store)
	for _, c := range credits {
		tx.addInput(c)
	}
	for i, amount := range outputAmounts {
		request := TstNewOutputRequest(
			t, uint32(i), "34eVkREKgvvGASZW7hkgE2uNc1yycntMK6", btcutil.Amount(amount), net)
		tx.addOutput(request)
	}
	return tx
}

func createMsgTx(pkScript []byte, amts []int64) *wire.MsgTx {
	msgtx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.ShaHash{},
					Index: 0xffffffff,
				},
				SignatureScript: []byte{txscript.OP_NOP},
				Sequence:        0xffffffff,
			},
		},
		LockTime: 0,
	}

	for _, amt := range amts {
		msgtx.AddTxOut(wire.NewTxOut(amt, pkScript))
	}
	return msgtx
}

func TstNewDepositScript(t *testing.T, p *Pool, seriesID uint32, branch Branch, idx Index) []byte {
	script, err := p.DepositScript(seriesID, branch, idx)
	if err != nil {
		t.Fatalf("Failed to create deposit script for series %d, branch %d, index %d: %v",
			seriesID, branch, idx, err)
	}
	return script
}

// TstEnsureUsedAddr ensures the addresses defined by the given series/branch and
// index==0..idx are present in the set of used addresses for the given Pool.
func TstEnsureUsedAddr(t *testing.T, p *Pool, seriesID uint32, branch Branch, idx Index) []byte {
	addr, err := p.getUsedAddr(seriesID, branch, idx)
	if err != nil {
		t.Fatal(err)
	} else if addr != nil {
		var script []byte
		TstRunWithManagerUnlocked(t, p.Manager(), func() {
			script, err = addr.Script()
		})
		if err != nil {
			t.Fatal(err)
		}
		return script
	}
	TstRunWithManagerUnlocked(t, p.Manager(), func() {
		err = p.EnsureUsedAddr(seriesID, branch, idx)
	})
	if err != nil {
		t.Fatal(err)
	}
	return TstNewDepositScript(t, p, seriesID, branch, idx)
}

func TstCreatePkScript(t *testing.T, p *Pool, seriesID uint32, branch Branch, idx Index) []byte {
	script := TstEnsureUsedAddr(t, p, seriesID, branch, idx)
	addr, err := p.addressFor(script)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}
	return pkScript
}

func TstCreateTxStore(t *testing.T) (store *txstore.Store, tearDown func()) {
	dir, err := ioutil.TempDir("", "tx.bin")
	if err != nil {
		t.Fatalf("Failed to create db file: %v", err)
	}
	s := txstore.New(dir)
	return s, func() { os.RemoveAll(dir) }
}

type TstSeriesDef struct {
	ReqSigs  uint32
	PubKeys  []string
	PrivKeys []string
	SeriesID uint32
	Inactive bool
}

// TstCreateSeries creates a new Series for every definition in the given slice
// of TstSeriesDef. If the definition includes any private keys, the Series is
// empowered with them.
func TstCreateSeries(t *testing.T, pool *Pool, definitions []TstSeriesDef) {
	for _, def := range definitions {
		err := pool.CreateSeries(CurrentVersion, def.SeriesID, def.ReqSigs, def.PubKeys)
		if err != nil {
			t.Fatalf("Cannot creates series %d: %v", def.SeriesID, err)
		}
		TstRunWithManagerUnlocked(t, pool.Manager(), func() {
			for _, key := range def.PrivKeys {
				if err := pool.EmpowerSeries(def.SeriesID, key); err != nil {
					t.Fatal(err)
				}
			}
		})
		pool.Series(def.SeriesID).active = !def.Inactive
	}
}

func TstCreateMasterKey(t *testing.T, seed []byte) *hdkeychain.ExtendedKey {
	key, err := hdkeychain.NewMaster(seed)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// createMasterKeys creates count master ExtendedKeys with unique seeds.
func createMasterKeys(t *testing.T, count int) []*hdkeychain.ExtendedKey {
	keys := make([]*hdkeychain.ExtendedKey, count)
	for i := range keys {
		keys[i] = TstCreateMasterKey(t, bytes.Repeat(uint32ToBytes(getUniqueID()), 4))
	}
	return keys
}

// TstCreateSeriesDef creates a TstSeriesDef with a unique SeriesID, the given
// reqSigs and the raw public/private keys extracted from the list of private
// keys. The new series will be empowered with all private keys.
func TstCreateSeriesDef(t *testing.T, pool *Pool, reqSigs uint32, keys []*hdkeychain.ExtendedKey) TstSeriesDef {
	pubKeys := make([]string, len(keys))
	privKeys := make([]string, len(keys))
	for i, key := range keys {
		privKeys[i] = key.String()
		pubkey, _ := key.Neuter()
		pubKeys[i] = pubkey.String()
	}
	seriesID := uint32(len(pool.seriesLookup))
	if seriesID == 0 {
		seriesID++
	}
	return TstSeriesDef{
		ReqSigs: reqSigs, SeriesID: seriesID, PubKeys: pubKeys, PrivKeys: privKeys}
}

func TstCreatePoolAndTxStore(t *testing.T) (tearDown func(), pool *Pool, store *txstore.Store) {
	mgrTearDown, _, pool := TstCreatePool(t)
	store, storeTearDown := TstCreateTxStore(t)
	tearDown = func() {
		mgrTearDown()
		storeTearDown()
	}
	return tearDown, pool, store
}

// TstCreateCredits creates a new Series (with a unique ID) and a slice of
// credits locked to the series' address with branch==1 and index==0. The new
// Series will use a 2-of-3 configuration and will be empowered with all of its
// private keys.
func TstCreateCredits(t *testing.T, pool *Pool, amounts []int64, store *txstore.Store) (
	uint32, []Credit) {
	masters := []*hdkeychain.ExtendedKey{
		TstCreateMasterKey(t, bytes.Repeat(uint32ToBytes(getUniqueID()), 4)),
		TstCreateMasterKey(t, bytes.Repeat(uint32ToBytes(getUniqueID()), 4)),
		TstCreateMasterKey(t, bytes.Repeat(uint32ToBytes(getUniqueID()), 4)),
	}
	def := TstCreateSeriesDef(t, pool, 2, masters)
	TstCreateSeries(t, pool, []TstSeriesDef{def})
	return def.SeriesID, TstCreateCreditsOnSeries(t, pool, def.SeriesID, amounts, store)
}

// TstCreateCreditsOnSeries creates a slice of credits locked to the given
// series' address with branch==1 and index==0.
func TstCreateCreditsOnSeries(t *testing.T, pool *Pool, seriesID uint32, amounts []int64,
	store *txstore.Store) []Credit {
	branch := Branch(1)
	idx := Index(0)
	pkScript := TstCreatePkScript(t, pool, seriesID, branch, idx)
	eligible := make([]Credit, len(amounts))
	for i, credit := range TstCreateInputs(t, store, pkScript, amounts) {
		eligible[i] = newCredit(credit, *TstNewWithdrawalAddress(t, pool, seriesID, branch, idx))
	}
	return eligible
}

// TstCreateInputs is a convenience function.  See TstCreateInputsOnBlock
// for a more flexible version.
func TstCreateInputs(t *testing.T, store *txstore.Store, pkScript []byte, amounts []int64) []txstore.Credit {
	return TstCreateInputsOnBlock(t, store, 1, pkScript, amounts)
}

// TstCreateInputsOnBlock creates a number of inputs by creating a transaction
// with a number of outputs corresponding to the elements of the amounts slice.
//
// The transaction is added to a block and the index and blockheight must be
// specified.
func TstCreateInputsOnBlock(t *testing.T, s *txstore.Store,
	blockTxIndex int, pkScript []byte, amounts []int64) []txstore.Credit {
	msgTx := createMsgTx(pkScript, amounts)
	block := &txstore.Block{
		Height: TstInputsBlock,
	}

	tx := btcutil.NewTx(msgTx)
	tx.SetIndex(blockTxIndex)

	r, err := s.InsertTx(tx, block)
	if err != nil {
		t.Fatal("Failed to create inputs: ", err)
	}

	credits := make([]txstore.Credit, len(msgTx.TxOut))
	for i := range msgTx.TxOut {
		credit, err := r.AddCredit(uint32(i), false)
		if err != nil {
			t.Fatal("Failed to create inputs: ", err)
		}
		credits[i] = credit
	}
	return credits
}

// TstCreatePool creates a Pool on a fresh walletdb and returns it. It also
// returns the pool's waddrmgr.Manager (which uses the same walletdb, but with a
// different namespace) as a convenience, and a teardown function that closes
// the Manager and removes the directory used to store the database.
func TstCreatePool(t *testing.T) (tearDownFunc func(), mgr *waddrmgr.Manager, pool *Pool) {
	// This should be moved somewhere else eventually as not all of our tests
	// call this function, but right now the only option would be to have the
	// t.Parallel() call in each of our tests.
	t.Parallel()

	// Create a new wallet DB and addr manager.
	dir, err := ioutil.TempDir("", "pool_test")
	if err != nil {
		t.Fatalf("Failed to create db dir: %v", err)
	}
	db, err := walletdb.Create("bdb", filepath.Join(dir, "wallet.db"))
	if err != nil {
		t.Fatalf("Failed to create wallet DB: %v", err)
	}
	mgrNamespace, err := db.Namespace([]byte("waddrmgr"))
	if err != nil {
		t.Fatalf("Failed to create addr manager DB namespace: %v", err)
	}
	var fastScrypt = &waddrmgr.Options{ScryptN: 16, ScryptR: 8, ScryptP: 1}
	mgr, err = waddrmgr.Create(mgrNamespace, seed, pubPassphrase, privPassphrase,
		&chaincfg.MainNetParams, fastScrypt)
	if err != nil {
		t.Fatalf("Failed to create addr manager: %v", err)
	}

	// Create a walletdb for votingpools.
	vpNamespace, err := db.Namespace([]byte("votingpool"))
	if err != nil {
		t.Fatalf("Failed to create VotingPool DB namespace: %v", err)
	}
	pool, err = Create(vpNamespace, mgr, []byte{0x00})
	if err != nil {
		t.Fatalf("Voting Pool creation failed: %v", err)
	}
	tearDownFunc = func() {
		db.Close()
		mgr.Close()
		os.RemoveAll(dir)
	}
	return tearDownFunc, mgr, pool
}

func TstNewOutputRequest(t *testing.T, transaction uint32, address string, amount btcutil.Amount,
	net *chaincfg.Params) OutputRequest {
	addr, err := btcutil.DecodeAddress(address, net)
	if err != nil {
		t.Fatalf("Unable to decode address %s", address)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("Unable to generate pkScript for %v", addr)
	}
	return OutputRequest{
		PkScript:    pkScript,
		Address:     addr,
		Amount:      amount,
		Server:      "server",
		Transaction: transaction,
	}
}

func TstNewWithdrawalOutput(r OutputRequest, status outputStatus,
	outpoints []OutBailmentOutpoint) *WithdrawalOutput {
	output := &WithdrawalOutput{
		request:   r,
		status:    status,
		outpoints: outpoints,
	}
	return output
}

func TstNewWithdrawalAddress(t *testing.T, p *Pool, seriesID uint32, branch Branch,
	index Index) (addr *WithdrawalAddress) {
	TstEnsureUsedAddr(t, p, seriesID, branch, index)
	var err error
	TstRunWithManagerUnlocked(t, p.Manager(), func() {
		addr, err = p.WithdrawalAddress(seriesID, branch, index)
	})
	if err != nil {
		t.Fatalf("Failed to get WithdrawalAddress: %v", err)
	}
	return addr
}

func TstNewChangeAddress(t *testing.T, p *Pool, seriesID uint32, idx Index) (addr *ChangeAddress) {
	addr, err := p.ChangeAddress(seriesID, idx)
	if err != nil {
		t.Fatalf("Failed to get ChangeAddress: %v", err)
	}
	return addr
}

func TstConstantFee(fee btcutil.Amount) func(tx *withdrawalTx) btcutil.Amount {
	return func(tx *withdrawalTx) btcutil.Amount { return fee }
}
