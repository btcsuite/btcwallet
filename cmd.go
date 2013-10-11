/*
 * Copyright (c) 2013 Conformal Systems LLC <info@conformal.com>
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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"github.com/conformal/seelog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	satoshiPerBTC = 100000000
)

var (
	// ErrNoWallet describes an error where a wallet does not exist and
	// must be created first.
	ErrNoWallet = errors.New("wallet file does not exist")

	cfg *config
	log = seelog.Default

	curHeight = struct {
		sync.RWMutex
		h int64
	}{
		h: btcutil.BlockHeightUnknown,
	}
	wallets = NewBtcWalletStore()
)

// BtcWallet is a structure containing all the components for a
// complete wallet.  It contains the Armory-style wallet (to store
// addresses and keys), and tx and utxo data stores, along with locks
// to prevent against incorrect multiple access.
type BtcWallet struct {
	*wallet.Wallet
	mtx            sync.RWMutex
	name           string
	dirty          bool
	NewBlockTxSeqN uint64
	UtxoStore      struct {
		sync.RWMutex
		dirty bool
		s     tx.UtxoStore
	}
	TxStore struct {
		sync.RWMutex
		dirty bool
		s     tx.TxStore
	}
}

type BtcWalletStore struct {
	sync.RWMutex
	m map[string]*BtcWallet
}

// NewBtcWalletStore returns an initialized and empty BtcWalletStore.
func NewBtcWalletStore() *BtcWalletStore {
	return &BtcWalletStore{
		m: make(map[string]*BtcWallet),
	}
}

// Rollback reverts each stored BtcWallet to a state before the block
// with the passed chainheight and block hash was connected to the main
// chain.  This is used to remove transactions and utxos for each wallet
// that occured on a chain no longer considered to be the main chain.
func (s *BtcWalletStore) Rollback(height int64, hash *btcwire.ShaHash) {
	s.Lock()
	for _, w := range s.m {
		w.Rollback(height, hash)
	}
	s.Unlock()
}

func (w *BtcWallet) Rollback(height int64, hash *btcwire.ShaHash) {
	w.UtxoStore.Lock()
	w.UtxoStore.dirty = w.UtxoStore.dirty || w.UtxoStore.s.Rollback(height, hash)
	w.UtxoStore.Unlock()

	w.TxStore.Lock()
	w.TxStore.dirty = w.TxStore.dirty || w.TxStore.s.Rollback(height, hash)
	w.TxStore.Unlock()
}

// walletdir returns the directory path which holds the wallet, utxo,
// and tx files.
func walletdir(cfg *config, account string) string {
	var wname string
	if account == "" {
		wname = "btcwallet"
	} else {
		wname = fmt.Sprintf("btcwallet-%s", account)
	}

	return filepath.Join(cfg.DataDir, wname)
}

// OpenWallet opens a wallet described by account in the data
// directory specified by cfg.  If the wallet does not exist, ErrNoWallet
// is returned as an error.
func OpenWallet(cfg *config, account string) (*BtcWallet, error) {
	wdir := walletdir(cfg, account)
	fi, err := os.Stat(wdir)
	if err != nil {
		if os.IsNotExist(err) {
			// Attempt data directory creation
			if err = os.MkdirAll(wdir, 0700); err != nil {
				return nil, fmt.Errorf("cannot create data directory: %s", err)
			}
		} else {
			return nil, fmt.Errorf("error checking data directory: %s", err)
		}
	} else {
		if !fi.IsDir() {
			return nil, fmt.Errorf("data directory '%s' is not a directory", cfg.DataDir)
		}
	}

	wfilepath := filepath.Join(wdir, "wallet.bin")
	txfilepath := filepath.Join(wdir, "tx.bin")
	utxofilepath := filepath.Join(wdir, "utxo.bin")
	var wfile, txfile, utxofile *os.File
	if wfile, err = os.Open(wfilepath); err != nil {
		if os.IsNotExist(err) {
			// Must create and save wallet first.
			return nil, ErrNoWallet
		}
		return nil, fmt.Errorf("cannot open wallet file: %s", err)
	}
	defer wfile.Close()
	if txfile, err = os.Open(txfilepath); err != nil {
		if os.IsNotExist(err) {
			if txfile, err = os.Create(txfilepath); err != nil {
				return nil, fmt.Errorf("cannot create tx file: %s", err)
			}
		} else {
			return nil, fmt.Errorf("cannot open tx file: %s", err)
		}
	}
	defer txfile.Close()
	if utxofile, err = os.Open(utxofilepath); err != nil {
		if os.IsNotExist(err) {
			if utxofile, err = os.Create(utxofilepath); err != nil {
				return nil, fmt.Errorf("cannot create utxo file: %s", err)
			}
		} else {
			return nil, fmt.Errorf("cannot open utxo file: %s", err)
		}
	}
	defer utxofile.Close()

	wlt := new(wallet.Wallet)
	if _, err = wlt.ReadFrom(wfile); err != nil {
		return nil, fmt.Errorf("cannot read wallet: %s", err)
	}

	var txs tx.TxStore
	if _, err = txs.ReadFrom(txfile); err != nil {
		return nil, fmt.Errorf("cannot read tx file: %s", err)
	}

	var utxos tx.UtxoStore
	if _, err = utxos.ReadFrom(utxofile); err != nil {
		return nil, fmt.Errorf("cannot read utxo file: %s", err)
	}

	w := &BtcWallet{
		Wallet: wlt,
		name:   account,
		//NewBlockTxSeqN: // TODO(jrick): this MUST be set or notifications will be lost.
	}
	w.UtxoStore.s = utxos
	w.TxStore.s = txs

	return w, nil
}

func getCurHeight() (height int64) {
	curHeight.RLock()
	height = curHeight.h
	curHeight.RUnlock()
	if height != btcutil.BlockHeightUnknown {
		return height
	}

	seq.Lock()
	n := seq.n
	seq.n++
	seq.Unlock()

	m, err := btcjson.CreateMessageWithId("getblockcount",
		fmt.Sprintf("btcwallet(%v)", n))
	if err != nil {
		// Can't continue.
		return btcutil.BlockHeightUnknown
	}

	c := make(chan int64)

	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}, e *btcjson.Error) bool {
		if e != nil {
			c <- btcutil.BlockHeightUnknown
			return true
		}
		if balance, ok := result.(float64); ok {
			c <- int64(balance)
		} else {
			c <- btcutil.BlockHeightUnknown
		}
		return true
	}
	replyHandlers.Unlock()

	// send message
	btcdMsgs <- m

	// Block until reply is ready.
	height = <-c
	curHeight.Lock()
	if height > curHeight.h {
		curHeight.h = height
	} else {
		height = curHeight.h
	}
	curHeight.Unlock()

	return height
}

// CalculateBalance sums the amounts of all unspent transaction
// outputs to addresses of a wallet and returns the balance as a
// float64.
func (w *BtcWallet) CalculateBalance(confirmations int) float64 {
	var bal uint64 // Measured in satoshi

	height := getCurHeight()
	if height == btcutil.BlockHeightUnknown {
		return 0.
	}

	w.UtxoStore.RLock()
	for _, u := range w.UtxoStore.s {
		if int(height-u.Height) >= confirmations {
			bal += u.Amt
		}
	}
	w.UtxoStore.RUnlock()
	return float64(bal) / satoshiPerBTC
}

// Track requests btcd to send notifications of new transactions for
// each address stored in a wallet and sets up a new reply handler for
// these notifications.
func (w *BtcWallet) Track() {
	seq.Lock()
	n := seq.n
	seq.n++
	seq.Unlock()

	w.mtx.Lock()
	w.NewBlockTxSeqN = n
	w.mtx.Unlock()

	replyHandlers.Lock()
	replyHandlers.m[n] = w.newBlockTxHandler
	replyHandlers.Unlock()
	for _, addr := range w.GetActiveAddresses() {
		go w.ReqNewTxsForAddress(addr)
	}
}

// RescanForAddress requests btcd to rescan the blockchain for new
// transactions to addr.  This is useful for making btcwallet catch up to
// a long-running btcd process, or for importing addresses and rescanning
// for unspent tx outputs.  If len(blocks) is 0, the entire blockchain is
// rescanned.  If len(blocks) is 1, the rescan will begin at height
// blocks[0].  If len(blocks) is 2 or greater, the rescan will be
// performed for the block range blocks[0]...blocks[1] (inclusive).
func (w *BtcWallet) RescanForAddress(addr string, blocks ...int) {
	seq.Lock()
	n := seq.n
	seq.n++
	seq.Unlock()

	params := []interface{}{addr}
	if len(blocks) > 0 {
		params = append(params, blocks[0])
	}
	if len(blocks) > 1 {
		params = append(params, blocks[1])
	}
	m := &btcjson.Message{
		Jsonrpc: "1.0",
		Id:      fmt.Sprintf("btcwallet(%v)", n),
		Method:  "rescan",
		Params:  params,
	}
	msg, _ := json.Marshal(m)

	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}, e *btcjson.Error) bool {
		// TODO(jrick)

		// btcd returns a nil result when the rescan is complete.
		// Returning true signals that this handler is finished
		// and can be removed.
		return result == nil
	}
	replyHandlers.Unlock()

	btcdMsgs <- msg
}

// ReqNewTxsForAddress sends a message to btcd to request tx updates
// for addr for each new block that is added to the blockchain.
func (w *BtcWallet) ReqNewTxsForAddress(addr string) {
	w.mtx.RLock()
	n := w.NewBlockTxSeqN
	w.mtx.RUnlock()

	m := &btcjson.Message{
		Jsonrpc: "1.0",
		Id:      fmt.Sprintf("btcwallet(%d)", n),
		Method:  "notifynewtxs",
		Params:  []interface{}{addr},
	}
	msg, _ := json.Marshal(m)

	btcdMsgs <- msg
}

// newBlockTxHandler is the handler function for btcd transaction
// notifications resulting from newly-attached blocks.
func (w *BtcWallet) newBlockTxHandler(result interface{}, e *btcjson.Error) bool {
	if e != nil {
		log.Errorf("Tx Handler: Error %d received from btcd: %s",
			e.Code, e.Message)
		return false
	}

	v, ok := result.(map[string]interface{})
	if !ok {
		// The first result sent from btcd is nil.  This could be used to
		// indicate that the request for notifications succeeded.
		if result != nil {
			log.Errorf("Tx Handler: Unexpected result type %T.", result)
		}
		return false
	}
	sender, ok := v["sender"].(string)
	if !ok {
		log.Error("Tx Handler: Unspecified sender.")
		return false
	}
	receiver, ok := v["receiver"].(string)
	if !ok {
		log.Error("Tx Handler: Unspecified receiver.")
		return false
	}
	blockhashBE, ok := v["blockhash"].(string)
	if !ok {
		log.Error("Tx Handler: Unspecified block hash.")
		return false
	}
	height, ok := v["height"].(float64)
	if !ok {
		log.Error("Tx Handler: Unspecified height.")
		return false
	}
	txhashBE, ok := v["txhash"].(string)
	if !ok {
		log.Error("Tx Handler: Unspecified transaction hash.")
		return false
	}
	index, ok := v["index"].(float64)
	if !ok {
		log.Error("Tx Handler: Unspecified transaction index.")
		return false
	}
	amt, ok := v["amount"].(float64)
	if !ok {
		log.Error("Tx Handler: Unspecified amount.")
		return false
	}
	pkscript58, ok := v["pkscript"].(string)
	if !ok {
		log.Error("Tx Handler: Unspecified pubkey script.")
		return false
	}
	pkscript := btcutil.Base58Decode(pkscript58)
	spent, ok := v["spent"].(bool)
	if !ok {
		log.Error("Tx Handler: Unspecified spent field.")
		return false
	}

	// btcd sends the block and tx hashes as BE strings.  Convert both
	// to a LE ShaHash.
	blockhash, err := btcwire.NewShaHashFromStr(blockhashBE)
	if err != nil {
		log.Error("Tx Handler: Block hash string cannot be parsed: " + err.Error())
		return false
	}
	txhash, err := btcwire.NewShaHashFromStr(txhashBE)
	if err != nil {
		log.Error("Tx Handler: Tx hash string cannot be parsed: " + err.Error())
		return false
	}

	// TODO(jrick): btcd does not find the sender yet.
	senderHash, _, _ := btcutil.DecodeAddress(sender)
	receiverHash, _, err := btcutil.DecodeAddress(receiver)
	if err != nil {
		log.Error("Tx Handler: receiver address can not be decoded: " + err.Error())
		return false
	}

	go func() {
		t := &tx.RecvTx{
			Amt: uint64(amt),
		}
		copy(t.TxHash[:], txhash[:])
		copy(t.BlockHash[:], blockhash[:])
		copy(t.SenderAddr[:], senderHash)
		copy(t.ReceiverAddr[:], receiverHash)

		w.TxStore.Lock()
		txs := w.TxStore.s
		w.TxStore.s = append(txs, t)
		w.TxStore.dirty = true
		w.TxStore.Unlock()
	}()

	// Do not add output to utxo store if spent.
	if !spent {
		go func() {
			u := &tx.Utxo{
				Amt:    uint64(amt),
				Height: int64(height),
				Subscript: pkscript,
			}
			copy(u.Out.Hash[:], txhash[:])
			u.Out.Index = uint32(index)
			
			copy(u.AddrHash[:], receiverHash)
			copy(u.BlockHash[:], blockhash[:])

			w.UtxoStore.Lock()
			w.UtxoStore.s = append(w.UtxoStore.s, u)
			w.UtxoStore.dirty = true
			w.UtxoStore.Unlock()
			confirmed := w.CalculateBalance(6)
			unconfirmed := w.CalculateBalance(0) - confirmed
			NotifyWalletBalance(frontendNotificationMaster, w.name, confirmed)
			NotifyWalletBalanceUnconfirmed(frontendNotificationMaster, w.name, unconfirmed)
		}()
	}

	// Never remove this handler.
	return false
}

func main() {
	tcfg, _, err := loadConfig()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	cfg = tcfg

	// Open wallet
	w, err := OpenWallet(cfg, "")
	if err != nil {
		log.Info(err.Error())
	} else {
		wallets.Lock()
		wallets.m[""] = w
		wallets.Unlock()
	}

	go func() {
		// Start HTTP server to listen and send messages to frontend and btcd
		// backend.  Try reconnection if connection failed.
		for {
			if err := FrontendListenAndServe(); err == ErrConnRefused {
				// wait and try again.
				log.Info("Unable to start frontend HTTP server. Retrying in 5 seconds.")
				time.Sleep(5 * time.Second)
			}
		}
	}()

	for {
		replies := make(chan error)
		done := make(chan int)
		go func() {
			BtcdConnect(replies)
			close(done)
		}()
	selectLoop:
		for {
			select {
			case <-done:
				break selectLoop
			case err := <-replies:
				switch err {
				case ErrConnRefused:
					btcdConnected.c <- false
					log.Info("btcd connection refused, retying in 5 seconds")
					time.Sleep(5 * time.Second)
				case ErrConnLost:
					btcdConnected.c <- false
					log.Info("btcd connection lost, retrying in 5 seconds")
					time.Sleep(5 * time.Second)
				case nil:
					btcdConnected.c <- true
					log.Info("Established connection to btcd.")
				default:
					log.Infof("Unhandled error: %v", err)
				}
			}
		}
	}
}
