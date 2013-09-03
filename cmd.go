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
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/seelog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrNoWallet = errors.New("Wallet file does not exist.")
)

var (
	log     seelog.LoggerInterface = seelog.Default
	cfg     *config
	wallets = struct {
		sync.RWMutex
		m map[string]*BtcWallet
	}{
		m: make(map[string]*BtcWallet),
	}
)

func main() {
	tcfg, _, err := loadConfig()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cfg = tcfg

	// Open wallet
	w, err := OpenWallet(cfg, "")
	if err != nil {
		log.Info(err.Error())
	} else {
		w.Track()
	}

	// Start HTTP server to listen and send messages to frontend and btcd
	// backend.  Try reconnection if connection failed.
	for {
		if err := ListenAndServe(); err == ConnRefused {
			// wait and try again.
			log.Info("Unable to connect to btcd. Retrying in 5 seconds.")
			time.Sleep(5 * time.Second)
		} else if err != nil {
			log.Info(err.Error())
			break
		}
	}
}

type BtcWallet struct {
	*wallet.Wallet
	mtx       sync.RWMutex
	dirty     bool
	UtxoStore struct {
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

func OpenWallet(cfg *config, account string) (*BtcWallet, error) {
	wdir := walletdir(cfg, account)
	fi, err := os.Stat(wdir)
	if err != nil {
		if os.IsNotExist(err) {
			// Attempt data directory creation
			if err = os.MkdirAll(wdir, 0700); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	} else {
		if !fi.IsDir() {
			return nil, fmt.Errorf("Data directory '%s' is not a directory.", cfg.DataDir)
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
		} else {
			return nil, err
		}
	}
	defer wfile.Close()
	if txfile, err = os.Open(txfilepath); err != nil {
		if os.IsNotExist(err) {
			if txfile, err = os.Create(txfilepath); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	defer txfile.Close()
	if utxofile, err = os.Open(utxofilepath); err != nil {
		if os.IsNotExist(err) {
			if utxofile, err = os.Create(utxofilepath); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	defer utxofile.Close()

	wlt := new(wallet.Wallet)
	if _, err = wlt.ReadFrom(wfile); err != nil {
		return nil, err
	}

	var txs tx.TxStore
	if _, err = txs.ReadFrom(txfile); err != nil {
		return nil, err
	}

	var utxos tx.UtxoStore
	if _, err = utxos.ReadFrom(utxofile); err != nil {

	}

	w := &BtcWallet{
		Wallet: wlt,
	}
	w.UtxoStore.s = utxos
	w.TxStore.s = txs

	return w, nil
}

func (w *BtcWallet) Track() {
	wallets.Lock()
	name := w.Name()
	if wallets.m[name] == nil {
		wallets.m[name] = w
	}
	wallets.Unlock()

	for _, addr := range w.GetActiveAddresses() {
		go w.ReqUtxoForAddress(addr)
	}
}

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
	replyHandlers.m[n] = func(result interface{}) bool {
		// TODO(jrick)

		// btcd returns a nil result when the rescan is complete.
		// Returning true signals that this handler is finished
		// and can be removed.
		return result == nil
	}
	replyHandlers.Unlock()

	btcdMsgs <- msg
}

func (w *BtcWallet) ReqUtxoForAddress(addr string) {
	seq.Lock()
	n := seq.n
	seq.n++
	seq.Unlock()

	m := &btcjson.Message{
		Jsonrpc: "1.0",
		Id:      fmt.Sprintf("btcwallet(%d)", n),
		Method:  "requestutxos",
		Params:  []interface{}{addr},
	}
	msg, _ := json.Marshal(m)

	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}) bool {
		// TODO(jrick)

		// Never remove this handler.
		return false
	}
	replyHandlers.Unlock()

	btcdMsgs <- msg
}

func (w *BtcWallet) ReqTxsForAddress(addr string) {
	seq.Lock()
	n := seq.n
	seq.n++
	seq.Unlock()

	m := &btcjson.Message{
		Jsonrpc: "1.0",
		Id:      fmt.Sprintf("btcwallet(%d)", n),
		Method:  "requesttxs",
		Params:  []interface{}{addr},
	}
	msg, _ := json.Marshal(m)

	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}) bool {
		// TODO(jrick)

		// Never remove this handler.
		return false
	}
	replyHandlers.Unlock()

	btcdMsgs <- msg
}
