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
		go w.ReqNewTxsForAddress(addr)
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

func (w *BtcWallet) ReqNewTxsForAddress(addr string) {
	seq.Lock()
	n := seq.n
	seq.n++
	seq.Unlock()

	m := &btcjson.Message{
		Jsonrpc: "1.0",
		Id:      fmt.Sprintf("btcwallet(%d)", n),
		Method:  "notifynewtxs",
		Params:  []interface{}{addr},
	}
	msg, _ := json.Marshal(m)

	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}) bool {
		// TODO(jrick): btcd also sends the block hash in the reply.
		// Do we want it saved as well?
		v, ok := result.(map[string]interface{})
		if !ok {
			log.Error("Tx Handler: Unexpected result type.")
			return false
		}
		sender58, ok := v["sender"].(string)
		if !ok {
			log.Error("Tx Handler: Unspecified sender.")
			return false
		}
		receiver58, ok := v["receiver"].(string)
		if !ok {
			log.Error("Tx Handler: Unspecified receiver.")
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
		amt, ok := v["amount"].(float64)
		if !ok {
			log.Error("Tx Handler: Unspecified amount.")
			return false
		}
		spent, ok := v["spent"].(bool)
		if !ok {
			log.Error("Tx Handler: Unspecified spent field.")
			return false
		}

		// btcd sends the tx  hashe as a BE string.  Convert to a
		// LE ShaHash.
		txhash, err := btcwire.NewShaHashFromStr(txhashBE)
		if err != nil {
			log.Error("Tx Handler: Tx hash string cannot be parsed: " + err.Error())
			return false
		}

		sender := btcutil.Base58Decode(sender58)
		receiver := btcutil.Base58Decode(receiver58)

		go func() {
			t := &tx.RecvTx{
				Amt: int64(amt),
			}
			copy(t.TxHash[:], txhash[:])
			copy(t.SenderAddr[:], sender)
			copy(t.ReceiverAddr[:], receiver)

			w.TxStore.Lock()
			txs := w.TxStore.s
			w.TxStore.s = append(txs, t)
			w.TxStore.dirty = true
			w.TxStore.Unlock()
		}()

		go func() {
			// Do not add output to utxo store if spent.
			if spent {
				return
			}

			u := &tx.Utxo{
				Amt:    int64(amt),
				Height: int64(height),
			}
			copy(u.Out.Hash[:], txhash[:])
			copy(u.Addr[:], receiver)

			w.UtxoStore.Lock()
			// All newly saved utxos are first classified as unconfirmed.
			utxos := w.UtxoStore.s.Unconfirmed
			w.UtxoStore.s.Unconfirmed = append(utxos, u)
			w.UtxoStore.dirty = true
			w.UtxoStore.Unlock()
		}()

		// Never remove this handler.
		return false
	}
	replyHandlers.Unlock()

	btcdMsgs <- msg
}

// Marshalling and unmarshalling byte arrays or slices results in ugly
// []interface{} slices where each interface{} is a float64.  This
// function unmangles this to return a byte slice.
func UnmangleJsonByteSlice(mangled []interface{}) (unmangled []byte) {
	unmangled = make([]byte, len(mangled))
	for i, _ := range mangled[:] {
		unmangled[i] = byte(mangled[i].(float64))
	}
	return unmangled
}
