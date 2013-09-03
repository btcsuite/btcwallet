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
	"fmt"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/seelog"
	"os"
	"path/filepath"
	"sync"
	"time"
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

	/*
		// Open wallet
		file, err := os.Open(cfg.WalletFile)
		if err != nil {
			log.Error("Error opening wallet:", err)
		}
		w := new(wallet.Wallet)
		if _, err = w.ReadFrom(file); err != nil {
			log.Error(err)
		}
	*/

	// Open wallet
	btcw, err := OpenOrCreateWallet(cfg, "")
	if err != nil {
		panic(err)
	}
	_ = btcw

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
	tx.UtxoStore
	tx.TxStore
}

func OpenOrCreateWallet(cfg *config, account string) (*BtcWallet, error) {
	// Open wallet file specified by account.
	var wname string
	if account == "" {
		wname = "btcwallet"
	} else {
		wname = fmt.Sprintf("btcwallet-%s", account)
	}

	wdir := filepath.Join(cfg.DataDir, wname)
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
			if wfile, err = os.Create(wfilepath); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	if txfile, err = os.Open(txfilepath); err != nil {
		if os.IsNotExist(err) {
			if txfile, err = os.Create(txfilepath); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	if utxofile, err = os.Open(utxofilepath); err != nil {
		if os.IsNotExist(err) {
			if utxofile, err = os.Create(utxofilepath); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

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
		Wallet:    wlt,
		UtxoStore: utxos,
		TxStore:   txs,
	}

	// Associate this wallet with default account.
	wallets.Lock()
	wallets.m[account] = w
	wallets.Unlock()

	return w, nil
}
