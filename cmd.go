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
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/seelog"
	"os"
	"time"
)

var (
	log     seelog.LoggerInterface = seelog.Default
	cfg     *config
	wallets = make(map[string]*wallet.Wallet)
)

func main() {
	tcfg, _, err := loadConfig()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cfg = tcfg

	// Open wallet
	file, err := os.Open(cfg.WalletFile)
	if err != nil {
		log.Error("Error opening wallet:", err)
	}
	w := new(wallet.Wallet)
	if _, err = w.ReadFrom(file); err != nil {
		log.Error(err)
	}

	// Associate this wallet with default account.
	wallets[""] = w

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
