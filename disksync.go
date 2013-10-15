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
	"os"
	"path/filepath"
	"time"
)

var dirtyAccountSet = make(map[*BtcWallet]bool)
var addDirtyAccount = make(chan *BtcWallet)

// DirtyAccountUpdater is responsible for listening for listens for new
// dirty wallets (changed in memory with updaets not yet saved to disk)
// to add to dirtyAccountSet.  This is designed to run as a single goroutine.
func DirtyAccountUpdater() {
	timer := time.Tick(time.Minute)
	for {
		select {
		case w := <-addDirtyAccount:
			dirtyAccountSet[w] = true

		case <-timer:
			for w := range dirtyAccountSet {
				if err := w.writeDirtyToDisk(); err != nil {
					log.Errorf("cannot sync dirty wallet '%v': %v", w.name, err)
				} else {
					delete(dirtyAccountSet, w)
					log.Infof("removed dirty wallet '%v'", w.name)
				}
			}
		}
	}
}

// AddDirtyAccount adds w to a set of items to be synced to disk.  The
// dirty flag must still be set on the various dirty elements of the
// account (wallet, transactions, and/or utxos) or nothing will be
// written to disk during the next scheduled sync.
func AddDirtyAccount(w *BtcWallet) {
	addDirtyAccount <- w
}

// writeDirtyToDisk checks for the dirty flag on an account's wallet,
// txstore, and utxostore, writing them to disk if any are dirty.
func (w *BtcWallet) writeDirtyToDisk() error {
	// Temporary files append the current time to the normal file name.
	// In caes of failure, the most recent temporary file can be inspected
	// for validity, and moved to replace the main file.
	timeStr := fmt.Sprintf("%v", time.Now().Unix())

	wdir := walletdir(cfg, w.name)
	wfilepath := filepath.Join(wdir, "wallet.bin")
	txfilepath := filepath.Join(wdir, "tx.bin")
	utxofilepath := filepath.Join(wdir, "utxo.bin")

	// Wallet
	if w.dirty {
		w.mtx.RLock()
		defer w.mtx.RUnlock()
		tmpfilepath := wfilepath + "-" + timeStr
		tmpfile, err := os.Create(tmpfilepath)
		if err != nil {
			return err
		}
		if _, err = w.WriteTo(tmpfile); err != nil {
			return err
		}

		// TODO(jrick): this should be atomic on *nix, but is not on
		// Windows.  Use _windows.go to provide atomic renames.
		if err = os.Rename(tmpfilepath, wfilepath); err != nil {
			return err
		}
	}

	// Transactions
	if w.TxStore.dirty {
		w.TxStore.RLock()
		defer w.TxStore.RUnlock()
		tmpfilepath := txfilepath + "-" + timeStr
		tmpfile, err := os.Create(tmpfilepath)
		if err != nil {
			return err
		}
		if _, err = w.TxStore.s.WriteTo(tmpfile); err != nil {
			return err
		}

		// TODO(jrick): this should be atomic on *nix, but is not on
		// Windows.  Use _windows.go to provide atomic renames.
		if err = os.Rename(tmpfilepath, txfilepath); err != nil {
			return err
		}
	}

	// UTXOs
	if w.UtxoStore.dirty {
		w.UtxoStore.RLock()
		defer w.UtxoStore.RUnlock()
		tmpfilepath := utxofilepath + "-" + timeStr
		tmpfile, err := os.Create(tmpfilepath)
		if err != nil {
			return err
		}
		if _, err = w.UtxoStore.s.WriteTo(tmpfile); err != nil {
			return err
		}

		// TODO(jrick): this should be atomic on *nix, but is not on
		// Windows.  Use _windows.go to provide atomic renames.
		if err = os.Rename(tmpfilepath, utxofilepath); err != nil {
			return err
		}
	}

	return nil
}
