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
		w.mtx.Lock()
		defer w.mtx.Unlock()
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

		w.dirty = false
	}

	// Transactions
	if w.TxStore.dirty {
		w.TxStore.Lock()
		defer w.TxStore.Unlock()
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

		w.TxStore.dirty = false
	}

	// UTXOs
	if w.UtxoStore.dirty {
		w.UtxoStore.Lock()
		defer w.UtxoStore.Unlock()
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

		w.UtxoStore.dirty = false
	}

	return nil
}
