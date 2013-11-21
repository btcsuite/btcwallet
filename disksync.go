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
	"sync"
	"time"
)

var (
	// dirtyAccounts holds a set of accounts that include dirty components.
	dirtyAccounts = struct {
		sync.Mutex
		m map[*Account]bool
	}{
		m: make(map[*Account]bool),
	}
)

// DirtyAccountSyncer synces dirty accounts for cases where the updated
// information was not required to be immediately written to disk.  Accounts
// may be added to dirtyAccounts and will be checked and processed every 10
// seconds by this function.
//
// This never returns and is meant to be called from a goroutine.
func DirtyAccountSyncer() {
	ticker := time.Tick(10 * time.Second)
	for {
		select {
		case <-ticker:
			dirtyAccounts.Lock()
			for a := range dirtyAccounts.m {
				log.Debugf("Syncing account '%v' to disk",
					a.Wallet.Name())
				if err := a.writeDirtyToDisk(); err != nil {
					log.Errorf("cannot sync dirty wallet: %v",
						err)
				} else {
					delete(dirtyAccounts.m, a)
				}
			}
			dirtyAccounts.Unlock()
		}
	}
}

// writeDirtyToDisk checks for the dirty flag on an account's wallet,
// txstore, and utxostore, writing them to disk if any are dirty.
func (w *Account) writeDirtyToDisk() error {
	// Temporary files append the current time to the normal file name.
	// In caes of failure, the most recent temporary file can be inspected
	// for validity, and moved to replace the main file.
	timeStr := fmt.Sprintf("%v", time.Now().Unix())

	adir := accountdir(cfg, w.name)
	if err := checkCreateAccountDir(adir); err != nil {
		return err
	}

	wfilepath := filepath.Join(adir, "wallet.bin")
	txfilepath := filepath.Join(adir, "tx.bin")
	utxofilepath := filepath.Join(adir, "utxo.bin")

	// UTXOs and transactions are synced to disk first.  This prevents
	// any races from saving a wallet marked to be synced with block N
	// and btcwallet closing while the UTXO and Tx files are only synced
	// with block N-1.

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
		tmpfile.Close()

		// TODO(jrick): this should be atomic on *nix, but is not on
		// Windows.  Use _windows.go to provide atomic renames.
		if err = os.Rename(tmpfilepath, utxofilepath); err != nil {
			return err
		}

		w.UtxoStore.dirty = false
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
		tmpfile.Close()

		// TODO(jrick): this should be atomic on *nix, but is not on
		// Windows.  Use _windows.go to provide atomic renames.
		if err = os.Rename(tmpfilepath, txfilepath); err != nil {
			return err
		}

		w.TxStore.dirty = false
	}

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
		tmpfile.Close()

		// TODO(jrick): this should be atomic on *nix, but is not on
		// Windows.  Use _windows.go to provide atomic renames.
		if err = os.Rename(tmpfilepath, wfilepath); err != nil {
			return err
		}

		w.dirty = false
	}

	return nil
}
