/*
 * Copyright (c) 2013, 2014 Conformal Systems LLC <info@conformal.com>
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
	"github.com/conformal/btcwire"
	"io/ioutil"
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

// networkDir returns the base directory name for the bitcoin network
// net.
func networkDir(net btcwire.BitcoinNet) string {
	var netname string
	if net == btcwire.MainNet {
		netname = "mainnet"
	} else {
		netname = "testnet"
	}
	return filepath.Join(cfg.DataDir, netname)
}

// checkCreateDir checks that the path exists and is a directory.
// If path does not exist, it is created.
func checkCreateDir(path string) error {
	if fi, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// Attempt data directory creation
			if err = os.MkdirAll(path, 0700); err != nil {
				return fmt.Errorf("cannot create directory: %s", err)
			}
		} else {
			return fmt.Errorf("error checking directory: %s", err)
		}
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("path '%s' is not a directory", path)
		}
	}

	return nil
}

// accountFilename returns the filepath of an account file given the
// filename suffix ("wallet.bin", "tx.bin", or "utxo.bin"), account
// name and the network directory holding the file.
func accountFilename(suffix, account, netdir string) string {
	if account == "" {
		// default account
		return filepath.Join(netdir, suffix)
	}

	// non-default account
	return filepath.Join(netdir, fmt.Sprintf("%v-%v", account, suffix))
}

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
func (a *Account) writeDirtyToDisk() error {
	// Temporary files append the current time to the normal file name.
	// In caes of failure, the most recent temporary file can be inspected
	// for validity, and moved to replace the main file.
	timeStr := fmt.Sprintf("%v", time.Now().Unix())

	netdir := networkDir(cfg.Net())
	if err := checkCreateDir(netdir); err != nil {
		return err
	}

	wfilepath := accountFilename("wallet.bin", a.name, netdir)
	txfilepath := accountFilename("tx.bin", a.name, netdir)
	utxofilepath := accountFilename("utxo.bin", a.name, netdir)

	// UTXOs and transactions are synced to disk first.  This prevents
	// any races from saving a wallet marked to be synced with block N
	// and btcwallet closing while the UTXO and Tx files are only synced
	// with block N-1.

	// UTXOs
	a.UtxoStore.RLock()
	dirty := a.TxStore.dirty
	a.UtxoStore.RUnlock()
	if dirty {
		netdir, filename := filepath.Split(utxofilepath)
		tmpfile, err := ioutil.TempFile(netdir, filename)
		if err != nil {
			return err
		}

		a.UtxoStore.Lock()
		defer a.UtxoStore.Unlock()

		if _, err = a.UtxoStore.s.WriteTo(tmpfile); err != nil {
			return err
		}
		tmpfile.Close()

		if err = Rename(tmpfile.Name(), utxofilepath); err != nil {
			return err
		}

		a.UtxoStore.dirty = false
	}

	// Transactions
	a.TxStore.RLock()
	dirty = a.TxStore.dirty
	a.TxStore.RUnlock()
	if dirty {
		netdir, filename := filepath.Split(txfilepath)
		tmpfile, err := ioutil.TempFile(netdir, filename)
		if err != nil {
			return err
		}

		a.TxStore.Lock()
		defer a.TxStore.Unlock()

		if _, err = a.TxStore.s.WriteTo(tmpfile); err != nil {
			return err
		}
		tmpfile.Close()

		if err = Rename(tmpfile.Name(), txfilepath); err != nil {
			return err
		}

		a.TxStore.dirty = false
	}

	// Wallet
	a.mtx.RLock()
	dirty = a.dirty
	a.mtx.RUnlock()
	if dirty {
		netdir, filename := filepath.Split(wfilepath)
		tmpfile, err := ioutil.TempFile(netdir, filename)
		if err != nil {
			return err
		}

		a.mtx.Lock()
		defer a.mtx.Unlock()

		if _, err = a.WriteTo(tmpfile); err != nil {
			return err
		}
		tmpfile.Close()

		if err = Rename(tmpfile.Name(), wfilepath); err != nil {
			return err
		}

		a.dirty = false
	}

	return nil
}
