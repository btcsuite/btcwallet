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

// networkDir returns the directory name of a network directory to hold account
// files.
func networkDir(net btcwire.BitcoinNet) string {
	var netname string
	if net == btcwire.MainNet {
		netname = "mainnet"
	} else {
		netname = "testnet"
	}
	return filepath.Join(cfg.DataDir, netname)
}

// tmpNetworkDir returns the temporary directory name for a given network.
func tmpNetworkDir(net btcwire.BitcoinNet) string {
	return networkDir(net) + "_tmp"
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

// freshDir creates a new directory specified by path if it does not
// exist.  If the directory already exists, all files contained in the
// directory are removed.
func freshDir(path string) error {
	if err := checkCreateDir(path); err != nil {
		return err
	}

	// Remove all files in the directory.
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()
	names, err := fd.Readdirnames(0)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := os.RemoveAll(name); err != nil {
			return err
		}
	}

	return nil
}

// writeAllToFreshDir writes all account files to the specified directory.
// If dir already exists, any old files are removed.  If dir does not
// exist, it is created.
//
// It is a runtime error to call this function while not holding each
// wallet, tx store, and utxo store writer lock.
func (a *Account) writeAllToFreshDir(dir string) error {
	if err := freshDir(dir); err != nil {
		return err
	}

	wfilepath := accountFilename("wallet.bin", a.name, dir)
	txfilepath := accountFilename("tx.bin", a.name, dir)
	utxofilepath := accountFilename("utxo.bin", a.name, dir)

	wfile, err := os.Create(wfilepath)
	if err != nil {
		return err
	}
	defer wfile.Close()
	txfile, err := os.Create(txfilepath)
	if err != nil {
		return err
	}
	defer txfile.Close()
	utxofile, err := os.Create(utxofilepath)
	if err != nil {
		return err
	}
	defer utxofile.Close()

	if _, err := a.Wallet.WriteTo(wfile); err != nil {
		return err
	}
	a.dirty = false

	if _, err := a.TxStore.s.WriteTo(txfile); err != nil {
		return err
	}
	a.TxStore.dirty = false

	if _, err := a.UtxoStore.s.WriteTo(utxofile); err != nil {
		return err
	}
	a.UtxoStore.dirty = false

	return nil
}

// writeDirtyToDisk checks for the dirty flag on an account's wallet,
// txstore, and utxostore, writing them to disk if any are dirty.
func (a *Account) writeDirtyToDisk() error {
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
		defer tmpfile.Close()

		a.UtxoStore.RLock()
		_, err = a.UtxoStore.s.WriteTo(tmpfile)
		a.UtxoStore.RUnlock()
		if err != nil {
			return err
		}

		if err = Rename(tmpfile.Name(), utxofilepath); err != nil {
			return err
		}

		a.UtxoStore.Lock()
		a.UtxoStore.dirty = false
		a.UtxoStore.Unlock()
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
		defer tmpfile.Close()

		a.TxStore.RLock()
		_, err = a.TxStore.s.WriteTo(tmpfile)
		a.TxStore.RUnlock()
		if err != nil {
			return err
		}

		if err = Rename(tmpfile.Name(), txfilepath); err != nil {
			return err
		}

		a.TxStore.Lock()
		a.TxStore.dirty = false
		a.TxStore.Unlock()
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
		defer tmpfile.Close()

		a.mtx.RLock()
		_, err = a.Wallet.WriteTo(tmpfile)
		a.mtx.RUnlock()
		if err != nil {
			return err
		}

		if err = Rename(tmpfile.Name(), wfilepath); err != nil {
			return err
		}

		a.mtx.Lock()
		a.dirty = false
		a.mtx.Unlock()
	}

	return nil
}

// WriteExport writes an account to a special export directory named
// by dirName.  Any previous files are overwritten.
func (a *Account) WriteExport(dirName string) error {
	exportPath := filepath.Join(networkDir(cfg.Net()), dirName)
	if err := checkCreateDir(exportPath); err != nil {
		return err
	}

	aname := a.Name()
	wfilepath := accountFilename("wallet.bin", aname, exportPath)
	txfilepath := accountFilename("tx.bin", aname, exportPath)
	utxofilepath := accountFilename("utxo.bin", aname, exportPath)

	utxofile, err := os.Create(utxofilepath)
	if err != nil {
		return err
	}
	defer utxofile.Close()
	a.UtxoStore.RLock()
	_, err = a.UtxoStore.s.WriteTo(utxofile)
	a.UtxoStore.RUnlock()
	if err != nil {
		return err
	}

	txfile, err := os.Create(txfilepath)
	if err != nil {
		return err
	}
	defer txfile.Close()
	a.TxStore.RLock()
	_, err = a.TxStore.s.WriteTo(txfile)
	a.TxStore.RUnlock()
	if err != nil {
		return err
	}

	wfile, err := os.Create(wfilepath)
	if err != nil {
		return err
	}
	defer wfile.Close()
	a.mtx.RLock()
	_, err = a.Wallet.WriteTo(wfile)
	a.mtx.RUnlock()
	if err != nil {
		return err
	}

	return nil
}
