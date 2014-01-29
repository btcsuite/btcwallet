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
	"time"
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

// syncSchedule references the account files which have been
// scheduled to be written and the directory to write to.
type syncSchedule struct {
	dir     string
	wallets map[*Account]struct{}
	txs     map[*Account]struct{}
	utxos   map[*Account]struct{}
}

func newSyncSchedule(dir string) *syncSchedule {
	s := &syncSchedule{
		dir:     dir,
		wallets: make(map[*Account]struct{}),
		txs:     make(map[*Account]struct{}),
		utxos:   make(map[*Account]struct{}),
	}
	return s
}

// FlushAccount writes all scheduled account files to disk for
// a single account and removes them from the schedule.
func (s *syncSchedule) FlushAccount(a *Account) error {
	if _, ok := s.utxos[a]; ok {
		if err := a.writeUtxoStore(s.dir); err != nil {
			return err
		}
		delete(s.utxos, a)
	}
	if _, ok := s.txs[a]; ok {
		if err := a.writeTxStore(s.dir); err != nil {
			return err
		}
		delete(s.txs, a)
	}
	if _, ok := s.wallets[a]; ok {
		if err := a.writeWallet(s.dir); err != nil {
			return err
		}
		delete(s.wallets, a)
	}

	return nil
}

// Flush writes all scheduled account files and removes each
// from the schedule.
func (s *syncSchedule) Flush() error {
	for a := range s.utxos {
		if err := a.writeUtxoStore(s.dir); err != nil {
			return err
		}
		delete(s.utxos, a)
	}

	for a := range s.txs {
		if err := a.writeTxStore(s.dir); err != nil {
			return err
		}
		delete(s.txs, a)
	}

	for a := range s.wallets {
		if err := a.writeWallet(s.dir); err != nil {
			return err
		}
		delete(s.wallets, a)
	}

	return nil
}

// Channels for AccountDiskSyncer.
var (
	scheduleWalletWrite    = make(chan *Account)
	scheduleTxStoreWrite   = make(chan *Account)
	scheduleUtxoStoreWrite = make(chan *Account)
	syncBatch              = make(chan *syncBatchRequest)
	syncAccount            = make(chan *syncRequest)
	exportAccount          = make(chan *exportRequest)
)

type syncRequest struct {
	a   *Account
	err chan error
}

type syncBatchRequest struct {
	a   []*Account
	err chan error
}

type exportRequest struct {
	dir string
	a   *Account
	err chan error
}

// AccountDiskSyncer manages a set of "dirty" account files which must
// be written to disk, and synchronizes all writes in a single goroutine.
// After 10 seconds since the latest sync, all unwritten files are written
// and removed.  Writes for a single account may be scheduled immediately by
// calling WriteScheduledToDisk.
//
// This never returns and is meant to be called from a goroutine.
func AccountDiskSyncer() {
	netdir := networkDir(cfg.Net())
	if err := checkCreateDir(netdir); err != nil {
		log.Errorf("Unable to create or write to account directory: %v", err)
	}
	tmpnetdir := tmpNetworkDir(cfg.Net())

	schedule := newSyncSchedule(netdir)
	ticker := time.Tick(10 * time.Second)
	for {
		select {
		case a := <-scheduleWalletWrite:
			schedule.wallets[a] = struct{}{}

		case a := <-scheduleTxStoreWrite:
			schedule.txs[a] = struct{}{}

		case a := <-scheduleUtxoStoreWrite:
			schedule.utxos[a] = struct{}{}

		case sr := <-syncAccount:
			sr.err <- schedule.FlushAccount(sr.a)

		case sr := <-syncBatch:
			err := batchWriteAccounts(sr.a, tmpnetdir, netdir)
			if err == nil {
				// All accounts have been synced, old schedule
				// can be discarded.
				schedule = newSyncSchedule(netdir)
			}
			sr.err <- err

		case er := <-exportAccount:
			a := er.a
			dir := er.dir
			er.err <- a.writeAll(dir)

		case <-ticker:
			if err := schedule.Flush(); err != nil {
				log.Errorf("Cannot write account: %v", err)
			}
		}
	}
}

// WriteAllToDisk writes all account files for all accounts at once.  Unlike
// writing individual account files, this causes each account file to be
// written to a new network directory to replace the old one.  Use this
// function when it is needed to ensure an all or nothing write for all
// account files.
//
// It is a runtime error to call this without holding the store writer lock.
func (store *AccountStore) WriteAllToDisk() error {
	accts := make([]*Account, 0, len(store.accounts))
	for _, a := range store.accounts {
		accts = append(accts, a)
	}

	err := make(chan error, 1)
	syncBatch <- &syncBatchRequest{
		a:   accts,
		err: err,
	}
	return <-err
}

func batchWriteAccounts(accts []*Account, tmpdir, netdir string) error {
	if err := freshDir(tmpdir); err != nil {
		return err
	}
	for _, a := range accts {
		if err := a.writeAll(tmpdir); err != nil {
			return err
		}
	}
	// This is technically NOT an atomic operation, but at startup, if the
	// network directory is missing but the temporary network directory
	// exists, the temporary is moved before accounts are opened.
	if err := os.RemoveAll(netdir); err != nil {
		return err
	}
	if err := Rename(tmpdir, netdir); err != nil {
		return err
	}
	return nil
}

// WriteScheduledToDisk signals AccountDiskSyncer to write all scheduled
// account files for a to disk now instead of waiting for the next sync
// interval. This function blocks until all the file writes for a have
// finished, and returns a non-nil error if any of the file writes failed.
func (a *Account) WriteScheduledToDisk() error {
	err := make(chan error, 1)
	syncAccount <- &syncRequest{
		a:   a,
		err: err,
	}
	return <-err
}

// ScheduleWalletWrite schedules a write of an account's wallet file.
func (a *Account) ScheduleWalletWrite() {
	scheduleWalletWrite <- a
}

// ScheduleTxStoreWrite schedules a write of an account's tx store file.
func (a *Account) ScheduleTxStoreWrite() {
	scheduleTxStoreWrite <- a
}

// ScheduleUtxoStoreWrite schedules a write of an account's utxo store file.
func (a *Account) ScheduleUtxoStoreWrite() {
	scheduleUtxoStoreWrite <- a
}

// ExportToDirectory writes an account to a special export directory.  Any
// previous files are overwritten.
func (a *Account) ExportToDirectory(dirBaseName string) error {
	dir := filepath.Join(networkDir(cfg.Net()), dirBaseName)
	if err := checkCreateDir(dir); err != nil {
		return err
	}

	err := make(chan error)
	er := &exportRequest{
		dir: dir,
		a:   a,
		err: err,
	}
	exportAccount <- er
	return <-err
}

func (a *Account) writeAll(dir string) error {
	if err := a.writeUtxoStore(dir); err != nil {
		return err
	}
	if err := a.writeTxStore(dir); err != nil {
		return err
	}
	if err := a.writeWallet(dir); err != nil {
		return err
	}
	return nil
}

func (a *Account) writeWallet(dir string) error {
	wfilepath := accountFilename("wallet.bin", a.name, dir)
	_, filename := filepath.Split(wfilepath)
	tmpfile, err := ioutil.TempFile(dir, filename)
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

	return nil
}

func (a *Account) writeTxStore(dir string) error {
	txfilepath := accountFilename("tx.bin", a.name, dir)
	_, filename := filepath.Split(txfilepath)
	tmpfile, err := ioutil.TempFile(dir, filename)
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

	return nil
}

func (a *Account) writeUtxoStore(dir string) error {
	utxofilepath := accountFilename("utxo.bin", a.name, dir)
	_, filename := filepath.Split(utxofilepath)
	tmpfile, err := ioutil.TempFile(dir, filename)
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

	return nil
}
