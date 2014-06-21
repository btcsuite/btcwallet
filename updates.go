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
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ErrNotAccountDir describes an error where a directory in the btcwallet
// data directory cannot be parsed as a directory holding account files.
var ErrNotAccountDir = errors.New("directory is not an account directory")

// updateOldFileLocations moves files for wallets, transactions, and
// recorded unspent transaction outputs to more recent locations.
func updateOldFileLocations() error {
	// Before version 0.1.1, accounts were saved with the following
	// format:
	//
	//   ~/.btcwallet/
	//     - btcwallet/
	//       - wallet.bin
	//       - tx.bin
	//       - utxo.bin
	//     - btcwallet-AccountA/
	//       - wallet.bin
	//       - tx.bin
	//       - utxo.bin
	//
	// This format does not scale well (see Github issue #16), and
	// since version 0.1.1, the above directory format has changed
	// to the following:
	//
	//   ~/.btcwallet/
	//     - testnet/
	//       - wallet.bin
	//       - tx.bin
	//       - utxo.bin
	//       - AccountA-wallet.bin
	//       - AccountA-tx.bin
	//       - AccountA-utxo.bin
	//
	// Previous account files are placed in the testnet directory
	// as 0.1.0 and earlier only ran on testnet.
	//
	// UTXOs and transaction history are intentionally not moved over, as
	// the UTXO file is no longer used (it was combined with txstore), and
	// the tx history is now written in an incompatible format and would
	// be ignored on first read.

	datafi, err := os.Open(cfg.DataDir)
	if err != nil {
		return nil
	}
	defer func() {
		if err := datafi.Close(); err != nil {
			log.Warnf("Cannot close data directory: %v", err)
		}
	}()

	// Get info on all files in the data directory.
	fi, err := datafi.Readdir(0)
	if err != nil {
		log.Errorf("Cannot read files in data directory: %v", err)
		return err
	}

	acctsExist := false
	for i := range fi {
		// Ignore non-directories.
		if !fi[i].IsDir() {
			continue
		}

		if strings.HasPrefix(fi[i].Name(), "btcwallet") {
			acctsExist = true
			break
		}
	}
	if !acctsExist {
		return nil
	}

	// Create testnet directory, if it doesn't already exist.
	netdir := filepath.Join(cfg.DataDir, "testnet")
	if err := checkCreateDir(netdir); err != nil {
		log.Errorf("Cannot continue without a testnet directory: %v", err)
		return err
	}

	// Check all files in the datadir for old accounts to update.
	for i := range fi {
		// Ignore non-directories.
		if !fi[i].IsDir() {
			continue
		}

		account, err := parseOldAccountDir(cfg.DataDir, fi[i].Name())
		switch err {
		case nil:
			break

		case ErrNotAccountDir:
			continue

		default: // all other non-nil errors
			log.Errorf("Cannot open old account directory: %v", err)
			return err
		}

		log.Infof("Updating old file locations for account %v", account)

		// Move old wallet.bin, if any.
		old := filepath.Join(cfg.DataDir, fi[i].Name(), "wallet.bin")
		if fileExists(old) {
			new := accountFilename("wallet.bin", account, netdir)
			if err := Rename(old, new); err != nil {
				log.Errorf("Cannot move old %v for account %v to new location: %v",
					"wallet.bin", account, err)
				return err
			}
		}

		// Cleanup old account directory.
		if err := os.RemoveAll(filepath.Join(cfg.DataDir, fi[i].Name())); err != nil {
			log.Warnf("Could not remove pre 0.1.1 account directory: %v", err)
		}
	}

	return nil
}

type oldAccountDir struct {
	account string
	dir     *os.File
}

func parseOldAccountDir(dir, base string) (string, error) {
	if base == "btcwallet" {
		return "", nil
	}

	const accountPrefix = "btcwallet-"
	if strings.HasPrefix(base, accountPrefix) {
		account := strings.TrimPrefix(base, accountPrefix)
		return account, nil
	}

	return "", ErrNotAccountDir
}
