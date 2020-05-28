// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/jessevdk/go-flags"
)

const defaultNet = "mainnet"

var datadir = btcutil.AppDataDir("btcwallet", false)

// Flags.
var opts = struct {
	Force      bool   `short:"f" description:"Force removal without prompt"`
	DbPath     string `long:"db" description:"Path to wallet database"`
	DropLabels bool   `long:"droplabels" description:"Drop transaction labels"`
}{
	Force:  false,
	DbPath: filepath.Join(datadir, defaultNet, "wallet.db"),
}

func init() {
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}
}

var (
	// Namespace keys.
	waddrmgrNamespace = []byte("waddrmgr")
	wtxmgrNamespace   = []byte("wtxmgr")

	// Bucket names.
	bucketTxLabels = []byte("l")
)

func yes(s string) bool {
	switch s {
	case "y", "Y", "yes", "Yes":
		return true
	default:
		return false
	}
}

func no(s string) bool {
	switch s {
	case "n", "N", "no", "No":
		return true
	default:
		return false
	}
}

func main() {
	os.Exit(mainInt())
}

func mainInt() int {
	fmt.Println("Database path:", opts.DbPath)
	_, err := os.Stat(opts.DbPath)
	if os.IsNotExist(err) {
		fmt.Println("Database file does not exist")
		return 1
	}

	for !opts.Force {
		fmt.Print("Drop all btcwallet transaction history? [y/N] ")

		scanner := bufio.NewScanner(bufio.NewReader(os.Stdin))
		if !scanner.Scan() {
			// Exit on EOF.
			return 0
		}
		err := scanner.Err()
		if err != nil {
			fmt.Println()
			fmt.Println(err)
			return 1
		}
		resp := scanner.Text()
		if yes(resp) {
			break
		}
		if no(resp) || resp == "" {
			return 0
		}

		fmt.Println("Enter yes or no.")
	}

	db, err := walletdb.Open("bdb", opts.DbPath, true)
	if err != nil {
		fmt.Println("Failed to open database:", err)
		return 1
	}
	defer db.Close()

	fmt.Println("Dropping btcwallet transaction history")

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		// If we want to keep our tx labels, we read them out so we
		// can re-add them after we have deleted our wtxmgr.
		var labels map[chainhash.Hash]string
		if !opts.DropLabels {
			labels, err = fetchAllLabels(tx)
			if err != nil {
				return err
			}
		}

		err := tx.DeleteTopLevelBucket(wtxmgrNamespace)
		if err != nil && err != walletdb.ErrBucketNotFound {
			return err
		}
		ns, err := tx.CreateTopLevelBucket(wtxmgrNamespace)
		if err != nil {
			return err
		}
		err = wtxmgr.Create(ns)
		if err != nil {
			return err
		}

		// If we want to re-add our labels, we do so now.
		if !opts.DropLabels {
			if err := putTxLabels(ns, labels); err != nil {
				return err
			}
		}

		ns = tx.ReadWriteBucket(waddrmgrNamespace)
		birthdayBlock, err := waddrmgr.FetchBirthdayBlock(ns)
		if err != nil {
			fmt.Println("Wallet does not have a birthday block " +
				"set, falling back to rescan from genesis")

			startBlock, err := waddrmgr.FetchStartBlock(ns)
			if err != nil {
				return err
			}
			return waddrmgr.PutSyncedTo(ns, startBlock)
		}

		// We'll need to remove our birthday block first because it
		// serves as a barrier when updating our state to detect reorgs
		// due to the wallet not storing all block hashes of the chain.
		if err := waddrmgr.DeleteBirthdayBlock(ns); err != nil {
			return err
		}

		if err := waddrmgr.PutSyncedTo(ns, &birthdayBlock); err != nil {
			return err
		}
		return waddrmgr.PutBirthdayBlock(ns, birthdayBlock)
	})
	if err != nil {
		fmt.Println("Failed to drop and re-create namespace:", err)
		return 1
	}

	return 0
}

// fetchAllLabels returns a map of hex-encoded txid to label.
func fetchAllLabels(tx walletdb.ReadWriteTx) (map[chainhash.Hash]string,
	error) {

	// Get our top level bucket, if it does not exist we just exit.
	txBucket := tx.ReadBucket(wtxmgrNamespace)
	if txBucket == nil {
		return nil, nil
	}

	// If we do not have a labels bucket, there are no labels so we exit.
	labelsBucket := txBucket.NestedReadBucket(bucketTxLabels)
	if labelsBucket == nil {
		return nil, nil
	}

	labels := make(map[chainhash.Hash]string)
	if err := labelsBucket.ForEach(func(k, v []byte) error {
		txid, err := chainhash.NewHash(k)
		if err != nil {
			return err
		}

		label, err := wtxmgr.DeserializeLabel(v)
		if err != nil {
			return err
		}

		// Add an entry to our map of labels.
		labels[*txid] = label

		return nil
	}); err != nil {
		return nil, err
	}

	return labels, nil
}

// putTxLabels re-adds a nested labels bucket and entries to the bucket provided
// if there are any labels present.
func putTxLabels(ns walletdb.ReadWriteBucket,
	labels map[chainhash.Hash]string) error {

	// If there are no labels, exit early.
	if len(labels) == 0 {
		return nil
	}

	// First, we create a labels bucket which we will add all labels to.
	labelBucket, err := ns.CreateBucketIfNotExists(bucketTxLabels)
	if err != nil {
		return err
	}

	// Next, we re-add every label to the bucket.
	for txid, label := range labels {
		err := wtxmgr.PutTxLabel(labelBucket, txid, label)
		if err != nil {
			return err
		}
	}

	return nil
}
