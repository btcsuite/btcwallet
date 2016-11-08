// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"encoding/hex"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrwallet/chain"
	"github.com/decred/dcrwallet/walletdb"
	"github.com/decred/dcrwallet/wtxmgr"
)

const maxBlocksPerRescan = 2000

// TODO: track whether a rescan is already in progress, and cancel either it or
// this new rescan, keeping the one that still has the most blocks to scan.

// rescan synchronously scans over all blocks on the main chain starting at
// startHash and height up through the recorded main chain tip block.
func (w *Wallet) rescan(chainClient *chain.RPCClient, startHash *chainhash.Hash, height int32) error {
	blockHashStorage := make([]chainhash.Hash, maxBlocksPerRescan)
	rescanFrom := *startHash
	inclusive := true
	for {
		var rescanBlocks []chainhash.Hash
		err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
			txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)
			var err error
			rescanBlocks, err = w.TxStore.GetMainChainBlockHashes(txmgrNs,
				&rescanFrom, inclusive, blockHashStorage)
			return err
		})
		if err != nil {
			return err
		}
		if len(rescanBlocks) == 0 {
			return nil
		}

		log.Infof("Rescanning blocks %v-%v...", height,
			height+int32(len(rescanBlocks))-1)
		rescanResults, err := chainClient.Rescan(rescanBlocks)
		if err != nil {
			return err
		}
		var rawBlockHeader wtxmgr.RawBlockHeader
		err = walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
			txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
			for _, r := range rescanResults.DiscoveredData {
				blockHash, err := chainhash.NewHashFromStr(r.Hash)
				if err != nil {
					return err
				}
				blockMeta, err := w.TxStore.GetBlockMetaForHash(txmgrNs, blockHash)
				if err != nil {
					return err
				}
				serHeader, err := w.TxStore.GetSerializedBlockHeader(txmgrNs,
					blockHash)
				if err != nil {
					return err
				}
				err = copyHeaderSliceToArray(&rawBlockHeader, serHeader)
				if err != nil {
					return err
				}

				for _, hexTx := range r.Transactions {
					serTx, err := hex.DecodeString(hexTx)
					if err != nil {
						return err
					}
					err = w.processTransaction(dbtx, serTx, &rawBlockHeader,
						&blockMeta)
					if err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		rescanFrom = rescanBlocks[len(rescanBlocks)-1]
		height += int32(len(rescanBlocks))
		inclusive = false
	}
}

// Rescan starts a rescan of the wallet for all blocks on the main chain
// beginning at startHash.
//
// An error channel is returned for consumers of this API, but it is not
// required to be read.  If the error can not be immediately written to the
// returned channel, the error will be logged and the channel will be closed.
func (w *Wallet) Rescan(chainClient *chain.RPCClient, startHash *chainhash.Hash) <-chan error {
	errc := make(chan error)

	go func() (err error) {
		defer func() {
			select {
			case errc <- err:
			default:
				if err != nil {
					log.Errorf("Rescan failed: %v", err)
				}
				close(errc)
			}
		}()

		var startHeight int32
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
			header, err := w.TxStore.GetSerializedBlockHeader(txmgrNs, startHash)
			if err != nil {
				return err
			}
			startHeight = wtxmgr.ExtractBlockHeaderHeight(header)
			return nil
		})
		if err != nil {
			return err
		}

		return w.rescan(chainClient, startHash, startHeight)
	}()

	return errc
}

// RescanFromHeight is an alternative to Rescan that takes a block height
// instead of a hash.  See Rescan for more details.
func (w *Wallet) RescanFromHeight(chainClient *chain.RPCClient, startHeight int32) <-chan error {
	errc := make(chan error)

	go func() (err error) {
		defer func() {
			select {
			case errc <- err:
			default:
				if err != nil {
					log.Errorf("Rescan failed: %v", err)
				}
				close(errc)
			}
		}()

		var startHash chainhash.Hash
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
			var err error
			startHash, err = w.TxStore.GetMainChainBlockHashForHeight(
				txmgrNs, startHeight)
			return err
		})
		if err != nil {
			return err
		}

		return w.rescan(chainClient, &startHash, startHeight)
	}()

	return errc
}
