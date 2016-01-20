/*
 * Copyright (c) 2013-2015 The btcsuite developers
 * Copyright (c) 2015 The Decred developers
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

package wtxmgr

import (
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrwallet/walletdb"
)

// insertMemPoolTx inserts the unmined transaction record.  It also marks
// previous outputs referenced by the inputs as spent.
func (s *Store) insertMemPoolTx(ns walletdb.Bucket, rec *TxRecord) error {
	v := existsRawUnmined(ns, rec.Hash[:])
	if v != nil {
		// TODO: compare serialized txs to ensure this isn't a hash collision?
		return nil
	}

	log.Infof("Inserting unconfirmed transaction %v", rec.Hash)
	v, err := valueTxRecord(rec)
	if err != nil {
		return err
	}
	err = putRawUnmined(ns, rec.Hash[:], v)
	if err != nil {
		return err
	}

	for _, input := range rec.MsgTx.TxIn {
		prevOut := &input.PreviousOutPoint
		k := canonicalOutPoint(&prevOut.Hash, prevOut.Index)
		err = putRawUnminedInput(ns, k, rec.Hash[:])
		if err != nil {
			return err
		}
	}

	// TODO: increment credit amount for each credit (but those are unknown
	// here currently).

	return nil
}

// removeDoubleSpends checks for any unmined transactions which would introduce
// a double spend if tx was added to the store (either as a confirmed or unmined
// transaction).  Each conflicting transaction and all transactions which spend
// it are recursively removed.
func (s *Store) removeDoubleSpends(ns walletdb.Bucket, rec *TxRecord) error {
	for _, input := range rec.MsgTx.TxIn {
		prevOut := &input.PreviousOutPoint
		prevOutKey := canonicalOutPoint(&prevOut.Hash, prevOut.Index)
		doubleSpendHash := existsRawUnminedInput(ns, prevOutKey)
		if doubleSpendHash != nil {
			var doubleSpend TxRecord
			doubleSpendVal := existsRawUnmined(ns, doubleSpendHash)
			copy(doubleSpend.Hash[:], doubleSpendHash) // Silly but need an array
			err := readRawTxRecord(&doubleSpend.Hash, doubleSpendVal,
				&doubleSpend)
			if err != nil {
				return err
			}

			log.Debugf("Removing double spending transaction %v",
				doubleSpend.Hash)
			err = s.removeConflict(ns, &doubleSpend)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// removeConflict removes an unmined transaction record and all spend chains
// deriving from it from the store.  This is designed to remove transactions
// that would otherwise result in double spend conflicts if left in the store,
// and to remove transactions that spend coinbase transactions on reorgs.
func (s *Store) removeConflict(ns walletdb.Bucket, rec *TxRecord) error {
	// For each potential credit for this record, each spender (if any) must
	// be recursively removed as well.  Once the spenders are removed, the
	// credit is deleted.
	numOuts := uint32(len(rec.MsgTx.TxOut))
	for i := uint32(0); i < numOuts; i++ {
		k := canonicalOutPoint(&rec.Hash, i)
		spenderHash := existsRawUnminedInput(ns, k)
		if spenderHash != nil {
			var spender TxRecord
			spenderVal := existsRawUnmined(ns, spenderHash)
			copy(spender.Hash[:], spenderHash) // Silly but need an array
			err := readRawTxRecord(&spender.Hash, spenderVal, &spender)
			if err != nil {
				return err
			}

			log.Debugf("Transaction %v is part of a removed conflict "+
				"chain -- removing as well", spender.Hash)
			err = s.removeConflict(ns, &spender)
			if err != nil {
				return err
			}
		}
		err := deleteRawUnminedCredit(ns, k)
		if err != nil {
			return err
		}
	}

	// If this tx spends any previous credits (either mined or unmined), set
	// each unspent.  Mined transactions are only marked spent by having the
	// output in the unmined inputs bucket.
	for _, input := range rec.MsgTx.TxIn {
		prevOut := &input.PreviousOutPoint
		k := canonicalOutPoint(&prevOut.Hash, prevOut.Index)
		err := deleteRawUnminedInput(ns, k)
		if err != nil {
			return err
		}
	}

	return deleteRawUnmined(ns, rec.Hash[:])
}

// UnminedTxs returns the underlying transactions for all unmined transactions
// which are not known to have been mined in a block.
func (s *Store) UnminedTxs() ([]*wire.MsgTx, error) {
	var txs []*wire.MsgTx
	err := scopedView(s.namespace, func(ns walletdb.Bucket) error {
		var err error
		txs, err = s.unminedTxs(ns)
		return err
	})
	if err != nil {
		return nil, err
	}

	return txs, nil
}

func (s *Store) unminedTxs(ns walletdb.Bucket) ([]*wire.MsgTx, error) {
	var unmined []*TxRecord
	err := ns.Bucket(bucketUnmined).ForEach(func(k, v []byte) error {
		// TODO: Parsing transactions from the db may be a little
		// expensive.  It's possible the caller only wants the
		// serialized transactions.
		var txHash chainhash.Hash
		err := readRawUnminedHash(k, &txHash)
		if err != nil {
			return err
		}

		var rec TxRecord
		err = readRawTxRecord(&txHash, v, &rec)
		if err != nil {
			return err
		}

		unmined = append(unmined, &rec)
		return nil
	})

	// Sort by dependency on other transactions, if any.
	g, i, err := parseTxRecsAsGraph(unmined)
	if err != nil {
		return nil, err
	}

	order, _, err := topSortKahn(g, i)
	if err != nil {
		return nil, err
	}

	// Transactions with no local depencies are excluded from this list, so
	// we need to add them back now. First, find transactions with local
	// dependencies. Then, sort those as DAGs. Finally, append all the
	// transactions with no local dependencies and ship them out to the
	// caller.
	numTxs := len(unmined)
	numOrder := len(order)
	allTxs := make([]*TxRecord, numTxs, numTxs)
	orderTxs := make([]*TxRecord, numOrder, numOrder)
	if order != nil {
		for idx, tx := range order {
			allTxs[idx] = txRecFromSliceByHash(unmined, tx)
			orderTxs[idx] = txRecFromSliceByHash(unmined, tx)
		}
	} else {
		orderTxs = nil
	}

	itr := len(order)
	for _, tx := range unmined {
		if !txRecExistsInSlice(orderTxs, tx) {
			allTxs[itr] = tx
			itr++
		}
	}

	txs := make([]*wire.MsgTx, numTxs, numTxs)
	for i, txr := range allTxs {
		txs[i] = &txr.MsgTx
	}

	return txs, err
}
