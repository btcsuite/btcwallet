// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"github.com/jadeblaquiere/ctcd/chaincfg/chainhash"
	"github.com/jadeblaquiere/ctcd/wire"
	"github.com/jadeblaquiere/ctcwallet/walletdb"
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
// which are not known to have been mined in a block.  Transactions are
// guaranteed to be sorted by their dependency order.
func (s *Store) UnminedTxs() ([]*wire.MsgTx, error) {
	var recSet map[chainhash.Hash]*TxRecord
	err := scopedView(s.namespace, func(ns walletdb.Bucket) error {
		var err error
		recSet, err = s.unminedTxRecords(ns)
		return err
	})
	if err != nil {
		return nil, err
	}

	recs := dependencySort(recSet)
	txs := make([]*wire.MsgTx, 0, len(recs))
	for _, rec := range recs {
		txs = append(txs, &rec.MsgTx)
	}
	return txs, nil
}

func (s *Store) unminedTxRecords(ns walletdb.Bucket) (map[chainhash.Hash]*TxRecord, error) {
	unmined := make(map[chainhash.Hash]*TxRecord)
	err := ns.Bucket(bucketUnmined).ForEach(func(k, v []byte) error {
		var txHash chainhash.Hash
		err := readRawUnminedHash(k, &txHash)
		if err != nil {
			return err
		}

		rec := new(TxRecord)
		err = readRawTxRecord(&txHash, v, rec)
		if err != nil {
			return err
		}
		unmined[rec.Hash] = rec
		return nil
	})
	return unmined, err
}

// UnminedTxHashes returns the hashes of all transactions not known to have been
// mined in a block.
func (s *Store) UnminedTxHashes() ([]*chainhash.Hash, error) {
	var hashes []*chainhash.Hash
	err := scopedView(s.namespace, func(ns walletdb.Bucket) error {
		var err error
		hashes, err = s.unminedTxHashes(ns)
		return err
	})
	return hashes, err
}

func (s *Store) unminedTxHashes(ns walletdb.Bucket) ([]*chainhash.Hash, error) {
	var hashes []*chainhash.Hash
	err := ns.Bucket(bucketUnmined).ForEach(func(k, v []byte) error {
		hash := new(chainhash.Hash)
		err := readRawUnminedHash(k, hash)
		if err == nil {
			hashes = append(hashes, hash)
		}
		return err
	})
	return hashes, err
}
