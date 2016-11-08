// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"testing"
	"time"

	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/walletdb"
	_ "github.com/decred/dcrwallet/walletdb/bdb"
)

func TestStakeInvalidationOfTip(t *testing.T) {
	db, s, teardown, err := setup()
	defer teardown()
	if err != nil {
		t.Fatal(err)
	}

	g := makeBlockGenerator()
	block1Header := g.generate(dcrutil.BlockValid)
	block2Header := g.generate(dcrutil.BlockValid)
	block3Header := g.generate(0)

	block1Tx := wire.MsgTx{
		TxOut: []*wire.TxOut{{Value: 2e8}},
	}
	block2Tx := wire.MsgTx{
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: block1Tx.TxSha(), Index: 0, Tree: 0}},
		},
		TxOut: []*wire.TxOut{{Value: 1e8}},
	}
	block1TxRec, err := NewTxRecordFromMsgTx(&block1Tx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	block2TxRec, err := NewTxRecordFromMsgTx(&block2Tx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}

	const balanceFlag = BFBalanceSpendable

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		err := s.InsertMemPoolTx(ns, block1TxRec)
		if err != nil {
			return err
		}
		err = s.AddCredit(ns, block1TxRec, nil, 0, false, 0)
		if err != nil {
			return err
		}
		err = s.InsertMemPoolTx(ns, block2TxRec)
		if err != nil {
			return err
		}
		err = s.AddCredit(ns, block2TxRec, nil, 0, false, 0)
		if err != nil {
			return err
		}

		bal, err := s.Balance(ns, addrmgrNs, 0, balanceFlag, false, 0)
		if err != nil {
			return err
		}
		if bal != 1e8 {
			t.Errorf("Wrong balance before mining either transaction: %v", bal)
		}

		headerData := makeHeaderDataSlice(block1Header, block2Header)
		err = s.InsertMainChainHeaders(ns, addrmgrNs, headerData)
		if err != nil {
			return err
		}

		err = s.InsertMinedTx(ns, addrmgrNs, block1TxRec, &headerData[0].BlockHash)
		if err != nil {
			return err
		}
		err = s.InsertMinedTx(ns, addrmgrNs, block2TxRec, &headerData[1].BlockHash)
		if err != nil {
			return err
		}

		// At this point there should only be one credit for the tx in block 2.
		bal, err = s.Balance(ns, addrmgrNs, 1, balanceFlag, false, 0)
		if err != nil {
			return err
		}
		if bal != dcrutil.Amount(block2Tx.TxOut[0].Value) {
			t.Errorf("Wrong balance: expected %v got %v", dcrutil.Amount(block2Tx.TxOut[0].Value), bal)
		}
		credits, err := s.UnspentOutputs(ns)
		if err != nil {
			return err
		}
		if len(credits) != 1 {
			t.Errorf("Expected only 1 credit, got %v", len(credits))
			return nil
		}
		if credits[0].Hash != block2Tx.TxSha() {
			t.Errorf("Credit hash does match tx from block 2")
			return nil
		}
		if credits[0].Amount != dcrutil.Amount(block2Tx.TxOut[0].Value) {
			t.Errorf("Credit value does not match tx output 0 from block 2")
			return nil
		}

		// Add the next block header which invalidates the regular tx tree of
		// block 2.
		t.Log("Invalidating block 2")
		headerData = makeHeaderDataSlice(block3Header)
		err = s.InsertMainChainHeaders(ns, addrmgrNs, headerData)
		if err != nil {
			return err
		}
		/*
			d := makeHeaderData(block3Header)
			err = s.ExtendMainChain(ns, &d)
			if err != nil {
				return err
			}
		*/

		// Now the transaction in block 2 is invalidated.  There should only be
		// one unspent output, from block 1.
		bal, err = s.Balance(ns, addrmgrNs, 1, balanceFlag, false, 0)
		if err != nil {
			return err
		}
		if bal != dcrutil.Amount(block1Tx.TxOut[0].Value) {
			t.Errorf("Wrong balance: expected %v got %v", dcrutil.Amount(block1Tx.TxOut[0].Value), bal)
		}
		credits, err = s.UnspentOutputs(ns)
		if err != nil {
			return err
		}
		if len(credits) != 1 {
			t.Errorf("Expected only 1 credit, got %v", len(credits))
			return nil
		}
		if credits[0].Hash != block1Tx.TxSha() {
			t.Errorf("Credit hash does not match tx from block 1")
			return nil
		}
		if credits[0].Amount != dcrutil.Amount(block1Tx.TxOut[0].Value) {
			t.Errorf("Credit value does not match tx output 0 from block 1")
			return nil
		}

		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestStakeInvalidationTxInsert(t *testing.T) {
	db, s, teardown, err := setup()
	defer teardown()
	if err != nil {
		t.Fatal(err)
	}

	g := makeBlockGenerator()
	block1Header := g.generate(dcrutil.BlockValid)
	block2Header := g.generate(dcrutil.BlockValid)
	block3Header := g.generate(0)

	block1Tx := wire.MsgTx{
		TxOut: []*wire.TxOut{{Value: 2e8}},
	}
	block2Tx := wire.MsgTx{
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: block1Tx.TxSha(), Index: 0, Tree: 0}},
		},
		TxOut: []*wire.TxOut{{Value: 1e8}},
	}
	block1TxRec, err := NewTxRecordFromMsgTx(&block1Tx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	block2TxRec, err := NewTxRecordFromMsgTx(&block2Tx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		headerData := makeHeaderDataSlice(block1Header, block2Header, block3Header)
		err = s.InsertMainChainHeaders(ns, addrmgrNs, headerData)
		if err != nil {
			return err
		}

		err = s.InsertMinedTx(ns, addrmgrNs, block1TxRec, &headerData[0].BlockHash)
		if err != nil {
			return err
		}
		err = s.AddCredit(ns, block1TxRec, makeBlockMeta(block1Header), 0, false, 0)
		if err != nil {
			return err
		}
		err = s.InsertMinedTx(ns, addrmgrNs, block2TxRec, &headerData[1].BlockHash)
		if err != nil {
			return err
		}
		err = s.AddCredit(ns, block2TxRec, makeBlockMeta(block2Header), 0, false, 0)
		if err != nil {
			return err
		}

		// The transaction in block 2 was inserted invalidated.  There should
		// only be one unspent output, from block 1.
		bal, err := s.Balance(ns, addrmgrNs, 1, BFBalanceFullScan, true, 0)
		if err != nil {
			return err
		}
		if bal != dcrutil.Amount(block1Tx.TxOut[0].Value) {
			t.Errorf("Wrong balance: expected %v got %v", dcrutil.Amount(block1Tx.TxOut[0].Value), bal)
		}
		bal, err = s.Balance(ns, addrmgrNs, 1, BFBalanceSpendable, true, 0)
		if err != nil {
			return err
		}
		if bal != dcrutil.Amount(block1Tx.TxOut[0].Value) {
			t.Errorf("Wrong balance: expected %v got %v", dcrutil.Amount(block1Tx.TxOut[0].Value), bal)
		}
		credits, err := s.UnspentOutputs(ns)
		if err != nil {
			return err
		}
		if len(credits) != 1 {
			t.Errorf("Expected only 1 credit, got %v", len(credits))
			return nil
		}
		if credits[0].Hash != block1Tx.TxSha() {
			t.Errorf("Credit hash does not match tx from block 1")
			return nil
		}
		if credits[0].Amount != dcrutil.Amount(block1Tx.TxOut[0].Value) {
			t.Errorf("Credit value does not match tx output 0 from block 1")
			return nil
		}

		return nil
	})
	if err != nil {
		t.Error(err)
	}
}
