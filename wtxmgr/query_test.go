// Copyright (c) 2015-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
)

type queryState struct {
	// slice items are ordered by height, mempool comes last.
	blocks    [][]TxDetails
	txDetails map[chainhash.Hash][]TxDetails
}

func newQueryState() *queryState {
	return &queryState{
		txDetails: make(map[chainhash.Hash][]TxDetails),
	}
}

func (q *queryState) deepCopy() *queryState {
	cpy := newQueryState()
	for _, blockDetails := range q.blocks {
		var cpyDetails []TxDetails
		for _, detail := range blockDetails {
			cpyDetails = append(cpyDetails, *deepCopyTxDetails(&detail))
		}
		cpy.blocks = append(cpy.blocks, cpyDetails)
	}
	cpy.txDetails = make(map[chainhash.Hash][]TxDetails)
	for txHash, details := range q.txDetails {
		detailsSlice := make([]TxDetails, len(details))
		for i, detail := range details {
			detailsSlice[i] = *deepCopyTxDetails(&detail)
		}
		cpy.txDetails[txHash] = detailsSlice
	}
	return cpy
}

func deepCopyTxDetails(d *TxDetails) *TxDetails {
	cpy := *d
	cpy.MsgTx = *d.MsgTx.Copy()
	if cpy.SerializedTx != nil {
		cpy.SerializedTx = make([]byte, len(cpy.SerializedTx))
		copy(cpy.SerializedTx, d.SerializedTx)
	}
	cpy.Credits = make([]CreditRecord, len(d.Credits))
	copy(cpy.Credits, d.Credits)
	cpy.Debits = make([]DebitRecord, len(d.Debits))
	copy(cpy.Debits, d.Debits)
	return &cpy
}

func (q *queryState) compare(s *Store, ns walletdb.ReadBucket,
	changeDesc string) error {

	fwdBlocks := q.blocks
	revBlocks := make([][]TxDetails, len(q.blocks))
	copy(revBlocks, q.blocks)
	for i := 0; i < len(revBlocks)/2; i++ {
		revBlocks[i], revBlocks[len(revBlocks)-1-i] = revBlocks[len(revBlocks)-1-i], revBlocks[i]
	}
	checkBlock := func(blocks [][]TxDetails) func([]TxDetails) (bool, error) {
		return func(got []TxDetails) (bool, error) {
			if len(fwdBlocks) == 0 {
				return false, errors.New("entered range " +
					"when no more details expected")
			}
			exp := blocks[0]
			if len(got) != len(exp) {
				return false, fmt.Errorf("got len(details)=%d "+
					"in transaction range, expected %d",
					len(got), len(exp))
			}
			for i := range got {
				err := equalTxDetails(&got[i], &exp[i])
				if err != nil {
					return false, fmt.Errorf("failed "+
						"comparing range of "+
						"transaction details: %v", err)
				}
			}
			blocks = blocks[1:]
			return false, nil
		}
	}
	err := s.RangeTransactions(ns, 0, -1, checkBlock(fwdBlocks))
	if err != nil {
		return fmt.Errorf("%s: failed in RangeTransactions (forwards "+
			"iteration): %v", changeDesc, err)
	}
	err = s.RangeTransactions(ns, -1, 0, checkBlock(revBlocks))
	if err != nil {
		return fmt.Errorf("%s: failed in RangeTransactions (reverse "+
			"iteration): %v", changeDesc, err)
	}

	for txHash, details := range q.txDetails {
		for _, detail := range details {
			blk := &detail.Block.Block
			if blk.Height == -1 {
				blk = nil
			}
			d, err := s.UniqueTxDetails(ns, &txHash, blk)
			if err != nil {
				return err
			}
			if d == nil {
				return fmt.Errorf("found no matching "+
					"transaction at height %d",
					detail.Block.Height)
			}
			if err := equalTxDetails(d, &detail); err != nil {
				return fmt.Errorf("%s: failed querying latest "+
					"details regarding transaction %v",
					changeDesc, txHash)
			}
		}

		// For the most recent tx with this hash, check that
		// TxDetails (not looking up a tx at any particular
		// height) matches the last.
		detail := &details[len(details)-1]
		d, err := s.TxDetails(ns, &txHash)
		if err != nil {
			return err
		}
		if err := equalTxDetails(d, detail); err != nil {
			return fmt.Errorf("%s: failed querying latest details "+
				"regarding transaction %v", changeDesc, txHash)
		}
	}

	return nil
}

func equalTxDetails(got, exp *TxDetails) error {
	// Need to avoid using reflect.DeepEqual against slices, since it
	// returns false for nil vs non-nil zero length slices.
	if err := equalTxs(&got.MsgTx, &exp.MsgTx); err != nil {
		return err
	}

	if got.Hash != exp.Hash {
		return fmt.Errorf("found mismatched hashes: got %v, expected %v",
			got.Hash, exp.Hash)
	}
	if got.Received != exp.Received {
		return fmt.Errorf("found mismatched receive time: got %v, "+
			"expected %v", got.Received, exp.Received)
	}
	if !bytes.Equal(got.SerializedTx, exp.SerializedTx) {
		return fmt.Errorf("found mismatched serialized txs: got %v, "+
			"expected %v", got.SerializedTx, exp.SerializedTx)
	}
	if got.Block != exp.Block {
		return fmt.Errorf("found mismatched block meta: got %v, "+
			"expected %v", got.Block, exp.Block)
	}
	if len(got.Credits) != len(exp.Credits) {
		return fmt.Errorf("credit slice lengths differ: got %d, "+
			"expected %d", len(got.Credits), len(exp.Credits))
	}
	for i := range got.Credits {
		if got.Credits[i] != exp.Credits[i] {
			return fmt.Errorf("found mismatched credit[%d]: got %v, "+
				"expected %v", i, got.Credits[i], exp.Credits[i])
		}
	}
	if len(got.Debits) != len(exp.Debits) {
		return fmt.Errorf("debit slice lengths differ: got %d, "+
			"expected %d", len(got.Debits), len(exp.Debits))
	}
	for i := range got.Debits {
		if got.Debits[i] != exp.Debits[i] {
			return fmt.Errorf("found mismatched debit[%d]: got %v, "+
				"expected %v", i, got.Debits[i], exp.Debits[i])
		}
	}

	return nil
}

func equalTxs(got, exp *wire.MsgTx) error {
	var bufGot, bufExp bytes.Buffer
	err := got.Serialize(&bufGot)
	if err != nil {
		return err
	}
	err = exp.Serialize(&bufExp)
	if err != nil {
		return err
	}
	if !bytes.Equal(bufGot.Bytes(), bufExp.Bytes()) {
		return fmt.Errorf("found unexpected wire.MsgTx: got: %v, "+
			"expected %v", got, exp)
	}

	return nil
}

// Returns time.Now() with seconds resolution, this is what Store saves.
func timeNow() time.Time {
	return time.Unix(time.Now().Unix(), 0)
}

// Returns a copy of a TxRecord without the serialized tx.
func stripSerializedTx(rec *TxRecord) *TxRecord {
	ret := *rec
	ret.SerializedTx = nil
	return &ret
}

func makeBlockMeta(height int32) BlockMeta {
	if height == -1 {
		return BlockMeta{Block: Block{Height: -1}}
	}

	b := BlockMeta{
		Block: Block{Height: height},
		Time:  timeNow(),
	}
	// Give it a fake block hash created from the height and time.
	binary.LittleEndian.PutUint32(b.Hash[0:4], uint32(height))
	binary.LittleEndian.PutUint64(b.Hash[4:12], uint64(b.Time.Unix()))
	return b
}

func TestStoreQueries(t *testing.T) {
	t.Parallel()

	type queryTest struct {
		desc    string
		updates func(ns walletdb.ReadWriteBucket) error
		state   *queryState
	}
	var tests []queryTest

	// Create the store and test initial state.
	s, db, teardown, err := testStore()
	defer teardown()
	if err != nil {
		t.Fatal(err)
	}
	lastState := newQueryState()
	tests = append(tests, queryTest{
		desc:    "initial store",
		updates: func(walletdb.ReadWriteBucket) error { return nil },
		state:   lastState,
	})

	// Insert an unmined transaction.  Mark no credits yet.
	txA := spendOutput(&chainhash.Hash{}, 0, 100e8)
	recA, err := NewTxRecordFromMsgTx(txA, timeNow())
	if err != nil {
		t.Fatal(err)
	}
	newState := lastState.deepCopy()
	newState.blocks = [][]TxDetails{
		{
			{
				TxRecord: *stripSerializedTx(recA),
				Block:    BlockMeta{Block: Block{Height: -1}},
			},
		},
	}
	newState.txDetails[recA.Hash] = []TxDetails{
		newState.blocks[0][0],
	}
	lastState = newState
	tests = append(tests, queryTest{
		desc: "insert tx A unmined",
		updates: func(ns walletdb.ReadWriteBucket) error {
			return s.InsertTx(ns, recA, nil)
		},
		state: newState,
	})

	// Add txA:0 as a change credit.
	newState = lastState.deepCopy()
	newState.blocks[0][0].Credits = []CreditRecord{
		{
			Index:  0,
			Amount: btcutil.Amount(recA.MsgTx.TxOut[0].Value),
			Spent:  false,
			Change: true,
		},
	}
	newState.txDetails[recA.Hash][0].Credits = newState.blocks[0][0].Credits
	lastState = newState
	tests = append(tests, queryTest{
		desc: "mark unconfirmed txA:0 as credit",
		updates: func(ns walletdb.ReadWriteBucket) error {
			return s.AddCredit(ns, recA, nil, 0, true)
		},
		state: newState,
	})

	// Insert another unmined transaction which spends txA:0, splitting the
	// amount into outputs of 40 and 60 BTC.
	txB := spendOutput(&recA.Hash, 0, 40e8, 60e8)
	recB, err := NewTxRecordFromMsgTx(txB, timeNow())
	if err != nil {
		t.Fatal(err)
	}
	newState = lastState.deepCopy()
	newState.blocks[0][0].Credits[0].Spent = true
	newState.blocks[0] = append(newState.blocks[0], TxDetails{
		TxRecord: *stripSerializedTx(recB),
		Block:    BlockMeta{Block: Block{Height: -1}},
		Debits: []DebitRecord{
			{
				Amount: btcutil.Amount(recA.MsgTx.TxOut[0].Value),
				Index:  0, // recB.MsgTx.TxIn index
			},
		},
	})
	newState.txDetails[recA.Hash][0].Credits[0].Spent = true
	newState.txDetails[recB.Hash] = []TxDetails{newState.blocks[0][1]}
	lastState = newState
	tests = append(tests, queryTest{
		desc: "insert tx B unmined",
		updates: func(ns walletdb.ReadWriteBucket) error {
			return s.InsertTx(ns, recB, nil)
		},
		state: newState,
	})
	newState = lastState.deepCopy()
	newState.blocks[0][1].Credits = []CreditRecord{
		{
			Index:  0,
			Amount: btcutil.Amount(recB.MsgTx.TxOut[0].Value),
			Spent:  false,
			Change: false,
		},
	}
	newState.txDetails[recB.Hash][0].Credits = newState.blocks[0][1].Credits
	lastState = newState
	tests = append(tests, queryTest{
		desc: "mark txB:0 as non-change credit",
		updates: func(ns walletdb.ReadWriteBucket) error {
			return s.AddCredit(ns, recB, nil, 0, false)
		},
		state: newState,
	})

	// Mine tx A at block 100.  Leave tx B unmined.
	b100 := makeBlockMeta(100)
	newState = lastState.deepCopy()
	newState.blocks[0] = newState.blocks[0][:1]
	newState.blocks[0][0].Block = b100
	newState.blocks = append(newState.blocks, lastState.blocks[0][1:])
	newState.txDetails[recA.Hash][0].Block = b100
	lastState = newState
	tests = append(tests, queryTest{
		desc: "mine tx A",
		updates: func(ns walletdb.ReadWriteBucket) error {
			return s.InsertTx(ns, recA, &b100)
		},
		state: newState,
	})

	// Mine tx B at block 101.
	b101 := makeBlockMeta(101)
	newState = lastState.deepCopy()
	newState.blocks[1][0].Block = b101
	newState.txDetails[recB.Hash][0].Block = b101
	lastState = newState
	tests = append(tests, queryTest{
		desc: "mine tx B",
		updates: func(ns walletdb.ReadWriteBucket) error {
			return s.InsertTx(ns, recB, &b101)
		},
		state: newState,
	})

	for _, tst := range tests {
		err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(namespaceKey)
			if err := tst.updates(ns); err != nil {
				return err
			}
			return tst.state.compare(s, ns, tst.desc)
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Run some additional query tests with the current store's state:
	//   - Verify that querying for a transaction not in the store returns
	//     nil without failure.
	//   - Verify that querying for a unique transaction at the wrong block
	//     returns nil without failure.
	//   - Verify that breaking early on RangeTransactions stops further
	//     iteration.

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(namespaceKey)

		missingTx := spendOutput(&recB.Hash, 0, 40e8)
		missingRec, err := NewTxRecordFromMsgTx(missingTx, timeNow())
		if err != nil {
			return err
		}
		missingBlock := makeBlockMeta(102)
		missingDetails, err := s.TxDetails(ns, &missingRec.Hash)
		if err != nil {
			return err
		}
		if missingDetails != nil {
			return fmt.Errorf("Expected no details, found details "+
				"for tx %v", missingDetails.Hash)
		}
		missingUniqueTests := []struct {
			hash  *chainhash.Hash
			block *Block
		}{
			{&missingRec.Hash, &b100.Block},
			{&missingRec.Hash, &missingBlock.Block},
			{&missingRec.Hash, nil},
			{&recB.Hash, &b100.Block},
			{&recB.Hash, &missingBlock.Block},
			{&recB.Hash, nil},
		}
		for _, tst := range missingUniqueTests {
			missingDetails, err = s.UniqueTxDetails(ns, tst.hash, tst.block)
			if err != nil {
				t.Fatal(err)
			}
			if missingDetails != nil {
				t.Errorf("Expected no details, found details for tx %v", missingDetails.Hash)
			}
		}

		iterations := 0
		err = s.RangeTransactions(ns, 0, -1, func([]TxDetails) (bool, error) {
			iterations++
			return true, nil
		})
		if iterations != 1 {
			t.Errorf("RangeTransactions (forwards) ran func %d times", iterations)
		}
		iterations = 0
		err = s.RangeTransactions(ns, -1, 0, func([]TxDetails) (bool, error) {
			iterations++
			return true, nil
		})
		if iterations != 1 {
			t.Errorf("RangeTransactions (reverse) ran func %d times", iterations)
		}
		// Make sure it also breaks early after one iteration through unmined transactions.
		if err := s.Rollback(ns, b101.Height); err != nil {
			return err
		}
		iterations = 0
		err = s.RangeTransactions(ns, -1, 0, func([]TxDetails) (bool, error) {
			iterations++
			return true, nil
		})
		if iterations != 1 {
			t.Errorf("RangeTransactions (reverse) ran func %d times", iterations)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// None of the above tests have tested RangeTransactions with multiple
	// txs per block, so do that now.  Start by moving tx B to block 100
	// (same block as tx A), and then rollback from block 100 onwards so
	// both are unmined.
	newState = lastState.deepCopy()
	newState.blocks[0] = append(newState.blocks[0], newState.blocks[1]...)
	newState.blocks[0][1].Block = b100
	newState.blocks = newState.blocks[:1]
	newState.txDetails[recB.Hash][0].Block = b100
	lastState = newState
	tests = append(tests[:0:0], queryTest{
		desc: "move tx B to block 100",
		updates: func(ns walletdb.ReadWriteBucket) error {
			return s.InsertTx(ns, recB, &b100)
		},
		state: newState,
	})
	newState = lastState.deepCopy()
	newState.blocks[0][0].Block = makeBlockMeta(-1)
	newState.blocks[0][1].Block = makeBlockMeta(-1)
	newState.txDetails[recA.Hash][0].Block = makeBlockMeta(-1)
	newState.txDetails[recB.Hash][0].Block = makeBlockMeta(-1)
	lastState = newState
	tests = append(tests, queryTest{
		desc: "rollback block 100",
		updates: func(ns walletdb.ReadWriteBucket) error {
			return s.Rollback(ns, b100.Height)
		},
		state: newState,
	})

	for _, tst := range tests {
		err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(namespaceKey)
			if err := tst.updates(ns); err != nil {
				return err
			}
			return tst.state.compare(s, ns, tst.desc)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPreviousPkScripts(t *testing.T) {
	t.Parallel()

	s, db, teardown, err := testStore()
	defer teardown()
	if err != nil {
		t.Fatal(err)
	}

	// Invalid scripts but sufficient for testing.
	var (
		scriptA0 = []byte("tx A output 0")
		scriptA1 = []byte("tx A output 1")
		scriptB0 = []byte("tx B output 0")
		scriptB1 = []byte("tx B output 1")
		scriptC0 = []byte("tx C output 0")
		scriptC1 = []byte("tx C output 1")
	)

	// Create a transaction spending two prevous outputs and generating two
	// new outputs the passed pkScipts.  Spends outputs 0 and 1 from prevHash.
	buildTx := func(prevHash *chainhash.Hash, script0, script1 []byte) *wire.MsgTx {
		return &wire.MsgTx{
			TxIn: []*wire.TxIn{
				{PreviousOutPoint: wire.OutPoint{
					Hash:  *prevHash,
					Index: 0,
				}},
				{PreviousOutPoint: wire.OutPoint{
					Hash: *prevHash, Index: 1,
				}},
			},
			TxOut: []*wire.TxOut{
				{Value: 1e8, PkScript: script0},
				{Value: 1e8, PkScript: script1},
			},
		}
	}

	newTxRecordFromMsgTx := func(tx *wire.MsgTx) *TxRecord {
		rec, err := NewTxRecordFromMsgTx(tx, timeNow())
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}

	// Create transactions with the fake output scripts.
	var (
		txA  = buildTx(&chainhash.Hash{}, scriptA0, scriptA1)
		recA = newTxRecordFromMsgTx(txA)
		txB  = buildTx(&recA.Hash, scriptB0, scriptB1)
		recB = newTxRecordFromMsgTx(txB)
		txC  = buildTx(&recB.Hash, scriptC0, scriptC1)
		recC = newTxRecordFromMsgTx(txC)
		txD  = buildTx(&recC.Hash, nil, nil)
		recD = newTxRecordFromMsgTx(txD)
	)

	insertTx := func(ns walletdb.ReadWriteBucket, rec *TxRecord, block *BlockMeta) {
		err := s.InsertTx(ns, rec, block)
		if err != nil {
			t.Fatal(err)
		}
	}
	addCredit := func(ns walletdb.ReadWriteBucket, rec *TxRecord, block *BlockMeta, index uint32) {
		err := s.AddCredit(ns, rec, block, index, false)
		if err != nil {
			t.Fatal(err)
		}
	}

	type scriptTest struct {
		rec     *TxRecord
		block   *Block
		scripts [][]byte
	}
	runTest := func(ns walletdb.ReadWriteBucket, tst *scriptTest) {
		scripts, err := s.PreviousPkScripts(ns, tst.rec, tst.block)
		if err != nil {
			t.Fatal(err)
		}
		height := int32(-1)
		if tst.block != nil {
			height = tst.block.Height
		}
		if len(scripts) != len(tst.scripts) {
			t.Errorf("Transaction %v height %d: got len(scripts)=%d, expected %d",
				tst.rec.Hash, height, len(scripts), len(tst.scripts))
			return
		}
		for i := range scripts {
			if !bytes.Equal(scripts[i], tst.scripts[i]) {
				// Format scripts with %s since they are (should be) ascii.
				t.Errorf("Transaction %v height %d script %d: got '%s' expected '%s'",
					tst.rec.Hash, height, i, scripts[i], tst.scripts[i])
			}
		}
	}

	dbtx, err := db.BeginReadWriteTx()
	if err != nil {
		t.Fatal(err)
	}
	defer dbtx.Commit()
	ns := dbtx.ReadWriteBucket(namespaceKey)

	// Insert transactions A-C unmined, but mark no credits yet.  Until
	// these are marked as credits, PreviousPkScripts should not return
	// them.
	insertTx(ns, recA, nil)
	insertTx(ns, recB, nil)
	insertTx(ns, recC, nil)

	b100 := makeBlockMeta(100)
	b101 := makeBlockMeta(101)

	tests := []scriptTest{
		{recA, nil, nil},
		{recA, &b100.Block, nil},
		{recB, nil, nil},
		{recB, &b100.Block, nil},
		{recC, nil, nil},
		{recC, &b100.Block, nil},
	}
	for _, tst := range tests {
		runTest(ns, &tst)
	}
	if t.Failed() {
		t.Fatal("Failed after unmined tx inserts")
	}

	// Mark credits.  Tx C output 1 not marked as a credit: tx D will spend
	// both later but when C is mined, output 1's script should not be
	// returned.
	addCredit(ns, recA, nil, 0)
	addCredit(ns, recA, nil, 1)
	addCredit(ns, recB, nil, 0)
	addCredit(ns, recB, nil, 1)
	addCredit(ns, recC, nil, 0)
	tests = []scriptTest{
		{recA, nil, nil},
		{recA, &b100.Block, nil},
		{recB, nil, [][]byte{scriptA0, scriptA1}},
		{recB, &b100.Block, nil},
		{recC, nil, [][]byte{scriptB0, scriptB1}},
		{recC, &b100.Block, nil},
	}
	for _, tst := range tests {
		runTest(ns, &tst)
	}
	if t.Failed() {
		t.Fatal("Failed after marking unmined credits")
	}

	// Mine tx A in block 100.  Test results should be identical.
	insertTx(ns, recA, &b100)
	for _, tst := range tests {
		runTest(ns, &tst)
	}
	if t.Failed() {
		t.Fatal("Failed after mining tx A")
	}

	// Mine tx B in block 101.
	insertTx(ns, recB, &b101)
	tests = []scriptTest{
		{recA, nil, nil},
		{recA, &b100.Block, nil},
		{recB, nil, nil},
		{recB, &b101.Block, [][]byte{scriptA0, scriptA1}},
		{recC, nil, [][]byte{scriptB0, scriptB1}},
		{recC, &b101.Block, nil},
	}
	for _, tst := range tests {
		runTest(ns, &tst)
	}
	if t.Failed() {
		t.Fatal("Failed after mining tx B")
	}

	// Mine tx C in block 101 (same block as tx B) to test debits from the
	// same block.
	insertTx(ns, recC, &b101)
	tests = []scriptTest{
		{recA, nil, nil},
		{recA, &b100.Block, nil},
		{recB, nil, nil},
		{recB, &b101.Block, [][]byte{scriptA0, scriptA1}},
		{recC, nil, nil},
		{recC, &b101.Block, [][]byte{scriptB0, scriptB1}},
	}
	for _, tst := range tests {
		runTest(ns, &tst)
	}
	if t.Failed() {
		t.Fatal("Failed after mining tx C")
	}

	// Insert tx D, which spends C:0 and C:1.  However, only C:0 is marked
	// as a credit, and only that output script should be returned.
	insertTx(ns, recD, nil)
	tests = append(tests, scriptTest{recD, nil, [][]byte{scriptC0}})
	tests = append(tests, scriptTest{recD, &b101.Block, nil})
	for _, tst := range tests {
		runTest(ns, &tst)
	}
	if t.Failed() {
		t.Fatal("Failed after inserting tx D")
	}
}
