// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/jadeblaquiere/ctcd/chaincfg/chainhash"
	"github.com/jadeblaquiere/ctcd/wire"
	"github.com/jadeblaquiere/ctcutil"
	. "github.com/jadeblaquiere/ctcwallet/wtxmgr"
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

func (q *queryState) compare(t *testing.T, s *Store, changeDesc string) {
	defer func() {
		if t.Failed() {
			t.Fatalf("Store state queries failed after '%s'", changeDesc)
		}
	}()

	fwdBlocks := q.blocks
	revBlocks := make([][]TxDetails, len(q.blocks))
	copy(revBlocks, q.blocks)
	for i := 0; i < len(revBlocks)/2; i++ {
		revBlocks[i], revBlocks[len(revBlocks)-1-i] = revBlocks[len(revBlocks)-1-i], revBlocks[i]
	}
	checkBlock := func(blocks [][]TxDetails) func([]TxDetails) (bool, error) {
		return func(got []TxDetails) (bool, error) {
			if len(fwdBlocks) == 0 {
				return false, fmt.Errorf("entered range when no more details expected")
			}
			exp := blocks[0]
			if len(got) != len(exp) {
				return false, fmt.Errorf("got len(details)=%d in transaction range, expected %d", len(got), len(exp))
			}
			for i := range got {
				equalTxDetails(t, &got[i], &exp[i])
			}
			if t.Failed() {
				return false, fmt.Errorf("Failed comparing range of transaction details")
			}
			blocks = blocks[1:]
			return false, nil
		}
	}
	err := s.RangeTransactions(0, -1, checkBlock(fwdBlocks))
	if err != nil {
		t.Fatalf("Failed in RangeTransactions (forwards iteration): %v", err)
	}
	err = s.RangeTransactions(-1, 0, checkBlock(revBlocks))
	if err != nil {
		t.Fatalf("Failed in RangeTransactions (reverse iteration): %v", err)
	}

	for txHash, details := range q.txDetails {
		for _, detail := range details {
			blk := &detail.Block.Block
			if blk.Height == -1 {
				blk = nil
			}
			d, err := s.UniqueTxDetails(&txHash, blk)
			if err != nil {
				t.Fatal(err)
			}
			if d == nil {
				t.Errorf("Found no matching transaction at height %d", detail.Block.Height)
				continue
			}
			equalTxDetails(t, d, &detail)
		}
		if t.Failed() {
			t.Fatalf("Failed querying unique details regarding transaction %v", txHash)
		}

		// For the most recent tx with this hash, check that
		// TxDetails (not looking up a tx at any particular
		// height) matches the last.
		detail := &details[len(details)-1]
		d, err := s.TxDetails(&txHash)
		if err != nil {
			t.Fatal(err)
		}
		equalTxDetails(t, d, detail)
		if t.Failed() {
			t.Fatalf("Failed querying latest details regarding transaction %v", txHash)
		}
	}
}

func equalTxDetails(t *testing.T, got, exp *TxDetails) {
	// Need to avoid using reflect.DeepEqual against slices, since it
	// returns false for nil vs non-nil zero length slices.

	equalTxs(t, &got.MsgTx, &exp.MsgTx)
	if got.Hash != exp.Hash {
		t.Errorf("Found mismatched hashes")
		t.Errorf("Got: %v", got.Hash)
		t.Errorf("Expected: %v", exp.Hash)
	}
	if got.Received != exp.Received {
		t.Errorf("Found mismatched receive time")
		t.Errorf("Got: %v", got.Received)
		t.Errorf("Expected: %v", exp.Received)
	}
	if !bytes.Equal(got.SerializedTx, exp.SerializedTx) {
		t.Errorf("Found mismatched serialized txs")
		t.Errorf("Got: %x", got.SerializedTx)
		t.Errorf("Expected: %x", exp.SerializedTx)
	}
	if got.Block != exp.Block {
		t.Errorf("Found mismatched block meta")
		t.Errorf("Got: %v", got.Block)
		t.Errorf("Expected: %v", exp.Block)
	}
	if len(got.Credits) != len(exp.Credits) {
		t.Errorf("Credit slice lengths differ: Got %d Expected %d", len(got.Credits), len(exp.Credits))
	} else {
		for i := range got.Credits {
			if got.Credits[i] != exp.Credits[i] {
				t.Errorf("Found mismatched Credit[%d]", i)
				t.Errorf("Got: %v", got.Credits[i])
				t.Errorf("Expected: %v", exp.Credits[i])
			}
		}
	}
	if len(got.Debits) != len(exp.Debits) {
		t.Errorf("Debit slice lengths differ: Got %d Expected %d", len(got.Debits), len(exp.Debits))
	} else {
		for i := range got.Debits {
			if got.Debits[i] != exp.Debits[i] {
				t.Errorf("Found mismatched Debit[%d]", i)
				t.Errorf("Got: %v", got.Debits[i])
				t.Errorf("Expected: %v", exp.Debits[i])
			}
		}
	}
}

func equalTxs(t *testing.T, got, exp *wire.MsgTx) {
	var bufGot, bufExp bytes.Buffer
	err := got.Serialize(&bufGot)
	if err != nil {
		t.Fatal(err)
	}
	err = exp.Serialize(&bufExp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bufGot.Bytes(), bufExp.Bytes()) {
		t.Errorf("Found unexpected wire.MsgTx:")
		t.Errorf("Got: %v", got)
		t.Errorf("Expected: %v", exp)
	}
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
		updates func() // Unwinds from t.Fatal if the update errors.
		state   *queryState
	}
	var tests []queryTest

	// Create the store and test initial state.
	s, teardown, err := testStore()
	defer teardown()
	if err != nil {
		t.Fatal(err)
	}
	lastState := newQueryState()
	tests = append(tests, queryTest{
		desc:    "initial store",
		updates: func() {},
		state:   lastState,
	})

	// simplify error handling
	insertTx := func(rec *TxRecord, block *BlockMeta) {
		err := s.InsertTx(rec, block)
		if err != nil {
			t.Fatal(err)
		}
	}
	addCredit := func(s *Store, rec *TxRecord, block *BlockMeta, index uint32, change bool) {
		err := s.AddCredit(rec, block, index, change)
		if err != nil {
			t.Fatal(err)
		}
	}
	newTxRecordFromMsgTx := func(tx *wire.MsgTx, received time.Time) *TxRecord {
		rec, err := NewTxRecordFromMsgTx(tx, received)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	rollback := func(height int32) {
		err := s.Rollback(height)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Insert an unmined transaction.  Mark no credits yet.
	txA := spendOutput(&chainhash.Hash{}, 0, 100e8)
	recA := newTxRecordFromMsgTx(txA, timeNow())
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
		desc:    "insert tx A unmined",
		updates: func() { insertTx(recA, nil) },
		state:   newState,
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
		desc:    "mark unconfirmed txA:0 as credit",
		updates: func() { addCredit(s, recA, nil, 0, true) },
		state:   newState,
	})

	// Insert another unmined transaction which spends txA:0, splitting the
	// amount into outputs of 40 and 60 BTC.
	txB := spendOutput(&recA.Hash, 0, 40e8, 60e8)
	recB := newTxRecordFromMsgTx(txB, timeNow())
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
		desc:    "insert tx B unmined",
		updates: func() { insertTx(recB, nil) },
		state:   newState,
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
		desc:    "mark txB:0 as non-change credit",
		updates: func() { addCredit(s, recB, nil, 0, false) },
		state:   newState,
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
		desc:    "mine tx A",
		updates: func() { insertTx(recA, &b100) },
		state:   newState,
	})

	// Mine tx B at block 101.
	b101 := makeBlockMeta(101)
	newState = lastState.deepCopy()
	newState.blocks[1][0].Block = b101
	newState.txDetails[recB.Hash][0].Block = b101
	lastState = newState
	tests = append(tests, queryTest{
		desc:    "mine tx B",
		updates: func() { insertTx(recB, &b101) },
		state:   newState,
	})

	for _, tst := range tests {
		tst.updates()
		tst.state.compare(t, s, tst.desc)
	}

	// Run some additional query tests with the current store's state:
	//   - Verify that querying for a transaction not in the store returns
	//     nil without failure.
	//   - Verify that querying for a unique transaction at the wrong block
	//     returns nil without failure.
	//   - Verify that breaking early on RangeTransactions stops further
	//     iteration.

	missingTx := spendOutput(&recB.Hash, 0, 40e8)
	missingRec := newTxRecordFromMsgTx(missingTx, timeNow())
	missingBlock := makeBlockMeta(102)
	missingDetails, err := s.TxDetails(&missingRec.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if missingDetails != nil {
		t.Errorf("Expected no details, found details for tx %v", missingDetails.Hash)
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
		missingDetails, err = s.UniqueTxDetails(tst.hash, tst.block)
		if err != nil {
			t.Fatal(err)
		}
		if missingDetails != nil {
			t.Errorf("Expected no details, found details for tx %v", missingDetails.Hash)
		}
	}

	iterations := 0
	err = s.RangeTransactions(0, -1, func([]TxDetails) (bool, error) {
		iterations++
		return true, nil
	})
	if iterations != 1 {
		t.Errorf("RangeTransactions (forwards) ran func %d times", iterations)
	}
	iterations = 0
	err = s.RangeTransactions(-1, 0, func([]TxDetails) (bool, error) {
		iterations++
		return true, nil
	})
	if iterations != 1 {
		t.Errorf("RangeTransactions (reverse) ran func %d times", iterations)
	}
	// Make sure it also breaks early after one iteration through unmined transactions.
	rollback(b101.Height)
	iterations = 0
	err = s.RangeTransactions(-1, 0, func([]TxDetails) (bool, error) {
		iterations++
		return true, nil
	})
	if iterations != 1 {
		t.Errorf("RangeTransactions (reverse) ran func %d times", iterations)
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
		desc:    "move tx B to block 100",
		updates: func() { insertTx(recB, &b100) },
		state:   newState,
	})
	newState = lastState.deepCopy()
	newState.blocks[0][0].Block = makeBlockMeta(-1)
	newState.blocks[0][1].Block = makeBlockMeta(-1)
	newState.txDetails[recA.Hash][0].Block = makeBlockMeta(-1)
	newState.txDetails[recB.Hash][0].Block = makeBlockMeta(-1)
	lastState = newState
	tests = append(tests, queryTest{
		desc:    "rollback block 100",
		updates: func() { rollback(b100.Height) },
		state:   newState,
	})

	// None of the above tests have tested transactions with colliding
	// hashes, so mine tx A in block 100, and then insert tx A again
	// unmined.  Also mine tx A in block 101 (this moves it from unmined).
	// This is a valid test because the store does not perform signature
	// validation or keep a full utxo set, and duplicated transaction hashes
	// from different blocks are allowed so long as all previous outputs are
	// spent.
	newState = lastState.deepCopy()
	newState.blocks = append(newState.blocks, newState.blocks[0][1:])
	newState.blocks[0] = newState.blocks[0][:1:1]
	newState.blocks[0][0].Block = b100
	newState.blocks[1] = []TxDetails{
		{
			TxRecord: *stripSerializedTx(recA),
			Block:    makeBlockMeta(-1),
		},
		newState.blocks[1][0],
	}
	newState.txDetails[recA.Hash][0].Block = b100
	newState.txDetails[recA.Hash] = append(newState.txDetails[recA.Hash], newState.blocks[1][0])
	lastState = newState
	tests = append(tests, queryTest{
		desc:    "insert duplicate tx A",
		updates: func() { insertTx(recA, &b100); insertTx(recA, nil) },
		state:   newState,
	})
	newState = lastState.deepCopy()
	newState.blocks = [][]TxDetails{
		newState.blocks[0],
		[]TxDetails{newState.blocks[1][0]},
		[]TxDetails{newState.blocks[1][1]},
	}
	newState.blocks[1][0].Block = b101
	newState.txDetails[recA.Hash][1].Block = b101
	lastState = newState
	tests = append(tests, queryTest{
		desc:    "mine duplicate tx A",
		updates: func() { insertTx(recA, &b101) },
		state:   newState,
	})

	for _, tst := range tests {
		tst.updates()
		tst.state.compare(t, s, tst.desc)
	}
}

func TestPreviousPkScripts(t *testing.T) {
	t.Parallel()

	s, teardown, err := testStore()
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
				&wire.TxIn{PreviousOutPoint: wire.OutPoint{
					Hash:  *prevHash,
					Index: 0,
				}},
				&wire.TxIn{PreviousOutPoint: wire.OutPoint{
					Hash: *prevHash, Index: 1,
				}},
			},
			TxOut: []*wire.TxOut{
				&wire.TxOut{Value: 1e8, PkScript: script0},
				&wire.TxOut{Value: 1e8, PkScript: script1},
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

	insertTx := func(rec *TxRecord, block *BlockMeta) {
		err := s.InsertTx(rec, block)
		if err != nil {
			t.Fatal(err)
		}
	}
	addCredit := func(rec *TxRecord, block *BlockMeta, index uint32) {
		err := s.AddCredit(rec, block, index, false)
		if err != nil {
			t.Fatal(err)
		}
	}

	type scriptTest struct {
		rec     *TxRecord
		block   *Block
		scripts [][]byte
	}
	runTest := func(tst *scriptTest) {
		scripts, err := s.PreviousPkScripts(tst.rec, tst.block)
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

	// Insert transactions A-C unmined, but mark no credits yet.  Until
	// these are marked as credits, PreviousPkScripts should not return
	// them.
	insertTx(recA, nil)
	insertTx(recB, nil)
	insertTx(recC, nil)

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
		runTest(&tst)
	}
	if t.Failed() {
		t.Fatal("Failed after unmined tx inserts")
	}

	// Mark credits.  Tx C output 1 not marked as a credit: tx D will spend
	// both later but when C is mined, output 1's script should not be
	// returned.
	addCredit(recA, nil, 0)
	addCredit(recA, nil, 1)
	addCredit(recB, nil, 0)
	addCredit(recB, nil, 1)
	addCredit(recC, nil, 0)
	tests = []scriptTest{
		{recA, nil, nil},
		{recA, &b100.Block, nil},
		{recB, nil, [][]byte{scriptA0, scriptA1}},
		{recB, &b100.Block, nil},
		{recC, nil, [][]byte{scriptB0, scriptB1}},
		{recC, &b100.Block, nil},
	}
	for _, tst := range tests {
		runTest(&tst)
	}
	if t.Failed() {
		t.Fatal("Failed after marking unmined credits")
	}

	// Mine tx A in block 100.  Test results should be identical.
	insertTx(recA, &b100)
	for _, tst := range tests {
		runTest(&tst)
	}
	if t.Failed() {
		t.Fatal("Failed after mining tx A")
	}

	// Mine tx B in block 101.
	insertTx(recB, &b101)
	tests = []scriptTest{
		{recA, nil, nil},
		{recA, &b100.Block, nil},
		{recB, nil, nil},
		{recB, &b101.Block, [][]byte{scriptA0, scriptA1}},
		{recC, nil, [][]byte{scriptB0, scriptB1}},
		{recC, &b101.Block, nil},
	}
	for _, tst := range tests {
		runTest(&tst)
	}
	if t.Failed() {
		t.Fatal("Failed after mining tx B")
	}

	// Mine tx C in block 101 (same block as tx B) to test debits from the
	// same block.
	insertTx(recC, &b101)
	tests = []scriptTest{
		{recA, nil, nil},
		{recA, &b100.Block, nil},
		{recB, nil, nil},
		{recB, &b101.Block, [][]byte{scriptA0, scriptA1}},
		{recC, nil, nil},
		{recC, &b101.Block, [][]byte{scriptB0, scriptB1}},
	}
	for _, tst := range tests {
		runTest(&tst)
	}
	if t.Failed() {
		t.Fatal("Failed after mining tx C")
	}

	// Insert tx D, which spends C:0 and C:1.  However, only C:0 is marked
	// as a credit, and only that output script should be returned.
	insertTx(recD, nil)
	tests = append(tests, scriptTest{recD, nil, [][]byte{scriptC0}})
	tests = append(tests, scriptTest{recD, &b101.Block, nil})
	for _, tst := range tests {
		runTest(&tst)
	}
	if t.Failed() {
		t.Fatal("Failed after inserting tx D")
	}
}
