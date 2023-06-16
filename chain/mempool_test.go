package chain

import (
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestCachedInputsHasInput checks that `hasInput` works as expected.
func TestCachedInputsHasInput(t *testing.T) {
	require := require.New(t)

	// Create a test input and tx.
	op := wire.OutPoint{Hash: chainhash.Hash{1}}
	tx := &wire.MsgTx{
		LockTime: 1,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: op}},
	}

	// Mannually construct the state.
	c := newCachedInputs()
	c.inputs[op.Hash] = map[txIndex]chainhash.Hash{
		txIndex(op.Index): tx.TxHash(),
	}

	// Lookup should now give us the txid.
	txid, ok := c.hasInput(op)
	require.True(ok)
	require.Equal(tx.TxHash(), txid)

	// Lookup a non-existent input.
	opNotExists := wire.OutPoint{Hash: chainhash.Hash{2}}
	txid, ok = c.hasInput(opNotExists)
	require.False(ok)
	require.Zero(txid)

	// Lookup an input whose tx hash exists but with a different index.
	op.Index = 2
	txid, ok = c.hasInput(op)
	require.False(ok)
	require.Zero(txid)
}

// TestCachedInputsUpdateInputs checks `updateInputs` behaves as expected.
func TestCachedInputsUpdateInputs(t *testing.T) {
	require := require.New(t)

	// Create twp inputs that share the same tx hash.
	opHash := chainhash.Hash{1}
	op1 := wire.OutPoint{
		Hash:  opHash,
		Index: 1,
	}
	op2 := wire.OutPoint{
		Hash:  opHash,
		Index: 2,
	}

	tx := &wire.MsgTx{
		LockTime: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op1},
			{PreviousOutPoint: op2},
		},
	}

	// Create a new cachedInputs.
	c := newCachedInputs()

	// Add first input.
	oldTxid, isReplacement := c.updateInputs(op1, tx.TxHash())

	// We should see an empty txid and isReplacement should be false.
	require.Empty(oldTxid)
	require.False(isReplacement)

	// Check the internal state.
	//
	// We should have one input tx hash.
	require.Len(c.inputs, 1)
	require.Contains(c.inputs, opHash)

	// We should have one input index under this tx hash.
	require.Len(c.inputs[opHash], 1)
	require.Contains(c.inputs[opHash], txIndex(op1.Index))

	// The input should point to tx.
	require.Equal(tx.TxHash(), c.inputs[opHash][txIndex(op1.Index)])

	// Add the second input.
	oldTxid, isReplacement = c.updateInputs(op2, tx.TxHash())

	// We should see an empty txid and isReplacement should be false.
	require.Empty(oldTxid)
	require.False(isReplacement)

	// Check the internal state and it should be updated.
	//
	// We should have one input tx hash.
	require.Len(c.inputs, 1)
	require.Contains(c.inputs, opHash)

	// We should have two input indexes under this tx hash.
	require.Len(c.inputs[opHash], 2)
	require.Contains(c.inputs[opHash], txIndex(op1.Index))
	require.Contains(c.inputs[opHash], txIndex(op2.Index))

	// They should all point to the txid.
	require.Equal(tx.TxHash(), c.inputs[opHash][txIndex(op1.Index)])
	require.Equal(tx.TxHash(), c.inputs[opHash][txIndex(op2.Index)])

	// Create a replacement tx.
	tx2 := &wire.MsgTx{
		LockTime: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op2},
		},
	}

	// Add first input again.
	oldTxid, isReplacement = c.updateInputs(op2, tx2.TxHash())

	// The old txid should be the same as tx.TxHash and isReplacement
	// should be true.
	require.Equal(tx.TxHash(), oldTxid)
	require.True(isReplacement)

	// Check the internal state and it should be updated.
	//
	// We should have one input tx hash.
	require.Len(c.inputs, 1)
	require.Contains(c.inputs, opHash)

	// We should have two input indexes under this tx hash.
	require.Len(c.inputs[opHash], 2)
	require.Contains(c.inputs[opHash], txIndex(op1.Index))
	require.Contains(c.inputs[opHash], txIndex(op2.Index))

	// They should point to different txids.
	require.Equal(tx.TxHash(), c.inputs[opHash][txIndex(op1.Index)])
	require.Equal(tx2.TxHash(), c.inputs[opHash][txIndex(op2.Index)])
}

// TestCachedInputsUpdateInputsTwice checks when calling `updateInputs` twice
// with the same arguments, the internal state should remain the same for the
// second call.
func TestCachedInputsUpdateInputsTwice(t *testing.T) {
	require := require.New(t)

	// Create twp inputs that share the same tx hash.
	op := wire.OutPoint{Hash: chainhash.Hash{1}}
	tx := &wire.MsgTx{
		LockTime: 1,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: op}},
	}

	// Create a new cachedInputs.
	c := newCachedInputs()

	// Add the input.
	oldTxid, isReplacement := c.updateInputs(op, tx.TxHash())

	// We should see an empty txid and isReplacement should be false.
	require.Empty(oldTxid)
	require.False(isReplacement)

	// Add the input again.
	oldTxid, isReplacement = c.updateInputs(op, tx.TxHash())

	// The old txid should be the same as tx.TxHash and isReplacement
	// should stay false.
	require.Equal(tx.TxHash(), oldTxid)
	require.False(isReplacement)

	// Check the internal state.
	//
	// We should have one input tx hash.
	require.Len(c.inputs, 1)
	require.Contains(c.inputs, op.Hash)

	// We should have one input index under this tx hash.
	require.Len(c.inputs[op.Hash], 1)
	require.Contains(c.inputs[op.Hash], txIndex(op.Index))

	// The input should point to tx.
	require.Equal(tx.TxHash(), c.inputs[op.Hash][txIndex(op.Index)])
}

// TestCachedInputs tests that the cachedInputs works as expected.
func TestCachedInputs(t *testing.T) {
	require := require.New(t)

	// Create test inputs and tx.
	op1 := wire.OutPoint{Hash: chainhash.Hash{1}}
	op2 := wire.OutPoint{Hash: chainhash.Hash{2}}
	tx := &wire.MsgTx{
		LockTime: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op1},
			{PreviousOutPoint: op2},
		},
	}

	c := newCachedInputs()

	// Lookup should give us nothing.
	txid, ok := c.hasInput(op1)
	require.False(ok)
	require.Zero(txid)

	// Add the input.
	c.addInput(op1, tx.TxHash())

	// Lookup should now give us the txid.
	txid, ok = c.hasInput(op1)
	require.True(ok)
	require.Equal(tx.TxHash(), txid)

	// Add another input.
	c.addInput(op2, tx.TxHash())

	// Delete the inputs.
	c.removeInputsFromTx(txid)

	// Lookup should now give us nothing.
	txid, ok = c.hasInput(op1)
	require.False(ok)
	require.Zero(txid)

	txid, ok = c.hasInput(op2)
	require.False(ok)
	require.Zero(txid)
}

// TestCachedInputsAddInputDifferent checks that when adding two different txes
// the internal state of cachedInputs is updated as expected.
func TestCachedInputsAddInputDifferent(t *testing.T) {
	require := require.New(t)

	// Create a test input and tx.
	op1 := wire.OutPoint{Hash: chainhash.Hash{1}}
	tx1 := &wire.MsgTx{
		LockTime: 1,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: op1}},
	}

	// Create another test input and tx.
	op2 := wire.OutPoint{Hash: chainhash.Hash{2}}
	tx2 := &wire.MsgTx{
		LockTime: 1,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: op2}},
	}

	c := newCachedInputs()

	// Add the input.
	c.addInput(op1, tx1.TxHash())
	c.addInput(op2, tx2.TxHash())

	// Lookup should now give us the txid.
	txid, ok := c.hasInput(op1)
	require.True(ok)
	require.Equal(tx1.TxHash(), txid)

	txid, ok = c.hasInput(op2)
	require.True(ok)
	require.Equal(tx2.TxHash(), txid)

	// Check the internal state.
	//
	// We should only have two inputs and two txids.
	require.Len(c.inputs, 2)
	require.Len(c.txids, 2)

	// Each txid's nested map should have one entry.
	require.Len(c.txids[tx1.TxHash()], 1)
	require.Len(c.txids[tx2.TxHash()], 1)
}

// TestCachedInputsAddInputReplacement checks that when a replacement tx is
// added, the internal state of cachedInputs is updated as expected.
func TestCachedInputsAddInputReplacement(t *testing.T) {
	require := require.New(t)

	// Create a test input and tx.
	op := wire.OutPoint{Hash: chainhash.Hash{1}}
	tx := &wire.MsgTx{
		LockTime: 1,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: op}},
	}

	// replacedTx spends the same input as tx.
	replacedTx := &wire.MsgTx{
		// Use a different locktime to ensure the txid is different.
		LockTime: 2,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: op}},
	}

	c := newCachedInputs()

	// Add the input.
	c.addInput(op, tx.TxHash())

	// Lookup should now give us the txid.
	txid, ok := c.hasInput(op)
	require.True(ok)
	require.Equal(tx.TxHash(), txid)

	// Check the internal state. Since we've just added one input, there
	// should be exactly one item in each map.
	require.Len(c.inputs, 1)
	require.Len(c.txids, 1)
	require.Len(c.txids[tx.TxHash()], 1)

	// Add the input again using the replacement tx.
	c.addInput(op, replacedTx.TxHash())

	// Lookup should now give us the replacement txid.
	txid, ok = c.hasInput(op)
	require.True(ok)
	require.Equal(replacedTx.TxHash(), txid)

	// Check the internal state.
	//
	// We should only have one input.
	require.Len(c.inputs, 1)

	// Expect two transactions.
	require.Len(c.txids, 2)

	// The new txid should be present.
	require.Len(c.txids[replacedTx.TxHash()], 1)

	// The nested map under old txid should be empty.
	require.Empty(c.txids[tx.TxHash()][op.Hash])
}

// TestCachedInputsAddInputTwice checks that when the same tx is added again it
// won't change the cachedInputs's internal state.
func TestCachedInputsAddInputTwice(t *testing.T) {
	require := require.New(t)

	// Create a test input and tx.
	op := wire.OutPoint{Hash: chainhash.Hash{1}}
	tx := &wire.MsgTx{
		LockTime: 1,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: op}},
	}

	c := newCachedInputs()

	// Add the input.
	c.addInput(op, tx.TxHash())

	// Lookup should now give us the txid.
	txid, ok := c.hasInput(op)
	require.True(ok)
	require.Equal(tx.TxHash(), txid)

	// Check the internal state. Since we've just added one input, there
	// should be exactly one item in each map.
	require.Len(c.inputs, 1)
	require.Len(c.txids, 1)
	require.Len(c.txids[tx.TxHash()], 1)

	// Add the input again.
	c.addInput(op, tx.TxHash())

	// Lookup should now give us same result.
	txid, ok = c.hasInput(op)
	require.True(ok)
	require.Equal(tx.TxHash(), txid)

	// Check the internal state. Since it's the same tx we should have the
	// same state.
	require.Len(c.inputs, 1)
	require.Len(c.txids, 1)
	require.Len(c.txids[tx.TxHash()], 1)
}

// TestCachedInputsAddInputSpendsSameTx checks that when spending inputs that
// shares the same tx hash, the internal state of cachedInputs is updated as
// expected.
func TestCachedInputsAddInputSpendsSameTx(t *testing.T) {
	require := require.New(t)

	// Create two inputs that share the same tx hash.
	op1 := wire.OutPoint{
		Hash:  chainhash.Hash{1},
		Index: 1,
	}
	op2 := wire.OutPoint{
		Hash:  chainhash.Hash{1},
		Index: 2,
	}

	tx := &wire.MsgTx{
		LockTime: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op1},
			{PreviousOutPoint: op2},
		},
	}

	c := newCachedInputs()

	// Add the input.
	c.addInput(op1, tx.TxHash())
	c.addInput(op2, tx.TxHash())

	// Check the internal state.
	//
	// Expect one input tx hash.
	require.Len(c.inputs, 1)

	// Expect two input indexes.
	require.Len(c.inputs[op1.Hash], 2)

	// Expect one txid.
	require.Len(c.txids, 1)

	// Expect one input tx hash under the txid.
	require.Len(c.txids[tx.TxHash()], 1)

	// Expect two input indexes under the txid.
	require.Len(c.txids[tx.TxHash()][op1.Hash], 2)
}

// TestMempool tests that each method of the mempool struct works as expected.
func TestMempool(t *testing.T) {
	require := require.New(t)

	m := newMempool(nil)

	// Create a transaction.
	op1 := wire.OutPoint{Hash: chainhash.Hash{1}}
	tx1 := &wire.MsgTx{
		LockTime: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op1},
		},
	}

	// Check that mempool doesn't have the tx yet.
	require.False(m.containsTx(tx1.TxHash()))

	// Check that mempool doesn't have the input yet.
	_, found := m.containsInput(op1)
	require.False(found)

	// Now add the tx.
	m.add(tx1)

	// Mempool should now contain the tx.
	require.True(m.containsTx(tx1.TxHash()))

	// Mempool should now also contain the input.
	txid, found := m.containsInput(op1)
	require.True(found)
	require.Equal(tx1.TxHash(), txid)

	// Add another tx to the mempool.
	op2 := wire.OutPoint{Hash: chainhash.Hash{2}}
	op3 := wire.OutPoint{Hash: chainhash.Hash{3}}
	tx2 := &wire.MsgTx{
		LockTime: 2,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op2},
			{PreviousOutPoint: op3},
		},
	}
	m.add(tx2)
	require.True(m.containsTx(tx2.TxHash()))

	// Clean the mempool of tx1 (this simulates a block being confirmed
	// with tx1 in the block).
	m.Clean([]*wire.MsgTx{tx1})

	// Ensure that tx1 is no longer in the mempool but that tx2 still is.
	require.False(m.containsTx(tx1.TxHash()))
	require.True(m.containsTx(tx2.TxHash()))

	// Ensure that the inputs of tx1 are no longer in the mempool but that
	// the inputs of tx2 still are.
	_, found = m.containsInput(op1)
	require.False(found)

	// Inputs of tx2 should still be in the mempool.
	txid, found = m.containsInput(op2)
	require.True(found)
	require.Equal(tx2.TxHash(), txid)

	txid, found = m.containsInput(op3)
	require.True(found)
	require.Equal(tx2.TxHash(), txid)

	// Lastly, we test that only marked transactions are deleted from the
	// mempool.

	// Let's first re-add tx1 so that we have more txs to work with.
	m.add(tx1)

	// Now, we unmark all the transactions.
	m.unmarkAll()

	// Add tx3. This should automatically mark tx3. We also make tx3 spend
	// the same input(op3) in tx2, and test that op3 is now updated.
	tx3 := &wire.MsgTx{
		LockTime: 3,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op3},
		},
	}
	m.add(tx3)

	// Let us now manually mark tx2.
	m.mark(tx2.TxHash())

	// Now we delete all unmarked txs. This should leave only tx2 and tx3
	// in the mempool.
	m.deleteUnmarked()

	require.False(m.containsTx(tx1.TxHash()))
	require.True(m.containsTx(tx2.TxHash()))
	require.True(m.containsTx(tx3.TxHash()))

	// Inputs of tx1 should be removed.
	_, found = m.containsInput(op1)
	require.False(found)

	// Inputs of tx2 should still be in the mempool.
	txid, found = m.containsInput(op2)
	require.True(found)
	require.Equal(tx2.TxHash(), txid)

	// Input3 should be in mempool and now point to tx3.
	txid, found = m.containsInput(op3)
	require.True(found)
	require.Equal(tx3.TxHash(), txid)
}

// TestMempoolAdd adds a coinbase tx, a normal tx, and a replacement tx to the
// mempool and checks the mempool's internal state is updated as expected.
func TestMempoolAdd(t *testing.T) {
	require := require.New(t)

	m := newMempool(nil)

	// Create a coinbase transaction.
	tx0 := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: math.MaxUint32,
				},
			},
		},
	}

	// Create a normal transaction that has two inputs.
	op1 := wire.OutPoint{Hash: chainhash.Hash{1}}
	op2 := wire.OutPoint{Hash: chainhash.Hash{2}}
	tx1 := &wire.MsgTx{
		LockTime: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op1},
			{PreviousOutPoint: op2},
		},
	}

	// Create a replacement transaction that spends one of the inputs as
	// tx1.
	op3 := wire.OutPoint{Hash: chainhash.Hash{3}}
	tx2 := &wire.MsgTx{
		LockTime: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op2},
			{PreviousOutPoint: op3},
		},
	}

	// Now add all the transactions.
	m.add(tx0)
	m.add(tx1)
	m.add(tx2)

	// Check transactions are updated, mempool should now contain two
	// transactions.
	require.False(m.containsTx(tx0.TxHash()))
	require.True(m.containsTx(tx1.TxHash()))
	require.True(m.containsTx(tx2.TxHash()))

	// Check inputs are updated.
	//
	// Mempool should contain op1 and point it to tx1.
	txid, found := m.containsInput(op1)
	require.True(found)
	require.Equal(tx1.TxHash(), txid)

	// Mempool should contain op2 and point it to tx2 since it's replace.
	txid, found = m.containsInput(op2)
	require.True(found)
	require.Equal(tx2.TxHash(), txid)

	// Mempool should contain op3 and point it to tx2.
	txid, found = m.containsInput(op3)
	require.True(found)
	require.Equal(tx2.TxHash(), txid)

	// Check the mempool's internal state.
	//
	// We should see two transactions in the mempool, tx1 and tx2.
	require.Len(m.txs, 2)

	// Check the internal state of the mempool's inputs.
	cachedInputs := m.inputs

	// We should see three inputs.
	require.Len(cachedInputs.inputs, 3)

	// We should see two transactions.
	require.Len(cachedInputs.txids, 2)

	// We should see two input tx hashes under tx1's nested map.
	require.Len(cachedInputs.txids[tx1.TxHash()], 2)

	// We should see one input index under op1 in tx1's nested map.
	require.Len(cachedInputs.txids[tx1.TxHash()][op1.Hash], 1)

	// We should see an empty map under op2 in tx1's nested map because
	// it's replaced.
	require.Empty(cachedInputs.txids[tx1.TxHash()][op2.Hash])

	// We should see two input under tx2's nested map.
	require.Len(cachedInputs.txids[tx2.TxHash()], 2)

	// We should see one input index under op2 in tx2's nested map.
	require.Len(cachedInputs.txids[tx2.TxHash()][op2.Hash], 1)

	// We should see one input index under op3 in tx2's nested map.
	require.Len(cachedInputs.txids[tx2.TxHash()][op3.Hash], 1)
}

// TestUpdateMempoolTxes tests that the mempool's internal state is updated as
// expected when receiving new transactions.
func TestUpdateMempoolTxes(t *testing.T) {
	require := require.New(t)

	// Create a mock client and init our mempool.
	mockRPC := &mockRPCClient{}
	m := newMempool(mockRPC)

	// Create a normal transaction that has two inputs.
	op1 := wire.OutPoint{Hash: chainhash.Hash{1}}
	op2 := wire.OutPoint{Hash: chainhash.Hash{2}}
	tx1 := &wire.MsgTx{
		LockTime: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op1},
			{PreviousOutPoint: op2},
		},
	}
	tx1Hash := tx1.TxHash()
	btcTx1 := btcutil.NewTx(tx1)

	// Create another transaction.
	op3 := wire.OutPoint{Hash: chainhash.Hash{3}}
	tx2 := &wire.MsgTx{
		LockTime: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op3},
		},
	}
	tx2Hash := tx2.TxHash()
	btctx2 := btcutil.NewTx(tx2)

	// Create the current mempool state.
	mempool1 := []*chainhash.Hash{&tx1Hash, &tx2Hash}

	// Mock the client to return the txes.
	mockRPC.On("GetRawTransaction", &tx1Hash).Return(btcTx1, nil).Once()
	mockRPC.On("GetRawTransaction", &tx2Hash).Return(btctx2, nil).Once()

	// Update our mempool using the above mempool state.
	newTxes := m.UpdateMempoolTxes(mempool1)

	// We expect two transactions.
	require.Len(newTxes, 2)

	// Create a new mempool state.
	//
	// Create a tx that replaces one input of tx1.
	tx3 := &wire.MsgTx{
		LockTime: 2,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op1},
		},
	}
	tx3Hash := tx3.TxHash()
	btctx3 := btcutil.NewTx(tx3)

	// Create a tx that replaces tx2.
	tx4 := &wire.MsgTx{
		LockTime: 2,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op3},
		},
	}
	tx4Hash := tx4.TxHash()
	btctx4 := btcutil.NewTx(tx4)

	// Create the new mempool state, where tx1 and tx2 are evicted and tx3
	// and tx4 are added.
	//
	// NOTE: tx1 and tx2 must not exist since they are replaced.
	mempool2 := []*chainhash.Hash{&tx3Hash, &tx4Hash}

	// Mock the client to return the txes.
	mockRPC.On("GetRawTransaction", &tx3Hash).Return(btctx3, nil).Once()
	mockRPC.On("GetRawTransaction", &tx4Hash).Return(btctx4, nil).Once()

	// Update our mempool using the above mempool state.
	newTxes = m.UpdateMempoolTxes(mempool2)

	// We expect two transactions.
	require.Len(newTxes, 2)

	// Assert the mock client was called the expected number of times.
	mockRPC.AssertExpectations(t)

	// In addition, we want to check the mempool's internal state.
	//
	// We should see three transactions in the mempool.
	require.Len(m.txs, 2)

	// Get the cachedInputs's internal state.
	txidsMap := m.inputs.txids
	inputsMap := m.inputs.inputs

	// We should see two input tx hashes.
	require.Len(inputsMap, 2)
	require.Equal(tx3Hash, inputsMap[op1.Hash][txIndex(op1.Index)])
	require.Equal(tx4Hash, inputsMap[op3.Hash][txIndex(op3.Index)])

	// We should see two transactions.
	require.Len(txidsMap, 2)

	// We should one input under tx3's nested map and it should be op1.
	require.Len(txidsMap[tx3.TxHash()], 1)
	require.Contains(txidsMap[tx3.TxHash()], op1.Hash)

	// We should one input under tx4's nested map and it should be op3.
	require.Len(txidsMap[tx4.TxHash()], 1)
	require.Contains(txidsMap[tx4.TxHash()], op3.Hash)

	// We should see tx1 and tx2 being removed.
	require.NotContains(txidsMap, tx1Hash)
	require.NotContains(txidsMap, tx2Hash)
}
