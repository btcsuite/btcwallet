package chain

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

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

	// The old txid should be an empty map.
	require.Empty(c.txids[tx.TxHash()])
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
