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

func TestCachedInputsAddInput(t *testing.T) {
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

	// Add the input again using the replacement tx.
	c.addInput(op, replacedTx.TxHash())

	// Lookup should now give us the replacement txid.
	txid, ok = c.hasInput(op)
	require.True(ok)
	require.Equal(replacedTx.TxHash(), txid)
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
