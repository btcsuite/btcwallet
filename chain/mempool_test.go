package chain

import (
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestMempool tests that each method of the mempool struct works as expected.
func TestMempool(t *testing.T) {
	m := newMempool()

	// Create a transaction.
	tx1 := &wire.MsgTx{LockTime: 1}

	// Check that mempool doesn't have the tx yet.
	require.False(t, m.contains(tx1.TxHash()))

	// Now add the tx.
	m.add(tx1.TxHash())

	// Mempool should now contain the tx.
	require.True(t, m.contains(tx1.TxHash()))

	// Add another tx to the mempool.
	tx2 := &wire.MsgTx{LockTime: 2}
	m.add(tx2.TxHash())
	require.True(t, m.contains(tx2.TxHash()))

	// Clean the mempool of tx1 (this simulates a block being confirmed
	// with tx1 in the block).
	m.clean([]*wire.MsgTx{tx1})

	// Ensure that tx1 is no longer in the mempool but that tx2 still is.
	require.False(t, m.contains(tx1.TxHash()))
	require.True(t, m.contains(tx2.TxHash()))

	// Lastly, we test that only marked transactions are deleted from the
	// mempool.

	// Let's first re-add tx1 so that we have more txs to work with.
	m.add(tx1.TxHash())

	// Now, we unmark all the transactions.
	m.unmarkAll()

	// Add tx3. This should automatically mark tx3.
	tx3 := &wire.MsgTx{LockTime: 3}
	m.add(tx3.TxHash())

	// Let us now manually mark tx2.
	m.mark(tx2.TxHash())

	// Now we delete all unmarked txs. This should leave only tx2 and tx3
	// in the mempool.
	m.deleteUnmarked()

	require.False(t, m.contains(tx1.TxHash()))
	require.True(t, m.contains(tx2.TxHash()))
	require.True(t, m.contains(tx3.TxHash()))
}
