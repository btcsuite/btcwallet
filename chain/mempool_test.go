package chain

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// testTimeout is used to ensure the test will time out if the expected result
// is not returned in 5 seconds.
const testTimeout = 5 * time.Second

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

	m := newMempool(&mempoolConfig{
		batchWaitInterval: 0,
		getRawTxBatchSize: 1,
	})

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

	m := newMempool(&mempoolConfig{
		batchWaitInterval: 0,
		getRawTxBatchSize: 1,
	})

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

	// We should one input under tx1's nested map.
	require.Len(cachedInputs.txids[tx1.TxHash()], 1)

	// We should see two input under tx2's nested map.
	require.Len(cachedInputs.txids[tx2.TxHash()], 2)
}

// TestUpdateMempoolTxes tests that the mempool's internal state is updated as
// expected when receiving new transactions.
func TestUpdateMempoolTxes(t *testing.T) {
	require := require.New(t)

	// Create a mock client and init our mempool.
	mockRPC := &mockRPCClient{}
	m := newMempool(&mempoolConfig{
		client:            mockRPC,
		batchWaitInterval: 0,
		getRawTxBatchSize: 1,
	})

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
	btctx1 := btcutil.NewTx(tx1)

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

	// Create mock receivers.
	mockTx1Receiver := make(rpcclient.FutureGetRawTransactionResult)
	mockTx2Receiver := make(rpcclient.FutureGetRawTransactionResult)
	mockTx3Receiver := make(rpcclient.FutureGetRawTransactionResult)
	mockTx4Receiver := make(rpcclient.FutureGetRawTransactionResult)

	// Mock the client to return the txes.
	mockRPC.On("GetRawTransactionAsync", &tx1Hash).Return(
		mockTx1Receiver).Once()
	mockRPC.On("GetRawTransactionAsync", &tx2Hash).Return(
		mockTx2Receiver).Once()
	mockRPC.On("Send").Return(nil).Twice()

	// Mock our rawMempoolGetter and rawTxReceiver.
	m.cfg.rawMempoolGetter = func() ([]*chainhash.Hash, error) {
		return mempool1, nil
	}
	m.cfg.rawTxReceiver = func(txid chainhash.Hash,
		reciever getRawTxReceiver) *btcutil.Tx {

		switch reciever {
		case mockTx1Receiver:
			return btctx1
		case mockTx2Receiver:
			return btctx2
		}

		require.Fail("unexpected receiver")
		return nil
	}

	// Update our mempool using the above mempool state.
	newTxes := m.UpdateMempoolTxes()

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

	// Create the new mempool state, where tx2 is evicted and tx3 and tx4
	// are added. Technically it's impossible to have tx1 still in the
	// mempool.
	mempool2 := []*chainhash.Hash{&tx1Hash, &tx3Hash, &tx4Hash}

	// Mock the client to return the txes.
	mockRPC.On("GetRawTransactionAsync",
		&tx3Hash).Return(mockTx3Receiver).Once()
	mockRPC.On("GetRawTransactionAsync",
		&tx4Hash).Return(mockTx4Receiver).Once()
	mockRPC.On("Send").Return(nil).Twice()

	// Mock our rawMempoolGetter and rawTxReceiver.
	m.cfg.rawMempoolGetter = func() ([]*chainhash.Hash, error) {
		return mempool2, nil
	}
	m.cfg.rawTxReceiver = func(txid chainhash.Hash,
		reciever getRawTxReceiver) *btcutil.Tx {

		switch reciever {
		case mockTx3Receiver:
			return btctx3
		case mockTx4Receiver:
			return btctx4
		}

		require.Fail("unexpected receiver")
		return nil
	}

	// Update our mempool using the above mempool state.
	newTxes = m.UpdateMempoolTxes()

	// We expect two transactions.
	require.Len(newTxes, 2)

	// Assert the mock client was called the expected number of times.
	mockRPC.AssertExpectations(t)

	// In addition, we want to check the mempool's internal state.
	//
	// We should see three transactions in the mempool.
	require.Len(m.txs, 3)

	// We should see three inputs.
	require.Len(m.inputs.inputs, 3)

	// We should see three transactions.
	require.Len(m.inputs.txids, 3)

	// We should one input under tx1's nested map and it should be op2
	// since op1 is replaced.
	require.Len(m.inputs.txids[tx1.TxHash()], 1)
	require.Contains(m.inputs.txids[tx1.TxHash()], op2)

	// We should one input under tx3's nested map and it should be op1.
	require.Len(m.inputs.txids[tx3.TxHash()], 1)
	require.Contains(m.inputs.txids[tx3.TxHash()], op1)

	// We should one input under tx4's nested map and it should be op3.
	require.Len(m.inputs.txids[tx4.TxHash()], 1)
	require.Contains(m.inputs.txids[tx4.TxHash()], op3)

	// We should see tx2 being removed.
	require.NotContains(m.inputs.txids, tx2Hash)
}

// TestUpdateMempoolTxesOnShutdown tests that when the mempool is shutting
// down, UpdateMempoolTxes will also exit immediately.
func TestUpdateMempoolTxesOnShutdown(t *testing.T) {
	require := require.New(t)

	// Create a mock client and init our mempool.
	mockRPC := &mockRPCClient{}
	m := newMempool(&mempoolConfig{
		client:            mockRPC,
		batchWaitInterval: 0,
		getRawTxBatchSize: 1,
	})

	// Create a normal transaction.
	op1 := wire.OutPoint{Hash: chainhash.Hash{1}}
	tx1 := &wire.MsgTx{
		LockTime: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op1},
		},
	}
	tx1Hash := tx1.TxHash()

	// Create the current mempool state.
	mempool := []*chainhash.Hash{&tx1Hash}

	// Mock our rawMempoolGetter and rawTxReceiver.
	m.cfg.rawMempoolGetter = func() ([]*chainhash.Hash, error) {
		return mempool, nil
	}

	// Shutdown the mempool before updating the txes.
	m.Shutdown()

	// Update our mempool using the above mempool state.
	newTxes := m.UpdateMempoolTxes()

	// We expect two transactions.
	require.Empty(newTxes)

	// Assert GetRawTransaction is not called because mempool is quit.
	mockRPC.AssertNotCalled(t, "GetRawTransactionAsync")
}

// TestGetRawTxIgnoreErr tests that the mempool's GetRawTxIgnoreErr method
// works as expected.
func TestGetRawTxIgnoreErr(t *testing.T) {
	require := require.New(t)

	// Create a normal transaction that has two inputs.
	op := wire.OutPoint{Hash: chainhash.Hash{1}}
	tx := &wire.MsgTx{
		LockTime: 1,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: op}},
	}
	btctx := btcutil.NewTx(tx)

	// Mock the receiver.
	mockReceiver := &mockGetRawTxReceiver{}
	mockReceiver.On("Receive").Return(btctx, nil).Once()

	// Call the method and expect the tx to be returned.
	resp := getRawTxIgnoreErr(tx.TxHash(), mockReceiver)
	require.Equal(btctx, resp)

	// Mock the reciever to return an error.
	dummyErr := errors.New("dummy error")
	mockReceiver.On("Receive").Return(nil, dummyErr).Once()

	// Call the method again and expect nil response.
	resp = getRawTxIgnoreErr(tx.TxHash(), mockReceiver)
	require.Nil(resp)

	// Assert the mock client was called as expected.
	mockReceiver.AssertExpectations(t)
}

// TestBatchGetRawTxesOnBatchSize checks that the batch size is properly
// handled. It defines a testing batch size of 3, and creates 7 testing
// transactions. Then it asserts there are 3 batches created and handled.
func TestBatchGetRawTxesOnBatchSize(t *testing.T) {
	require := require.New(t)

	const (
		// Define a small batch size for testing only.
		testBatchSize = 3

		// Create 7 test transactions so we can hit our batching logic
		// - we should create two full batches and one batch with the
		// remaining transaction.
		numTxes = testBatchSize*2 + 1
	)

	// Create a mock client and init our mempool.
	mockRPC := &mockRPCClient{}
	m := newMempool(&mempoolConfig{
		client:            mockRPC,
		batchWaitInterval: 0,
		getRawTxBatchSize: testBatchSize,
	})

	// Create test transactions and mempool state.
	mempool := make([]*chainhash.Hash, 0, numTxes)

	// Create a map of raw tx response receivers, keyed by txid.
	mockTxResponses := make(map[chainhash.Hash]*btcutil.Tx, numTxes)

	// Fill up the slices and mock the methods.
	for i := 0; i < numTxes; i++ {
		// Create testing transactions.
		op := wire.OutPoint{Hash: chainhash.Hash{byte(i)}}
		tx := &wire.MsgTx{
			LockTime: 1,
			TxIn:     []*wire.TxIn{{PreviousOutPoint: op}},
		}

		// Fill the testing mempool.
		txHash := tx.TxHash()
		mempool = append(mempool, &txHash)

		// Create a testing resposne receiver to be returned by
		// GetRawTransactionAsync.
		mockTxReceiver := make(rpcclient.FutureGetRawTransactionResult)

		// Add this tx to our mocked responses.
		btcTx := btcutil.NewTx(tx)
		mockTxResponses[txHash] = btcTx

		// Mock `GetRawTransactionAsync` to return the mocked value.
		mockRPC.On("GetRawTransactionAsync",
			&txHash).Return(mockTxReceiver).Once()
	}

	// Mock the rawTxReceiver to find and return the tx found in map
	// `mockTxResponses`.
	m.cfg.rawTxReceiver = func(txid chainhash.Hash,
		reciever getRawTxReceiver) *btcutil.Tx {

		btcTx, ok := mockTxResponses[txid]
		require.Truef(ok, "unexpected receiver for %v", txid)

		return btcTx
	}

	// We expect to send the batched requests three times - two for the
	// full batch and one for the remaining batch.
	mockRPC.On("Send").Return(nil).Times(3)

	// Call the method under test.
	newTxes, err := m.batchGetRawTxes(mempool, true)
	require.NoError(err)

	// Validate we have the expected number of transactions returned.
	require.Len(newTxes, numTxes)

	// Assert the mock methods are called as expected.
	mockRPC.AssertExpectations(t)
}

// TestBatchGetRawTxesOnShutdown checks that the method returns immediately
// when the mempool is shutting down.
func TestBatchGetRawTxesOnShutdown(t *testing.T) {
	require := require.New(t)

	// Create a mock client and init our mempool.
	mockRPC := &mockRPCClient{}
	m := newMempool(&mempoolConfig{
		client:            mockRPC,
		batchWaitInterval: 0,
		getRawTxBatchSize: 1,
	})

	// Create a normal transaction.
	op1 := wire.OutPoint{Hash: chainhash.Hash{1}}
	tx1 := &wire.MsgTx{
		LockTime: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: op1},
		},
	}
	tx1Hash := tx1.TxHash()

	// Create the current mempool state.
	mempool := []*chainhash.Hash{&tx1Hash}

	// Shutdown the mempool before call the method.
	m.Shutdown()

	// Call the method under test.
	newTxes, err := m.batchGetRawTxes(mempool, true)

	// We expect no error and transactions.
	require.NoError(err)
	require.Empty(newTxes)

	// Assert GetRawTransaction is not called because mempool has quit.
	mockRPC.AssertNotCalled(t, "GetRawTransactionAsync")
	mockRPC.AssertNotCalled(t, "Send")
}

// TestBatchGetRawTxesOnWait checks that the method stays on hold once the
// first batch is finished.
func TestBatchGetRawTxesOnWait(t *testing.T) {
	require := require.New(t)

	const (
		// Define a long wait interval for testing only.
		testWaitInterval = 10 * time.Minute

		// Define a small batch size for testing only.
		testBatchSize = 3

		// Create 4 test transactions so we can hit our batching logic
		// once and then starts waiting.
		numTxes = testBatchSize + 1
	)

	// Create a mock client and init our mempool.
	mockRPC := &mockRPCClient{}
	m := newMempool(&mempoolConfig{
		client:            mockRPC,
		batchWaitInterval: testWaitInterval,
		getRawTxBatchSize: testBatchSize,
	})

	// Create test transactions and mempool state.
	mempool := make([]*chainhash.Hash, 0, numTxes)

	// Create a map of raw tx response receivers, keyed by txid.
	mockTxResponses := make(map[chainhash.Hash]*btcutil.Tx, numTxes)

	// Fill up the slices.
	for i := 0; i < numTxes; i++ {
		// Create testing transactions.
		op := wire.OutPoint{Hash: chainhash.Hash{byte(i)}}
		tx := &wire.MsgTx{
			LockTime: 1,
			TxIn:     []*wire.TxIn{{PreviousOutPoint: op}},
		}

		// Fill the testing mempool.
		txHash := tx.TxHash()
		mempool = append(mempool, &txHash)

		// Add this tx to our mocked responses.
		btcTx := btcutil.NewTx(tx)
		mockTxResponses[txHash] = btcTx
	}

	// Mock GetRawTransactionAsync. We expect it to be called 3 times.
	for i := 0; i < testBatchSize; i++ {
		// Create a testing resposne receiver.
		mockTxReceiver := make(rpcclient.FutureGetRawTransactionResult)

		// Mock `GetRawTransactionAsync` to return the mocked value.
		mockRPC.On("GetRawTransactionAsync",
			mempool[i]).Return(mockTxReceiver).Once()
	}

	// Mock the rawTxReceiver to find and return the tx found in map
	// `mockTxResponses`.
	m.cfg.rawTxReceiver = func(txid chainhash.Hash,
		reciever getRawTxReceiver) *btcutil.Tx {

		btcTx, ok := mockTxResponses[txid]
		require.Truef(ok, "unexpected receiver for %v", txid)

		return btcTx
	}

	// We expect to send the batched requests exactly one time as the
	// second batch will be blocked on the waiting.
	mockRPC.On("Send").Return(nil).Once()

	var (
		err     error
		newTxes []*wire.MsgTx
		done    = make(chan struct{})
	)

	// Call the method under test in a goroutine so we don't need to wait.
	go func() {
		newTxes, err = m.batchGetRawTxes(mempool, true)

		// Signal it's returned.
		close(done)
	}()

	// Sleep one second to allow the mempool moves to the point where the
	// first batch is finished and it's now blocked on the waiting. We then
	// shut down the mempool so batchGetRawTxes will return immediately.
	time.Sleep(1 * time.Second)
	m.Shutdown()

	// Catch the returned values with timeout.
	select {
	case <-done:
		// Assert no error is returned, and we should get a nil slice
		// since mempool is shut down.
		require.NoError(err)
		require.Nil(newTxes)

	case <-time.After(testTimeout):
		require.Fail("timeout waiting for batchGetRawTxes")
	}

	// Assert the mock methods are called as expected.
	mockRPC.AssertExpectations(t)
}

// TestNewMempool tests that `newMempool` behaves as expected.
func TestNewMempool(t *testing.T) {
	// Create a new mempool with an empty config.
	cfg := &mempoolConfig{}
	m := newMempool(cfg)

	// Validate that the mempool is initialized as expected.
	require.Equal(t, cfg, m.cfg)
	require.NotNil(t, m.cfg.rawMempoolGetter)
	require.NotNil(t, m.cfg.rawTxReceiver)
	require.NotNil(t, m.txs)
	require.NotNil(t, m.initFin)
	require.NotNil(t, m.quit)
	require.NotNil(t, m.inputs)

	// Create a new config to check that the mempool is initialized without
	// the `inputs` map when `hasPrevoutRPC` is true.
	cfg = &mempoolConfig{hasPrevoutRPC: true}
	m = newMempool(cfg)

	// Validate that the mempool is initialized as expected.
	require.Equal(t, cfg, m.cfg)
	require.NotNil(t, m.cfg.rawMempoolGetter)
	require.NotNil(t, m.cfg.rawTxReceiver)
	require.NotNil(t, m.txs)
	require.NotNil(t, m.initFin)
	require.NotNil(t, m.quit)
	require.Nil(t, m.inputs)
}

// TestMempoolAddNoInputs adds a coinbase tx, a normal tx, and a replacement tx
// to the mempool and checks the mempool's internal state is updated as
// expected when the `hasPrevoutRPC` is set.
func TestMempoolAddNoInputs(t *testing.T) {
	require := require.New(t)

	m := newMempool(&mempoolConfig{
		batchWaitInterval: 0,
		getRawTxBatchSize: 1,
		hasPrevoutRPC:     true,
	})

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

	// Check inputs are NOT updated here because we don't track them when
	// `hasPrevoutRPC` is true.
	//
	// Mempool should NOT contain op1.
	txid, found := m.containsInput(op1)
	require.False(found)
	require.Empty(txid)

	// Mempool should NOT contain op2.
	txid, found = m.containsInput(op2)
	require.False(found)
	require.Empty(txid)

	// Mempool should NOT contain op3.
	txid, found = m.containsInput(op3)
	require.False(found)
	require.Empty(txid)

	// Check the mempool's internal state.
	//
	// We should see two transactions in the mempool, tx1 and tx2.
	require.Len(m.txs, 2)

	// The mempool's inputs should be nil.
	require.Nil(m.inputs)
}
