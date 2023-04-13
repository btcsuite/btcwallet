package chain

import (
	"sync"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// mempool represents our view of the mempool and helps to keep track of which
// mempool transactions we already know about. The boolean in the txs map is
// used to indicate if we should remove the tx from our local mempool due to
// the chain backend's mempool no longer containing it.
type mempool struct {
	sync.RWMutex

	// txs stores the txids in the mempool.
	txs map[chainhash.Hash]bool

	// inputs stores the inputs of the txids in the mempool. This is
	// created for fast lookup.
	//
	// TODO(yy): create similar maps to provide faster lookup for output
	// scripts.
	inputs map[wire.OutPoint]chainhash.Hash
}

// newMempool creates a new mempool object.
func newMempool() *mempool {
	return &mempool{
		txs:    make(map[chainhash.Hash]bool),
		inputs: make(map[wire.OutPoint]chainhash.Hash),
	}
}

// clean removes any of the given transactions from the mempool if they are
// found there.
func (m *mempool) clean(txs []*wire.MsgTx) {
	m.Lock()
	defer m.Unlock()

	for _, tx := range txs {
		txid := tx.TxHash()

		// If the transaction is in our mempool map, we need to delete
		// it.
		delete(m.txs, txid)

		// Remove the inputs stored of this tx.
		m.removeInputs(txid)
	}
}

// containsTx returns true if the given transaction hash is already in our
// mempool.
func (m *mempool) containsTx(hash chainhash.Hash) bool {
	m.RLock()
	defer m.RUnlock()

	_, ok := m.txs[hash]
	return ok
}

// containsInput returns true if the given input is already found spent in our
// mempool.
func (m *mempool) containsInput(op wire.OutPoint) (chainhash.Hash, bool) {
	m.RLock()
	defer m.RUnlock()

	txid, ok := m.inputs[op]
	return txid, ok
}

// add inserts the given hash into our mempool and marks it to indicate that it
// should not be deleted.
func (m *mempool) add(tx *wire.MsgTx) {
	m.Lock()
	defer m.Unlock()

	hash := tx.TxHash()

	// Add the txid to the mempool map.
	m.txs[hash] = true

	// Update the inputs being spent.
	m.updateInputs(tx)
}

// unmarkAll un-marks all the transactions in the mempool. This should be done
// just before we re-evaluate the contents of our local mempool comared to the
// chain backend's mempool.
func (m *mempool) unmarkAll() {
	m.Lock()
	defer m.Unlock()

	for hash := range m.txs {
		m.txs[hash] = false
	}
}

// mark marks the transaction of the given hash to indicate that it is still
// present in the chain backend's mempool.
func (m *mempool) mark(hash chainhash.Hash) {
	m.Lock()
	defer m.Unlock()

	if _, ok := m.txs[hash]; !ok {
		return
	}

	m.txs[hash] = true
}

// deleteUnmarked removes all the unmarked transactions from our local mempool.
func (m *mempool) deleteUnmarked() {
	m.Lock()
	defer m.Unlock()

	for hash, marked := range m.txs {
		if marked {
			continue
		}

		delete(m.txs, hash)

		// Remove the inputs stored of this tx.
		m.removeInputs(hash)
	}
}

// removeInputs takes a txid and removes the inputs of the tx from the
// mempool's inputs map.
//
// NOTE: must be used inside a lock.
//
// TODO(yy): create a txid -> [inputs] map to make this faster.
func (m *mempool) removeInputs(tx chainhash.Hash) {
	for outpoint, txid := range m.inputs {
		if txid.IsEqual(&tx) {
			// NOTE: it's safe to delete while iterating go map.
			delete(m.inputs, outpoint)
		}
	}
}

// updateInputs takes a txid and populates the inputs of the tx into the
// mempool's inputs map.
//
// NOTE: must be used inside a lock.
func (m *mempool) updateInputs(tx *wire.MsgTx) {
	// Skip coinbase inputs.
	if blockchain.IsCoinBaseTx(tx) {
		log.Debugf("Skipping coinbase tx %v", tx.TxHash())
		return
	}

	// Iterate the tx's inputs.
	for _, input := range tx.TxIn {
		outpoint := input.PreviousOutPoint

		// Check whether this input has been spent in an old tx.
		oldTxid, ok := m.inputs[outpoint]

		// If not, add it to the map and continue.
		if !ok {
			m.inputs[outpoint] = tx.TxHash()
			continue
		}

		log.Tracef("Input %s was spent in tx %s, now spent in %s",
			outpoint, oldTxid, tx.TxHash())

		// If the input has been spent in an old tx, we need to
		// overwrite it.
		m.inputs[outpoint] = tx.TxHash()
	}
}
