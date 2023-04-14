package chain

import (
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// mempool represents our view of the mempool and helps to keep track of which
// mempool transactions we already know about. The boolean in the txs map is
// used to indicate if we should remove the tx from our local mempool due to
// the chain backend's mempool no longer containing it.
type mempool struct {
	sync.RWMutex
	txs map[chainhash.Hash]bool
}

// newMempool creates a new mempool object.
func newMempool() *mempool {
	return &mempool{
		txs: make(map[chainhash.Hash]bool),
	}
}

// clean removes any of the given transactions from the mempool if they are
// found there.
func (m *mempool) clean(txs []*wire.MsgTx) {
	m.Lock()
	defer m.Unlock()

	for _, tx := range txs {
		// If the transaction is in our mempool map, we need to delete
		// it.
		delete(m.txs, tx.TxHash())
	}
}

// contains returns true if the given transaction hash is already in our
// mempool.
func (m *mempool) contains(hash chainhash.Hash) bool {
	m.RLock()
	defer m.RUnlock()

	_, ok := m.txs[hash]
	return ok
}

// add inserts the given hash into our mempool and marks it to indicate that it
// should not be deleted.
func (m *mempool) add(hash chainhash.Hash) {
	m.Lock()
	defer m.Unlock()

	m.txs[hash] = true
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
	}
}
