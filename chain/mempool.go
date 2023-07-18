package chain

import (
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"golang.org/x/sync/errgroup"
)

// txNotFoundErr is an error returned from bitcoind's `getrawtransaction` RPC
// when the requested txid cannot be found.
const txNotFoundErr = "-5: No such mempool or blockchain transaction"

// cachedInputs caches the inputs of the transactions in the mempool. This is
// used to provide fast lookup between txids and inputs.
type cachedInputs struct {
	// inputs provides a fast lookup from input -> txid.
	inputs map[wire.OutPoint]chainhash.Hash

	// txids provides a fast lookup from txid -> inputs.
	txids map[chainhash.Hash]map[wire.OutPoint]struct{}
}

// newCachedInputs creates a new cachedInputs.
func newCachedInputs() *cachedInputs {
	return &cachedInputs{
		inputs: make(map[wire.OutPoint]chainhash.Hash),
		txids:  make(map[chainhash.Hash]map[wire.OutPoint]struct{}),
	}
}

// hasInput returns the txid and a boolean to indicate the given input is
// found.
func (c *cachedInputs) hasInput(op wire.OutPoint) (chainhash.Hash, bool) {
	txid, ok := c.inputs[op]
	return txid, ok
}

// addInput adds the given input to our cached inputs. If the input already
// exists, the `inputs` map will be overwritten and the `txids` map will be
// updated.
func (c *cachedInputs) addInput(op wire.OutPoint, txid chainhash.Hash) {
	// Init the map for this txid if it doesn't exist.
	if _, ok := c.txids[txid]; !ok {
		c.txids[txid] = make(map[wire.OutPoint]struct{})
	}

	// Add the input under this txid.
	c.txids[txid][op] = struct{}{}

	// Check if the input already exists.
	oldTxid, existed := c.inputs[op]

	// If the oldTxid exists and is different from the current txid, we
	// need to update the oldTxid's inputs map.
	isReplacement := false
	if existed && oldTxid != txid {
		isReplacement = true
	}

	// If the input is replaced, update the old txid to remove the input.
	if isReplacement {
		log.Tracef("Input %s was spent in tx %s, now spent in %s",
			op, oldTxid, txid)

		// Delete the input from the nested map under this old tx.
		delete(c.txids[oldTxid], op)
	}

	// Add the input to the inputs map with the new txid.
	c.inputs[op] = txid
}

// removeInputsFromTx removes the inputs of the given txid from our cached
// inputs maps.
func (c *cachedInputs) removeInputsFromTx(txid chainhash.Hash) {
	// Remove the inputs stored of this tx.
	for op := range c.txids[txid] {
		delete(c.inputs, op)
	}

	delete(c.txids, txid)
}

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
	inputs *cachedInputs

	// client is the rpc client that we'll use to query for the mempool.
	client rpcClient

	// initFin is a channel that will be closed once the mempool has been
	// initialized.
	initFin chan struct{}
}

// newMempool creates a new mempool object.
func newMempool(client rpcClient) *mempool {
	return &mempool{
		txs:     make(map[chainhash.Hash]bool),
		inputs:  newCachedInputs(),
		initFin: make(chan struct{}),
		client:  client,
	}
}

// Clean removes any of the given transactions from the mempool if they are
// found there.
func (m *mempool) Clean(txs []*wire.MsgTx) {
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

// Add inserts the given hash into our mempool and marks it to indicate that it
// should not be deleted.
func (m *mempool) Add(tx *wire.MsgTx) {
	m.Lock()
	defer m.Unlock()

	m.add(tx)
}

// ContainsTx returns true if the given transaction hash is already in our
// mempool.
//
// NOTE: must be used inside a lock.
func (m *mempool) ContainsTx(hash chainhash.Hash) bool {
	m.Lock()
	defer m.Unlock()

	return m.containsTx(hash)
}

// containsTx returns true if the given transaction hash is already in our
// mempool.
//
// NOTE: must be used inside a lock.
func (m *mempool) containsTx(hash chainhash.Hash) bool {
	_, ok := m.txs[hash]
	return ok
}

// containsInput returns true if the given input is already found spent in our
// mempool.
//
// NOTE: must be used inside a lock.
func (m *mempool) containsInput(op wire.OutPoint) (chainhash.Hash, bool) {
	return m.inputs.hasInput(op)
}

// add inserts the given hash into our mempool and marks it to indicate that it
// should not be deleted.
//
// NOTE: must be used inside a lock.
func (m *mempool) add(tx *wire.MsgTx) {
	// Skip coinbase inputs.
	if blockchain.IsCoinBaseTx(tx) {
		log.Debugf("Skipping coinbase tx %v", tx.TxHash())
		return
	}

	hash := tx.TxHash()

	// Add the txid to the mempool map.
	m.txs[hash] = true

	// Update the inputs being spent.
	m.updateInputs(tx)
}

// UnmarkAll un-marks all the transactions in the mempool. This should be done
// just before we re-evaluate the contents of our local mempool compared to the
// chain backend's mempool.
func (m *mempool) UnmarkAll() {
	m.Lock()
	defer m.Unlock()

	m.unmarkAll()
}

// unmarkAll un-marks all the transactions in the mempool. This should be done
// just before we re-evaluate the contents of our local mempool compared to the
// chain backend's mempool.
//
// NOTE: must be used inside a lock.
func (m *mempool) unmarkAll() {
	for hash := range m.txs {
		m.txs[hash] = false
	}
}

// Mark marks the transaction of the given hash to indicate that it is still
// present in the chain backend's mempool.
func (m *mempool) Mark(hash chainhash.Hash) {
	m.Lock()
	defer m.Unlock()

	m.mark(hash)
}

// mark marks the transaction of the given hash to indicate that it is still
// present in the chain backend's mempool.
//
// NOTE: must be used inside a lock.
func (m *mempool) mark(hash chainhash.Hash) {
	if _, ok := m.txs[hash]; !ok {
		return
	}

	m.txs[hash] = true
}

// DeleteUnmarked removes all the unmarked transactions from our local mempool.
//
// NOTE: must be used inside a lock.
func (m *mempool) DeleteUnmarked() {
	m.Lock()
	defer m.Unlock()

	m.deleteUnmarked()
}

// deleteUnmarked removes all the unmarked transactions from our local mempool.
//
// NOTE: must be used inside a lock.
func (m *mempool) deleteUnmarked() {
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
func (m *mempool) removeInputs(tx chainhash.Hash) {
	m.inputs.removeInputsFromTx(tx)
}

// updateInputs takes a txid and populates the inputs of the tx into the
// mempool's inputs map.
//
// NOTE: must be used inside a lock.
func (m *mempool) updateInputs(tx *wire.MsgTx) {
	// Iterate the tx's inputs.
	for _, input := range tx.TxIn {
		outpoint := input.PreviousOutPoint

		// Add the input to the cache.
		m.inputs.addInput(outpoint, tx.TxHash())
	}
}

// WaitForInit waits for the mempool to be initialized.
func (m *mempool) WaitForInit() {
	<-m.initFin
}

// LoadMempool loads all the raw transactions found in mempool.
func (m *mempool) LoadMempool() error {
	log.Debugf("Loading mempool spends...")

	now := time.Now()

	txs, err := m.client.GetRawMempool()
	if err != nil {
		log.Errorf("Unable to get raw mempool txs: %v", err)
		return err
	}

	go func() {
		var eg errgroup.Group
		eg.SetLimit(runtime.NumCPU())

		for _, txHash := range txs {
			txHash := txHash

			eg.Go(func() error {
				// Grab full mempool transaction from hash.
				tx := m.getRawTxIgnoreErr(txHash)
				if tx == nil {
					return nil
				}

				// Add the transaction to our local mempool.
				m.Add(tx.MsgTx())
				return nil
			})
		}

		_ = eg.Wait()

		log.Debugf("Loaded mempool spends in %v", time.Since(now))

		close(m.initFin)

	}()

	return nil
}

// UpdateMempoolTxes takes a slice of transactions from the current mempool and
// use it to update its internal mempool. It returns a slice of transactions
// that's new to its internal mempool.
func (m *mempool) UpdateMempoolTxes(txids []*chainhash.Hash) []*wire.MsgTx {
	// txesToNotify is a list of txes to be notified to the client.
	var notixyMx sync.Mutex
	txesToNotify := make([]*wire.MsgTx, 0, len(txids))

	// Set all mempool txs to false.
	m.UnmarkAll()

	var eg errgroup.Group
	eg.SetLimit(runtime.NumCPU())

	// We'll scan through the most recent txs in the mempool to see whether
	// there are new txs that we need to send to the client.
	for _, txHash := range txids {
		txHash := txHash

		// If the transaction is already in our local mempool, then we
		// have already sent it to the client.
		if m.ContainsTx(*txHash) {
			// Mark the tx as true so that we know not to remove it
			// from our internal mempool.
			m.Mark(*txHash)
			continue
		}

		eg.Go(func() error {
			// Grab full mempool transaction from hash.
			tx := m.getRawTxIgnoreErr(txHash)
			if tx == nil {
				return nil
			}

			// Add the transaction to our local mempool. Note that
			// we only do this after fetching the full raw
			// transaction from bitcoind. We do this so that if
			// that call happens to initially fail, then we will
			// retry it on the next interval since it is still not
			// in our local mempool.
			m.Add(tx.MsgTx())

			// Save the tx to the slice.
			notixyMx.Lock()
			txesToNotify = append(txesToNotify, tx.MsgTx())
			notixyMx.Unlock()

			return nil
		})
	}

	_ = eg.Wait()

	// Now, we clear our internal mempool of any unmarked transactions.
	// These are all the transactions that we still have in the mempool but
	// that were not returned in the latest GetRawMempool query.
	m.DeleteUnmarked()

	return txesToNotify
}

// getRawTxIgnoreErr wraps the GetRawTransaction call to bitcoind, and ignores
// the error returned since we can't do anything about it here in the mempool.
//
// NOTE: if `txindex` is not enabled, `GetRawTransaction` will only look for
// the txid in bitocind's mempool. If the tx is replaced, confirmed, or not yet
// included in bitcoind's mempool, the error txNotFoundErr will be returned.
func (m *mempool) getRawTxIgnoreErr(txid *chainhash.Hash) *btcutil.Tx {
	tx, err := m.client.GetRawTransaction(txid)

	// Exit early if there's no error.
	if err == nil {
		return tx
	}

	// If this is the txNotFoundErr, we'll create a debug log.
	errStr := strings.ToLower(err.Error())
	errExp := strings.ToLower(txNotFoundErr)
	if strings.Contains(errStr, errExp) {
		log.Debugf("unable to fetch transaction %s from mempool: %v",
			txid, err)

	} else {
		// Otherwise, unexpected error is found, we'll create an error
		// log.
		log.Errorf("unable to fetch transaction %s from mempool: %v",
			txid, err)
	}

	return nil
}
