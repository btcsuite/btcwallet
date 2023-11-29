package chain

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

const (
	// txNotFoundErr is an error returned from bitcoind's
	// `getrawtransaction` RPC when the requested txid cannot be found.
	// https://github.com/bitcoin/bitcoin/blob/fa05a726c225dc65dee79367bb67f099ae4f99e6/src/rpc/rawtransaction.cpp#L366
	txNotFoundErr = "-5: No such mempool"

	// DefaultGetRawTxBatchSize specifies the default number of requests to
	// be batched before sending them to the bitcoind client.
	DefaultGetRawTxBatchSize = 1000

	// DefaultBatchWaitInterval defines the default time to sleep between
	// each batched calls.
	DefaultBatchWaitInterval = 1 * time.Second
)

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

	// stopped is used to make sure we only stop mempool once.
	stopped sync.Once

	// cfg specifies the config for the mempool.
	cfg *mempoolConfig

	// txs stores the txids in the mempool.
	txs map[chainhash.Hash]bool

	// inputs stores the inputs of the txids in the mempool. This is
	// created for fast lookup.
	//
	// TODO(yy): create similar maps to provide faster lookup for output
	// scripts.
	inputs *cachedInputs

	// initFin is a channel that will be closed once the mempool has been
	// initialized.
	initFin chan struct{}

	// quit is a channel that will be closed when the mempool exits.
	quit chan struct{}
}

// mempoolConfig holds a list of config values specified by the callers.
type mempoolConfig struct {
	// client is the rpc client that we'll use to query for the mempool.
	client batchClient

	// getRawTxBatchSize specifies the number of getrawtransaction requests
	// to be batched before sending them to the bitcoind client.
	getRawTxBatchSize uint32

	// batchWaitInterval defines the default time to sleep between each
	// batched calls.
	batchWaitInterval time.Duration

	// rawMempoolGetter mounts to `m.getRawMempool` and is only changed in
	// unit tests.
	//
	// TODO(yy): interface rpcclient.FutureGetRawMempoolResult so we can
	// remove this hack.
	rawMempoolGetter func() ([]*chainhash.Hash, error)

	// rawTxReceiver mounts to `m.getRawTxIgnoreErr` and is only changed in
	// unit tests.
	//
	// TODO(yy): interface rpcclient.FutureGetRawTransactionResult so we
	// can remove this hack.
	rawTxReceiver func(chainhash.Hash, getRawTxReceiver) *btcutil.Tx

	// hasPrevoutRPC is set when the bitcoind version is >= 24.0.0, in
	// which `gettxspendingprevout` can be used to fetch mempool spent for
	// a given input so there's no need to create the `inputs` map used in
	// `mempool` here.
	hasPrevoutRPC bool
}

// newMempool creates a new mempool object.
func newMempool(cfg *mempoolConfig) *mempool {
	m := &mempool{
		cfg:     cfg,
		txs:     make(map[chainhash.Hash]bool),
		initFin: make(chan struct{}),
		quit:    make(chan struct{}),
	}

	// Init the `inputs` map if the bitcoind version doesn't support
	// `gettxspendingprevout`.
	if !cfg.hasPrevoutRPC {
		m.inputs = newCachedInputs()
	}

	// Mount the default methods.
	m.cfg.rawMempoolGetter = m.getRawMempool
	m.cfg.rawTxReceiver = getRawTxIgnoreErr

	return m
}

// Shutdown signals the mempool to exit.
func (m *mempool) Shutdown() {
	log.Debug("Local mempool shutting down...")
	defer log.Debug("Local mempool shutdown complete")

	m.stopped.Do(func() {
		close(m.quit)
	})
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
	// TODO(yy): port `getprevout` to bitcoind and use it here?
	if m.inputs == nil {
		return chainhash.Hash{}, false
	}

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
	// We won't have the `inputs` map if `hasPrevoutRPC` is true.
	if m.inputs == nil {
		return
	}

	m.inputs.removeInputsFromTx(tx)
}

// updateInputs takes a txid and populates the inputs of the tx into the
// mempool's inputs map.
//
// NOTE: must be used inside a lock.
func (m *mempool) updateInputs(tx *wire.MsgTx) {
	// We won't have the `inputs` map if `hasPrevoutRPC` is true.
	if m.inputs == nil {
		return
	}

	// Iterate the tx's inputs.
	for _, input := range tx.TxIn {
		outpoint := input.PreviousOutPoint

		// Add the input to the cache.
		m.inputs.addInput(outpoint, tx.TxHash())
	}
}

// WaitForInit waits for the mempool to be initialized.
func (m *mempool) WaitForInit() {
	select {
	case <-m.initFin:
	case <-m.quit:
		log.Debugf("Mempool shutting down before init finished")
	}
}

// isShuttingDown returns true if the mempool is shutting down.
func (m *mempool) isShuttingDown() bool {
	select {
	case <-m.quit:
		return true
	default:
		return false
	}
}

// LoadMempool loads all the raw transactions found in mempool.
func (m *mempool) LoadMempool() error {
	log.Debugf("Loading mempool spends...")
	now := time.Now()

	// Fetch the latest mempool.
	txids, err := m.cfg.rawMempoolGetter()
	if err != nil {
		log.Errorf("Unable to get raw mempool txs: %v", err)
		return err
	}

	// Load the mempool in a goroutine and signal it when done.
	go func() {
		_, err := m.batchGetRawTxes(txids, false)
		if err != nil {
			log.Errorf("LoadMempool got error: %v", err)
		}

		log.Debugf("Loaded mempool spends in %v", time.Since(now))
		close(m.initFin)
	}()

	return nil
}

// UpdateMempoolTxes takes a slice of transactions from the current mempool and
// use it to update its internal mempool. It returns a slice of transactions
// that's new to its internal mempool.
func (m *mempool) UpdateMempoolTxes() []*wire.MsgTx {
	// Fetch the latest mempool.
	txids, err := m.cfg.rawMempoolGetter()
	if err != nil {
		log.Errorf("Unable to get raw mempool txs: %v", err)
		return nil
	}

	// Set all mempool txs to false.
	m.UnmarkAll()

	// newTxids stores a list of unseen txids found in the mempool.
	newTxids := make([]*chainhash.Hash, 0)

	// We'll scan through the most recent txs in the mempool to see whether
	// there are new txs that we need to send to the client.
	for _, txHash := range txids {
		txHash := txHash

		// Before we load the tx, we'll check if we're shutting down.
		// If so, we'll exit early.
		if m.isShuttingDown() {
			log.Info("UpdateMempoolTxes exited due to shutdown")

			return nil
		}

		// If the transaction is already in our local mempool, then we
		// have already sent it to the client.
		if m.ContainsTx(*txHash) {
			// Mark the tx as true so that we know not to remove it
			// from our internal mempool.
			m.Mark(*txHash)
			continue
		}

		newTxids = append(newTxids, txHash)
	}

	// Now, we clear our internal mempool of any unmarked transactions.
	// These are all the transactions that we still have in the mempool but
	// that were not returned in the latest GetRawMempool query.
	m.DeleteUnmarked()

	// Fetch the raw transactions in batch.
	txesToNotify, err := m.batchGetRawTxes(newTxids, true)
	if err != nil {
		log.Error("Batch getrawtransaction got %v", err)

	}

	return txesToNotify
}

// getRawMempool returns all the raw transactions found in mempool.
func (m *mempool) getRawMempool() ([]*chainhash.Hash, error) {
	// Create an async request and send it immediately.
	result := m.cfg.client.GetRawMempoolAsync()

	err := m.cfg.client.Send()
	if err != nil {
		log.Errorf("Unable to send GetRawMempool: %v", err)
		return nil, err
	}

	// Receive the response.
	txids, err := result.Receive()
	if err != nil {
		log.Errorf("Unable to get raw mempool txs: %v", err)
		return nil, err
	}

	return txids, nil
}

// batchGetRawTxes makes async GetRawTransaction requests in batches. Each
// batch has either a default size of 10000, or the value specified in
// getRawTxBatchSize. Once a batch is processed, it will wait for
// batchWaitInterval(1s) before attempting the next batch.
func (m *mempool) batchGetRawTxes(txids []*chainhash.Hash,
	returnNew bool) ([]*wire.MsgTx, error) {

	log.Debugf("Batching GetRawTransaction in %v batches...",
		uint32(len(txids))/m.cfg.getRawTxBatchSize+1)
	defer log.Debugf("Finished batch GetRawTransaction")

	// txRecievers defines a map that has the txid as its key and the tx's
	// response reciever as its value.
	type txRecievers map[chainhash.Hash]getRawTxReceiver

	// respReceivers stores a list of response receivers returned from
	// batch calling `GetRawTransactionAsync`.
	respReceivers := make(txRecievers, m.cfg.getRawTxBatchSize)

	// Conditionally init a newTxes slice.
	var newTxes []*wire.MsgTx
	if returnNew {
		newTxes = make([]*wire.MsgTx, 0, len(txids))
	}

	// processBatch asks the batch client to send its cached requests to
	// bitcoind and waits for all the responses to return. Each time a
	// response is received, it will be used to update the local mempool
	// state and conditionally saved to a slice that will be returned.
	processBatch := func(results txRecievers) error {
		// Ask the client to send all the batched requests.
		err := m.cfg.client.Send()
		if err != nil {
			return fmt.Errorf("Send GetRawTransaction got %v", err)
		}

		// Iterate the recievers and fetch the response.
		for txid, resp := range results {
			tx := m.cfg.rawTxReceiver(txid, resp)
			if tx == nil {
				continue
			}

			// Add the transaction to our local mempool.
			m.Add(tx.MsgTx())

			// Add the tx to the slice if specified.
			if returnNew {
				newTxes = append(newTxes, tx.MsgTx())
			}
		}

		return nil
	}

	// Iterate all the txids.
	for i, txHash := range txids {
		// Before we load the tx, we'll check if we're shutting down.
		// If so, we'll exit early.
		if m.isShuttingDown() {
			log.Info("LoadMempool exited due to shutdown")
			return nil, nil
		}

		// Create the async request and save it to txRespReceivers.
		resp := m.cfg.client.GetRawTransactionAsync(txHash)
		respReceivers[*txHash] = resp

		// When getRawTxBatchSize is reached, we'd ask the batch client
		// to send the requests and process the responses.
		if uint32(len(respReceivers))%m.cfg.getRawTxBatchSize == 0 {
			log.Debugf("Processing GetRawTransaction for batch "+
				"%v...", uint32(i)/m.cfg.getRawTxBatchSize)

			if err := processBatch(respReceivers); err != nil {
				return nil, err
			}

			// We now pause the duration defined in
			// `batchWaitInterval` or exit on quit signal.
			select {
			case <-time.After(m.cfg.batchWaitInterval):
			case <-m.quit:
				return nil, nil
			}

			// Empty the slice for next batch iteration.
			respReceivers = make(
				txRecievers, m.cfg.getRawTxBatchSize,
			)
		}
	}

	// Exit early if the receivers are all processed.
	if len(respReceivers) == 0 {
		return newTxes, nil
	}

	// Process the remaining recievers.
	if err := processBatch(respReceivers); err != nil {
		return nil, err
	}

	return newTxes, nil
}

// getRawTxIgnoreErr takes a response receiver returned from
// `GetRawTransactionAsync` and receives the response. It ignores the error
// returned since we can't do anything about it here in the mempool.
//
// NOTE: if `txindex` is not enabled, `GetRawTransactionAsync` will only look
// for the txid in bitcoind's mempool. If the tx is replaced, confirmed, or not
// yet included in bitcoind's mempool, the error txNotFoundErr will be
// returned.
func getRawTxIgnoreErr(txid chainhash.Hash,
	rawTx getRawTxReceiver) *btcutil.Tx {

	tx, err := rawTx.Receive()

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
