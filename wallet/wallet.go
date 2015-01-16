/*
 * Copyright (c) 2013, 2014 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package wallet

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/legacy/txstore"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

const (
	walletDbWatchingOnlyName = "wowallet.db"
)

// ErrNotSynced describes an error where an operation cannot complete
// due wallet being out of sync (and perhaps currently syncing with)
// the remote chain server.
var ErrNotSynced = errors.New("wallet is not synchronized with the chain server")

var (
	// waddrmgrNamespaceKey is the namespace key for the waddrmgr package.
	waddrmgrNamespaceKey = []byte("waddrmgr")
)

type noopLocker struct{}

func (noopLocker) Lock()   {}
func (noopLocker) Unlock() {}

// Wallet is a structure containing all the components for a
// complete wallet.  It contains the Armory-style key store
// addresses and keys),
type Wallet struct {
	// Data stores
	db      walletdb.DB
	Manager *waddrmgr.Manager
	TxStore *txstore.Store

	chainSvr        *chain.Client
	chainSvrLock    sync.Locker
	chainSvrSynced  bool
	chainSvrSyncMtx sync.Mutex

	lockedOutpoints map[wire.OutPoint]struct{}
	FeeIncrement    btcutil.Amount
	DisallowFree    bool

	// Channels for rescan processing.  Requests are added and merged with
	// any waiting requests, before being sent to another goroutine to
	// call the rescan RPC.
	rescanAddJob        chan *RescanJob
	rescanBatch         chan *rescanBatch
	rescanNotifications chan interface{} // From chain server
	rescanProgress      chan *RescanProgressMsg
	rescanFinished      chan *RescanFinishedMsg

	// Channel for transaction creation requests.
	createTxRequests chan createTxRequest

	// Channels for the manager locker.
	unlockRequests     chan unlockRequest
	lockRequests       chan struct{}
	holdUnlockRequests chan chan HeldUnlock
	lockState          chan bool
	changePassphrase   chan changePassphraseRequest

	// Notification channels so other components can listen in on wallet
	// activity.  These are initialized as nil, and must be created by
	// calling one of the Listen* methods.
	connectedBlocks    chan waddrmgr.BlockStamp
	disconnectedBlocks chan waddrmgr.BlockStamp
	lockStateChanges   chan bool // true when locked
	confirmedBalance   chan btcutil.Amount
	unconfirmedBalance chan btcutil.Amount
	notificationLock   sync.Locker

	chainParams *chaincfg.Params
	Config      *Config
	wg          sync.WaitGroup
	quit        chan struct{}
}

// newWallet creates a new Wallet structure with the provided address manager
// and transaction store.
func newWallet(mgr *waddrmgr.Manager, txs *txstore.Store, db *walletdb.DB) *Wallet {
	return &Wallet{
		db:                  *db,
		Manager:             mgr,
		TxStore:             txs,
		chainSvrLock:        new(sync.Mutex),
		lockedOutpoints:     map[wire.OutPoint]struct{}{},
		FeeIncrement:        defaultFeeIncrement,
		rescanAddJob:        make(chan *RescanJob),
		rescanBatch:         make(chan *rescanBatch),
		rescanNotifications: make(chan interface{}),
		rescanProgress:      make(chan *RescanProgressMsg),
		rescanFinished:      make(chan *RescanFinishedMsg),
		createTxRequests:    make(chan createTxRequest),
		unlockRequests:      make(chan unlockRequest),
		lockRequests:        make(chan struct{}),
		holdUnlockRequests:  make(chan chan HeldUnlock),
		lockState:           make(chan bool),
		changePassphrase:    make(chan changePassphraseRequest),
		notificationLock:    new(sync.Mutex),
		quit:                make(chan struct{}),
	}
}

// ErrDuplicateListen is returned for any attempts to listen for the same
// notification more than once.  If callers must pass along a notifiation to
// multiple places, they must broadcast it themself.
var ErrDuplicateListen = errors.New("duplicate listen")

func (w *Wallet) updateNotificationLock() {
	switch {
	case w.connectedBlocks == nil:
		fallthrough
	case w.disconnectedBlocks == nil:
		fallthrough
	case w.lockStateChanges == nil:
		fallthrough
	case w.confirmedBalance == nil:
		fallthrough
	case w.unconfirmedBalance == nil:
		return
	}
	w.notificationLock = noopLocker{}
}

// CreditAccount returns the first account that can be associated
// with the given credit.
// If no account is found, ErrAccountNotFound is returned.
func (w *Wallet) CreditAccount(c txstore.Credit) (uint32, error) {
	_, addrs, _, _ := c.Addresses(w.chainParams)
	addr := addrs[0]
	return w.Manager.AddrAccount(addr)
}

// ListenConnectedBlocks returns a channel that passes all blocks that a wallet
// has been marked in sync with. The channel must be read, or other wallet
// methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenConnectedBlocks() (<-chan waddrmgr.BlockStamp, error) {
	w.notificationLock.Lock()
	defer w.notificationLock.Unlock()

	if w.connectedBlocks != nil {
		return nil, ErrDuplicateListen
	}
	w.connectedBlocks = make(chan waddrmgr.BlockStamp)
	w.updateNotificationLock()
	return w.connectedBlocks, nil
}

// ListenDisconnectedBlocks returns a channel that passes all blocks that a
// wallet has detached.  The channel must be read, or other wallet methods will
// block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenDisconnectedBlocks() (<-chan waddrmgr.BlockStamp, error) {
	w.notificationLock.Lock()
	defer w.notificationLock.Unlock()

	if w.disconnectedBlocks != nil {
		return nil, ErrDuplicateListen
	}
	w.disconnectedBlocks = make(chan waddrmgr.BlockStamp)
	w.updateNotificationLock()
	return w.disconnectedBlocks, nil
}

// ListenLockStatus returns a channel that passes the current lock state
// of the wallet whenever the lock state is changed.  The value is true for
// locked, and false for unlocked.  The channel must be read, or other wallet
// methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenLockStatus() (<-chan bool, error) {
	w.notificationLock.Lock()
	defer w.notificationLock.Unlock()

	if w.lockStateChanges != nil {
		return nil, ErrDuplicateListen
	}
	w.lockStateChanges = make(chan bool)
	w.updateNotificationLock()
	return w.lockStateChanges, nil
}

// ListenConfirmedBalance returns a channel that passes the confirmed balance
// when any changes to the balance are made.  This channel must be read, or
// other wallet methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenConfirmedBalance() (<-chan btcutil.Amount, error) {
	w.notificationLock.Lock()
	defer w.notificationLock.Unlock()

	if w.confirmedBalance != nil {
		return nil, ErrDuplicateListen
	}
	w.confirmedBalance = make(chan btcutil.Amount)
	w.updateNotificationLock()
	return w.confirmedBalance, nil
}

// ListenUnconfirmedBalance returns a channel that passes the unconfirmed
// balance when any changes to the balance are made.  This channel must be
// read, or other wallet methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenUnconfirmedBalance() (<-chan btcutil.Amount, error) {
	w.notificationLock.Lock()
	defer w.notificationLock.Unlock()

	if w.unconfirmedBalance != nil {
		return nil, ErrDuplicateListen
	}
	w.unconfirmedBalance = make(chan btcutil.Amount)
	w.updateNotificationLock()
	return w.unconfirmedBalance, nil
}

// markAddrsUsed marks the addresses credited by the given transaction
// record as used.
func (w *Wallet) markAddrsUsed(t *txstore.TxRecord) error {
	for _, c := range t.Credits() {
		// Errors don't matter here.  If addrs is nil, the
		// range below does nothing.
		_, addrs, _, _ := c.Addresses(w.chainParams)
		for _, addr := range addrs {
			if err := w.Manager.MarkUsed(addr); err != nil {
				return err
			}
			log.Infof("Marked address used %s", addr.EncodeAddress())
		}
	}
	return nil
}

func (w *Wallet) notifyConnectedBlock(block waddrmgr.BlockStamp) {
	w.notificationLock.Lock()
	if w.connectedBlocks != nil {
		w.connectedBlocks <- block
	}
	w.notificationLock.Unlock()
}

func (w *Wallet) notifyDisconnectedBlock(block waddrmgr.BlockStamp) {
	w.notificationLock.Lock()
	if w.disconnectedBlocks != nil {
		w.disconnectedBlocks <- block
	}
	w.notificationLock.Unlock()
}

func (w *Wallet) notifyLockStateChange(locked bool) {
	w.notificationLock.Lock()
	if w.lockStateChanges != nil {
		w.lockStateChanges <- locked
	}
	w.notificationLock.Unlock()
}

func (w *Wallet) notifyConfirmedBalance(bal btcutil.Amount) {
	w.notificationLock.Lock()
	if w.confirmedBalance != nil {
		w.confirmedBalance <- bal
	}
	w.notificationLock.Unlock()
}

func (w *Wallet) notifyUnconfirmedBalance(bal btcutil.Amount) {
	w.notificationLock.Lock()
	if w.unconfirmedBalance != nil {
		w.unconfirmedBalance <- bal
	}
	w.notificationLock.Unlock()
}

// Start starts the goroutines necessary to manage a wallet.
func (w *Wallet) Start(chainServer *chain.Client) {
	select {
	case <-w.quit:
		return
	default:
	}

	w.chainSvrLock.Lock()
	defer w.chainSvrLock.Unlock()

	w.chainSvr = chainServer
	w.chainSvrLock = noopLocker{}

	w.wg.Add(7)
	go w.diskWriter()
	go w.handleChainNotifications()
	go w.txCreator()
	go w.walletLocker()
	go w.rescanBatchHandler()
	go w.rescanProgressHandler()
	go w.rescanRPCHandler()
}

// Stop signals all wallet goroutines to shutdown.
func (w *Wallet) Stop() {
	select {
	case <-w.quit:
	default:
		close(w.quit)
		w.chainSvrLock.Lock()
		if w.chainSvr != nil {
			w.chainSvr.Stop()
		}
		w.chainSvrLock.Unlock()
	}
}

// ShuttingDown returns whether the wallet is currently in the process of
// shutting down or not.
func (w *Wallet) ShuttingDown() bool {
	select {
	case <-w.quit:
		return true
	default:
		return false
	}
}

// WaitForShutdown blocks until all wallet goroutines have finished executing.
func (w *Wallet) WaitForShutdown() {
	w.chainSvrLock.Lock()
	if w.chainSvr != nil {
		w.chainSvr.WaitForShutdown()
	}
	w.chainSvrLock.Unlock()
	w.wg.Wait()
}

// ChainSynced returns whether the wallet has been attached to a chain server
// and synced up to the best block on the main chain.
func (w *Wallet) ChainSynced() bool {
	w.chainSvrSyncMtx.Lock()
	synced := w.chainSvrSynced
	w.chainSvrSyncMtx.Unlock()
	return synced
}

// SetChainSynced marks whether the wallet is connected to and currently in sync
// with the latest block notified by the chain server.
//
// NOTE: Due to an API limitation with btcrpcclient, this may return true after
// the client disconnected (and is attempting a reconnect).  This will be unknown
// until the reconnect notification is received, at which point the wallet can be
// marked out of sync again until after the next rescan completes.
func (w *Wallet) SetChainSynced(synced bool) {
	w.chainSvrSyncMtx.Lock()
	w.chainSvrSynced = synced
	w.chainSvrSyncMtx.Unlock()
}

// activeData returns the currently-active receiving addresses and all unspent
// outputs.  This is primarely intended to provide the parameters for a
// rescan request.
func (w *Wallet) activeData() ([]btcutil.Address, []txstore.Credit, error) {
	addrs, err := w.Manager.AllActiveAddresses()
	if err != nil {
		return nil, nil, err
	}
	unspent, err := w.TxStore.UnspentOutputs()
	return addrs, unspent, err
}

// syncWithChain brings the wallet up to date with the current chain server
// connection.  It creates a rescan request and blocks until the rescan has
// finished.
//
func (w *Wallet) syncWithChain() error {
	// Request notifications for connected and disconnected blocks.
	//
	// TODO(jrick): Either request this notification only once, or when
	// btcrpcclient is modified to allow some notification request to not
	// automatically resent on reconnect, include the notifyblocks request
	// as well.  I am leaning towards allowing off all btcrpcclient
	// notification re-registrations, in which case the code here should be
	// left as is.
	err := w.chainSvr.NotifyBlocks()
	if err != nil {
		return err
	}

	// Request notifications for transactions sending to all wallet
	// addresses.
	addrs, unspent, err := w.activeData()
	if err != nil {
		return err
	}

	// TODO(jrick): How should this handle a synced height earlier than
	// the chain server best block?

	// Check that there was not any reorgs done since last connection.
	// If so, rollback and rescan to catch up.
	iter := w.Manager.NewIterateRecentBlocks()
	for cont := iter != nil; cont; cont = iter.Prev() {
		bs := iter.BlockStamp()
		log.Debugf("Checking for previous saved block with height %v hash %v",
			bs.Height, bs.Hash)
		_, err = w.chainSvr.GetBlock(&bs.Hash)
		if err != nil {
			continue
		}

		log.Debug("Found matching block.")

		// If we had to go back to any previous blocks (iter.Next
		// returns true), then rollback the next and all child blocks.
		if iter.Next() {
			bs := iter.BlockStamp()
			w.Manager.SetSyncedTo(&bs)
			err = w.TxStore.Rollback(bs.Height)
			if err != nil {
				return err
			}
			w.TxStore.MarkDirty()
		}

		break
	}

	return w.Rescan(addrs, unspent)
}

type (
	createTxRequest struct {
		account uint32
		pairs   map[string]btcutil.Amount
		minconf int
		resp    chan createTxResponse
	}
	createTxResponse struct {
		tx  *CreatedTx
		err error
	}
)

// txCreator is responsible for the input selection and creation of
// transactions.  These functions are the responsibility of this method
// (designed to be run as its own goroutine) since input selection must be
// serialized, or else it is possible to create double spends by choosing the
// same inputs for multiple transactions.  Along with input selection, this
// method is also responsible for the signing of transactions, since we don't
// want to end up in a situation where we run out of inputs as multiple
// transactions are being created.  In this situation, it would then be possible
// for both requests, rather than just one, to fail due to not enough available
// inputs.
func (w *Wallet) txCreator() {
out:
	for {
		select {
		case txr := <-w.createTxRequests:
			tx, err := w.txToPairs(txr.pairs, txr.account, txr.minconf)
			txr.resp <- createTxResponse{tx, err}

		case <-w.quit:
			break out
		}
	}
	w.wg.Done()
}

// CreateSimpleTx creates a new signed transaction spending unspent P2PKH
// outputs with at laest minconf confirmations spending to any number of
// address/amount pairs.  Change and an appropiate transaction fee are
// automatically included, if necessary.  All transaction creation through
// this function is serialized to prevent the creation of many transactions
// which spend the same outputs.
func (w *Wallet) CreateSimpleTx(account uint32, pairs map[string]btcutil.Amount,
	minconf int) (*CreatedTx, error) {

	req := createTxRequest{
		account: account,
		pairs:   pairs,
		minconf: minconf,
		resp:    make(chan createTxResponse),
	}
	w.createTxRequests <- req
	resp := <-req.resp
	return resp.tx, resp.err
}

type (
	unlockRequest struct {
		passphrase []byte
		timeout    time.Duration // Zero value prevents the timeout.
		err        chan error
	}

	changePassphraseRequest struct {
		old, new []byte
		err      chan error
	}

	// HeldUnlock is a tool to prevent the wallet from automatically
	// locking after some timeout before an operation which needed
	// the unlocked wallet has finished.  Any aquired HeldUnlock
	// *must* be released (preferably with a defer) or the wallet
	// will forever remain unlocked.
	HeldUnlock chan struct{}
)

// walletLocker manages the locked/unlocked state of a wallet.
func (w *Wallet) walletLocker() {
	var timeout <-chan time.Time
	holdChan := make(HeldUnlock)
out:
	for {
		select {
		case req := <-w.unlockRequests:
			err := w.Manager.Unlock(req.passphrase)
			if err != nil {
				req.err <- err
				continue
			}
			w.notifyLockStateChange(false)
			if req.timeout == 0 {
				timeout = nil
			} else {
				timeout = time.After(req.timeout)
			}
			req.err <- nil
			continue

		case req := <-w.changePassphrase:
			err := w.Manager.ChangePassphrase(req.old, req.new, true)
			req.err <- err
			continue

		case req := <-w.holdUnlockRequests:
			if w.Manager.IsLocked() {
				close(req)
				continue
			}

			req <- holdChan
			<-holdChan // Block until the lock is released.

			// If, after holding onto the unlocked wallet for some
			// time, the timeout has expired, lock it now instead
			// of hoping it gets unlocked next time the top level
			// select runs.
			select {
			case <-timeout:
				// Let the top level select fallthrough so the
				// wallet is locked.
			default:
				continue
			}

		case w.lockState <- w.Manager.IsLocked():
			continue

		case <-w.quit:
			break out

		case <-w.lockRequests:
		case <-timeout:
		}

		// Select statement fell through by an explicit lock or the
		// timer expiring.  Lock the manager here.
		timeout = nil
		err := w.Manager.Lock()
		if err != nil {
			log.Errorf("Could not lock wallet: %v", err)
		} else {
			w.notifyLockStateChange(true)
		}
	}
	w.wg.Done()
}

// Unlock unlocks the wallet's address manager and relocks it after timeout has
// expired.  If the wallet is already unlocked and the new passphrase is
// correct, the current timeout is replaced with the new one.  The wallet will
// be locked if the passphrase is incorrect or any other error occurs during the
// unlock.
func (w *Wallet) Unlock(passphrase []byte, timeout time.Duration) error {
	err := make(chan error, 1)
	w.unlockRequests <- unlockRequest{
		passphrase: passphrase,
		timeout:    timeout,
		err:        err,
	}
	return <-err
}

// Lock locks the wallet's address manager.
func (w *Wallet) Lock() {
	w.lockRequests <- struct{}{}
}

// Locked returns whether the account manager for a wallet is locked.
func (w *Wallet) Locked() bool {
	return <-w.lockState
}

// HoldUnlock prevents the wallet from being locked.  The HeldUnlock object
// *must* be released, or the wallet will forever remain unlocked.
//
// TODO: To prevent the above scenario, perhaps closures should be passed
// to the walletLocker goroutine and disallow callers from explicitly
// handling the locking mechanism.
func (w *Wallet) HoldUnlock() (HeldUnlock, error) {
	req := make(chan HeldUnlock)
	w.holdUnlockRequests <- req
	hl, ok := <-req
	if !ok {
		// TODO(davec): This should be defined and exported from
		// waddrmgr.
		return nil, waddrmgr.ManagerError{
			ErrorCode:   waddrmgr.ErrLocked,
			Description: "address manager is locked",
		}
	}
	return hl, nil
}

// Release releases the hold on the unlocked-state of the wallet and allows the
// wallet to be locked again.  If a lock timeout has already expired, the
// wallet is locked again as soon as Release is called.
func (c HeldUnlock) Release() {
	c <- struct{}{}
}

// ChangePassphrase attempts to change the passphrase for a wallet from old
// to new.  Changing the passphrase is synchronized with all other address
// manager locking and unlocking.  The lock state will be the same as it was
// before the password change.
func (w *Wallet) ChangePassphrase(old, new []byte) error {
	err := make(chan error, 1)
	w.changePassphrase <- changePassphraseRequest{
		old: old,
		new: new,
		err: err,
	}
	return <-err
}

// diskWriter periodically (every 10 seconds) writes out the transaction store
// to disk if it is marked dirty.
func (w *Wallet) diskWriter() {
	ticker := time.NewTicker(10 * time.Second)
	var wg sync.WaitGroup
	var done bool

	for {
		select {
		case <-ticker.C:
		case <-w.quit:
			done = true
		}

		log.Trace("Writing txstore")

		wg.Add(1)
		go func() {
			err := w.TxStore.WriteIfDirty()
			if err != nil {
				log.Errorf("Cannot write txstore: %v",
					err)
			}
			wg.Done()
		}()
		wg.Wait()

		if done {
			break
		}
	}
	w.wg.Done()
}

// AccountUsed returns whether there are any recorded transactions spending to
// a given account. It returns true if atleast one address in the account was
// used and false if no address in the account was used.
func (w *Wallet) AccountUsed(account uint32) (bool, error) {
	addrs, err := w.Manager.AllAccountAddresses(account)
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		used, err := addr.Used()
		if err != nil {
			return false, err
		}
		if used {
			return true, nil
		}
	}
	return false, nil
}

// CalculateBalance sums the amounts of all unspent transaction
// outputs to addresses of a wallet and returns the balance.
//
// If confirmations is 0, all UTXOs, even those not present in a
// block (height -1), will be used to get the balance.  Otherwise,
// a UTXO must be in a block.  If confirmations is 1 or greater,
// the balance will be calculated based on how many how many blocks
// include a UTXO.
func (w *Wallet) CalculateBalance(confirms int) (btcutil.Amount, error) {
	blk := w.Manager.SyncedTo()
	return w.TxStore.Balance(confirms, blk.Height)
}

// CalculateAccountBalance sums the amounts of all unspent transaction
// outputs to the given account of a wallet and returns the balance.
func (w *Wallet) CalculateAccountBalance(account uint32, confirms int) (btcutil.Amount, error) {
	var bal btcutil.Amount

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	blk := w.Manager.SyncedTo()

	unspent, err := w.TxStore.UnspentOutputs()
	if err != nil {
		return 0, err
	}
	for _, c := range unspent {
		if c.IsCoinbase() {
			if !c.Confirmed(blockchain.CoinbaseMaturity, blk.Height) {
				continue
			}
		}
		if c.Confirmed(confirms, blk.Height) {
			creditAccount, err := w.CreditAccount(c)
			if err != nil {
				continue
			}
			if creditAccount == account {
				bal += c.Amount()
			}
		}
	}
	return bal, nil
}

// CurrentAddress gets the most recently requested Bitcoin payment address
// from a wallet.  If the address has already been used (there is at least
// one transaction spending to it in the blockchain or btcd mempool), the next
// chained address is returned.
func (w *Wallet) CurrentAddress(account uint32) (btcutil.Address, error) {
	addr, err := w.Manager.LastExternalAddress(account)
	if err != nil {
		// If no address exists yet, create the first external address
		merr, ok := err.(waddrmgr.ManagerError)
		if ok && merr.ErrorCode == waddrmgr.ErrAddressNotFound {
			return w.NewAddress(account)
		}
		return nil, err
	}

	// Get next chained address if the last one has already been used.
	used, err := addr.Used()
	if err != nil {
		return nil, err
	}
	if used {
		return w.NewAddress(account)
	}

	return addr.Address(), nil
}

// ListSinceBlock returns a slice of objects with details about transactions
// since the given block. If the block is -1 then all transactions are included.
// This is intended to be used for listsinceblock RPC replies.
func (w *Wallet) ListSinceBlock(since, curBlockHeight int32,
	minconf int) ([]btcjson.ListTransactionsResult, error) {

	txList := []btcjson.ListTransactionsResult{}
	for _, txRecord := range w.TxStore.Records() {
		// Transaction records must only be considered if they occur
		// after the block height since.
		if since != -1 && txRecord.BlockHeight <= since {
			continue
		}

		// Transactions that have not met minconf confirmations are to
		// be ignored.
		if !txRecord.Confirmed(minconf, curBlockHeight) {
			continue
		}

		jsonResults, err := txRecord.ToJSON(waddrmgr.DefaultAccountName, curBlockHeight,
			w.Manager.ChainParams())
		if err != nil {
			return nil, err
		}
		txList = append(txList, jsonResults...)
	}

	return txList, nil
}

// ListTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listtransactions RPC
// replies.
func (w *Wallet) ListTransactions(from, count int) ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	blk := w.Manager.SyncedTo()

	records := w.TxStore.Records()
	lastLookupIdx := len(records) - count
	// Search in reverse order: lookup most recently-added first.
	for i := len(records) - 1; i >= from && i >= lastLookupIdx; i-- {
		jsonResults, err := records[i].ToJSON(waddrmgr.DefaultAccountName, blk.Height,
			w.Manager.ChainParams())
		if err != nil {
			return nil, err
		}
		txList = append(txList, jsonResults...)
	}

	return txList, nil
}

// ListAddressTransactions returns a slice of objects with details about
// recorded transactions to or from any address belonging to a set.  This is
// intended to be used for listaddresstransactions RPC replies.
func (w *Wallet) ListAddressTransactions(pkHashes map[string]struct{}) (
	[]btcjson.ListTransactionsResult, error) {

	txList := []btcjson.ListTransactionsResult{}

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	blk := w.Manager.SyncedTo()

	for _, r := range w.TxStore.Records() {
		for _, c := range r.Credits() {
			// We only care about the case where len(addrs) == 1,
			// and err will never be non-nil in that case.
			_, addrs, _, _ := c.Addresses(w.chainParams)
			if len(addrs) != 1 {
				continue
			}
			apkh, ok := addrs[0].(*btcutil.AddressPubKeyHash)
			if !ok {
				continue
			}

			if _, ok := pkHashes[string(apkh.ScriptAddress())]; !ok {
				continue
			}
			jsonResult, err := c.ToJSON(waddrmgr.DefaultAccountName, blk.Height,
				w.Manager.ChainParams())
			if err != nil {
				return nil, err
			}
			txList = append(txList, jsonResult)
		}
	}

	return txList, nil
}

// ListAllTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listalltransactions RPC
// replies.
func (w *Wallet) ListAllTransactions() ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	blk := w.Manager.SyncedTo()

	// Search in reverse order: lookup most recently-added first.
	records := w.TxStore.Records()
	for i := len(records) - 1; i >= 0; i-- {
		jsonResults, err := records[i].ToJSON(waddrmgr.DefaultAccountName, blk.Height,
			w.Manager.ChainParams())
		if err != nil {
			return nil, err
		}
		txList = append(txList, jsonResults...)
	}

	return txList, nil
}

// ListUnspent returns a slice of objects representing the unspent wallet
// transactions fitting the given criteria. The confirmations will be more than
// minconf, less than maxconf and if addresses is populated only the addresses
// contained within it will be considered.  If we know nothing about a
// transaction an empty array will be returned.
func (w *Wallet) ListUnspent(minconf, maxconf int,
	addresses map[string]bool) ([]*btcjson.ListUnspentResult, error) {

	results := []*btcjson.ListUnspentResult{}

	blk := w.Manager.SyncedTo()

	filter := len(addresses) != 0

	unspent, err := w.TxStore.SortedUnspentOutputs()
	if err != nil {
		return nil, err
	}

	for _, credit := range unspent {
		confs := credit.Confirmations(blk.Height)
		if int(confs) < minconf || int(confs) > maxconf {
			continue
		}
		if credit.IsCoinbase() {
			if !credit.Confirmed(blockchain.CoinbaseMaturity, blk.Height) {
				continue
			}
		}
		if w.LockedOutpoint(*credit.OutPoint()) {
			continue
		}

		creditAccount, err := w.CreditAccount(credit)
		if err != nil {
			continue
		}
		accountName, err := w.Manager.AccountName(creditAccount)
		if err != nil {
			return nil, err
		}

		_, addrs, _, _ := credit.Addresses(w.chainParams)
		if filter {
			for _, addr := range addrs {
				_, ok := addresses[addr.EncodeAddress()]
				if ok {
					goto include
				}
			}
			continue
		}
	include:
		result := &btcjson.ListUnspentResult{
			TxId:          credit.Tx().Sha().String(),
			Vout:          credit.OutputIndex,
			Account:       accountName,
			ScriptPubKey:  hex.EncodeToString(credit.TxOut().PkScript),
			Amount:        credit.Amount().ToBTC(),
			Confirmations: int64(confs),
		}

		// BUG: this should be a JSON array so that all
		// addresses can be included, or removed (and the
		// caller extracts addresses from the pkScript).
		if len(addrs) > 0 {
			result.Address = addrs[0].EncodeAddress()
		}

		results = append(results, result)
	}

	return results, nil
}

// DumpPrivKeys returns the WIF-encoded private keys for all addresses with
// private keys in a wallet.
func (w *Wallet) DumpPrivKeys() ([]string, error) {
	addrs, err := w.Manager.AllActiveAddresses()
	if err != nil {
		return nil, err
	}

	// Iterate over each active address, appending the private key to
	// privkeys.
	privkeys := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ma, err := w.Manager.Address(addr)
		if err != nil {
			return nil, err
		}

		// Only those addresses with keys needed.
		pka, ok := ma.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			continue
		}

		wif, err := pka.ExportPrivKey()
		if err != nil {
			// It would be nice to zero out the array here. However,
			// since strings in go are immutable, and we have no
			// control over the caller I don't think we can. :(
			return nil, err
		}
		privkeys = append(privkeys, wif.String())
	}

	return privkeys, nil
}

// DumpWIFPrivateKey returns the WIF encoded private key for a
// single wallet address.
func (w *Wallet) DumpWIFPrivateKey(addr btcutil.Address) (string, error) {
	// Get private key from wallet if it exists.
	address, err := w.Manager.Address(addr)
	if err != nil {
		return "", err
	}

	pka, ok := address.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return "", fmt.Errorf("address %s is not a key type", addr)
	}

	wif, err := pka.ExportPrivKey()
	if err != nil {
		return "", err
	}
	return wif.String(), nil
}

// ImportPrivateKey imports a private key to the wallet and writes the new
// wallet to disk.
func (w *Wallet) ImportPrivateKey(wif *btcutil.WIF, bs *waddrmgr.BlockStamp,
	rescan bool) (string, error) {

	// The starting block for the key is the genesis block unless otherwise
	// specified.
	if bs == nil {
		bs = &waddrmgr.BlockStamp{
			Hash:   *w.chainParams.GenesisHash,
			Height: 0,
		}
	}

	// Attempt to import private key into wallet.
	addr, err := w.Manager.ImportPrivateKey(wif, bs)
	if err != nil {
		return "", err
	}

	// Rescan blockchain for transactions with txout scripts paying to the
	// imported address.
	if rescan {
		job := &RescanJob{
			Addrs:      []btcutil.Address{addr.Address()},
			OutPoints:  nil,
			BlockStamp: *bs,
		}

		// Submit rescan job and log when the import has completed.
		// Do not block on finishing the rescan.  The rescan success
		// or failure is logged elsewhere, and the channel is not
		// required to be read, so discard the return value.
		_ = w.SubmitRescan(job)
	}

	addrStr := addr.Address().EncodeAddress()
	log.Infof("Imported payment address %s", addrStr)

	// Return the payment address string of the imported private key.
	return addrStr, nil
}

// ExportWatchingWallet returns a watching-only version of the wallet serialized
// in a map.
func (w *Wallet) ExportWatchingWallet(pubPass string) (map[string]string, error) {
	tmpDir, err := ioutil.TempDir("", "btcwallet")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	// Create a new file and write a copy of the current database into it.
	woDbPath := filepath.Join(tmpDir, walletDbWatchingOnlyName)
	fi, err := os.OpenFile(woDbPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := w.db.Copy(fi); err != nil {
		fi.Close()
		return nil, err
	}
	fi.Close()
	defer os.Remove(woDbPath)

	// Open the new database, get the address manager namespace, and open
	// it.
	woDb, err := walletdb.Open("bdb", woDbPath)
	if err != nil {
		_ = os.Remove(woDbPath)
		return nil, err
	}
	defer woDb.Close()

	namespace, err := woDb.Namespace(waddrmgrNamespaceKey)
	if err != nil {
		return nil, err
	}
	woMgr, err := waddrmgr.Open(namespace, []byte(pubPass),
		w.chainParams, nil)
	if err != nil {
		return nil, err
	}
	defer woMgr.Close()

	// Convert the namespace to watching only if needed.
	if err := woMgr.ConvertToWatchingOnly(); err != nil {
		// Only return the error is it's not because it's already
		// watching-only.  When it is already watching-only, the code
		// just falls through to the export below.
		if merr, ok := err.(waddrmgr.ManagerError); ok &&
			merr.ErrorCode != waddrmgr.ErrWatchingOnly {
			return nil, err
		}
	}

	// Export the watching only wallet's serialized data.
	woWallet := *w
	woWallet.db = woDb
	woWallet.Manager = woMgr
	return woWallet.exportBase64()
}

// exportBase64 exports a wallet's serialized database and tx store as
// base64-encoded values in a map.
func (w *Wallet) exportBase64() (map[string]string, error) {
	var buf bytes.Buffer
	m := make(map[string]string)

	if err := w.db.Copy(&buf); err != nil {
		return nil, err
	}
	m["wallet"] = base64.StdEncoding.EncodeToString(buf.Bytes())
	buf.Reset()

	if _, err := w.TxStore.WriteTo(&buf); err != nil {
		return nil, err
	}
	m["tx"] = base64.StdEncoding.EncodeToString(buf.Bytes())
	buf.Reset()

	return m, nil
}

// LockedOutpoint returns whether an outpoint has been marked as locked and
// should not be used as an input for created transactions.
func (w *Wallet) LockedOutpoint(op wire.OutPoint) bool {
	_, locked := w.lockedOutpoints[op]
	return locked
}

// LockOutpoint marks an outpoint as locked, that is, it should not be used as
// an input for newly created transactions.
func (w *Wallet) LockOutpoint(op wire.OutPoint) {
	w.lockedOutpoints[op] = struct{}{}
}

// UnlockOutpoint marks an outpoint as unlocked, that is, it may be used as an
// input for newly created transactions.
func (w *Wallet) UnlockOutpoint(op wire.OutPoint) {
	delete(w.lockedOutpoints, op)
}

// ResetLockedOutpoints resets the set of locked outpoints so all may be used
// as inputs for new transactions.
func (w *Wallet) ResetLockedOutpoints() {
	w.lockedOutpoints = map[wire.OutPoint]struct{}{}
}

// LockedOutpoints returns a slice of currently locked outpoints.  This is
// intended to be used by marshaling the result as a JSON array for
// listlockunspent RPC results.
func (w *Wallet) LockedOutpoints() []btcjson.TransactionInput {
	locked := make([]btcjson.TransactionInput, len(w.lockedOutpoints))
	i := 0
	for op := range w.lockedOutpoints {
		locked[i] = btcjson.TransactionInput{
			Txid: op.Hash.String(),
			Vout: op.Index,
		}
		i++
	}
	return locked
}

// ResendUnminedTxs iterates through all transactions that spend from wallet
// credits that are not known to have been mined into a block, and attempts
// to send each to the chain server for relay.
func (w *Wallet) ResendUnminedTxs() {
	txs := w.TxStore.UnminedDebitTxs()
	for _, tx := range txs {
		_, err := w.chainSvr.SendRawTransaction(tx.MsgTx(), false)
		if err != nil {
			// TODO(jrick): Check error for if this tx is a double spend,
			// remove it if so.
			log.Debugf("Could not resend transaction %v: %v",
				tx.Sha(), err)
			continue
		}
		log.Debugf("Resent unmined transaction %v", tx.Sha())
	}
}

// SortedActivePaymentAddresses returns a slice of all active payment
// addresses in a wallet.
func (w *Wallet) SortedActivePaymentAddresses() ([]string, error) {
	addrs, err := w.Manager.AllActiveAddresses()
	if err != nil {
		return nil, err
	}

	addrStrs := make([]string, len(addrs))
	for i, addr := range addrs {
		addrStrs[i] = addr.EncodeAddress()
	}

	sort.Sort(sort.StringSlice(addrStrs))
	return addrStrs, nil
}

// NewAddress returns the next external chained address for a wallet.
func (w *Wallet) NewAddress(account uint32) (btcutil.Address, error) {
	// Get next address from wallet.
	addrs, err := w.Manager.NextExternalAddresses(account, 1)
	if err != nil {
		return nil, err
	}

	// Request updates from btcd for new transactions sent to this address.
	utilAddrs := make([]btcutil.Address, len(addrs))
	for i, addr := range addrs {
		utilAddrs[i] = addr.Address()
	}
	if err := w.chainSvr.NotifyReceived(utilAddrs); err != nil {
		return nil, err
	}

	return utilAddrs[0], nil
}

// NewChangeAddress returns a new change address for a wallet.
func (w *Wallet) NewChangeAddress(account uint32) (btcutil.Address, error) {
	// Get next chained change address from wallet for account.
	addrs, err := w.Manager.NextInternalAddresses(account, 1)
	if err != nil {
		return nil, err
	}

	// Request updates from btcd for new transactions sent to this address.
	utilAddrs := make([]btcutil.Address, len(addrs))
	for i, addr := range addrs {
		utilAddrs[i] = addr.Address()
	}

	if err := w.chainSvr.NotifyReceived(utilAddrs); err != nil {
		return nil, err
	}

	return utilAddrs[0], nil
}

// TotalReceivedForAccount iterates through a wallet's transaction history,
// returning the total amount of bitcoins received for a single wallet
// account.
func (w *Wallet) TotalReceivedForAccount(account uint32, confirms int) (btcutil.Amount, uint64, error) {
	blk := w.Manager.SyncedTo()

	// Number of confirmations of the last transaction.
	var confirmations uint64

	var amount btcutil.Amount
	for _, r := range w.TxStore.Records() {
		for _, c := range r.Credits() {
			if !c.Confirmed(confirms, blk.Height) {
				// Not enough confirmations, skip the current block.
				continue
			}
			creditAccount, err := w.CreditAccount(c)
			if err != nil {
				continue
			}
			if creditAccount == account {
				amount += c.Amount()
				confirmations = uint64(c.Confirmations(blk.Height))
				break
			}
		}
	}

	return amount, confirmations, nil
}

// TotalReceivedForAddr iterates through a wallet's transaction history,
// returning the total amount of bitcoins received for a single wallet
// address.
func (w *Wallet) TotalReceivedForAddr(addr btcutil.Address, confirms int) (btcutil.Amount, error) {
	blk := w.Manager.SyncedTo()

	addrStr := addr.EncodeAddress()
	var amount btcutil.Amount
	for _, r := range w.TxStore.Records() {
		for _, c := range r.Credits() {
			if !c.Confirmed(confirms, blk.Height) {
				continue
			}

			_, addrs, _, err := c.Addresses(w.chainParams)
			// An error creating addresses from the output script only
			// indicates a non-standard script, so ignore this credit.
			if err != nil {
				continue
			}
			for _, a := range addrs {
				if addrStr == a.EncodeAddress() {
					amount += c.Amount()
					break
				}
			}
		}
	}

	return amount, nil
}

// TxRecord iterates through all transaction records saved in the store,
// returning the first with an equivalent transaction hash.
func (w *Wallet) TxRecord(txSha *wire.ShaHash) (r *txstore.TxRecord, ok bool) {
	for _, r = range w.TxStore.Records() {
		if *r.Tx().Sha() == *txSha {
			return r, true
		}
	}
	return nil, false
}

// Db returns wallet db being used by a wallet
func (w *Wallet) Db() walletdb.DB {
	return w.db
}

// Open opens a wallet from disk.
func Open(config *Config) *Wallet {
	wallet := newWallet(config.Waddrmgr, config.TxStore, config.Db)
	wallet.chainParams = config.ChainParams

	return wallet
}
