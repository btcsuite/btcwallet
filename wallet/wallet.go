// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	walletkvdb "github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/walletdb/migration"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/davecgh/go-spew/spew"
)

const (
	// InsecurePubPassphrase is the default outer encryption passphrase used
	// for public data (everything but private keys).  Using a non-default
	// public passphrase can prevent an attacker without the public
	// passphrase from discovering all past and future wallet addresses if
	// they gain access to the wallet database.
	//
	// NOTE: at time of writing, public encryption only applies to public
	// data in the waddrmgr namespace.  Transactions are not yet encrypted.
	InsecurePubPassphrase = "public"

	// recoveryBatchSize is the default number of blocks that will be
	// scanned successively by the recovery manager, in the event that the
	// wallet is started in recovery mode.
	recoveryBatchSize = 2000

	// defaultSyncRetryInterval is the default amount of time to wait
	// between re-tries on errors during initial sync.
	defaultSyncRetryInterval = 5 * time.Second
)

var (
	// ErrNotSynced describes an error where an operation cannot complete
	// due wallet being out of sync (and perhaps currently syncing with)
	// the remote chain server.
	ErrNotSynced = errors.New("wallet is not synchronized with the chain server")

	// ErrWalletShuttingDown is an error returned when we attempt to make a
	// request to the wallet but it is in the process of or has already shut
	// down.
	ErrWalletShuttingDown = errors.New("wallet shutting down")

	// ErrUnknownTransaction is returned when an attempt is made to label
	// a transaction that is not known to the wallet.
	ErrUnknownTransaction = errors.New("cannot label transaction not " +
		"known to wallet")

	// ErrTxLabelExists is returned when a transaction already has a label
	// and an attempt has been made to label it without setting overwrite
	// to true.
	ErrTxLabelExists = errors.New("transaction already labelled")

	// ErrNoTx is returned when a transaction can not be found.
	ErrNoTx = errors.New("can not find transaction")

	// ErrTxUnsigned is returned when a transaction is created in the
	// watch-only mode where we can select coins but not sign any inputs.
	ErrTxUnsigned = errors.New("watch-only wallet, transaction not signed")

	// Namespace bucket keys.
	waddrmgrNamespaceKey = []byte("waddrmgr")
	wtxmgrNamespaceKey   = []byte("wtxmgr")
)

// UnsupportedStoreOperationError reports a transaction-domain operation that
// has not yet been ported to store-backed wallets.
type UnsupportedStoreOperationError struct {
	// Operation identifies the unsupported public wallet method.
	Operation string
}

// Error describes the unsupported store-backed wallet operation.
func (e *UnsupportedStoreOperationError) Error() string {
	return e.Operation + " is unsupported for store-backed wallets"
}

// Coin represents a spendable UTXO which is available for coin selection.
type Coin struct {
	// TxOut describes the spendable output value and script.
	wire.TxOut

	// OutPoint identifies the transaction output being spent.
	wire.OutPoint
}

// CoinSelectionStrategy is an interface that represents a coin selection
// strategy. A coin selection strategy is responsible for ordering, shuffling or
// filtering a list of coins before they are passed to the coin selection
// algorithm.
type CoinSelectionStrategy interface {
	// ArrangeCoins takes a list of coins and arranges them according to the
	// specified coin selection strategy and fee rate.
	ArrangeCoins(eligible []Coin, feeSatPerKb btcutil.Amount) ([]Coin,
		error)
}

var (
	// CoinSelectionLargest always picks the largest available utxo to add
	// to the transaction next.
	CoinSelectionLargest CoinSelectionStrategy = &LargestFirstCoinSelector{}

	// CoinSelectionRandom randomly selects the next utxo to add to the
	// transaction. This strategy prevents the creation of ever smaller
	// utxos over time.
	CoinSelectionRandom CoinSelectionStrategy = &RandomCoinSelector{}
)

// Wallet is a structure containing all the components for a
// complete wallet.  It contains the Armory-style key store
// addresses and keys),
type Wallet struct {
	publicPassphrase []byte

	// Data stores
	db    walletdb.DB
	store walletstore.Store
	// Manager controls the wallet's address and key state.
	Manager *waddrmgr.Manager

	// TxStore controls the legacy wallet transaction state. It is nil for a
	// Store-backed wallet.
	TxStore *wtxmgr.Store

	chainClient        chain.Interface
	chainClientLock    sync.Mutex
	chainClientSynced  bool
	chainClientSyncMtx sync.Mutex

	newAddrMtx sync.Mutex

	lockedOutpoints    map[wire.OutPoint]struct{}
	lockedOutpointsMtx sync.Mutex

	recovering     atomic.Value
	recoveryWindow uint32

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
	holdUnlockRequests chan chan heldUnlock
	lockState          chan bool
	changePassphrase   chan changePassphraseRequest
	changePassphrases  chan changePassphrasesRequest

	// NtfnServer publishes wallet state changes to subscribers.
	NtfnServer *NotificationServer

	chainParams *chaincfg.Params
	wg          sync.WaitGroup

	started bool
	quit    chan struct{}
	quitMu  sync.Mutex

	// syncRetryInterval is the amount of time to wait between re-tries on
	// errors during initial sync.
	syncRetryInterval time.Duration
}

// Start starts the goroutines necessary to manage a wallet.
func (w *Wallet) Start() {
	w.quitMu.Lock()
	select {
	case <-w.quit:
		// Restart the wallet goroutines after shutdown finishes.
		w.WaitForShutdown()
		w.quit = make(chan struct{})
	default:
		// Ignore when the wallet is still running.
		if w.started {
			w.quitMu.Unlock()
			return
		}
		w.started = true
	}
	w.quitMu.Unlock()

	w.wg.Add(2)
	go w.txCreator()
	go w.walletLocker()
}

// SynchronizeRPC associates the wallet with the consensus RPC client,
// synchronizes the wallet with the latest changes to the blockchain, and
// continuously updates the wallet through RPC notifications.
//
// This method is unstable and will be removed when all syncing logic is moved
// outside of the wallet package.
func (w *Wallet) SynchronizeRPC(chainClient chain.Interface) {
	w.quitMu.Lock()
	select {
	case <-w.quit:
		w.quitMu.Unlock()
		return
	default:
	}
	w.quitMu.Unlock()

	// TODO: Ignoring the new client when one is already set breaks callers
	// who are replacing the client, perhaps after a disconnect.
	w.chainClientLock.Lock()
	if w.chainClient != nil {
		w.chainClientLock.Unlock()
		return
	}
	w.chainClient = chainClient

	// If the chain client is a NeutrinoClient instance, set a birthday so
	// we don't download all the filters as we go.
	switch cc := chainClient.(type) {
	case *chain.NeutrinoClient:
		cc.SetStartTime(w.Manager.Birthday())
	case *chain.BitcoindClient:
		cc.SetBirthday(w.Manager.Birthday())
	}
	w.chainClientLock.Unlock()

	// TODO: It would be preferable to either run these goroutines
	// separately from the wallet (use wallet mutator functions to
	// make changes from the RPC client) and not have to stop and
	// restart them each time the client disconnects and reconnets.
	w.wg.Add(4)
	go w.handleChainNotifications()
	go w.rescanBatchHandler()
	go w.rescanProgressHandler()
	go w.rescanRPCHandler()
}

// requireChainClient marks that a wallet method can only be completed when the
// consensus RPC server is set.  This function and all functions that call it
// are unstable and will need to be moved when the syncing code is moved out of
// the wallet.
func (w *Wallet) requireChainClient() (chain.Interface, error) {
	w.chainClientLock.Lock()
	chainClient := w.chainClient
	w.chainClientLock.Unlock()
	if chainClient == nil {
		return nil, errors.New("blockchain RPC is inactive")
	}
	return chainClient, nil
}

// ChainClient returns the optional consensus RPC client associated with the
// wallet.
//
// This function is unstable and will be removed once sync logic is moved out of
// the wallet.
func (w *Wallet) ChainClient() chain.Interface {
	w.chainClientLock.Lock()
	chainClient := w.chainClient
	w.chainClientLock.Unlock()
	return chainClient
}

// quitChan atomically reads the quit channel.
func (w *Wallet) quitChan() <-chan struct{} {
	w.quitMu.Lock()
	c := w.quit
	w.quitMu.Unlock()
	return c
}

// Stop signals all wallet goroutines to shutdown.
func (w *Wallet) Stop() {
	<-w.endRecovery()

	w.quitMu.Lock()
	quit := w.quit
	w.quitMu.Unlock()

	select {
	case <-quit:
	default:
		close(quit)
		w.chainClientLock.Lock()
		if w.chainClient != nil {
			w.chainClient.Stop()
			w.chainClient = nil
		}
		w.chainClientLock.Unlock()
	}
}

// ShuttingDown returns whether the wallet is currently in the process of
// shutting down or not.
func (w *Wallet) ShuttingDown() bool {
	select {
	case <-w.quitChan():
		return true
	default:
		return false
	}
}

// WaitForShutdown blocks until all wallet goroutines have finished executing.
func (w *Wallet) WaitForShutdown() {
	w.chainClientLock.Lock()
	if w.chainClient != nil {
		w.chainClient.WaitForShutdown()
	}
	w.chainClientLock.Unlock()
	w.wg.Wait()
}

// SynchronizingToNetwork returns whether the wallet is currently synchronizing
// with the Bitcoin network.
func (w *Wallet) SynchronizingToNetwork() bool {
	// At the moment, RPC is the only synchronization method.  In the
	// future, when SPV is added, a separate check will also be needed, or
	// SPV could always be enabled if RPC was not explicitly specified when
	// creating the wallet.
	w.chainClientSyncMtx.Lock()
	syncing := w.chainClient != nil
	w.chainClientSyncMtx.Unlock()
	return syncing
}

// ChainSynced returns whether the wallet has been attached to a chain server
// and synced up to the best block on the main chain.
func (w *Wallet) ChainSynced() bool {
	w.chainClientSyncMtx.Lock()
	synced := w.chainClientSynced
	w.chainClientSyncMtx.Unlock()
	return synced
}

// SetChainSynced marks whether the wallet is connected to and currently in sync
// with the latest block notified by the chain server.
//
// NOTE: Due to an API limitation with rpcclient, this may return true after
// the client disconnected (and is attempting a reconnect). This will be
// unknown until the reconnect notification is received, at which point the
// wallet can be marked out of sync again until after the next rescan completes.
func (w *Wallet) SetChainSynced(synced bool) {
	w.chainClientSyncMtx.Lock()
	w.chainClientSynced = synced
	w.chainClientSyncMtx.Unlock()
}

// activeData returns the currently-active receiving addresses and all unspent
// outputs.  This is primarely intended to provide the parameters for a
// rescan request.
func (w *Wallet) activeData(
	dbtx walletdb.ReadWriteTx) ([]address.Address, []wtxmgr.Credit, error) {

	addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	var addrs []address.Address
	err := w.Manager.ForEachRelevantActiveAddress(
		addrmgrNs, func(addr address.Address) error {
			addrs = append(addrs, addr)
			return nil
		},
	)
	if err != nil {
		return nil, nil, err
	}

	// Before requesting the list of spendable UTXOs, we'll delete any
	// expired output locks.
	err = w.TxStore.DeleteExpiredLockedOutputs(
		dbtx.ReadWriteBucket(wtxmgrNamespaceKey),
	)
	if err != nil {
		return nil, nil, err
	}

	unspent, err := w.TxStore.OutputsToWatch(txmgrNs)
	return addrs, unspent, err
}

type rollbackBlockHash struct {
	height int32
	hash   chainhash.Hash
}

// readStoreRollbackSnapshot detaches the durable starting sync state and its
// contiguous retained block hashes before any chain request is made.
func (w *Wallet) readStoreRollbackSnapshot(ctx context.Context) (
	waddrmgr.SyncState, []rollbackBlockHash, error) {

	var (
		state  waddrmgr.SyncState
		blocks []rollbackBlockHash
	)
	err := w.store.View(ctx, func(tx walletstore.ReadTx) error {
		var err error
		state, err = tx.Addr().SyncState()
		if err != nil {
			return err
		}

		for height := state.SyncedTo.Height; ; height-- {
			hash, err := tx.Addr().BlockHash(height)
			if waddrmgr.IsError(err, waddrmgr.ErrBlockNotFound) {
				break
			}
			if err != nil {
				return err
			}
			blocks = append(blocks, rollbackBlockHash{
				height: height,
				hash:   *hash,
			})
			if height == 0 {
				break
			}
		}

		if len(blocks) == 0 || blocks[0].hash != state.SyncedTo.Hash {
			return errors.New("durable synced tip has no matching block hash")
		}

		return nil
	}, func() {
		state = waddrmgr.SyncState{}
		blocks = nil
	})

	return state, blocks, err
}

// findStoreRollbackTarget finds the newest retained wallet block on the
// backend's active chain and validates the descending header linkage.
func findStoreRollbackTarget(chainClient chain.Interface,
	blocks []rollbackBlockHash) (waddrmgr.BlockStamp, error) {

	var expectedHash *chainhash.Hash
	for _, block := range blocks {
		chainHash, err := chainClient.GetBlockHash(int64(block.height))
		if err != nil {
			return waddrmgr.BlockStamp{}, err
		}
		if expectedHash != nil && *chainHash != *expectedHash {
			return waddrmgr.BlockStamp{}, fmt.Errorf(
				"chain changed while finding rollback ancestor at height %d",
				block.height,
			)
		}

		header, err := chainClient.GetBlockHeader(chainHash)
		if err != nil {
			return waddrmgr.BlockStamp{}, err
		}
		if header.BlockHash() != *chainHash {
			return waddrmgr.BlockStamp{}, fmt.Errorf(
				"header hash does not match block %v", chainHash,
			)
		}

		stamp := waddrmgr.BlockStamp{
			Hash:      *chainHash,
			Height:    block.height,
			Timestamp: header.Timestamp,
		}
		if block.hash == *chainHash {
			return stamp, nil
		}

		expectedHash = &header.PrevBlock
	}

	return waddrmgr.BlockStamp{}, errors.New(
		"no retained wallet block is on the active chain",
	)
}

// rollbackStoreToChain prepares a common-ancestor rollback without a Store
// transaction and atomically applies it against the exact durable starting tip.
func (w *Wallet) rollbackStoreToChain(chainClient chain.Interface,
	birthdayStamp *waddrmgr.BlockStamp) (bool, error) {

	ctx := context.Background()
	state, blocks, err := w.readStoreRollbackSnapshot(ctx)
	if err != nil {
		return false, err
	}
	target, err := findStoreRollbackTarget(chainClient, blocks)
	if err != nil {
		return false, err
	}
	start := state.SyncedTo
	if sameBlockPosition(start, target) {
		return false, nil
	}

	err = w.applyStorePlan(
		ctx, "initial rollback", func(tx walletstore.ReadWriteTx) error {
			current, err := tx.Addr().SyncState()
			if err != nil {
				return err
			}
			if !sameBlockPosition(current.SyncedTo, start) {
				return &StorePlanStaleError{
					Operation: "initial rollback",
					Reason: fmt.Sprintf("starting tip is %d:%v, want %d:%v",
						current.SyncedTo.Height, current.SyncedTo.Hash,
						start.Height, start.Hash),
				}
			}

			startHash, err := tx.Addr().BlockHash(start.Height)
			if err != nil {
				return err
			}
			if *startHash != start.Hash {
				return &StorePlanStaleError{
					Operation: "initial rollback",
					Reason:    "starting block hash changed",
				}
			}

			if err := w.Manager.SetSyncedToFromStore(
				tx.Addr(), &target,
			); err != nil {

				return err
			}
			if target.Height <= birthdayStamp.Height &&
				target.Hash != birthdayStamp.Hash {

				if err := w.Manager.SetBirthdayBlockFromStore(
					tx.Addr(), target, true,
				); err != nil {

					return err
				}
			}

			return tx.Tx().Rollback(target.Height + 1)
		}, func(tx walletstore.ReadTx) (storePlanStatus, error) {
			return storePlanCommitStatus(tx, start, target)
		}, nil,
	)
	if err != nil {
		return false, err
	}

	return true, nil
}

// syncWithChain brings the wallet up to date with the current chain server
// connection. It creates a rescan request and blocks until the rescan has
// finished. The birthday block can be passed in, if set, to ensure we can
// properly detect if it gets rolled back.
func (w *Wallet) syncWithChain(birthdayStamp *waddrmgr.BlockStamp) error {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return err
	}

	// Neutrino relies on the information given to it by the cfheader server
	// so it knows exactly whether it's synced up to the server's state or
	// not, even on dev chains. To recover a Neutrino wallet, we need to
	// make sure it's synced before we start scanning for addresses,
	// otherwise we might miss some if we only scan up to its current sync
	// point.
	neutrinoRecovery := chainClient.BackEnd() == "neutrino" &&
		w.recoveryWindow > 0

	// We'll wait until the backend is synced to ensure we get the latest
	// MaxReorgDepth blocks to store. We don't do this for development
	// environments as we can't guarantee a lively chain, except for
	// Neutrino, where the cfheader server tells us what it believes the
	// chain tip is.
	if !w.isDevEnv() || neutrinoRecovery {
		log.Debug("Waiting for chain backend to sync to tip")
		if err := w.waitUntilBackendSynced(chainClient); err != nil {
			return err
		}
		log.Debug("Chain backend synced to tip!")
	}

	// If we've yet to find our birthday block, we'll do so now.
	if birthdayStamp == nil {
		var err error
		birthdayStamp, err = locateBirthdayBlock(
			chainClient, w.Manager.Birthday(),
		)
		if err != nil {
			return fmt.Errorf("unable to locate birthday block: %w",
				err)
		}

		// We'll also determine our initial sync starting height. This
		// is needed as the wallet can now begin storing blocks from an
		// arbitrary height, rather than all the blocks from genesis, so
		// we persist this height to ensure we don't store any blocks
		// before it.
		startHeight := birthdayStamp.Height

		// With the starting height obtained, get the remaining block
		// details required by the wallet.
		startHash, err := chainClient.GetBlockHash(int64(startHeight))
		if err != nil {
			return err
		}
		startHeader, err := chainClient.GetBlockHeader(startHash)
		if err != nil {
			return err
		}

		if w.db != nil {
			err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				err := w.Manager.SetSyncedTo(ns, &waddrmgr.BlockStamp{
					Hash:      *startHash,
					Height:    startHeight,
					Timestamp: startHeader.Timestamp,
				})
				if err != nil {
					return err
				}
				return w.Manager.SetBirthdayBlock(
					ns, *birthdayStamp, true,
				)
			})
		} else {
			err = w.store.UpdateOnce(
				context.Background(),
				func(tx walletstore.ReadWriteTx) error {
					err := w.Manager.SetSyncedToFromStore(
						tx.Addr(), &waddrmgr.BlockStamp{
							Hash:      *startHash,
							Height:    startHeight,
							Timestamp: startHeader.Timestamp,
						},
					)
					if err != nil {
						return err
					}

					return w.Manager.SetBirthdayBlockFromStore(
						tx.Addr(), *birthdayStamp, true,
					)
				}, nil,
			)
		}
		if err != nil {
			return fmt.Errorf("unable to persist initial sync "+
				"data: %w", err)
		}
	}

	// If the wallet requested an on-chain recovery of its funds, we'll do
	// so now.
	if w.recoveryWindow > 0 {
		if err := w.recovery(chainClient, birthdayStamp); err != nil {
			return fmt.Errorf("unable to perform wallet recovery: "+
				"%w", err)
		}
	}

	// Compare previously-seen blocks against the current chain. If any of
	// these blocks no longer exist, rollback all of the missing blocks
	// before catching up with the rescan.
	rollback := false
	rollbackStamp := w.Manager.SyncedTo()
	if w.db != nil {
		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)

			for height := rollbackStamp.Height; true; height-- {
				hash, err := w.Manager.BlockHash(addrmgrNs, height)
				if err != nil {
					return err
				}
				chainHash, err := chainClient.GetBlockHash(int64(height))
				if err != nil {
					return err
				}
				header, err := chainClient.GetBlockHeader(chainHash)
				if err != nil {
					return err
				}

				rollbackStamp.Hash = *chainHash
				rollbackStamp.Height = height
				rollbackStamp.Timestamp = header.Timestamp

				if bytes.Equal(hash[:], chainHash[:]) {
					break
				}
				rollback = true
			}

			if !rollback {
				return nil
			}

			err := w.Manager.SetSyncedTo(addrmgrNs, &rollbackStamp)
			if err != nil {
				return err
			}
			if rollbackStamp.Height <= birthdayStamp.Height &&
				rollbackStamp.Hash != birthdayStamp.Hash {

				err := w.Manager.SetBirthdayBlock(
					addrmgrNs, rollbackStamp, true,
				)
				if err != nil {
					return err
				}
			}

			return w.TxStore.Rollback(
				txmgrNs, rollbackStamp.Height+1,
			)
		})
	} else {
		rollback, err = w.rollbackStoreToChain(chainClient, birthdayStamp)
	}
	if err != nil {
		return err
	}

	// Request notifications for connected and disconnected blocks.
	//
	// TODO(jrick): Either request this notification only once, or when
	// rpcclient is modified to allow some notification request to not
	// automatically resent on reconnect, include the notifyblocks request
	// as well.  I am leaning towards allowing off all rpcclient
	// notification re-registrations, in which case the code here should be
	// left as is.
	if err := chainClient.NotifyBlocks(); err != nil {
		return err
	}

	// Finally, we'll trigger a wallet rescan and request notifications for
	// transactions sending to all wallet addresses and spending all wallet
	// UTXOs.
	var (
		addrs   []address.Address
		unspent []wtxmgr.Credit
	)
	if w.db != nil {
		err = walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
			addrs, unspent, err = w.activeData(dbtx)
			return err
		})
	} else {
		err = w.store.UpdateOnce(
			context.Background(),
			func(tx walletstore.ReadWriteTx) error {
				addrs = nil
				unspent = nil
				err := w.Manager.ForEachRelevantActiveAddressFromStore(
					tx.Addr(), func(addr address.Address) error {
						addrs = append(addrs, addr)
						return nil
					},
				)
				if err != nil {
					return err
				}
				if err := tx.Tx().DeleteExpiredLockedOutputs(); err != nil {
					return err
				}
				unspent, err = tx.Tx().OutputsToWatch()
				return err
			}, func() {
				addrs = nil
				unspent = nil
			},
		)
	}
	if err != nil {
		return err
	}

	return w.rescanWithTarget(addrs, unspent, nil)
}

// isDevEnv determines whether the wallet is currently under a local developer
// environment, e.g. simnet or regtest.
func (w *Wallet) isDevEnv() bool {
	switch uint32(w.ChainParams().Net) {
	case uint32(chaincfg.RegressionNetParams.Net):
	case uint32(chaincfg.SimNetParams.Net):
	default:
		return false
	}
	return true
}

// waitUntilBackendSynced blocks until the chain backend considers itself
// "current".
func (w *Wallet) waitUntilBackendSynced(chainClient chain.Interface) error {
	// We'll poll every second to determine if our chain considers itself
	// "current".
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			if chainClient.IsCurrent() {
				return nil
			}
		case <-w.quitChan():
			return ErrWalletShuttingDown
		}
	}
}

// locateBirthdayBlock returns a block that meets the given birthday timestamp
// by a margin of +/-2 hours. This is safe to do as the timestamp is already 2
// days in the past of the actual timestamp.
func locateBirthdayBlock(chainClient chainConn,
	birthday time.Time) (*waddrmgr.BlockStamp, error) {

	// Retrieve the lookup range for our block.
	startHeight := int32(0)
	_, bestHeight, err := chainClient.GetBestBlock()
	if err != nil {
		return nil, err
	}

	log.Debugf("Locating suitable block for birthday %v between blocks "+
		"%v-%v", birthday, startHeight, bestHeight)

	var (
		birthdayBlock *waddrmgr.BlockStamp
		left, right   = startHeight, bestHeight
	)

	// Binary search for a block that meets the birthday timestamp by a
	// margin of +/-2 hours.
	for {
		// Retrieve the timestamp for the block halfway through our
		// range.
		mid := left + (right-left)/2
		hash, err := chainClient.GetBlockHash(int64(mid))
		if err != nil {
			return nil, err
		}
		header, err := chainClient.GetBlockHeader(hash)
		if err != nil {
			return nil, err
		}

		log.Debugf("Checking candidate block: height=%v, hash=%v, "+
			"timestamp=%v", mid, hash, header.Timestamp)

		// If the search happened to reach either of our range extremes,
		// then we'll just use that as there's nothing left to search.
		if mid == startHeight || mid == bestHeight || mid == left {
			birthdayBlock = &waddrmgr.BlockStamp{
				Hash:      *hash,
				Height:    mid,
				Timestamp: header.Timestamp,
			}
			break
		}

		// The block's timestamp is more than 2 hours after the
		// birthday, so look for a lower block.
		if header.Timestamp.Sub(birthday) > birthdayBlockDelta {
			right = mid
			continue
		}

		// The birthday is more than 2 hours before the block's
		// timestamp, so look for a higher block.
		if header.Timestamp.Sub(birthday) < -birthdayBlockDelta {
			left = mid
			continue
		}

		birthdayBlock = &waddrmgr.BlockStamp{
			Hash:      *hash,
			Height:    mid,
			Timestamp: header.Timestamp,
		}
		break
	}

	log.Debugf("Found birthday block: height=%d, hash=%v, timestamp=%v",
		birthdayBlock.Height, birthdayBlock.Hash,
		birthdayBlock.Timestamp)

	return birthdayBlock, nil
}

// recoverySyncer is used to synchronize wallet and address manager locking
// with the end of recovery. (*Wallet).recovery will store a recoverySyncer
// when invoked, and will close the done chan upon exit. Setting the quit flag
// will cause recovery to end after the current batch of blocks.
type recoverySyncer struct {
	done chan struct{}
	quit uint32 // atomic
}

// recovery attempts to recover any unspent outputs that pay to any of our
// addresses starting from our birthday, or the wallet's tip (if higher), which
// would indicate resuming a recovery after a restart.
func (w *Wallet) recovery(chainClient chain.Interface,
	birthdayBlock *waddrmgr.BlockStamp) error {

	log.Infof("RECOVERY MODE ENABLED -- rescanning for used addresses "+
		"with recovery_window=%d", w.recoveryWindow)

	// Wallet locking must synchronize with the end of recovery, since use of
	// keys in recovery is racy with manager IsLocked checks, which could
	// result in enrypting data with a zeroed key.
	syncer := &recoverySyncer{done: make(chan struct{})}
	w.recovering.Store(syncer)
	defer close(syncer.done)

	// We'll initialize the recovery manager with a default batch size of
	// 2000.
	recoveryMgr := NewRecoveryManager(
		w.recoveryWindow, recoveryBatchSize, w.chainParams,
	)

	// In the event that this recovery is being resumed, we will need to
	// repopulate all found addresses from the database. Ideally, for basic
	// recovery, we would only do so for the default scopes, but due to a
	// bug in which the wallet would create change addresses outside of the
	// default scopes, it's necessary to attempt all registered key scopes.
	scopedMgrs := make(map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager)
	for _, scopedMgr := range w.Manager.ActiveScopedKeyManagers() {
		scopedMgrs[scopedMgr.Scope()] = scopedMgr
	}
	var err error
	var recoveryStart waddrmgr.BlockStamp
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			txMgrNS := tx.ReadBucket(wtxmgrNamespaceKey)
			credits, err := w.TxStore.UnspentOutputs(txMgrNS)
			if err != nil {
				return err
			}
			addrMgrNS := tx.ReadBucket(waddrmgrNamespaceKey)
			return recoveryMgr.Resurrect(
				addrMgrNS, scopedMgrs, credits,
			)
		})
		recoveryStart = w.Manager.SyncedTo()
	} else {
		var (
			credits  []wtxmgr.Credit
			accounts map[waddrmgr.KeyScope]waddrmgr.AccountState
		)
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				var err error
				credits, err = tx.Tx().UnspentOutputs()
				if err != nil {
					return err
				}

				accounts = make(
					map[waddrmgr.KeyScope]waddrmgr.AccountState,
					len(scopedMgrs),
				)
				for scope := range scopedMgrs {
					account, err := tx.Addr().Account(
						scope, waddrmgr.DefaultAccountNum,
					)
					if err != nil {
						return err
					}
					accounts[scope] = account
				}

				state, err := tx.Addr().SyncState()
				if err != nil {
					return err
				}
				recoveryStart = state.SyncedTo

				return nil
			}, func() {
				credits = nil
				accounts = nil
				recoveryStart = waddrmgr.BlockStamp{}
			},
		)
		if err == nil {
			err = recoveryMgr.resurrectFromAccountStates(
				accounts, scopedMgrs, credits,
			)
		}
	}
	if err != nil {
		return err
	}

	// Fetch the best height from the backend to determine when we should
	// stop.
	_, bestHeight, err := chainClient.GetBestBlock()
	if err != nil {
		return err
	}

	// Now we can begin scanning the chain from the wallet's current tip to
	// ensure we properly handle restarts. Since the recovery process itself
	// acts as rescan, we'll also update our wallet's synced state along the
	// way to reflect the blocks we process and prevent rescanning them
	// later on.
	//
	// NOTE: We purposefully don't update our best height since we assume
	// that a wallet rescan will be performed from the wallet's tip, which
	// will be of bestHeight after completing the recovery process.
	var blocks []*waddrmgr.BlockStamp
	startHeight := recoveryStart.Height + 1
	previousHash := recoveryStart.Hash
	for height := startHeight; height <= bestHeight; height++ {
		if atomic.LoadUint32(&syncer.quit) == 1 {
			return errors.New("recovery: forced shutdown")
		}

		hash, err := chainClient.GetBlockHash(int64(height))
		if err != nil {
			return err
		}
		header, err := chainClient.GetBlockHeader(hash)
		if err != nil {
			return err
		}
		if w.db == nil {
			if header.BlockHash() != *hash {
				return fmt.Errorf("recovery header hash does not match %v",
					hash)
			}
			if header.PrevBlock != previousHash {
				return fmt.Errorf("recovery block %d does not link to %v",
					height, previousHash)
			}
			previousHash = *hash
		}
		blocks = append(blocks, &waddrmgr.BlockStamp{
			Hash:      *hash,
			Height:    height,
			Timestamp: header.Timestamp,
		})

		// It's possible for us to run into blocks before our birthday
		// if our birthday is after our reorg safe height, so we'll make
		// sure to not add those to the batch.
		if height >= birthdayBlock.Height {
			recoveryMgr.AddToBlockBatch(
				hash, height, header.Timestamp,
			)
		}

		// We'll perform our recovery in batches of 2000 blocks.  It's
		// possible for us to reach our best height without exceeding
		// the recovery batch size, so we can proceed to commit our
		// state to disk.
		recoveryBatch := recoveryMgr.BlockBatch()
		if len(recoveryBatch) == recoveryBatchSize || height == bestHeight {
			var err error
			if w.db != nil {
				err = walletdb.Update(
					w.db, func(tx walletdb.ReadWriteTx) error {
						ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
						if err := w.recoverScopedAddresses(
							chainClient, tx, ns, recoveryBatch,
							recoveryMgr.State(), scopedMgrs,
						); err != nil {

							return err
						}

						// TODO: Any error here will roll back this
						// entire tx. This may cause the in memory sync
						// point to become desyncronized. Refactor so
						// that this cannot happen.
						for _, block := range blocks {
							err := w.Manager.SetSyncedTo(ns, block)
							if err != nil {
								return err
							}
						}

						return nil
					},
				)
			} else {
				err = w.recoverStoreBatch(
					chainClient, recoveryMgr, recoveryBatch, blocks,
					scopedMgrs,
				)
			}
			if err != nil {
				return err
			}

			if len(recoveryBatch) > 0 {
				log.Infof("Recovered addresses from blocks "+
					"%d-%d", recoveryBatch[0].Height,
					recoveryBatch[len(recoveryBatch)-1].Height)
			}

			// Clear the batch of all processed blocks to reuse the
			// same memory for future batches.
			blocks = blocks[:0]
			recoveryMgr.ResetBlockBatch()
		}
	}

	return nil
}

type recoveryStoreSnapshot struct {
	tip      waddrmgr.BlockStamp
	accounts map[waddrmgr.KeyScope]waddrmgr.AccountState
}

type recoveryPlannedTx struct {
	record *wtxmgr.TxRecord
	block  wtxmgr.BlockMeta
}

type recoveryAddressOwner struct {
	manager  *waddrmgr.ScopedKeyManager
	scope    waddrmgr.KeyScope
	internal bool
}

type recoveryAddressOwners map[string]recoveryAddressOwner

type recoveryScopedManagers map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager

type recoveryStorePlan struct {
	start        recoveryStoreSnapshot
	target       waddrmgr.BlockStamp
	finalState   *RecoveryState
	finalIndexes map[waddrmgr.KeyScope]waddrmgr.AccountState
	blocks       []waddrmgr.BlockStamp
	responses    []*chain.FilterBlocksResponse
	transactions []recoveryPlannedTx
	owners       recoveryAddressOwners
	managers     map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager
	scopes       []waddrmgr.KeyScope
}

// readRecoveryStoreSnapshot detaches the exact tip and default-account indexes
// needed to validate one recovery batch.
func (w *Wallet) readRecoveryStoreSnapshot(ctx context.Context,
	scopedMgrs map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager) (
	recoveryStoreSnapshot, error) {

	snapshot := recoveryStoreSnapshot{}
	err := w.store.View(ctx, func(tx walletstore.ReadTx) error {
		state, err := tx.Addr().SyncState()
		if err != nil {
			return err
		}
		snapshot.tip = state.SyncedTo
		snapshot.accounts = make(
			map[waddrmgr.KeyScope]waddrmgr.AccountState,
			len(scopedMgrs),
		)
		for scope := range scopedMgrs {
			account, err := tx.Addr().Account(
				scope, waddrmgr.DefaultAccountNum,
			)
			if err != nil {
				return err
			}
			snapshot.accounts[scope] = account
		}

		return nil
	}, func() {
		snapshot = recoveryStoreSnapshot{}
	})

	return snapshot, err
}

// expandScopeHorizonsFromAccountState derives one scope's transient lookahead
// from detached account state while no Store transaction is active.
func expandScopeHorizonsFromAccountState(account waddrmgr.AccountState,
	scopedMgr *waddrmgr.ScopedKeyManager,
	scopeState *ScopeRecoveryState) error {

	exHorizon, exWindow := scopeState.ExternalBranch.ExtendHorizon()
	count, childIndex := uint32(0), exHorizon
	for count < exWindow {
		addr, err := scopedMgr.DeriveFromKeyPathFromAccountState(
			account, externalKeyPath(childIndex),
		)
		switch {
		case errors.Is(err, hdkeychain.ErrInvalidChild):
			scopeState.ExternalBranch.MarkInvalidChild(childIndex)
			childIndex++
			continue

		case err != nil:
			return err
		}

		scopeState.ExternalBranch.AddAddr(childIndex, addr.Address())
		childIndex++
		count++
	}

	inHorizon, inWindow := scopeState.InternalBranch.ExtendHorizon()
	count, childIndex = 0, inHorizon
	for count < inWindow {
		addr, err := scopedMgr.DeriveFromKeyPathFromAccountState(
			account, internalKeyPath(childIndex),
		)
		switch {
		case errors.Is(err, hdkeychain.ErrInvalidChild):
			scopeState.InternalBranch.MarkInvalidChild(childIndex)
			childIndex++
			continue

		case err != nil:
			return err
		}

		scopeState.InternalBranch.AddAddr(childIndex, addr.Address())
		childIndex++
		count++
	}

	return nil
}

// cloneFilterBlocksResponse detaches all response maps and transactions from a
// chain backend before they are retained in a recovery plan.
func cloneFilterBlocksResponse(
	response *chain.FilterBlocksResponse) *chain.FilterBlocksResponse {

	clone := &chain.FilterBlocksResponse{
		BatchIndex: response.BatchIndex,
		BlockMeta:  response.BlockMeta,
		FoundExternalAddrs: make(
			map[waddrmgr.KeyScope]map[uint32]struct{},
			len(response.FoundExternalAddrs),
		),
		FoundInternalAddrs: make(
			map[waddrmgr.KeyScope]map[uint32]struct{},
			len(response.FoundInternalAddrs),
		),
		FoundOutPoints: make(
			map[wire.OutPoint]address.Address,
			len(response.FoundOutPoints),
		),
		RelevantTxns: make([]*wire.MsgTx, 0, len(response.RelevantTxns)),
	}
	for scope, indexes := range response.FoundExternalAddrs {
		clone.FoundExternalAddrs[scope] = make(
			map[uint32]struct{}, len(indexes),
		)
		for index := range indexes {
			clone.FoundExternalAddrs[scope][index] = struct{}{}
		}
	}
	for scope, indexes := range response.FoundInternalAddrs {
		clone.FoundInternalAddrs[scope] = make(
			map[uint32]struct{}, len(indexes),
		)
		for index := range indexes {
			clone.FoundInternalAddrs[scope][index] = struct{}{}
		}
	}
	for outPoint, addr := range response.FoundOutPoints {
		clone.FoundOutPoints[outPoint] = addr
	}
	for _, transaction := range response.RelevantTxns {
		clone.RelevantTxns = append(clone.RelevantTxns, transaction.Copy())
	}

	return clone
}

// advanceRecoveryPlanState records one immutable filter response in the cloned
// state used to prepare subsequent lookahead requests.
func advanceRecoveryPlanState(response *chain.FilterBlocksResponse,
	state *RecoveryState) {

	for scope, indexes := range response.FoundExternalAddrs {
		branch := state.StateForScope(scope).ExternalBranch
		for index := range indexes {
			branch.ReportFound(index)
		}
	}
	for scope, indexes := range response.FoundInternalAddrs {
		branch := state.StateForScope(scope).InternalBranch
		for index := range indexes {
			branch.ReportFound(index)
		}
	}
	for outPoint, addr := range response.FoundOutPoints {
		outPoint := outPoint
		state.AddWatchedOutPoint(&outPoint, addr)
	}
}

// validateRecoveryResponse ensures every found index was part of the request
// and belongs to a scope included in the recovery plan.
func validateRecoveryResponse(response *chain.FilterBlocksResponse,
	state *RecoveryState,
	scopedMgrs map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager) error {

	for scope, indexes := range response.FoundExternalAddrs {
		if scopedMgrs[scope] == nil {
			return fmt.Errorf("filter response contains unknown scope %s",
				scope)
		}
		branch := state.StateForScope(scope).ExternalBranch
		for index := range indexes {
			if branch.GetAddr(index) == nil {
				return fmt.Errorf("filter response external index %s:%d was "+
					"not requested", scope, index)
			}
		}
	}
	for scope, indexes := range response.FoundInternalAddrs {
		if scopedMgrs[scope] == nil {
			return fmt.Errorf("filter response contains unknown scope %s",
				scope)
		}
		branch := state.StateForScope(scope).InternalBranch
		for index := range indexes {
			if branch.GetAddr(index) == nil {
				return fmt.Errorf("filter response internal index %s:%d was "+
					"not requested", scope, index)
			}
		}
	}

	return nil
}

// recoveryPlanOwners indexes every transient derived address used to classify
// relevant transaction outputs without mutating manager caches during apply.
func recoveryPlanOwners(state *RecoveryState,
	scopedMgrs recoveryScopedManagers) recoveryAddressOwners {

	owners := make(recoveryAddressOwners)
	for scope, manager := range scopedMgrs {
		scopeState := state.StateForScope(scope)
		for _, addr := range scopeState.ExternalBranch.Addrs() {
			owners[string(addr.ScriptAddress())] = recoveryAddressOwner{
				manager: manager,
				scope:   scope,
			}
		}
		for _, addr := range scopeState.InternalBranch.Addrs() {
			owners[string(addr.ScriptAddress())] = recoveryAddressOwner{
				manager:  manager,
				scope:    scope,
				internal: true,
			}
		}
	}

	return owners
}

// prepareRecoveryStorePlan performs lookahead derivation and all filter RPCs
// against detached state, retaining immutable responses for atomic apply.
func (w *Wallet) prepareRecoveryStorePlan(chainClient chain.Interface,
	recoveryState *RecoveryState, batch []wtxmgr.BlockMeta,
	blocks []*waddrmgr.BlockStamp,
	scopedMgrs map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager) (
	*recoveryStorePlan, error) {

	if len(blocks) == 0 {
		return nil, errors.New("recovery Store plan has no block stamps")
	}

	ctx := context.Background()
	snapshot, err := w.readRecoveryStoreSnapshot(ctx, scopedMgrs)
	if err != nil {
		return nil, err
	}
	if blocks[0].Height != snapshot.tip.Height+1 {
		return nil, &StorePlanStaleError{
			Operation: "recovery",
			Reason: fmt.Sprintf("first block height is %d, want %d",
				blocks[0].Height, snapshot.tip.Height+1),
		}
	}
	firstHeader, err := chainClient.GetBlockHeader(&blocks[0].Hash)
	if err != nil {
		return nil, err
	}
	if firstHeader.BlockHash() != blocks[0].Hash ||
		firstHeader.PrevBlock != snapshot.tip.Hash {

		return nil, &StorePlanStaleError{
			Operation: "recovery",
			Reason:    "first block does not extend the starting tip",
		}
	}

	plan := &recoveryStorePlan{
		start:        snapshot,
		finalState:   recoveryState.Clone(),
		finalIndexes: make(map[waddrmgr.KeyScope]waddrmgr.AccountState),
		blocks:       make([]waddrmgr.BlockStamp, len(blocks)),
		managers: make(
			map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager,
			len(scopedMgrs),
		),
	}
	for scope, manager := range scopedMgrs {
		plan.managers[scope] = manager
	}
	for i, block := range blocks {
		plan.blocks[i] = *block
	}
	plan.target = plan.blocks[len(plan.blocks)-1]

	remaining := append([]wtxmgr.BlockMeta(nil), batch...)
	if len(remaining) > 0 {
		log.Infof("Scanning %d blocks for recoverable addresses",
			len(remaining))
	}
	for len(remaining) > 0 {
		for scope, scopedMgr := range scopedMgrs {
			account := snapshot.accounts[scope]
			scopeState := plan.finalState.StateForScope(scope)
			if err := expandScopeHorizonsFromAccountState(
				account, scopedMgr, scopeState,
			); err != nil {

				return nil, err
			}
		}

		request := newFilterBlocksRequest(
			remaining, scopedMgrs, plan.finalState,
		)
		response, err := chainClient.FilterBlocks(request)
		if err != nil {
			return nil, err
		}
		if response == nil {
			break
		}
		if int(response.BatchIndex) >= len(remaining) {
			return nil, fmt.Errorf("filter response index %d exceeds batch %d",
				response.BatchIndex, len(remaining))
		}

		block := remaining[response.BatchIndex]
		if response.BlockMeta.Height != block.Height ||
			response.BlockMeta.Hash != block.Hash {

			return nil, fmt.Errorf("filter response block %d:%v does not "+
				"match request %d:%v", response.BlockMeta.Height,
				response.BlockMeta.Hash, block.Height, block.Hash)
		}

		immutable := cloneFilterBlocksResponse(response)
		if err := validateRecoveryResponse(
			immutable, plan.finalState, scopedMgrs,
		); err != nil {

			return nil, err
		}
		logFilterBlocksResp(block, immutable)
		advanceRecoveryPlanState(immutable, plan.finalState)
		plan.responses = append(plan.responses, immutable)
		for _, transaction := range immutable.RelevantTxns {
			record, err := wtxmgr.NewTxRecordFromMsgTx(
				transaction, immutable.BlockMeta.Time,
			)
			if err != nil {
				return nil, err
			}
			plan.transactions = append(plan.transactions, recoveryPlannedTx{
				record: record,
				block:  immutable.BlockMeta,
			})
		}

		remaining = remaining[immutable.BatchIndex+1:]
	}

	for scope, account := range snapshot.accounts {
		scopeState := plan.finalState.StateForScope(scope)
		account.NextExternalIndex = max(
			account.NextExternalIndex,
			scopeState.ExternalBranch.NextUnfound(),
		)
		account.NextInternalIndex = max(
			account.NextInternalIndex,
			scopeState.InternalBranch.NextUnfound(),
		)
		plan.finalIndexes[scope] = account
		plan.scopes = append(plan.scopes, scope)
	}
	plan.owners = recoveryPlanOwners(
		plan.finalState, recoveryScopedManagers(scopedMgrs),
	)

	return plan, nil
}

// recoveryAccountsMatch reports whether all planned default-account indexes
// match their durable values.
func recoveryAccountsMatch(store walletstore.AddrReadStore,
	accounts map[waddrmgr.KeyScope]waddrmgr.AccountState) (bool, error) {

	for scope, expected := range accounts {
		account, err := store.Account(scope, waddrmgr.DefaultAccountNum)
		if err != nil {
			return false, err
		}
		if account.NextExternalIndex != expected.NextExternalIndex ||
			account.NextInternalIndex != expected.NextInternalIndex {

			return false, nil
		}
	}

	return true, nil
}

// recoveryPlanDurable verifies all address, used-state, and transaction writes
// that distinguish a committed recovery plan from an unrelated tip update.
func recoveryPlanDurable(tx walletstore.ReadTx,
	plan *recoveryStorePlan) (bool, error) {

	matches, err := recoveryAccountsMatch(tx.Addr(), plan.finalIndexes)
	if err != nil || !matches {
		return false, err
	}

	for _, response := range plan.responses {
		for scope, indexes := range response.FoundExternalAddrs {
			branch := plan.finalState.scopes[scope].ExternalBranch
			for index := range indexes {
				state, err := tx.Addr().Address(
					scope, branch.GetAddr(index).ScriptAddress(),
				)
				if err != nil || !state.Used {
					return false, err
				}
			}
		}
		for scope, indexes := range response.FoundInternalAddrs {
			branch := plan.finalState.scopes[scope].InternalBranch
			for index := range indexes {
				state, err := tx.Addr().Address(
					scope, branch.GetAddr(index).ScriptAddress(),
				)
				if err != nil || !state.Used {
					return false, err
				}
			}
		}
	}

	for _, transaction := range plan.transactions {
		details, err := tx.Tx().UniqueTxDetails(
			&transaction.record.Hash, &transaction.block.Block,
		)
		if err != nil || details == nil {
			return false, err
		}
	}

	return true, nil
}

// addRecoveryRelevantTxFromStore records a planned recovery transaction using
// detached address ownership, avoiding manager cache reads before commit.
func (w *Wallet) addRecoveryRelevantTxFromStore(
	tx walletstore.ReadWriteTx, planned recoveryPlannedTx,
	owners recoveryAddressOwners) error {

	exists, err := tx.Tx().InsertTxCheckIfExists(
		planned.record, &planned.block,
	)
	if err != nil || exists {
		return err
	}

	for i, output := range planned.record.MsgTx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams,
		)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			owner, ok := owners[string(addr.ScriptAddress())]
			if !ok || !waddrmgr.IsDefaultScope(owner.scope) {
				continue
			}

			isNew, err := tx.Tx().AddCredit(
				planned.record, &planned.block, uint32(i), owner.internal,
			)
			if err != nil {
				return err
			}
			if isNew {
				hash := planned.record.Hash
				index := uint32(i)
				tx.Addr().OnCommit(func() {
					w.NtfnServer.notifyUnspentOutput(
						waddrmgr.DefaultAccountNum, &hash, index,
					)
				})
			}
			if err := owner.manager.MarkUsedFromStore(
				tx.Addr(), addr,
			); err != nil {

				return err
			}
		}
	}

	hash := planned.record.Hash
	block := planned.block
	tx.Addr().OnCommit(func() {
		w.NtfnServer.notifyMinedTransactionFromStore(hash, &block)
	})

	return nil
}

// applyRecoveryStorePlan atomically persists a prepared recovery plan after
// revalidating its exact starting tip and all relevant account indexes.
func (w *Wallet) applyRecoveryStorePlan(plan *recoveryStorePlan) error {
	return w.applyStorePlan(
		context.Background(), "recovery",
		func(tx walletstore.ReadWriteTx) error {
			state, err := tx.Addr().SyncState()
			if err != nil {
				return err
			}
			if !sameBlockPosition(state.SyncedTo, plan.start.tip) {
				return &StorePlanStaleError{
					Operation: "recovery",
					Reason: fmt.Sprintf("starting tip is %d:%v, want %d:%v",
						state.SyncedTo.Height, state.SyncedTo.Hash,
						plan.start.tip.Height, plan.start.tip.Hash),
				}
			}

			matches, err := recoveryAccountsMatch(
				tx.Addr(), plan.start.accounts,
			)
			if err != nil {
				return err
			}
			if !matches {
				return &StorePlanStaleError{
					Operation: "recovery",
					Reason:    "default account indexes changed",
				}
			}

			for scope, target := range plan.finalIndexes {
				manager := plan.managers[scope]
				if target.NextExternalIndex > 0 {
					if err := extendScopeAddressesFromStore(
						tx.Addr(), manager,
						target.NextExternalIndex-1, false,
					); err != nil {

						return err
					}
				}
				if target.NextInternalIndex > 0 {
					if err := extendScopeAddressesFromStore(
						tx.Addr(), manager,
						target.NextInternalIndex-1, true,
					); err != nil {

						return err
					}
				}
			}

			for _, response := range plan.responses {
				for scope, indexes := range response.FoundExternalAddrs {
					manager := plan.managers[scope]
					branch := plan.finalState.scopes[scope].ExternalBranch
					for index := range indexes {
						if err := manager.MarkUsedFromStore(
							tx.Addr(), branch.GetAddr(index),
						); err != nil {

							return err
						}
					}
				}
				for scope, indexes := range response.FoundInternalAddrs {
					manager := plan.managers[scope]
					branch := plan.finalState.scopes[scope].InternalBranch
					for index := range indexes {
						if err := manager.MarkUsedFromStore(
							tx.Addr(), branch.GetAddr(index),
						); err != nil {

							return err
						}
					}
				}
			}

			for _, transaction := range plan.transactions {
				if err := w.addRecoveryRelevantTxFromStore(
					tx, transaction, plan.owners,
				); err != nil {

					return err
				}
			}

			for i := range plan.blocks {
				if err := w.Manager.SetSyncedToFromStore(
					tx.Addr(), &plan.blocks[i],
				); err != nil {

					return err
				}
			}

			return nil
		}, func(tx walletstore.ReadTx) (storePlanStatus, error) {
			state, err := tx.Addr().SyncState()
			if err != nil {
				return storePlanConflict, err
			}

			switch {
			case sameBlockPosition(state.SyncedTo, plan.target):
				durable, err := recoveryPlanDurable(tx, plan)
				if err != nil || !durable {
					return storePlanConflict, err
				}
				return storePlanCommitted, nil

			case sameBlockPosition(state.SyncedTo, plan.start.tip):
				matches, err := recoveryAccountsMatch(
					tx.Addr(), plan.start.accounts,
				)
				if err != nil || !matches {
					return storePlanConflict, err
				}
				return storePlanAbsent, nil

			default:
				return storePlanConflict, nil
			}
		}, plan.scopes,
	)
}

// recoverStoreBatch prepares and commits one recovery batch, adopting its
// cloned state only after the database transaction is known to be durable.
func (w *Wallet) recoverStoreBatch(chainClient chain.Interface,
	recoveryMgr *RecoveryManager, batch []wtxmgr.BlockMeta,
	blocks []*waddrmgr.BlockStamp,
	scopedMgrs map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager) error {

	plan, err := w.prepareRecoveryStorePlan(
		chainClient, recoveryMgr.State(), batch, blocks, scopedMgrs,
	)
	if err != nil {
		return err
	}
	if err := w.applyRecoveryStorePlan(plan); err != nil {
		return err
	}

	recoveryMgr.state = plan.finalState
	return nil
}

// recoverScopedAddresses scans a range of blocks in attempts to recover any
// previously used addresses for a particular account derivation path. At a high
// level, the algorithm works as follows:
//
//  1. Ensure internal and external branch horizons are fully expanded.
//  2. Filter the entire range of blocks, stopping if a non-zero number of
//     address are contained in a particular block.
//  3. Record all internal and external addresses found in the block.
//  4. Record any outpoints found in the block that should be watched for spends
//  5. Trim the range of blocks up to and including the one reporting the addrs.
//  6. Repeat from (1) if there are still more blocks in the range.
//
// TODO(conner): parallelize/pipeline/cache intermediate network requests
func (w *Wallet) recoverScopedAddresses(
	chainClient chain.Interface,
	tx walletdb.ReadWriteTx,
	ns walletdb.ReadWriteBucket,
	batch []wtxmgr.BlockMeta,
	recoveryState *RecoveryState,
	scopedMgrs map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager) error {

	// If there are no blocks in the batch, we are done.
	if len(batch) == 0 {
		return nil
	}

	log.Infof("Scanning %d blocks for recoverable addresses", len(batch))

expandHorizons:
	for scope, scopedMgr := range scopedMgrs {
		scopeState := recoveryState.StateForScope(scope)
		err := expandScopeHorizons(ns, scopedMgr, scopeState)
		if err != nil {
			return err
		}
	}

	// With the internal and external horizons properly expanded, we now
	// construct the filter blocks request. The request includes the range
	// of blocks we intend to scan, in addition to the scope-index -> addr
	// map for all internal and external branches.
	filterReq := newFilterBlocksRequest(batch, scopedMgrs, recoveryState)

	// Initiate the filter blocks request using our chain backend. If an
	// error occurs, we are unable to proceed with the recovery.
	filterResp, err := chainClient.FilterBlocks(filterReq)
	if err != nil {
		return err
	}

	// If the filter response is empty, this signals that the rest of the
	// batch was completed, and no other addresses were discovered. As a
	// result, no further modifications to our recovery state are required
	// and we can proceed to the next batch.
	if filterResp == nil {
		return nil
	}

	// Otherwise, retrieve the block info for the block that detected a
	// non-zero number of address matches.
	block := batch[filterResp.BatchIndex]

	// Log any non-trivial findings of addresses or outpoints.
	logFilterBlocksResp(block, filterResp)

	// Report any external or internal addresses found as a result of the
	// appropriate branch recovery state. Adding indexes above the
	// last-found index of either will result in the horizons being expanded
	// upon the next iteration. Any found addresses are also marked used
	// using the scoped key manager.
	err = extendFoundAddresses(ns, filterResp, scopedMgrs, recoveryState)
	if err != nil {
		return err
	}

	// Update the global set of watched outpoints with any that were found
	// in the block.
	for outPoint, addr := range filterResp.FoundOutPoints {
		outPoint := outPoint
		recoveryState.AddWatchedOutPoint(&outPoint, addr)
	}

	// Finally, record all of the relevant transactions that were returned
	// in the filter blocks response. This ensures that these transactions
	// and their outputs are tracked when the final rescan is performed.
	for _, txn := range filterResp.RelevantTxns {
		txRecord, err := wtxmgr.NewTxRecordFromMsgTx(
			txn, filterResp.BlockMeta.Time,
		)
		if err != nil {
			return err
		}

		err = w.addRelevantTx(tx, txRecord, &filterResp.BlockMeta)
		if err != nil {
			return err
		}
	}

	// Update the batch to indicate that we've processed all block through
	// the one that returned found addresses.
	batch = batch[filterResp.BatchIndex+1:]

	// If this was not the last block in the batch, we will repeat the
	// filtering process again after expanding our horizons.
	if len(batch) > 0 {
		goto expandHorizons
	}

	return nil
}

// expandScopeHorizons ensures that the ScopeRecoveryState has an adequately
// sized look ahead for both its internal and external branches. The keys
// derived here are added to the scope's recovery state, but do not affect the
// persistent state of the wallet. If any invalid child keys are detected, the
// horizon will be properly extended such that our lookahead always includes the
// proper number of valid child keys.
func expandScopeHorizons(ns walletdb.ReadWriteBucket,
	scopedMgr *waddrmgr.ScopedKeyManager,
	scopeState *ScopeRecoveryState) error {

	// Compute the current external horizon and the number of addresses we
	// must derive to ensure we maintain a sufficient recovery window for
	// the external branch.
	exHorizon, exWindow := scopeState.ExternalBranch.ExtendHorizon()
	count, childIndex := uint32(0), exHorizon
	for count < exWindow {
		keyPath := externalKeyPath(childIndex)
		addr, err := scopedMgr.DeriveFromKeyPath(ns, keyPath)
		switch {
		case err == hdkeychain.ErrInvalidChild:
			// Record the existence of an invalid child with the
			// external branch's recovery state. This also
			// increments the branch's horizon so that it accounts
			// for this skipped child index.
			scopeState.ExternalBranch.MarkInvalidChild(childIndex)
			childIndex++
			continue

		case err != nil:
			return err
		}

		// Register the newly generated external address and child index
		// with the external branch recovery state.
		scopeState.ExternalBranch.AddAddr(childIndex, addr.Address())

		childIndex++
		count++
	}

	// Compute the current internal horizon and the number of addresses we
	// must derive to ensure we maintain a sufficient recovery window for
	// the internal branch.
	inHorizon, inWindow := scopeState.InternalBranch.ExtendHorizon()
	count, childIndex = 0, inHorizon
	for count < inWindow {
		keyPath := internalKeyPath(childIndex)
		addr, err := scopedMgr.DeriveFromKeyPath(ns, keyPath)
		switch {
		case err == hdkeychain.ErrInvalidChild:
			// Record the existence of an invalid child with the
			// internal branch's recovery state. This also
			// increments the branch's horizon so that it accounts
			// for this skipped child index.
			scopeState.InternalBranch.MarkInvalidChild(childIndex)
			childIndex++
			continue

		case err != nil:
			return err
		}

		// Register the newly generated internal address and child index
		// with the internal branch recovery state.
		scopeState.InternalBranch.AddAddr(childIndex, addr.Address())

		childIndex++
		count++
	}

	return nil
}

// externalKeyPath returns the relative external derivation path /0/0/index.
func externalKeyPath(index uint32) waddrmgr.DerivationPath {
	return waddrmgr.DerivationPath{
		InternalAccount: waddrmgr.DefaultAccountNum,
		Account:         waddrmgr.DefaultAccountNum,
		Branch:          waddrmgr.ExternalBranch,
		Index:           index,
	}
}

// internalKeyPath returns the relative internal derivation path /0/1/index.
func internalKeyPath(index uint32) waddrmgr.DerivationPath {
	return waddrmgr.DerivationPath{
		InternalAccount: waddrmgr.DefaultAccountNum,
		Account:         waddrmgr.DefaultAccountNum,
		Branch:          waddrmgr.InternalBranch,
		Index:           index,
	}
}

// newFilterBlocksRequest constructs FilterBlocksRequests using our current
// block range, scoped managers, and recovery state.
func newFilterBlocksRequest(batch []wtxmgr.BlockMeta,
	scopedMgrs map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager,
	recoveryState *RecoveryState) *chain.FilterBlocksRequest {

	filterReq := &chain.FilterBlocksRequest{
		Blocks:           batch,
		ExternalAddrs:    make(map[waddrmgr.ScopedIndex]address.Address),
		InternalAddrs:    make(map[waddrmgr.ScopedIndex]address.Address),
		WatchedOutPoints: recoveryState.WatchedOutPoints(),
	}

	// Populate the external and internal addresses by merging the addresses
	// sets belong to all currently tracked scopes.
	for scope := range scopedMgrs {
		scopeState := recoveryState.StateForScope(scope)
		for index, addr := range scopeState.ExternalBranch.Addrs() {
			scopedIndex := waddrmgr.ScopedIndex{
				Scope: scope,
				Index: index,
			}
			filterReq.ExternalAddrs[scopedIndex] = addr
		}
		for index, addr := range scopeState.InternalBranch.Addrs() {
			scopedIndex := waddrmgr.ScopedIndex{
				Scope: scope,
				Index: index,
			}
			filterReq.InternalAddrs[scopedIndex] = addr
		}
	}

	return filterReq
}

// extendFoundAddresses accepts a filter blocks response that contains addresses
// found on chain, and advances the state of all relevant derivation paths to
// match the highest found child index for each branch.
func extendFoundAddresses(ns walletdb.ReadWriteBucket,
	filterResp *chain.FilterBlocksResponse,
	scopedMgrs map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager,
	recoveryState *RecoveryState) error {

	// Mark all recovered external addresses as used. This will be done only
	// for scopes that reported a non-zero number of external addresses in
	// this block.
	for scope, indexes := range filterResp.FoundExternalAddrs {
		// First, report all external child indexes found for this
		// scope. This ensures that the external last-found index will
		// be updated to include the maximum child index seen thus far.
		scopeState := recoveryState.StateForScope(scope)
		for index := range indexes {
			scopeState.ExternalBranch.ReportFound(index)
		}

		scopedMgr := scopedMgrs[scope]

		// Now, with all found addresses reported, derive and extend all
		// external addresses up to and including the current last found
		// index for this scope.
		exNextUnfound := scopeState.ExternalBranch.NextUnfound()

		exLastFound := exNextUnfound
		if exLastFound > 0 {
			exLastFound--
		}

		err := scopedMgr.ExtendExternalAddresses(
			ns, waddrmgr.DefaultAccountNum, exLastFound,
		)
		if err != nil {
			return err
		}

		// Finally, with the scope's addresses extended, we mark used
		// the external addresses that were found in the block and
		// belong to this scope.
		for index := range indexes {
			addr := scopeState.ExternalBranch.GetAddr(index)
			err := scopedMgr.MarkUsed(ns, addr)
			if err != nil {
				return err
			}
		}
	}

	// Mark all recovered internal addresses as used. This will be done only
	// for scopes that reported a non-zero number of internal addresses in
	// this block.
	for scope, indexes := range filterResp.FoundInternalAddrs {
		// First, report all internal child indexes found for this
		// scope. This ensures that the internal last-found index will
		// be updated to include the maximum child index seen thus far.
		scopeState := recoveryState.StateForScope(scope)
		for index := range indexes {
			scopeState.InternalBranch.ReportFound(index)
		}

		scopedMgr := scopedMgrs[scope]

		// Now, with all found addresses reported, derive and extend all
		// internal addresses up to and including the current last found
		// index for this scope.
		inNextUnfound := scopeState.InternalBranch.NextUnfound()

		inLastFound := inNextUnfound
		if inLastFound > 0 {
			inLastFound--
		}
		err := scopedMgr.ExtendInternalAddresses(
			ns, waddrmgr.DefaultAccountNum, inLastFound,
		)
		if err != nil {
			return err
		}

		// Finally, with the scope's addresses extended, we mark used
		// the internal addresses that were found in the blockand belong
		// to this scope.
		for index := range indexes {
			addr := scopeState.InternalBranch.GetAddr(index)
			err := scopedMgr.MarkUsed(ns, addr)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// extendScopeAddressesFromStore persists sequential addresses through the
// requested child index using the existing Store-backed derivation methods.
func extendScopeAddressesFromStore(tx waddrmgr.ManagerReadWriteTx,
	scopedMgr *waddrmgr.ScopedKeyManager, lastIndex uint32,
	internal bool) error {

	for {
		account, err := tx.Account(
			scopedMgr.Scope(), waddrmgr.DefaultAccountNum,
		)
		if err != nil {
			return err
		}

		nextIndex := account.NextExternalIndex
		if internal {
			nextIndex = account.NextInternalIndex
		}
		if nextIndex > lastIndex {
			return nil
		}

		if internal {
			_, _, err = scopedMgr.NextInternalAddressFromStore(
				tx, waddrmgr.DefaultAccountNum,
			)
		} else {
			_, _, err = scopedMgr.NextExternalAddressFromStore(
				tx, waddrmgr.DefaultAccountNum,
			)
		}
		if err != nil {
			return err
		}
	}
}

// logFilterBlocksResp provides useful logging information when filtering
// succeeded in finding relevant transactions.
func logFilterBlocksResp(block wtxmgr.BlockMeta,
	resp *chain.FilterBlocksResponse) {

	// Log the number of external addresses found in this block.
	var nFoundExternal int
	for _, indexes := range resp.FoundExternalAddrs {
		nFoundExternal += len(indexes)
	}
	if nFoundExternal > 0 {
		log.Infof("Recovered %d external addrs at height=%d hash=%v",
			nFoundExternal, block.Height, block.Hash)
	}

	// Log the number of internal addresses found in this block.
	var nFoundInternal int
	for _, indexes := range resp.FoundInternalAddrs {
		nFoundInternal += len(indexes)
	}
	if nFoundInternal > 0 {
		log.Infof("Recovered %d internal addrs at height=%d hash=%v",
			nFoundInternal, block.Height, block.Hash)
	}

	// Log the number of outpoints found in this block.
	nFoundOutPoints := len(resp.FoundOutPoints)
	if nFoundOutPoints > 0 {
		log.Infof("Found %d spends from watched outpoints at "+
			"height=%d hash=%v",
			nFoundOutPoints, block.Height, block.Hash)
	}
}

type (
	createTxRequest struct {
		coinSelectKeyScope    *waddrmgr.KeyScope
		changeKeyScope        *waddrmgr.KeyScope
		account               uint32
		outputs               []*wire.TxOut
		minconf               int32
		feeSatPerKB           btcutil.Amount
		coinSelectionStrategy CoinSelectionStrategy
		dryRun                bool
		resp                  chan createTxResponse
		selectUtxos           []wire.OutPoint
		allowUtxo             func(wtxmgr.Credit) bool
	}
	createTxResponse struct {
		tx  *txauthor.AuthoredTx
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
	quit := w.quitChan()
out:
	for {
		select {
		case txr := <-w.createTxRequests:
			// If the wallet can be locked because it contains
			// private key material, we need to prevent it from
			// doing so while we are assembling the transaction.
			release := func() {}
			if !w.Manager.WatchOnly() {
				heldUnlock, err := w.holdUnlock()
				if err != nil {
					txr.resp <- createTxResponse{nil, err}
					continue
				}

				release = heldUnlock.release
			}

			tx, err := w.txToOutputs(
				txr.outputs, txr.coinSelectKeyScope,
				txr.changeKeyScope, txr.account, txr.minconf,
				txr.feeSatPerKB, txr.coinSelectionStrategy,
				txr.dryRun, txr.selectUtxos, txr.allowUtxo,
			)

			release()
			txr.resp <- createTxResponse{tx, err}
		case <-quit:
			break out
		}
	}
	w.wg.Done()
}

// txCreateOptions is a set of optional arguments to modify the tx creation
// process. This can be used to do things like use a custom coin selection
// scope, which otherwise will default to the specified coin selection scope.
type txCreateOptions struct {
	changeKeyScope *waddrmgr.KeyScope
	selectUtxos    []wire.OutPoint
	allowUtxo      func(wtxmgr.Credit) bool
}

// TxCreateOption is a set of optional arguments to modify the tx creation
// process. This can be used to do things like use a custom coin selection
// scope, which otherwise will default to the specified coin selection scope.
type TxCreateOption func(*txCreateOptions)

// defaultTxCreateOptions is the default set of options.
func defaultTxCreateOptions() *txCreateOptions {
	return &txCreateOptions{}
}

// WithCustomChangeScope can be used to specify a change scope for the change
// address. If unspecified, then the same scope will be used for both inputs
// and the change addr. Not specifying any scope at all (nil) will use all
// available coins and the default change scope (P2TR).
func WithCustomChangeScope(changeScope *waddrmgr.KeyScope) TxCreateOption {
	return func(opts *txCreateOptions) {
		opts.changeKeyScope = changeScope
	}
}

// WithCustomSelectUtxos is used to specify the inputs to be used while
// creating txns.
func WithCustomSelectUtxos(utxos []wire.OutPoint) TxCreateOption {
	return func(opts *txCreateOptions) {
		opts.selectUtxos = utxos
	}
}

// WithUtxoFilter is used to restrict the selection of the internal wallet
// inputs by further external conditions. Utxos which pass the filter are
// considered when creating the transaction.
func WithUtxoFilter(allowUtxo func(utxo wtxmgr.Credit) bool) TxCreateOption {
	return func(opts *txCreateOptions) {
		opts.allowUtxo = allowUtxo
	}
}

// CreateSimpleTx creates a new signed transaction spending unspent outputs with
// at least minconf confirmations spending to any number of address/amount
// pairs. Only unspent outputs belonging to the given key scope and account will
// be selected, unless a key scope is not specified. In that case, inputs from
// all accounts may be selected, regardless of key scope. This handles the
// default account case, where a user wants to fund a PSBT
// with inputs regardless of their type (NP2WKH, P2WKH, etc.). Change and an
// appropriate transaction fee are automatically included, if necessary. All
// transaction creation through this function is serialized to prevent the
// creation of many transactions which spend the same outputs.
//
// A set of functional options can be passed in to apply modifications to the
// tx creation process such as using a custom change scope, which otherwise
// defaults to the same as the specified coin selection scope.
//
// NOTE: The dryRun argument can be set true to create a tx that doesn't alter
// the database. A tx created with this set to true SHOULD NOT be broadcast.
func (w *Wallet) CreateSimpleTx(coinSelectKeyScope *waddrmgr.KeyScope,
	account uint32, outputs []*wire.TxOut, minconf int32,
	satPerKb btcutil.Amount, coinSelectionStrategy CoinSelectionStrategy,
	dryRun bool, optFuncs ...TxCreateOption) (*txauthor.AuthoredTx, error) {

	opts := defaultTxCreateOptions()
	for _, optFunc := range optFuncs {
		optFunc(opts)
	}

	// If the change scope isn't set, then it should be the same as the
	// coin selection scope in order to match existing behavior.
	if opts.changeKeyScope == nil {
		opts.changeKeyScope = coinSelectKeyScope
	}

	req := createTxRequest{
		coinSelectKeyScope:    coinSelectKeyScope,
		changeKeyScope:        opts.changeKeyScope,
		account:               account,
		outputs:               outputs,
		minconf:               minconf,
		feeSatPerKB:           satPerKb,
		coinSelectionStrategy: coinSelectionStrategy,
		dryRun:                dryRun,
		resp:                  make(chan createTxResponse),
		selectUtxos:           opts.selectUtxos,
		allowUtxo:             opts.allowUtxo,
	}
	w.createTxRequests <- req
	resp := <-req.resp
	return resp.tx, resp.err
}

type (
	unlockRequest struct {
		passphrase []byte
		lockAfter  <-chan time.Time // nil prevents the timeout.
		err        chan error
	}

	changePassphraseRequest struct {
		old, new []byte
		private  bool
		err      chan error
	}

	changePassphrasesRequest struct {
		publicOld, publicNew   []byte
		privateOld, privateNew []byte
		err                    chan error
	}

	// heldUnlock is a tool to prevent the wallet from automatically
	// locking after some timeout before an operation which needed
	// the unlocked wallet has finished.  Any acquired heldUnlock
	// *must* be released (preferably with a defer) or the wallet
	// will forever remain unlocked.
	heldUnlock chan struct{}
)

// endRecovery tells (*Wallet).recovery to stop, if running, and returns a
// channel that will be closed when the recovery routine exits.
func (w *Wallet) endRecovery() <-chan struct{} {
	if recoverySyncI := w.recovering.Load(); recoverySyncI != nil {
		recoverySync := recoverySyncI.(*recoverySyncer)

		// If recovery is still running, it will end early with an error
		// once we set the quit flag.
		atomic.StoreUint32(&recoverySync.quit, 1)

		return recoverySync.done
	}
	c := make(chan struct{})
	close(c)
	return c
}

// walletLocker manages the locked/unlocked state of a wallet.
func (w *Wallet) walletLocker() {
	var timeout <-chan time.Time
	holdChan := make(heldUnlock)
	quit := w.quitChan()
out:
	for {
		select {
		case req := <-w.unlockRequests:
			var err error
			if w.db != nil {
				err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
					addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
					return w.Manager.Unlock(
						addrmgrNs, req.passphrase,
					)
				})
			} else {
				err = w.Manager.UnlockFromStore(req.passphrase)
			}
			if err != nil {
				req.err <- err
				continue
			}
			timeout = req.lockAfter
			if timeout == nil {
				log.Info("The wallet has been unlocked without a time limit")
			} else {
				log.Info("The wallet has been temporarily unlocked")
			}
			req.err <- nil
			continue

		case req := <-w.changePassphrase:
			var err error
			if w.db != nil {
				err = walletdb.Update(
					w.db, func(tx walletdb.ReadWriteTx) error {
						addrmgrNs := tx.ReadWriteBucket(
							waddrmgrNamespaceKey,
						)
						return w.Manager.ChangePassphrase(
							addrmgrNs, req.old, req.new, req.private,
							&waddrmgr.DefaultScryptOptions,
						)
					},
				)
			} else {
				var change *waddrmgr.PassphraseChange
				err = w.store.UpdateOnce(
					context.Background(),
					func(tx walletstore.ReadWriteTx) error {
						var err error
						change, err =
							w.Manager.ChangePassphraseFromStore(
								tx.Addr(), req.old, req.new,
								req.private,
								&waddrmgr.DefaultScryptOptions,
							)
						return err
					}, nil,
				)
				if err == nil {
					change.Apply()
				} else {
					change.Close()
				}
			}
			req.err <- err
			continue

		case req := <-w.changePassphrases:
			var err error
			if w.db != nil {
				err = walletdb.Update(
					w.db, func(tx walletdb.ReadWriteTx) error {
						addrmgrNs := tx.ReadWriteBucket(
							waddrmgrNamespaceKey,
						)
						err := w.Manager.ChangePassphrase(
							addrmgrNs, req.publicOld, req.publicNew,
							false, &waddrmgr.DefaultScryptOptions,
						)
						if err != nil {
							return err
						}

						return w.Manager.ChangePassphrase(
							addrmgrNs, req.privateOld,
							req.privateNew, true,
							&waddrmgr.DefaultScryptOptions,
						)
					},
				)
			} else {
				var publicChange, privateChange *waddrmgr.PassphraseChange
				err = w.store.UpdateOnce(
					context.Background(),
					func(tx walletstore.ReadWriteTx) error {
						var err error
						publicChange, err =
							w.Manager.ChangePassphraseFromStore(
								tx.Addr(), req.publicOld,
								req.publicNew, false,
								&waddrmgr.DefaultScryptOptions,
							)
						if err != nil {
							return err
						}

						privateChange, err =
							w.Manager.ChangePassphraseFromStore(
								tx.Addr(), req.privateOld,
								req.privateNew, true,
								&waddrmgr.DefaultScryptOptions,
							)
						return err
					}, nil,
				)
				if err == nil {
					publicChange.Apply()
					privateChange.Apply()
				} else {
					publicChange.Close()
					privateChange.Close()
				}
			}
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

		case <-quit:
			break out

		case <-w.lockRequests:
		case <-timeout:
		}

		// Select statement fell through by an explicit lock or the
		// timer expiring.  Lock the manager here.

		// We can't lock the manager if recovery is active because we use
		// cryptoKeyPriv and cryptoKeyScript in recovery.
		<-w.endRecovery()

		timeout = nil
		err := w.Manager.Lock()
		if err != nil && !waddrmgr.IsError(err, waddrmgr.ErrLocked) {
			log.Errorf("Could not lock wallet: %v", err)
		} else {
			log.Info("The wallet has been locked")
		}
	}
	w.wg.Done()
}

// Unlock unlocks the wallet's address manager and relocks it after timeout has
// expired.  If the wallet is already unlocked and the new passphrase is
// correct, the current timeout is replaced with the new one.  The wallet will
// be locked if the passphrase is incorrect or any other error occurs during the
// unlock.
func (w *Wallet) Unlock(passphrase []byte, lock <-chan time.Time) error {
	err := make(chan error, 1)
	w.unlockRequests <- unlockRequest{
		passphrase: passphrase,
		lockAfter:  lock,
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

// WatchOnly returns whether the wallet contains no private key material.
func (w *Wallet) WatchOnly() bool {
	return w.Manager.WatchOnly()
}

// holdUnlock prevents the wallet from being locked.  The heldUnlock object
// *must* be released, or the wallet will forever remain unlocked.
//
// TODO: To prevent the above scenario, perhaps closures should be passed
// to the walletLocker goroutine and disallow callers from explicitly
// handling the locking mechanism.
func (w *Wallet) holdUnlock() (heldUnlock, error) {
	req := make(chan heldUnlock)
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

// release releases the hold on the unlocked-state of the wallet and allows the
// wallet to be locked again.  If a lock timeout has already expired, the
// wallet is locked again as soon as release is called.
func (c heldUnlock) release() {
	c <- struct{}{}
}

// ChangePrivatePassphrase attempts to change the passphrase for a wallet from
// old to new.  Changing the passphrase is synchronized with all other address
// manager locking and unlocking.  The lock state will be the same as it was
// before the password change.
func (w *Wallet) ChangePrivatePassphrase(old, new []byte) error {
	err := make(chan error, 1)
	w.changePassphrase <- changePassphraseRequest{
		old:     old,
		new:     new,
		private: true,
		err:     err,
	}
	return <-err
}

// ChangePublicPassphrase modifies the public passphrase of the wallet.
func (w *Wallet) ChangePublicPassphrase(old, new []byte) error {
	err := make(chan error, 1)
	w.changePassphrase <- changePassphraseRequest{
		old:     old,
		new:     new,
		private: false,
		err:     err,
	}
	return <-err
}

// ChangePassphrases modifies the public and private passphrase of the wallet
// atomically.
func (w *Wallet) ChangePassphrases(publicOld, publicNew, privateOld,
	privateNew []byte) error {

	err := make(chan error, 1)
	w.changePassphrases <- changePassphrasesRequest{
		publicOld:  publicOld,
		publicNew:  publicNew,
		privateOld: privateOld,
		privateNew: privateNew,
		err:        err,
	}
	return <-err
}

// AccountAddresses returns the addresses for every created address for an
// account.
func (w *Wallet) AccountAddresses(account uint32) ([]address.Address, error) {
	var addrs []address.Address

	var err error
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

			return w.Manager.ForEachAccountAddress(
				addrmgrNs, account,
				func(maddr waddrmgr.ManagedAddress) error {
					addrs = append(addrs, maddr.Address())
					return nil
				},
			)
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				return w.Manager.ForEachAccountAddressFromStore(
					tx.Addr(), account,
					func(maddr waddrmgr.ManagedAddress) error {
						addrs = append(addrs, maddr.Address())
						return nil
					},
				)
			}, func() {
				addrs = nil
			},
		)
	}
	if err != nil {
		return nil, err
	}

	return addrs, nil
}

// AccountManagedAddresses returns the managed addresses for every created
// address for an account.
func (w *Wallet) AccountManagedAddresses(scope waddrmgr.KeyScope,
	accountNum uint32) ([]waddrmgr.ManagedAddress, error) {

	scopedMgr, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	addrs := make([]waddrmgr.ManagedAddress, 0)

	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

			return scopedMgr.ForEachAccountAddress(
				addrmgrNs, accountNum,
				func(a waddrmgr.ManagedAddress) error {
					addrs = append(addrs, a)

					return nil
				},
			)
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				return scopedMgr.ForEachAccountAddressFromStore(
					tx.Addr(), accountNum,
					func(a waddrmgr.ManagedAddress) error {
						addrs = append(addrs, a)
						return nil
					},
				)
			}, func() {
				addrs = nil
			},
		)
	}
	if err != nil {
		return nil, err
	}

	return addrs, nil
}

// CalculateBalance sums the amounts of all unspent transaction
// outputs to addresses of a wallet and returns the balance.
//
// If confirmations is 0, all UTXOs, even those not present in a
// block (height -1), will be used to get the balance.  Otherwise,
// a UTXO must be in a block.  If confirmations is 1 or greater,
// the balance will be calculated based on how many how many blocks
// include a UTXO.
func (w *Wallet) CalculateBalance(confirms int32) (btcutil.Amount, error) {
	var balance btcutil.Amount
	err := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			var err error
			block := w.Manager.SyncedTo()
			balance, err = tx.Tx().Balance(
				confirms, block.Height,
			)
			return err
		}, func() {
			balance = 0
		},
	)

	return balance, err
}

// Balances records total, spendable (by policy), and immature coinbase
// reward balance amounts.
type Balances struct {
	// Total is the account's total unspent balance.
	Total btcutil.Amount

	// Spendable is the account balance available under current policy.
	Spendable btcutil.Amount

	// ImmatureReward is the account's immature coinbase balance.
	ImmatureReward btcutil.Amount
}

// CalculateAccountBalances sums the amounts of all unspent transaction
// outputs to the given account of a wallet and returns the balance.
//
// This function is much slower than it needs to be since transactions outputs
// are not indexed by the accounts they credit to, and all unspent transaction
// outputs must be iterated.
func (w *Wallet) CalculateAccountBalances(account uint32,
	confirms int32) (Balances, error) {

	var bals Balances
	err := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			// Get current block.  The block height used for calculating
			// the number of tx confirmations.
			syncBlock := w.Manager.SyncedTo()

			unspent, err := tx.Tx().UnspentOutputs()
			if err != nil {
				return err
			}
			for i := range unspent {
				output := &unspent[i]

				var outputAcct uint32
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(
					output.PkScript, w.chainParams)
				if err == nil && len(addrs) > 0 {
					_, outputAcct, err = w.Manager.AddrAccountFromStore(
						tx.Addr(), addrs[0],
					)
				}
				if err != nil || outputAcct != account {
					continue
				}

				bals.Total += output.Amount
				if output.FromCoinBase && !hasMinConfs(
					int32(w.chainParams.CoinbaseMaturity),
					output.Height, syncBlock.Height,
				) {

					bals.ImmatureReward += output.Amount
				} else if hasMinConfs(
					confirms, output.Height, syncBlock.Height,
				) {

					bals.Spendable += output.Amount
				}
			}
			return nil
		}, func() {
			bals = Balances{}
		})

	return bals, err
}

// CurrentAddress gets the most recently requested Bitcoin payment address
// from a wallet for a particular key-chain scope.  If the address has already
// been used (there is at least one transaction spending to it in the
// blockchain or btcd mempool), the next chained address is returned.
func (w *Wallet) CurrentAddress(account uint32,
	scope waddrmgr.KeyScope) (address.Address, error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	// The address manager uses OnCommit on the walletdb tx to update the
	// in-memory state of the account state. But because the commit happens
	// _after_ the account manager internal lock has been released, there
	// is a chance for the address index to be accessed concurrently, even
	// though the closure in OnCommit re-acquires the lock. To avoid this
	// issue, we surround the whole address creation process with a lock.
	w.newAddrMtx.Lock()
	defer w.newAddrMtx.Unlock()

	var (
		addr  address.Address
		props *waddrmgr.AccountProperties
	)
	if w.db != nil {
		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			maddr, err := manager.LastExternalAddress(addrmgrNs, account)
			if err != nil {
				// If no address exists yet, create the first external
				// address.
				if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
					addr, props, err = w.newAddress(
						addrmgrNs, account, scope,
					)
				}
				return err
			}

			// Get next chained address if the last one has already been
			// used.
			if maddr.Used(addrmgrNs) {
				addr, props, err = w.newAddress(
					addrmgrNs, account, scope,
				)
				return err
			}

			addr = maddr.Address()
			return nil
		})
	} else {
		err = w.store.UpdateOnce(
			context.Background(),
			func(tx walletstore.ReadWriteTx) error {
				maddr, err := manager.LastExternalAddressFromStore(
					tx.Addr(), account,
				)
				if waddrmgr.IsError(
					err, waddrmgr.ErrAddressNotFound,
				) {

					maddr, props, err =
						manager.NextExternalAddressFromStore(
							tx.Addr(), account,
						)
				}
				if err != nil {
					return err
				}

				if maddr.Used(nil) {
					maddr, props, err =
						manager.NextExternalAddressFromStore(
							tx.Addr(), account,
						)
					if err != nil {
						return err
					}
				}

				addr = maddr.Address()
				return nil
			}, func() {
				addr = nil
				props = nil
			},
		)
	}
	if err != nil {
		var ambiguous *walletstore.AmbiguousCommitError
		if w.db == nil && errors.As(err, &ambiguous) {
			w.Manager.MarkAccountCacheStale(scope, account)
		}

		return nil, err
	}

	// If the props have been initially, then we had to create a new address
	// to satisfy the query. Notify the rpc server about the new address.
	if props != nil {
		err = chainClient.NotifyReceived([]address.Address{addr})
		if err != nil {
			return nil, err
		}

		w.NtfnServer.notifyAccountProperties(props)
	}

	return addr, nil
}

// PubKeyForAddress looks up the associated public key for a P2PKH address.
func (w *Wallet) PubKeyForAddress(a address.Address) (*btcec.PublicKey, error) {
	var pubKey *btcec.PublicKey
	readAddress := func(managedAddr waddrmgr.ManagedAddress) error {
		managedPubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return errors.New("address does not have an associated public key")
		}
		pubKey = managedPubKeyAddr.PubKey()
		return nil
	}

	var err error
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			managedAddr, err := w.Manager.Address(addrmgrNs, a)
			if err != nil {
				return err
			}

			return readAddress(managedAddr)
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				managedAddr, err := w.Manager.AddressFromStore(
					tx.Addr(), a,
				)
				if err != nil {
					return err
				}

				return readAddress(managedAddr)
			}, nil,
		)
	}
	return pubKey, err
}

// LabelTransaction adds a label to the transaction with the hash provided. The
// call will fail if the label is too long, or if the transaction already has
// a label and the overwrite boolean is not set.
func (w *Wallet) LabelTransaction(hash chainhash.Hash, label string,
	overwrite bool) error {

	return w.store.UpdateOnce(
		context.Background(), func(tx walletstore.ReadWriteTx) error {
			details, err := tx.Tx().TxDetails(&hash)
			if err != nil {
				return err
			}
			if details == nil {
				return ErrUnknownTransaction
			}

			existing, err := tx.Tx().TxLabel(hash)
			if err != nil {
				return err
			}
			if existing != "" && !overwrite {
				return ErrTxLabelExists
			}

			return tx.Tx().PutTxLabel(hash, label)
		}, nil)
}

// PrivKeyForAddress looks up the associated private key for a P2PKH or P2PK
// address.
func (w *Wallet) PrivKeyForAddress(
	a address.Address) (*btcec.PrivateKey, error) {

	var privKey *btcec.PrivateKey
	readAddress := func(managedAddr waddrmgr.ManagedAddress) error {
		managedPubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return errors.New("address does not have an associated private key")
		}
		var err error
		privKey, err = managedPubKeyAddr.PrivKey()
		return err
	}

	var err error
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			managedAddr, err := w.Manager.Address(addrmgrNs, a)
			if err != nil {
				return err
			}

			return readAddress(managedAddr)
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				managedAddr, err := w.Manager.AddressFromStore(
					tx.Addr(), a,
				)
				if err != nil {
					return err
				}

				return readAddress(managedAddr)
			}, nil,
		)
	}
	return privKey, err
}

// HaveAddress returns whether the wallet is the owner of the address a.
func (w *Wallet) HaveAddress(a address.Address) (bool, error) {
	var err error
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			_, err := w.Manager.Address(addrmgrNs, a)
			return err
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				_, err := w.Manager.AddressFromStore(tx.Addr(), a)
				return err
			}, nil,
		)
	}
	if err == nil {
		return true, nil
	}
	if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
		return false, nil
	}
	return false, err
}

// AccountOfAddress finds the account that an address is associated with.
func (w *Wallet) AccountOfAddress(a address.Address) (uint32, error) {
	var account uint32
	var err error
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			var err error
			_, account, err = w.Manager.AddrAccount(addrmgrNs, a)
			return err
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				var err error
				_, account, err = w.Manager.AddrAccountFromStore(
					tx.Addr(), a,
				)
				return err
			}, func() {
				account = 0
			},
		)
	}
	return account, err
}

// AddressInfo returns detailed information regarding a wallet address.
func (w *Wallet) AddressInfo(
	a address.Address) (waddrmgr.ManagedAddress, error) {

	var managedAddress waddrmgr.ManagedAddress
	var err error
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			var err error
			managedAddress, err = w.Manager.Address(addrmgrNs, a)
			return err
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				var err error
				managedAddress, err = w.Manager.AddressFromStore(
					tx.Addr(), a,
				)
				return err
			}, func() {
				managedAddress = nil
			},
		)
	}
	return managedAddress, err
}

// AccountNumber returns the account number for an account name under a
// particular key scope.
func (w *Wallet) AccountNumber(scope waddrmgr.KeyScope,
	accountName string) (uint32, error) {

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return 0, err
	}

	var account uint32
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			var err error
			account, err = manager.LookupAccount(addrmgrNs, accountName)
			return err
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				var err error
				account, err = manager.LookupAccountFromStore(
					tx.Addr(), accountName,
				)
				return err
			}, func() {
				account = 0
			},
		)
	}
	return account, err
}

// AccountName returns the name of an account.
func (w *Wallet) AccountName(scope waddrmgr.KeyScope,
	accountNumber uint32) (string, error) {

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return "", err
	}

	var accountName string
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			var err error
			accountName, err = manager.AccountName(
				addrmgrNs, accountNumber,
			)
			return err
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				var err error
				accountName, err = manager.AccountNameFromStore(
					tx.Addr(), accountNumber,
				)
				return err
			}, func() {
				accountName = ""
			},
		)
	}
	return accountName, err
}

// AccountProperties returns the properties of an account, including address
// indexes and name. It first fetches the desynced information from the address
// manager, then updates the indexes based on the address pools.
func (w *Wallet) AccountProperties(scope waddrmgr.KeyScope,
	acct uint32) (*waddrmgr.AccountProperties, error) {

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var props *waddrmgr.AccountProperties
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			waddrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			var err error
			props, err = manager.AccountProperties(waddrmgrNs, acct)
			return err
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				var err error
				props, err = manager.AccountPropertiesFromStore(
					tx.Addr(), acct,
				)
				return err
			}, func() {
				props = nil
			},
		)
	}
	return props, err
}

// AccountPropertiesByName returns the properties of an account by its name. It
// first fetches the desynced information from the address manager, then updates
// the indexes based on the address pools.
func (w *Wallet) AccountPropertiesByName(scope waddrmgr.KeyScope,
	name string) (*waddrmgr.AccountProperties, error) {

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var props *waddrmgr.AccountProperties
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			waddrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			acct, err := manager.LookupAccount(waddrmgrNs, name)
			if err != nil {
				return err
			}
			props, err = manager.AccountProperties(waddrmgrNs, acct)
			return err
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				acct, err := manager.LookupAccountFromStore(
					tx.Addr(), name,
				)
				if err != nil {
					return err
				}
				props, err = manager.AccountPropertiesFromStore(
					tx.Addr(), acct,
				)
				return err
			}, func() {
				props = nil
			},
		)
	}
	return props, err
}

// LookupAccount returns the corresponding key scope and account number for the
// account with the given name.
func (w *Wallet) LookupAccount(name string) (waddrmgr.KeyScope, uint32, error) {
	var (
		keyScope waddrmgr.KeyScope
		account  uint32
	)
	var err error
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			ns := tx.ReadBucket(waddrmgrNamespaceKey)
			var err error
			keyScope, account, err = w.Manager.LookupAccount(ns, name)
			return err
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				var err error
				keyScope, account, err =
					w.Manager.LookupAccountFromStore(tx.Addr(), name)
				return err
			}, func() {
				keyScope = waddrmgr.KeyScope{}
				account = 0
			},
		)
	}
	return keyScope, account, err
}

// RenameAccount sets the name for an account number to newName.
func (w *Wallet) RenameAccount(scope waddrmgr.KeyScope, account uint32,
	newName string) error {

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return err
	}

	var props *waddrmgr.AccountProperties
	if w.db != nil {
		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			err := manager.RenameAccount(addrmgrNs, account, newName)
			if err != nil {
				return err
			}
			props, err = manager.AccountProperties(addrmgrNs, account)
			return err
		})
	} else {
		err = w.store.UpdateOnce(
			context.Background(),
			func(tx walletstore.ReadWriteTx) error {
				var err error
				props, err = manager.RenameAccountFromStore(
					tx.Addr(), account, newName,
				)
				return err
			}, func() {
				props = nil
			},
		)
	}
	if w.db == nil {
		var ambiguous *walletstore.AmbiguousCommitError
		if errors.As(err, &ambiguous) {
			w.Manager.MarkAccountCacheStale(scope, account)
		}
	}
	if err == nil {
		w.NtfnServer.notifyAccountProperties(props)
	}
	return err
}

// NextAccount creates the next account and returns its account number.  The
// name must be unique to the account.  In order to support automatic seed
// restoring, new accounts may not be created when all of the previous 100
// accounts have no transaction history (this is a deviation from the BIP0044
// spec, which allows no unused account gaps).
func (w *Wallet) NextAccount(scope waddrmgr.KeyScope,
	name string) (uint32, error) {

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return 0, err
	}

	var (
		account uint32
		props   *waddrmgr.AccountProperties
	)
	if w.db != nil {
		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			var err error
			account, err = manager.NewAccount(addrmgrNs, name)
			if err != nil {
				return err
			}
			props, err = manager.AccountProperties(addrmgrNs, account)
			return err
		})
	} else {
		err = w.store.UpdateOnce(
			context.Background(),
			func(tx walletstore.ReadWriteTx) error {
				var err error
				account, props, err = manager.NewAccountFromStore(
					tx.Addr(), name,
				)
				return err
			}, func() {
				account = 0
				props = nil
			},
		)
	}
	if err != nil {
		log.Errorf("Cannot fetch new account properties for notification "+
			"after account creation: %v", err)
	} else {
		w.NtfnServer.notifyAccountProperties(props)
	}
	return account, err
}

// CreditCategory describes the type of wallet transaction output.  The category
// of "sent transactions" (debits) is always "send", and is not expressed by
// this type.
//
// TODO: This is a requirement of the RPC server and should be moved.
type CreditCategory byte

const (
	// CreditReceive identifies a non-coinbase received output.
	CreditReceive CreditCategory = iota

	// CreditGenerate identifies a mature coinbase output.
	CreditGenerate

	// CreditImmature identifies an immature coinbase output.
	CreditImmature
)

// String returns the category as a string.  This string may be used as the
// JSON string for categories as part of listtransactions and gettransaction
// RPC responses.
func (c CreditCategory) String() string {
	switch c {
	case CreditReceive:
		return "receive"
	case CreditGenerate:
		return "generate"
	case CreditImmature:
		return "immature"
	default:
		return "unknown"
	}
}

// RecvCategory returns the category of received credit outputs from a
// transaction record.  The passed block chain height is used to distinguish
// immature from mature coinbase outputs.
//
// TODO: This is intended for use by the RPC server and should be moved out of
// this package at a later time.
func RecvCategory(details *wtxmgr.TxDetails, syncHeight int32,
	net *chaincfg.Params) CreditCategory {

	if blockchain.IsCoinBaseTx(&details.MsgTx) {
		if hasMinConfs(
			int32(net.CoinbaseMaturity), details.Block.Height,
			syncHeight,
		) {

			return CreditGenerate
		}
		return CreditImmature
	}
	return CreditReceive
}

// listTransactions creates a object that may be marshalled to a response result
// for a listtransactions RPC.
//
// TODO: This should be moved to the legacyrpc package.
//
//nolint:cyclop,gocognit
func listTransactions(tx walletdb.ReadTx, details *wtxmgr.TxDetails,
	addrMgr *waddrmgr.Manager, syncHeight int32,
	net *chaincfg.Params) []btcjson.ListTransactionsResult {

	addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

	var (
		blockHashStr  string
		blockTime     int64
		confirmations int64
	)
	if details.Block.Height != -1 {
		blockHashStr = details.Block.Hash.String()
		blockTime = details.Block.Time.Unix()
		confirmations = int64(
			calcConf(details.Block.Height, syncHeight),
		)
	}

	results := []btcjson.ListTransactionsResult{}
	txHashStr := details.Hash.String()
	received := details.Received.Unix()
	generated := blockchain.IsCoinBaseTx(&details.MsgTx)
	recvCat := RecvCategory(details, syncHeight, net).String()

	send := len(details.Debits) != 0

	// Fee can only be determined if every input is a debit.
	var feeF64 float64
	if len(details.Debits) == len(details.MsgTx.TxIn) {
		var debitTotal btcutil.Amount
		for _, deb := range details.Debits {
			debitTotal += deb.Amount
		}
		var outputTotal btcutil.Amount
		for _, output := range details.MsgTx.TxOut {
			outputTotal += btcutil.Amount(output.Value)
		}
		// Note: The actual fee is debitTotal - outputTotal.  However,
		// this RPC reports negative numbers for fees, so the inverse
		// is calculated.
		feeF64 = (outputTotal - debitTotal).ToBTC()
	}

outputs:
	for i, output := range details.MsgTx.TxOut {
		// Determine if this output is a credit, and if so, determine
		// its spentness.
		var isCredit bool
		var spentCredit bool
		for _, cred := range details.Credits {
			if cred.Index == uint32(i) {
				// Change outputs are ignored.
				if cred.Change {
					continue outputs
				}

				isCredit = true
				spentCredit = cred.Spent
				break
			}
		}

		var address string
		var accountName string
		_, addrs, _, _ := txscript.ExtractPkScriptAddrs(output.PkScript, net)
		if len(addrs) == 1 {
			addr := addrs[0]
			address = addr.EncodeAddress()
			mgr, account, err := addrMgr.AddrAccount(addrmgrNs, addrs[0])
			if err == nil {
				accountName, err = mgr.AccountName(addrmgrNs, account)
				if err != nil {
					accountName = ""
				}
			}
		}

		amountF64 := btcutil.Amount(output.Value).ToBTC()
		result := btcjson.ListTransactionsResult{
			// Fields left zeroed:
			//   InvolvesWatchOnly
			//   BlockIndex
			//
			// Fields set below:
			//   Account (only for non-"send" categories)
			//   Category
			//   Amount
			//   Fee
			Address:         address,
			Vout:            uint32(i),
			Confirmations:   confirmations,
			Generated:       generated,
			BlockHash:       blockHashStr,
			BlockTime:       blockTime,
			TxID:            txHashStr,
			WalletConflicts: []string{},
			Time:            received,
			TimeReceived:    received,
		}

		// Add a received/generated/immature result if this is a credit.
		// If the output was spent, create a second result under the
		// send category with the inverse of the output amount.  It is
		// therefore possible that a single output may be included in
		// the results set zero, one, or two times.
		//
		// Since credits are not saved for outputs that are not
		// controlled by this wallet, all non-credits from transactions
		// with debits are grouped under the send category.

		if send || spentCredit {
			result.Category = "send"
			result.Amount = -amountF64
			result.Fee = &feeF64
			results = append(results, result)
		}
		if isCredit {
			result.Account = accountName
			result.Category = recvCat
			result.Amount = amountF64
			result.Fee = nil
			results = append(results, result)
		}
	}
	return results
}

// ListSinceBlock returns a slice of objects with details about transactions
// since the given block. If the block is -1 then all transactions are included.
// This is intended to be used for listsinceblock RPC replies.
func (w *Wallet) ListSinceBlock(start, end,
	syncHeight int32) ([]btcjson.ListTransactionsResult, error) {

	txList := []btcjson.ListTransactionsResult{}
	err := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
				for _, detail := range details {
					detail := detail

					jsonResults := listTransactionsFromStore(
						tx, w, &detail, syncHeight,
					)
					txList = append(txList, jsonResults...)
				}
				return false, nil
			}

			return tx.Tx().RangeTransactions(start, end, rangeFn)
		}, func() {
			txList = txList[:0]
		})

	return txList, err
}

// ListTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listtransactions RPC
// replies.
func (w *Wallet) ListTransactions(from,
	count int) ([]btcjson.ListTransactionsResult, error) {

	txList := []btcjson.ListTransactionsResult{}

	err := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			// Get current block.  The block height used for calculating
			// the number of tx confirmations.
			syncBlock := w.Manager.SyncedTo()

			// Need to skip the first from transactions, and after those, only
			// include the next count transactions.
			skipped := 0
			n := 0

			rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
				// Iterate over transactions at this height in reverse order.
				// This does nothing for unmined transactions, which are
				// unsorted, but it will process mined transactions in the
				// reverse order they were marked mined.
				for i := len(details) - 1; i >= 0; i-- {
					if from > skipped {
						skipped++
						continue
					}

					n++
					if n > count {
						return true, nil
					}

					jsonResults := listTransactionsFromStore(
						tx, w, &details[i], syncBlock.Height,
					)
					txList = append(txList, jsonResults...)

					if len(jsonResults) > 0 {
						n++
					}
				}

				return false, nil
			}

			// Return newer results first by starting at mempool height and
			// working down to the genesis block.
			return tx.Tx().RangeTransactions(-1, 0, rangeFn)
		}, func() {
			txList = txList[:0]
		})

	return txList, err
}

// ListAddressTransactions returns a slice of objects with details about
// recorded transactions to or from any address belonging to a set.  This is
// intended to be used for listaddresstransactions RPC replies.
func (w *Wallet) ListAddressTransactions(
	pkHashes map[string]struct{}) ([]btcjson.ListTransactionsResult, error) {

	txList := []btcjson.ListTransactionsResult{}
	err := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			// Get current block.  The block height used for calculating
			// the number of tx confirmations.
			syncBlock := w.Manager.SyncedTo()
			rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
			loopDetails:
				for i := range details {
					detail := &details[i]

					for _, cred := range detail.Credits {
						pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
						_, addrs, _, err := txscript.ExtractPkScriptAddrs(
							pkScript, w.chainParams)
						if err != nil || len(addrs) != 1 {
							continue
						}

						apkh, ok := addrs[0].(*address.AddressPubKeyHash)
						if !ok {
							continue
						}
						_, ok = pkHashes[string(apkh.ScriptAddress())]
						if !ok {
							continue
						}

						jsonResults := listTransactionsFromStore(
							tx, w, detail, syncBlock.Height,
						)
						txList = append(txList, jsonResults...)
						continue loopDetails
					}
				}
				return false, nil
			}

			return tx.Tx().RangeTransactions(0, -1, rangeFn)
		}, func() {
			txList = txList[:0]
		})

	return txList, err
}

// ListAllTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listalltransactions RPC
// replies.
func (w *Wallet) ListAllTransactions() ([]btcjson.ListTransactionsResult,
	error) {

	txList := []btcjson.ListTransactionsResult{}
	err := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			// Get current block.  The block height used for calculating
			// the number of tx confirmations.
			syncBlock := w.Manager.SyncedTo()

			rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
				// Iterate over transactions at this height in reverse order.
				// This does nothing for unmined transactions, which are
				// unsorted, but it will process mined transactions in the
				// reverse order they were marked mined.
				for i := len(details) - 1; i >= 0; i-- {
					jsonResults := listTransactionsFromStore(
						tx, w, &details[i], syncBlock.Height,
					)
					txList = append(txList, jsonResults...)
				}
				return false, nil
			}

			// Return newer results first by starting at mempool height and
			// working down to the genesis block.
			return tx.Tx().RangeTransactions(-1, 0, rangeFn)
		}, func() {
			txList = txList[:0]
		})

	return txList, err
}

// BlockIdentifier identifies a block by either a height or a hash.
type BlockIdentifier struct {
	height int32
	hash   *chainhash.Hash
}

// NewBlockIdentifierFromHeight constructs a BlockIdentifier for a block height.
func NewBlockIdentifierFromHeight(height int32) *BlockIdentifier {
	return &BlockIdentifier{height: height}
}

// NewBlockIdentifierFromHash constructs a BlockIdentifier for a block hash.
func NewBlockIdentifierFromHash(hash *chainhash.Hash) *BlockIdentifier {
	return &BlockIdentifier{hash: hash}
}

// GetTransactionsResult is the result of the wallet's GetTransactions method.
// See GetTransactions for more details.
type GetTransactionsResult struct {
	// MinedTransactions groups confirmed transactions by block.
	MinedTransactions []Block

	// UnminedTransactions contains currently unconfirmed transactions.
	UnminedTransactions []TransactionSummary
}

// GetTransactions returns transaction results between a starting and ending
// block.  Blocks in the block range may be specified by either a height or a
// hash.
//
// Because this is a possibly lenghtly operation, a cancel channel is provided
// to cancel the task.  If this channel unblocks, the results created thus far
// will be returned.
//
// Transaction results are organized by blocks in ascending order and unmined
// transactions in an unspecified order.  Mined transactions are saved in a
// Block structure which records properties about the block.
func (w *Wallet) GetTransactions(startBlock, endBlock *BlockIdentifier,
	_ string, cancel <-chan struct{}) (*GetTransactionsResult, error) {

	var start, end int32 = 0, -1

	w.chainClientLock.Lock()
	chainClient := w.chainClient
	w.chainClientLock.Unlock()

	// TODO: Fetching block heights by their hashes is inherently racy
	// because not all block headers are saved but when they are for SPV the
	// db can be queried directly without this.
	if startBlock != nil {
		if startBlock.hash == nil {
			start = startBlock.height
		} else {
			if chainClient == nil {
				return nil, errors.New("no chain server client")
			}
			switch client := chainClient.(type) {
			case *chain.RPCClient:
				startHeader, err := client.GetBlockHeaderVerbose(
					startBlock.hash,
				)
				if err != nil {
					return nil, err
				}
				start = startHeader.Height
			case *chain.BitcoindClient:
				var err error
				start, err = client.GetBlockHeight(startBlock.hash)
				if err != nil {
					return nil, err
				}
			case *chain.NeutrinoClient:
				var err error
				start, err = client.GetBlockHeight(startBlock.hash)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	if endBlock != nil {
		if endBlock.hash == nil {
			end = endBlock.height
		} else {
			if chainClient == nil {
				return nil, errors.New("no chain server client")
			}
			switch client := chainClient.(type) {
			case *chain.RPCClient:
				endHeader, err := client.GetBlockHeaderVerbose(
					endBlock.hash,
				)
				if err != nil {
					return nil, err
				}
				end = endHeader.Height
			case *chain.BitcoindClient:
				var err error
				start, err = client.GetBlockHeight(endBlock.hash)
				if err != nil {
					return nil, err
				}
			case *chain.NeutrinoClient:
				var err error
				end, err = client.GetBlockHeight(endBlock.hash)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	var res GetTransactionsResult
	err := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
				// TODO: probably should make RangeTransactions not reuse the
				// details backing array memory.
				dets := make([]wtxmgr.TxDetails, len(details))
				copy(dets, details)
				details = dets

				txs := make([]TransactionSummary, 0, len(details))
				for i := range details {
					txs = append(
						txs, makeTxSummaryFromStore(tx, w, &details[i]),
					)
				}

				if details[0].Block.Height != -1 {
					blockHash := details[0].Block.Hash
					res.MinedTransactions = append(res.MinedTransactions, Block{
						Hash:         &blockHash,
						Height:       details[0].Block.Height,
						Timestamp:    details[0].Block.Time.Unix(),
						Transactions: txs,
					})
				} else {
					res.UnminedTransactions = txs
				}

				select {
				case <-cancel:
					return true, nil
				default:
					return false, nil
				}
			}

			return tx.Tx().RangeTransactions(start, end, rangeFn)
		}, func() {
			res = GetTransactionsResult{}
		})

	return &res, err
}

// GetTransactionResult returns a summary of the transaction along with
// other block properties.
type GetTransactionResult struct {
	// Summary contains the transaction's wallet-relevant details.
	Summary TransactionSummary

	// Height is the transaction's block height or -1 when unmined.
	Height int32

	// BlockHash identifies the transaction's block when mined.
	BlockHash *chainhash.Hash

	// Confirmations is the transaction's current confirmation count.
	Confirmations int32

	// Timestamp is the transaction's block time when mined.
	Timestamp int64
}

// GetTransaction returns detailed data of a transaction given its id. In
// addition it returns properties about its block.
func (w *Wallet) GetTransaction(txHash chainhash.Hash) (*GetTransactionResult,
	error) {

	var res GetTransactionResult
	err := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			txDetail, err := tx.Tx().TxDetails(&txHash)
			if err != nil {
				return err
			}

			// If the transaction was not found we return an error.
			if txDetail == nil {
				return fmt.Errorf("%w: txid %v", ErrNoTx, txHash)
			}

			res = GetTransactionResult{
				Summary:       makeTxSummaryFromStore(tx, w, txDetail),
				BlockHash:     nil,
				Height:        -1,
				Confirmations: 0,
				Timestamp:     0,
			}

			// If it is a confirmed transaction we set the corresponding
			// block height, timestamp, hash, and confirmations.
			if txDetail.Block.Height != -1 {
				res.Height = txDetail.Block.Height
				res.Timestamp = txDetail.Block.Time.Unix()
				res.BlockHash = &txDetail.Block.Hash

				bestBlock := w.SyncedTo()
				blockHeight := txDetail.Block.Height
				res.Confirmations = calcConf(
					blockHeight, bestBlock.Height,
				)
			}

			return nil
		}, func() {
			res = GetTransactionResult{}
		})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// AccountResult is a single account result for the AccountsResult type.
type AccountResult struct {
	// AccountProperties contains the address manager's account metadata.
	waddrmgr.AccountProperties

	// TotalBalance is the account's total unspent balance.
	TotalBalance btcutil.Amount
}

// AccountsResult is the result of the wallet's Accounts method.  See that
// method for more details.
type AccountsResult struct {
	// Accounts contains the properties and balance of each account.
	Accounts []AccountResult

	// CurrentBlockHash identifies the chain tip used for the balances.
	CurrentBlockHash *chainhash.Hash

	// CurrentBlockHeight is the chain tip height used for the balances.
	CurrentBlockHeight int32
}

// Accounts returns the current names, numbers, and total balances of all
// accounts in the wallet restricted to a particular key scope.  The current
// chain tip is included in the result for atomicity reasons.
//
// TODO(jrick): Is the chain tip really needed, since only the total balances
// are included?
func (w *Wallet) Accounts(scope waddrmgr.KeyScope) (*AccountsResult, error) {
	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var (
		accounts        []AccountResult
		syncBlockHash   *chainhash.Hash
		syncBlockHeight int32
	)
	if w.db == nil {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				syncBlock := w.Manager.SyncedTo()
				syncBlockHash = &syncBlock.Hash
				syncBlockHeight = syncBlock.Height

				unspent, err := tx.Tx().UnspentOutputs()
				if err != nil {
					return err
				}
				err = manager.ForEachAccountFromStore(
					tx.Addr(), func(account uint32) error {
						props, err :=
							manager.AccountPropertiesFromStore(
								tx.Addr(), account,
							)
						if err != nil {
							return err
						}
						accounts = append(accounts, AccountResult{
							AccountProperties: *props,
						})
						return nil
					},
				)
				if err != nil {
					return err
				}

				balances := make(map[uint32]*btcutil.Amount)
				for i := range accounts {
					account := &accounts[i]
					balances[account.AccountNumber] =
						&account.TotalBalance
				}
				for i := range unspent {
					output := unspent[i]
					_, addrs, _, err := txscript.ExtractPkScriptAddrs(
						output.PkScript, w.chainParams,
					)
					if err != nil || len(addrs) == 0 {
						continue
					}
					outputAccount, err := manager.AddrAccountFromStore(
						tx.Addr(), addrs[0],
					)
					if err != nil {
						continue
					}
					balance := balances[outputAccount]
					if balance != nil {
						*balance += output.Amount
					}
				}

				return nil
			}, func() {
				accounts = nil
				syncBlockHash = nil
				syncBlockHeight = 0
			},
		)

		return &AccountsResult{
			Accounts:           accounts,
			CurrentBlockHash:   syncBlockHash,
			CurrentBlockHeight: syncBlockHeight,
		}, err
	}

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		syncBlock := w.Manager.SyncedTo()
		syncBlockHash = &syncBlock.Hash
		syncBlockHeight = syncBlock.Height
		unspent, err := w.TxStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		err = manager.ForEachAccount(addrmgrNs, func(acct uint32) error {
			props, err := manager.AccountProperties(addrmgrNs, acct)
			if err != nil {
				return err
			}
			accounts = append(accounts, AccountResult{
				AccountProperties: *props,
				// TotalBalance set below
			})
			return nil
		})
		if err != nil {
			return err
		}
		m := make(map[uint32]*btcutil.Amount)
		for i := range accounts {
			a := &accounts[i]
			m[a.AccountNumber] = &a.TotalBalance
		}
		for i := range unspent {
			output := unspent[i]
			var outputAcct uint32

			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				output.PkScript, w.chainParams,
			)
			if err == nil && len(addrs) > 0 {
				_, outputAcct, err = w.Manager.AddrAccount(addrmgrNs, addrs[0])
			}
			if err == nil {
				amt, ok := m[outputAcct]
				if ok {
					*amt += output.Amount
				}
			}
		}
		return nil
	})
	return &AccountsResult{
		Accounts:           accounts,
		CurrentBlockHash:   syncBlockHash,
		CurrentBlockHeight: syncBlockHeight,
	}, err
}

// AccountBalanceResult is a single result for the Wallet.AccountBalances
// method.
type AccountBalanceResult struct {
	// AccountNumber is the account's internal identifier.
	AccountNumber uint32

	// AccountName is the account's user-facing name.
	AccountName string

	// AccountBalance is the account's confirmed balance.
	AccountBalance btcutil.Amount
}

// AccountBalances returns all accounts in the wallet and their balances.
// Balances are determined by excluding transactions that have not met
// requiredConfs confirmations.
func (w *Wallet) AccountBalances(scope waddrmgr.KeyScope,
	requiredConfs int32) ([]AccountBalanceResult, error) {

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var results []AccountBalanceResult
	if w.db == nil {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				syncBlock := w.Manager.SyncedTo()
				accounts, err := tx.Addr().Accounts(scope)
				if err != nil {
					return err
				}

				results = make([]AccountBalanceResult, len(accounts))
				resultIndex := make(map[uint32]int, len(accounts))
				for i, account := range accounts {
					results[i].AccountNumber = account.Account
					results[i].AccountName = account.Name
					resultIndex[account.Account] = i
				}

				outputs, err := tx.Tx().UnspentOutputs()
				if err != nil {
					return err
				}
				for i := range outputs {
					output := &outputs[i]
					if !hasMinConfs(
						requiredConfs, output.Height, syncBlock.Height,
					) {

						continue
					}
					if output.FromCoinBase && !hasMinConfs(
						int32(w.ChainParams().CoinbaseMaturity),
						output.Height, syncBlock.Height,
					) {

						continue
					}

					_, addrs, _, err := txscript.ExtractPkScriptAddrs(
						output.PkScript, w.chainParams,
					)
					if err != nil || len(addrs) == 0 {
						continue
					}
					account, err := manager.AddrAccountFromStore(
						tx.Addr(), addrs[0],
					)
					if err != nil {
						continue
					}

					index, ok := resultIndex[account]
					if !ok {
						return errors.New("address account is not registered")
					}
					results[index].AccountBalance += output.Amount
				}

				return nil
			}, func() {
				results = nil
			},
		)
		return results, err
	}

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		syncBlock := w.Manager.SyncedTo()

		// Fill out all account info except for the balances.
		lastAcct, err := manager.LastAccount(addrmgrNs)
		if err != nil {
			return err
		}
		results = make([]AccountBalanceResult, lastAcct+2)
		for i := range results[:len(results)-1] {
			accountName, err := manager.AccountName(addrmgrNs, uint32(i))
			if err != nil {
				return err
			}
			results[i].AccountNumber = uint32(i)
			results[i].AccountName = accountName
		}
		results[len(results)-1].AccountNumber = waddrmgr.ImportedAddrAccount
		results[len(results)-1].AccountName = waddrmgr.ImportedAddrAccountName

		// Fetch all unspent outputs, and iterate over them tallying each
		// account's balance where the output script pays to an account address
		// and the required number of confirmations is met.
		unspentOutputs, err := w.TxStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		for i := range unspentOutputs {
			output := &unspentOutputs[i]
			if !hasMinConfs(
				requiredConfs, output.Height, syncBlock.Height,
			) {

				continue
			}

			if output.FromCoinBase && !hasMinConfs(
				int32(w.ChainParams().CoinbaseMaturity),
				output.Height, syncBlock.Height,
			) {

				continue
			}

			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				output.PkScript, w.chainParams,
			)
			if err != nil || len(addrs) == 0 {
				continue
			}
			outputAcct, err := manager.AddrAccount(addrmgrNs, addrs[0])
			if err != nil {
				continue
			}
			switch {
			case outputAcct == waddrmgr.ImportedAddrAccount:
				results[len(results)-1].AccountBalance += output.Amount
			case outputAcct > lastAcct:
				return errors.New("waddrmgr.Manager.AddrAccount returned " +
					"account beyond recorded last account")
			default:
				results[outputAcct].AccountBalance += output.Amount
			}
		}
		return nil
	})
	return results, err
}

// creditSlice satisifies the sort.Interface interface to provide sorting
// transaction credits from oldest to newest.  Credits with the same receive
// time and mined in the same block are not guaranteed to be sorted by the order
// they appear in the block.  Credits from the same transaction are sorted by
// output index.
type creditSlice []wtxmgr.Credit

// Len returns the number of credits in the slice.
func (s creditSlice) Len() int {
	return len(s)
}

// Less reports whether one credit should sort before another.
func (s creditSlice) Less(i, j int) bool {
	switch {
	// If both credits are from the same tx, sort by output index.
	case s[i].OutPoint.Hash == s[j].OutPoint.Hash:
		return s[i].OutPoint.Index < s[j].OutPoint.Index

	// If both transactions are unmined, sort by their received date.
	case s[i].Height == -1 && s[j].Height == -1:
		return s[i].Received.Before(s[j].Received)

	// Unmined (newer) txs always come last.
	case s[i].Height == -1:
		return false
	case s[j].Height == -1:
		return true

	// If both txs are mined in different blocks, sort by block height.
	default:
		return s[i].Height < s[j].Height
	}
}

// Swap exchanges two credits in the slice.
func (s creditSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// ListUnspent returns a slice of objects representing the unspent wallet
// transactions fitting the given criteria. The confirmations will be more than
// minconf, less than maxconf and if addresses is populated only the addresses
// contained within it will be considered.  If we know nothing about a
// transaction an empty array will be returned.
func (w *Wallet) ListUnspent(minconf, maxconf int32,
	accountName string) ([]*btcjson.ListUnspentResult, error) {

	var results []*btcjson.ListUnspentResult
	err := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			syncBlock := w.Manager.SyncedTo()

			filter := accountName != ""
			unspent, err := tx.Tx().UnspentOutputs()
			if err != nil {
				return err
			}
			sort.Sort(sort.Reverse(creditSlice(unspent)))

			defaultAccountName := "default"

			results = make([]*btcjson.ListUnspentResult, 0, len(unspent))
			for i := range unspent {
				output := unspent[i]

				// Outputs with fewer confirmations than the minimum or
				// more confs than the maximum are excluded.
				confs := calcConf(output.Height, syncBlock.Height)
				if confs < minconf || confs > maxconf {
					continue
				}

				// Only mature coinbase outputs are included.
				if output.FromCoinBase {
					target := int32(w.ChainParams().CoinbaseMaturity)
					if !hasMinConfs(
						target, output.Height, syncBlock.Height,
					) {

						continue
					}
				}

				// Exclude locked outputs from the result set.
				if w.LockedOutpoint(output.OutPoint) {
					continue
				}

				// Lookup the associated account for the output.  Use the
				// default account name in case there is no associated account
				// for some reason, although this should never happen.
				//
				// This will be unnecessary once transactions and outputs are
				// grouped under the associated account in the db.
				outputAcctName := defaultAccountName
				sc, addrs, _, err := txscript.ExtractPkScriptAddrs(
					output.PkScript, w.chainParams)
				if err != nil {
					continue
				}
				if len(addrs) > 0 {
					smgr, acct, err := w.Manager.AddrAccountFromStore(
						tx.Addr(), addrs[0],
					)
					if err == nil {
						s, err := smgr.AccountNameFromStore(
							tx.Addr(), acct,
						)
						if err == nil {
							outputAcctName = s
						}
					}
				}

				if filter && outputAcctName != accountName {
					continue
				}

				// At the moment watch-only addresses are not supported, so all
				// recorded outputs that are not multisig are "spendable".
				// Multisig outputs are only "spendable" if all keys are
				// controlled by this wallet.
				//
				// TODO: Each case will need updates when watch-only addrs
				// is added.  For P2PK, P2PKH, and P2SH, the address must be
				// looked up and not be watching-only.  For multisig, all
				// pubkeys must belong to the manager with the associated
				// private key (currently it only checks whether the pubkey
				// exists, since the private key is required at the moment).
				var spendable bool
			scSwitch:
				switch sc {
				case txscript.PubKeyHashTy:
					spendable = true
				case txscript.PubKeyTy:
					spendable = true
				case txscript.WitnessV0ScriptHashTy:
					spendable = true
				case txscript.WitnessV0PubKeyHashTy:
					spendable = true
				case txscript.MultiSigTy:
					for _, a := range addrs {
						_, err := w.Manager.AddressFromStore(tx.Addr(), a)
						if err == nil {
							continue
						}
						if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
							break scSwitch
						}
						return err
					}
					spendable = true
				}

				result := &btcjson.ListUnspentResult{
					TxID:          output.OutPoint.Hash.String(),
					Vout:          output.OutPoint.Index,
					Account:       outputAcctName,
					ScriptPubKey:  hex.EncodeToString(output.PkScript),
					Amount:        output.Amount.ToBTC(),
					Confirmations: int64(confs),
					Spendable:     spendable,
				}

				// BUG: this should be a JSON array so that all
				// addresses can be included, or removed (and the
				// caller extracts addresses from the pkScript).
				if len(addrs) > 0 {
					result.Address = addrs[0].EncodeAddress()
				}

				results = append(results, result)
			}
			return nil
		}, func() {
			results = nil
		})

	return results, err
}

// ListLeasedOutputResult is a single result for the Wallet.ListLeasedOutputs
// method. See that method for more details.
type ListLeasedOutputResult struct {
	// LockedOutput identifies the output lease and its owner.
	*wtxmgr.LockedOutput

	// Value is the leased output amount in satoshis.
	Value int64

	// PkScript is the leased output's public-key script.
	PkScript []byte
}

// ListLeasedOutputs returns a list of objects representing the currently locked
// utxos.
func (w *Wallet) ListLeasedOutputs() ([]*ListLeasedOutputResult, error) {
	var results []*ListLeasedOutputResult
	err := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			outputs, err := tx.Tx().ListLockedOutputs()
			if err != nil {
				return err
			}

			for _, output := range outputs {
				details, err := tx.Tx().TxDetails(&output.Outpoint.Hash)
				if err != nil {
					return err
				}

				if details == nil {
					log.Infof("unable to find tx details for "+
						"%v:%v", output.Outpoint.Hash,
						output.Outpoint.Index)
					continue
				}

				txOut := details.MsgTx.TxOut[output.Outpoint.Index]

				result := &ListLeasedOutputResult{
					LockedOutput: output,
					Value:        txOut.Value,
					PkScript:     txOut.PkScript,
				}

				results = append(results, result)
			}

			return nil
		}, func() {
			results = nil
		})

	return results, err
}

// DumpPrivKeys returns the WIF-encoded private keys for all addresses with
// private keys in a wallet.
func (w *Wallet) DumpPrivKeys() ([]string, error) {
	var privkeys []string
	appendKey := func(ma waddrmgr.ManagedAddress) error {
		// Only those addresses with keys needed.
		pka, ok := ma.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return nil
		}

		wif, err := pka.ExportPrivKey()
		if err != nil {
			return err
		}
		privkeys = append(privkeys, wif.String())

		return nil
	}

	var err error
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			return w.Manager.ForEachActiveAddress(
				addrmgrNs, func(addr address.Address) error {
					ma, err := w.Manager.Address(addrmgrNs, addr)
					if err != nil {
						return err
					}

					return appendKey(ma)
				},
			)
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				return w.Manager.ForEachActiveAddressFromStore(
					tx.Addr(), func(addr address.Address) error {
						ma, err := w.Manager.AddressFromStore(
							tx.Addr(), addr,
						)
						if err != nil {
							return err
						}

						return appendKey(ma)
					},
				)
			}, func() {
				privkeys = nil
			},
		)
	}
	return privkeys, err
}

// DumpWIFPrivateKey returns the WIF encoded private key for a
// single wallet address.
func (w *Wallet) DumpWIFPrivateKey(addr address.Address) (string, error) {
	var maddr waddrmgr.ManagedAddress
	var err error
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			waddrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			var err error
			maddr, err = w.Manager.Address(waddrmgrNs, addr)
			return err
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				var err error
				maddr, err = w.Manager.AddressFromStore(tx.Addr(), addr)
				return err
			}, func() {
				maddr = nil
			},
		)
	}
	if err != nil {
		return "", err
	}

	pka, ok := maddr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return "", fmt.Errorf("address %s is not a key type", addr)
	}

	wif, err := pka.ExportPrivKey()
	if err != nil {
		return "", err
	}
	return wif.String(), nil
}

// LockedOutpoint returns whether an outpoint has been marked as locked and
// should not be used as an input for created transactions.
func (w *Wallet) LockedOutpoint(op wire.OutPoint) bool {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

	_, locked := w.lockedOutpoints[op]
	return locked
}

// LockOutpoint marks an outpoint as locked, that is, it should not be used as
// an input for newly created transactions.
func (w *Wallet) LockOutpoint(op wire.OutPoint) {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

	w.lockedOutpoints[op] = struct{}{}
}

// UnlockOutpoint marks an outpoint as unlocked, that is, it may be used as an
// input for newly created transactions.
func (w *Wallet) UnlockOutpoint(op wire.OutPoint) {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

	delete(w.lockedOutpoints, op)
}

// ResetLockedOutpoints resets the set of locked outpoints so all may be used
// as inputs for new transactions.
func (w *Wallet) ResetLockedOutpoints() {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

	w.lockedOutpoints = map[wire.OutPoint]struct{}{}
}

// LockedOutpoints returns a slice of currently locked outpoints.  This is
// intended to be used by marshaling the result as a JSON array for
// listlockunspent RPC results.
func (w *Wallet) LockedOutpoints() []btcjson.TransactionInput {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

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

// LeaseOutput locks an output to the given ID, preventing it from being
// available for coin selection. The absolute time of the lock's expiration is
// returned. The expiration of the lock can be extended by successive
// invocations of this call.
//
// Outputs can be unlocked before their expiration through `UnlockOutput`.
// Otherwise, they are unlocked lazily through calls which iterate through all
// known outputs, e.g., `CalculateBalance`, `ListUnspent`.
//
// If the output is not known, ErrUnknownOutput is returned. If the output has
// already been locked to a different ID, then ErrOutputAlreadyLocked is
// returned.
//
// NOTE: This differs from LockOutpoint in that outputs are locked for a limited
// amount of time and their locks are persisted to disk.
func (w *Wallet) LeaseOutput(id wtxmgr.LockID, op wire.OutPoint,
	duration time.Duration) (time.Time, error) {

	var expiry time.Time
	err := w.store.UpdateOnce(
		context.Background(), func(tx walletstore.ReadWriteTx) error {
			var err error
			expiry, err = tx.Tx().LockOutput(id, op, duration)
			return err
		}, func() {
			expiry = time.Time{}
		},
	)

	return expiry, err
}

// ReleaseOutput unlocks an output, allowing it to be available for coin
// selection if it remains unspent. The ID should match the one used to
// originally lock the output.
func (w *Wallet) ReleaseOutput(id wtxmgr.LockID, op wire.OutPoint) error {
	return w.store.UpdateOnce(
		context.Background(), func(tx walletstore.ReadWriteTx) error {
			return tx.Tx().UnlockOutput(id, op)
		}, nil,
	)
}

// resendUnminedTxs iterates through all transactions that spend from wallet
// credits that are not known to have been mined into a block, and attempts
// to send each to the chain server for relay.
func (w *Wallet) resendUnminedTxs() {
	var txs []*wire.MsgTx
	var err error
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
			var err error
			txs, err = w.TxStore.UnminedTxs(txmgrNs)
			return err
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				var err error
				txs, err = tx.Tx().UnminedTxs()
				return err
			}, func() {
				txs = nil
			},
		)
	}
	if err != nil {
		log.Errorf("Unable to retrieve unconfirmed transactions to "+
			"resend: %v", err)
		return
	}

	for _, tx := range txs {
		txHash, err := w.publishTransaction(tx)
		if err != nil {
			log.Debugf("Unable to rebroadcast transaction %v: %v",
				tx.TxHash(), err)
			continue
		}

		log.Debugf("Successfully rebroadcast unconfirmed transaction %v",
			txHash)
	}
}

// SortedActivePaymentAddresses returns a slice of all active payment
// addresses in a wallet.
func (w *Wallet) SortedActivePaymentAddresses() ([]string, error) {
	var addrStrs []string
	appendAddress := func(addr address.Address) error {
		addrStrs = append(addrStrs, addr.EncodeAddress())
		return nil
	}

	var err error
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
			return w.Manager.ForEachActiveAddress(
				addrmgrNs, appendAddress,
			)
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				return w.Manager.ForEachActiveAddressFromStore(
					tx.Addr(), appendAddress,
				)
			}, func() {
				addrStrs = nil
			},
		)
	}
	if err != nil {
		return nil, err
	}

	sort.Strings(addrStrs)
	return addrStrs, nil
}

// NewAddress returns the next external chained address for a wallet.
func (w *Wallet) NewAddress(account uint32,
	scope waddrmgr.KeyScope) (address.Address, error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// The address manager uses OnCommit on the walletdb tx to update the
	// in-memory state of the account state. But because the commit happens
	// _after_ the account manager internal lock has been released, there
	// is a chance for the address index to be accessed concurrently, even
	// though the closure in OnCommit re-acquires the lock. To avoid this
	// issue, we surround the whole address creation process with a lock.
	w.newAddrMtx.Lock()
	defer w.newAddrMtx.Unlock()

	var (
		addr  address.Address
		props *waddrmgr.AccountProperties
	)
	if w.db != nil {
		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			var err error
			addr, props, err = w.newAddress(
				addrmgrNs, account, scope,
			)
			return err
		})
	} else {
		err = w.store.UpdateOnce(
			context.Background(), func(tx walletstore.ReadWriteTx) error {
				manager, err := w.Manager.FetchScopedKeyManager(scope)
				if err != nil {
					return err
				}

				managed, accountProps, err :=
					manager.NextExternalAddressFromStore(
						tx.Addr(), account,
					)
				if err != nil {
					return err
				}

				addr = managed.Address()
				props = accountProps

				return nil
			}, func() {
				addr = nil
				props = nil
			},
		)
	}
	if err != nil {
		var ambiguous *walletstore.AmbiguousCommitError
		if errors.As(err, &ambiguous) {
			w.Manager.MarkAccountCacheStale(scope, account)
		}

		return nil, err
	}

	// Notify the rpc server about the newly created address.
	err = chainClient.NotifyReceived([]address.Address{addr})
	if err != nil {
		return nil, err
	}

	w.NtfnServer.notifyAccountProperties(props)

	return addr, nil
}

// newAddress derives the next KV-backed external address and its updated
// account properties.
func (w *Wallet) newAddress(addrmgrNs walletdb.ReadWriteBucket, account uint32,
	scope waddrmgr.KeyScope) (address.Address, *waddrmgr.AccountProperties,
	error) {

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, nil, err
	}

	// Get next address from wallet.
	addrs, err := manager.NextExternalAddresses(addrmgrNs, account, 1)
	if err != nil {
		return nil, nil, err
	}

	props, err := manager.AccountProperties(addrmgrNs, account)
	if err != nil {
		log.Errorf("Cannot fetch account properties for notification "+
			"after deriving next external address: %v", err)
		return nil, nil, err
	}

	return addrs[0].Address(), props, nil
}

// NewChangeAddress returns a new change address for a wallet.
func (w *Wallet) NewChangeAddress(account uint32,
	scope waddrmgr.KeyScope) (address.Address, error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// The address manager uses OnCommit on the walletdb tx to update the
	// in-memory state of the account state. But because the commit happens
	// _after_ the account manager internal lock has been released, there
	// is a chance for the address index to be accessed concurrently, even
	// though the closure in OnCommit re-acquires the lock. To avoid this
	// issue, we surround the whole address creation process with a lock.
	w.newAddrMtx.Lock()
	defer w.newAddrMtx.Unlock()

	var addr address.Address
	if w.db != nil {
		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			var err error
			addr, err = w.newChangeAddress(addrmgrNs, account, scope)
			return err
		})
	} else {
		err = w.store.UpdateOnce(
			context.Background(),
			func(tx walletstore.ReadWriteTx) error {
				manager, err := w.Manager.FetchScopedKeyManager(scope)
				if err != nil {
					return err
				}

				managed, _, err := manager.NextInternalAddressFromStore(
					tx.Addr(), account,
				)
				if err != nil {
					return err
				}
				addr = managed.Address()

				return nil
			}, func() {
				addr = nil
			},
		)
	}
	if err != nil {
		var ambiguous *walletstore.AmbiguousCommitError
		if errors.As(err, &ambiguous) {
			w.Manager.MarkAccountCacheStale(scope, account)
		}

		return nil, err
	}

	// Notify the rpc server about the newly created address.
	err = chainClient.NotifyReceived([]address.Address{addr})
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// newChangeAddress returns a new change address for the wallet.
//
// NOTE: This method requires the caller to use the backend's NotifyReceived
// method in order to detect when an on-chain transaction pays to the address
// being created.
func (w *Wallet) newChangeAddress(addrmgrNs walletdb.ReadWriteBucket,
	account uint32, scope waddrmgr.KeyScope) (address.Address, error) {

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	// Get next chained change address from wallet for account.
	addrs, err := manager.NextInternalAddresses(addrmgrNs, account, 1)
	if err != nil {
		return nil, err
	}

	return addrs[0].Address(), nil
}

// hasMinConfs returns whether a transaction has met at least minConf
// confirmations at the current block height.
func hasMinConfs(minConf, txHeight, curHeight int32) bool {
	return calcConf(txHeight, curHeight) >= minConf
}

// calcConf returns the number of confirmations for a transaction given its
// containing block height and the current best block height. Unconfirmed
// transactions have a height of -1 and are considered to have 0 confirmations.
func calcConf(txHeight, curHeight int32) int32 {
	switch {
	// Unconfirmed transactions have 0 confirmations.
	case txHeight == -1:
		return 0

	// A transaction in a block after the current best block is considered
	// unconfirmed. This can happen during a chain reorg.
	case txHeight > curHeight:
		return 0

	// Confirmed transactions have at least one confirmation.
	default:
		return curHeight - txHeight + 1
	}
}

// AccountTotalReceivedResult is a single result for the
// Wallet.TotalReceivedForAccounts method.
type AccountTotalReceivedResult struct {
	// AccountNumber is the account's internal identifier.
	AccountNumber uint32

	// AccountName is the account's user-facing name.
	AccountName string

	// TotalReceived is the amount received by the account.
	TotalReceived btcutil.Amount

	// LastConfirmation is the confirmation count of the latest credit.
	LastConfirmation int32
}

// TotalReceivedForAccounts iterates through a wallet's transaction history,
// returning the total amount of Bitcoin received for all accounts.
func (w *Wallet) TotalReceivedForAccounts(scope waddrmgr.KeyScope,
	minConf int32) ([]AccountTotalReceivedResult, error) {

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var results []AccountTotalReceivedResult
	err = w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			syncBlock := w.Manager.SyncedTo()

			err := manager.ForEachAccountFromStore(
				tx.Addr(), func(account uint32) error {
					accountName, err := manager.AccountNameFromStore(
						tx.Addr(), account,
					)
					if err != nil {
						return err
					}
					results = append(results, AccountTotalReceivedResult{
						AccountNumber: account,
						AccountName:   accountName,
					})
					return nil
				})
			if err != nil {
				return err
			}
			resultIndex := make(map[uint32]int, len(results))
			for i := range results {
				resultIndex[results[i].AccountNumber] = i
			}

			var stopHeight int32

			if minConf > 0 {
				stopHeight = syncBlock.Height - minConf + 1
			} else {
				stopHeight = -1
			}

			rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
				for i := range details {
					detail := &details[i]
					for _, cred := range detail.Credits {
						pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
						_, addrs, _, err := txscript.ExtractPkScriptAddrs(
							pkScript, w.chainParams,
						)
						if err != nil || len(addrs) == 0 {
							continue
						}

						outputAccount, err := manager.AddrAccountFromStore(
							tx.Addr(), addrs[0],
						)
						if err != nil {
							continue
						}
						index, ok := resultIndex[outputAccount]
						if !ok {
							continue
						}

						res := &results[index]
						res.TotalReceived += cred.Amount
						res.LastConfirmation = calcConf(
							detail.Block.Height, syncBlock.Height,
						)
					}
				}
				return false, nil
			}
			return tx.Tx().RangeTransactions(0, stopHeight, rangeFn)
		}, func() {
			results = nil
		})

	return results, err
}

// TotalReceivedForAddr iterates through a wallet's transaction history,
// returning the total amount of bitcoins received for a single wallet
// address.
func (w *Wallet) TotalReceivedForAddr(addr address.Address,
	minConf int32) (btcutil.Amount, error) {

	var amount btcutil.Amount
	err := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			syncBlock := w.Manager.SyncedTo()

			var (
				addrStr    = addr.EncodeAddress()
				stopHeight int32
			)

			if minConf > 0 {
				stopHeight = syncBlock.Height - minConf + 1
			} else {
				stopHeight = -1
			}
			rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
				for i := range details {
					detail := &details[i]
					for _, cred := range detail.Credits {
						pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
						_, addrs, _, err :=
							txscript.ExtractPkScriptAddrs(
								pkScript, w.chainParams,
							)
						// An address error only indicates a non-standard
						// script, so ignore this credit.
						if err != nil {
							continue
						}
						for _, a := range addrs {
							if addrStr == a.EncodeAddress() {
								amount += cred.Amount
								break
							}
						}
					}
				}
				return false, nil
			}
			return tx.Tx().RangeTransactions(0, stopHeight, rangeFn)
		}, func() {
			amount = 0
		})

	return amount, err
}

// SendOutputs creates and sends payment transactions. Coin selection is
// performed by the wallet, choosing inputs that belong to the given key scope
// and account, unless a key scope is not specified. In that case, inputs from
// accounts matching the account number provided across all key scopes may be
// selected. This is done to handle the default account case, where a user wants
// to fund a PSBT with inputs regardless of their type (NP2WKH, P2WKH, etc.). It
// returns the transaction upon success.
func (w *Wallet) SendOutputs(outputs []*wire.TxOut, keyScope *waddrmgr.KeyScope,
	account uint32, minconf int32, satPerKb btcutil.Amount,
	coinSelectionStrategy CoinSelectionStrategy, label string) (*wire.MsgTx,
	error) {

	return w.sendOutputs(
		outputs, keyScope, account, minconf, satPerKb,
		coinSelectionStrategy, label,
	)
}

// SendOutputsWithInput creates and sends payment transactions using the
// provided selected utxos. It returns the transaction upon success.
func (w *Wallet) SendOutputsWithInput(outputs []*wire.TxOut,
	keyScope *waddrmgr.KeyScope,
	account uint32, minconf int32, satPerKb btcutil.Amount,
	coinSelectionStrategy CoinSelectionStrategy, label string,
	selectedUtxos []wire.OutPoint) (*wire.MsgTx, error) {

	return w.sendOutputs(outputs, keyScope, account, minconf, satPerKb,
		coinSelectionStrategy, label, selectedUtxos...)
}

// sendOutputs creates and sends payment transactions. It returns the
// transaction upon success.
func (w *Wallet) sendOutputs(outputs []*wire.TxOut, keyScope *waddrmgr.KeyScope,
	account uint32, minconf int32, satPerKb btcutil.Amount,
	coinSelectionStrategy CoinSelectionStrategy, label string,
	selectedUtxos ...wire.OutPoint) (*wire.MsgTx, error) {

	// Ensure the outputs to be created adhere to the network's consensus
	// rules.
	for _, output := range outputs {
		err := txrules.CheckOutput(
			output, txrules.DefaultRelayFeePerKb,
		)
		if err != nil {
			return nil, err
		}
	}

	// Create the transaction and broadcast it to the network. The
	// transaction will be added to the database in order to ensure that we
	// continue to re-broadcast the transaction upon restarts until it has
	// been confirmed.
	createdTx, err := w.CreateSimpleTx(
		keyScope, account, outputs, minconf, satPerKb,
		coinSelectionStrategy, false, WithCustomSelectUtxos(
			selectedUtxos,
		),
	)
	if err != nil {
		return nil, err
	}

	// If our wallet is read-only, we'll get a transaction with coins
	// selected but no witness data. In such a case we need to inform our
	// caller that they'll actually need to go ahead and sign the TX.
	if w.Manager.WatchOnly() {
		return createdTx.Tx, ErrTxUnsigned
	}

	txHash, err := w.reliablyPublishTransaction(createdTx.Tx, label)
	if err != nil {
		return nil, err
	}

	// Sanity check on the returned tx hash.
	if *txHash != createdTx.Tx.TxHash() {
		return nil, errors.New("tx hash mismatch")
	}

	return createdTx.Tx, nil
}

// SignatureError records the underlying error when validating a transaction
// input signature.
type SignatureError struct {
	// InputIndex identifies the transaction input with an invalid signature.
	InputIndex uint32

	// Error is the underlying signature validation failure.
	Error error
}

// SignTransaction uses secrets of the wallet, as well as additional secrets
// passed in by the caller, to create and add input signatures to a transaction.
//
// Transaction input script validation is used to confirm that all signatures
// are valid.  For any invalid input, a SignatureError is added to the returns.
// The final error return is reserved for unexpected or fatal errors, such as
// being unable to determine a previous output script to redeem.
//
// The transaction pointed to by tx is modified by this function.
func (w *Wallet) SignTransaction(tx *wire.MsgTx, hashType txscript.SigHashType,
	additionalPrevScripts map[wire.OutPoint][]byte,
	additionalKeysByAddress map[string]*btcutil.WIF,
	p2shRedeemScriptsByAddress map[string][]byte) ([]SignatureError, error) {

	if w.db == nil {
		return w.signTransactionFromStore(
			tx, hashType, additionalPrevScripts,
			additionalKeysByAddress, p2shRedeemScriptsByAddress,
		)
	}

	var signErrors []SignatureError
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		inputFetcher := txscript.NewMultiPrevOutFetcher(nil)
		for i, txIn := range tx.TxIn {
			prevOutScript, ok := additionalPrevScripts[txIn.PreviousOutPoint]
			if !ok {
				prevHash := &txIn.PreviousOutPoint.Hash
				prevIndex := txIn.PreviousOutPoint.Index
				txDetails, err := w.TxStore.TxDetails(txmgrNs, prevHash)
				if err != nil {
					return fmt.Errorf("cannot query previous transaction "+
						"details for %v: %w", txIn.PreviousOutPoint, err)
				}
				if txDetails == nil {
					return fmt.Errorf("%v not found",
						txIn.PreviousOutPoint)
				}
				prevOutScript = txDetails.MsgTx.TxOut[prevIndex].PkScript
			}
			inputFetcher.AddPrevOut(txIn.PreviousOutPoint, &wire.TxOut{
				PkScript: prevOutScript,
			})

			// Set up our callbacks that we pass to txscript so it can
			// look up the appropriate keys and scripts by address.
			getKey := txscript.KeyClosure(func(
				addr address.Address) (*btcec.PrivateKey, bool, error) {

				if len(additionalKeysByAddress) != 0 {
					addrStr := addr.EncodeAddress()
					wif, ok := additionalKeysByAddress[addrStr]
					if !ok {
						return nil, false,
							errors.New("no key for address")
					}
					return wif.PrivKey, wif.CompressPubKey, nil
				}
				address, err := w.Manager.Address(addrmgrNs, addr)
				if err != nil {
					return nil, false, err
				}

				pka, ok := address.(waddrmgr.ManagedPubKeyAddress)
				if !ok {
					return nil, false, fmt.Errorf("address %v is not "+
						"a pubkey address", address.Address().EncodeAddress())
				}

				key, err := pka.PrivKey()
				if err != nil {
					return nil, false, err
				}

				return key, pka.Compressed(), nil
			})
			getScript := txscript.ScriptClosure(func(
				addr address.Address) ([]byte, error) {

				// If keys were provided then we can only use the
				// redeem scripts provided with our inputs, too.
				if len(additionalKeysByAddress) != 0 {
					addrStr := addr.EncodeAddress()
					script, ok := p2shRedeemScriptsByAddress[addrStr]
					if !ok {
						return nil, errors.New("no script for address")
					}
					return script, nil
				}
				address, err := w.Manager.Address(addrmgrNs, addr)
				if err != nil {
					return nil, err
				}
				sa, ok := address.(waddrmgr.ManagedScriptAddress)
				if !ok {
					return nil, errors.New("address is not a script" +
						" address")
				}

				return sa.Script()
			})

			// SigHashSingle inputs can only be signed if there's a
			// corresponding output. However this could be already signed,
			// so we always verify the output.
			if (hashType&txscript.SigHashSingle) !=
				txscript.SigHashSingle || i < len(tx.TxOut) {

				script, err := txscript.SignTxOutput(w.ChainParams(),
					tx, i, prevOutScript, hashType, getKey,
					getScript, txIn.SignatureScript)
				// Failure to sign isn't an error, it just means that
				// the tx isn't complete.
				if err != nil {
					signErrors = append(signErrors, SignatureError{
						InputIndex: uint32(i),
						Error:      err,
					})
					continue
				}
				txIn.SignatureScript = script
			}

			// Either it was already signed or we just signed it.
			// Find out if it is completely satisfied or still needs more.
			vm, err := txscript.NewEngine(
				prevOutScript, tx, i,
				txscript.StandardVerifyFlags, nil, nil, 0,
				inputFetcher,
			)
			if err == nil {
				err = vm.Execute()
			}
			if err != nil {
				signErrors = append(signErrors, SignatureError{
					InputIndex: uint32(i),
					Error:      err,
				})
			}
		}
		return nil
	})
	return signErrors, err
}

// ErrDoubleSpend is an error returned from PublishTransaction in case the
// published transaction failed to propagate since it was double spending a
// confirmed transaction or a transaction in the mempool.
type ErrDoubleSpend struct {
	backendError error
}

// Error returns the string representation of ErrDoubleSpend.
//
// NOTE: Satisfies the error interface.
func (e *ErrDoubleSpend) Error() string {
	return fmt.Sprintf("double spend: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrDoubleSpend) Unwrap() error {
	return e.backendError
}

// ErrMempoolFee is an error returned from PublishTransaction in case the
// published transaction failed to propagate since it did not match the
// current mempool fee requirement.
type ErrMempoolFee struct {
	backendError error
}

// Error returns the string representation of ErrMempoolFee.
//
// NOTE: Satisfies the error interface.
func (e *ErrMempoolFee) Error() string {
	return fmt.Sprintf("mempool fee not met: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrMempoolFee) Unwrap() error {
	return e.backendError
}

// ErrAlreadyConfirmed is an error returned from PublishTransaction in case
// a transaction is already confirmed in the blockchain.
type ErrAlreadyConfirmed struct {
	backendError error
}

// Error returns the string representation of ErrAlreadyConfirmed.
//
// NOTE: Satisfies the error interface.
func (e *ErrAlreadyConfirmed) Error() string {
	return fmt.Sprintf("tx already confirmed: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrAlreadyConfirmed) Unwrap() error {
	return e.backendError
}

// ErrInMempool is an error returned from PublishTransaction in case a
// transaction is already in the mempool.
type ErrInMempool struct {
	backendError error
}

// Error returns the string representation of ErrInMempool.
//
// NOTE: Satisfies the error interface.
func (e *ErrInMempool) Error() string {
	return fmt.Sprintf("tx already in mempool: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrInMempool) Unwrap() error {
	return e.backendError
}

// PublishTransaction sends the transaction to the consensus RPC server so it
// can be propagated to other nodes and eventually mined.
//
// This function is unstable and will be removed once syncing code is moved out
// of the wallet.
func (w *Wallet) PublishTransaction(tx *wire.MsgTx, label string) error {
	_, err := w.reliablyPublishTransaction(tx, label)
	return err
}

// reliablyPublishTransaction is a superset of publishTransaction which contains
// the primary logic required for publishing a transaction, updating the
// relevant database state, and finally possible removing the transaction from
// the database (along with cleaning up all inputs used, and outputs created) if
// the transaction is rejected by the backend.
func (w *Wallet) reliablyPublishTransaction(tx *wire.MsgTx,
	label string) (*chainhash.Hash, error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// As we aim for this to be general reliable transaction broadcast API,
	// we'll write this tx to disk as an unconfirmed transaction. This way,
	// upon restarts, we'll always rebroadcast it, and also add it to our
	// set of records.
	txRec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	if err != nil {
		return nil, err
	}

	// Along the way, we'll extract our relevant destination addresses from
	// the transaction.
	var ourAddrs []address.Address
	if w.db != nil {
		err = walletdb.Update(w.db, func(dbTx walletdb.ReadWriteTx) error {
			addrmgrNs := dbTx.ReadWriteBucket(waddrmgrNamespaceKey)
			for _, txOut := range tx.TxOut {
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(
					txOut.PkScript, w.chainParams,
				)
				if err != nil {
					log.Warnf("Non-standard pkScript=%x in tx=%v",
						txOut.PkScript, tx.TxHash())
					continue
				}
				for _, addr := range addrs {
					_, err := w.Manager.Address(addrmgrNs, addr)
					if waddrmgr.IsError(
						err, waddrmgr.ErrAddressNotFound,
					) {

						continue
					}
					if err != nil {
						return err
					}
					ourAddrs = append(ourAddrs, addr)
				}
			}

			if len(label) != 0 {
				txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)
				err = w.TxStore.PutTxLabel(
					txmgrNs, tx.TxHash(), label,
				)
				if err != nil {
					return err
				}
			}

			return w.addRelevantTx(dbTx, txRec, nil)
		})
	} else {
		err = w.store.UpdateOnce(
			context.Background(), func(dbTx walletstore.ReadWriteTx) error {
				for _, txOut := range tx.TxOut {
					_, addrs, _, err := txscript.ExtractPkScriptAddrs(
						txOut.PkScript, w.chainParams,
					)
					if err != nil {
						log.Warnf("Non-standard pkScript=%x in tx=%v",
							txOut.PkScript, tx.TxHash())
						continue
					}
					for _, addr := range addrs {
						_, err := w.Manager.AddressFromStore(
							dbTx.Addr(), addr,
						)
						if waddrmgr.IsError(
							err, waddrmgr.ErrAddressNotFound,
						) {

							continue
						}
						if err != nil {
							return err
						}
						ourAddrs = append(ourAddrs, addr)
					}
				}

				if len(label) != 0 {
					if err := dbTx.Tx().PutTxLabel(
						tx.TxHash(), label,
					); err != nil {

						return err
					}
				}

				return w.addRelevantTxFromStore(dbTx, txRec, nil)
			}, func() {
				ourAddrs = nil
			},
		)
	}
	if err != nil {
		return nil, err
	}

	// We'll also ask to be notified of the transaction once it confirms
	// on-chain. This is done outside of the database transaction to prevent
	// backend interaction within it.
	if err := chainClient.NotifyReceived(ourAddrs); err != nil {
		return nil, err
	}

	return w.publishTransaction(tx)
}

// removeUnminedTransaction removes a transaction from the active manager
// backend after the chain backend reports that it should not be rebroadcast.
func (w *Wallet) removeUnminedTransaction(tx *wire.MsgTx) error {
	txRecord, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	if err != nil {
		return err
	}

	if w.db != nil {
		return walletdb.Update(w.db, func(dbTx walletdb.ReadWriteTx) error {
			txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)
			return w.TxStore.RemoveUnminedTx(txmgrNs, txRecord)
		})
	}

	return w.store.UpdateOnce(
		context.Background(), func(dbTx walletstore.ReadWriteTx) error {
			return dbTx.Tx().RemoveUnminedTx(txRecord)
		}, nil,
	)
}

// publishTransaction attempts to send an unconfirmed transaction to the
// wallet's current backend. In the event that sending the transaction fails for
// whatever reason, it will be removed from the wallet's unconfirmed transaction
// store.
func (w *Wallet) publishTransaction(tx *wire.MsgTx) (*chainhash.Hash, error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	txid := tx.TxHash()
	_, rpcErr := chainClient.SendRawTransaction(tx, false)
	if rpcErr == nil {
		return &txid, nil
	}

	switch {
	case errors.Is(rpcErr, chain.ErrTxAlreadyInMempool):
		log.Infof("%v: tx already in mempool", txid)
		return &txid, nil

	case errors.Is(rpcErr, chain.ErrTxAlreadyKnown),
		errors.Is(rpcErr, chain.ErrTxAlreadyConfirmed):

		dbErr := w.removeUnminedTransaction(tx)
		if dbErr != nil {
			log.Warnf("Unable to remove confirmed transaction %v "+
				"from unconfirmed store: %v", tx.TxHash(), dbErr)
		}

		log.Infof("%v: tx already confirmed", txid)

		return &txid, nil

	}

	// Log the causing error, even if we know how to handle it.
	log.Infof("%v: broadcast failed because of: %v", txid, rpcErr)

	// If the transaction was rejected for whatever other reason, then
	// we'll remove it from the transaction store, as otherwise, we'll
	// attempt to continually re-broadcast it, and the UTXO state of the
	// wallet won't be accurate.
	dbErr := w.removeUnminedTransaction(tx)
	if dbErr != nil {
		log.Warnf("Unable to remove invalid transaction %v: %v",
			tx.TxHash(), dbErr)
	} else {
		log.Infof("Removed invalid transaction: %v", tx.TxHash())

		// The serialized transaction is for logging only, don't fail
		// on the error.
		var txRaw bytes.Buffer
		_ = tx.Serialize(&txRaw)

		// Optionally log the tx in debug when the size is manageable.
		if txRaw.Len() < 1_000_000 {
			log.Debugf("Removed invalid transaction: %v \n hex=%x",
				newLogClosure(func() string {
					return spew.Sdump(tx)
				}), txRaw.Bytes())
		} else {
			log.Debug("Removed invalid transaction due to size " +
				"too large")
		}
	}

	return nil, rpcErr
}

// ChainParams returns the network parameters for the blockchain the wallet
// belongs to.
func (w *Wallet) ChainParams() *chaincfg.Params {
	return w.chainParams
}

// Database returns the underlying walletdb database. This method is provided
// in order to allow applications wrapping btcwallet to store app-specific data
// with the wallet's database. It returns nil for a Store-backed wallet.
func (w *Wallet) Database() walletdb.DB {
	return w.db
}

// RemoveDescendants attempts to remove any transaction from the wallet's tx
// store (that may be unconfirmed) that spends outputs created by the passed
// transaction. This remove propagates recursively down the chain of descendent
// transactions.
func (w *Wallet) RemoveDescendants(tx *wire.MsgTx) error {
	txRecord, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	if err != nil {
		return err
	}

	return w.store.UpdateOnce(
		context.Background(), func(tx walletstore.ReadWriteTx) error {
			return tx.Tx().RemoveUnminedTx(txRecord)
		}, nil,
	)
}

// BirthdayBlock returns the birthday block of the wallet.
//
// NOTE: The wallet won't start until the backend is synced, thus the birthday
// block won't be set and `ErrBirthdayBlockNotSet` will be returned.
func (w *Wallet) BirthdayBlock() (*waddrmgr.BlockStamp, error) {
	var birthdayBlock waddrmgr.BlockStamp

	var err error
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

			bb, _, err := w.Manager.BirthdayBlock(addrmgrNs)
			birthdayBlock = bb

			return err
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				bb, _, err := w.Manager.BirthdayBlockFromStore(
					tx.Addr(),
				)
				birthdayBlock = bb
				return err
			}, func() {
				birthdayBlock = waddrmgr.BlockStamp{}
			},
		)
	}
	if err != nil {
		return nil, err
	}

	return &birthdayBlock, nil
}

// AddScopeManager creates a new scoped key manager from the root manager.
func (w *Wallet) AddScopeManager(scope waddrmgr.KeyScope,
	addrSchema waddrmgr.ScopeAddrSchema) (
	*waddrmgr.ScopedKeyManager, error) {

	var scopedManager *waddrmgr.ScopedKeyManager

	var err error
	if w.db != nil {
		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

			manager, err := w.Manager.NewScopedKeyManager(
				addrmgrNs, scope, addrSchema,
			)
			scopedManager = manager

			return err
		})
	} else {
		err = w.store.UpdateOnce(
			context.Background(),
			func(tx walletstore.ReadWriteTx) error {
				var err error
				scopedManager, err =
					w.Manager.NewScopedKeyManagerFromStore(
						tx.Addr(), scope, addrSchema,
					)
				return err
			}, func() {
				scopedManager = nil
			},
		)
	}
	if err != nil {
		manager, attached := w.attachStoreScopeAfterAmbiguous(err, scope)
		if attached && manager.AddrSchema() == addrSchema {
			return manager, nil
		}

		return nil, err
	}

	return scopedManager, nil
}

// InitializeKeyScope ensures that a key scope and the exact requested accounts
// exist. Private key material is removed only after all accounts are durable
// when convertToWatchOnly is true.
func (w *Wallet) InitializeKeyScope(scope waddrmgr.KeyScope,
	addrSchema waddrmgr.ScopeAddrSchema, accounts []uint32,
	convertToWatchOnly bool) error {

	scopedManager, err := w.Manager.FetchScopedKeyManager(scope)
	if waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound) {
		scopedManager, err = w.AddScopeManager(scope, addrSchema)
	}
	if err != nil {
		return err
	}

	return w.initAccounts(
		scopedManager, convertToWatchOnly, accounts,
	)
}

// attachStoreScopeAfterAmbiguous reconstructs a scope that became durable even
// though its creation transaction returned an ambiguous commit error.
func (w *Wallet) attachStoreScopeAfterAmbiguous(err error,
	scope waddrmgr.KeyScope) (*waddrmgr.ScopedKeyManager, bool) {

	if w.db != nil {
		return nil, false
	}
	var ambiguous *walletstore.AmbiguousCommitError
	if !errors.As(err, &ambiguous) {
		return nil, false
	}

	var manager *waddrmgr.ScopedKeyManager
	attachErr := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			var err error
			manager, err = w.Manager.AttachScopedKeyManagerFromStore(
				tx.Addr(), scope,
			)
			return err
		}, func() {
			manager = nil
		},
	)
	if attachErr != nil {
		return nil, false
	}

	return manager, true
}

// refreshStartBlockAfterAmbiguous reloads the durable import start block when
// a Store cannot determine whether an import transaction committed.
func (w *Wallet) refreshStartBlockAfterAmbiguous(err error) {
	if w.db != nil {
		return
	}
	var ambiguous *walletstore.AmbiguousCommitError
	if !errors.As(err, &ambiguous) {
		return
	}

	refreshErr := w.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			return w.Manager.RefreshStartBlockFromStore(tx.Addr())
		}, nil,
	)
	if refreshErr != nil {
		log.Warnf("Unable to refresh ambiguous import start block: %v",
			refreshErr)
	}
}

// initAccounts ensures that the requested accounts exist in one backend
// transaction and optionally converts the wallet to watch-only afterward.
func (w *Wallet) initAccounts(scope *waddrmgr.ScopedKeyManager,
	watchOnly bool, accounts []uint32) error {

	if w.db == nil {
		return w.store.UpdateOnce(
			context.Background(),
			func(tx walletstore.ReadWriteTx) error {
				for _, account := range accounts {
					_, err := tx.Addr().Account(
						scope.Scope(), account,
					)
					if err == nil {
						continue
					}
					if !waddrmgr.IsError(
						err, waddrmgr.ErrAccountNotFound,
					) {

						return err
					}

					if err := scope.NewRawAccountFromStore(
						tx.Addr(), account,
					); err != nil {

						return err
					}
				}

				if watchOnly {
					return w.Manager.ConvertToWatchingOnlyFromStore(
						tx.Addr(),
					)
				}

				return nil
			}, nil,
		)
	}

	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		for _, account := range accounts {
			_, err := scope.AccountName(addrmgrNs, account)
			if err == nil {
				continue
			}
			if !waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
				return err
			}

			err = scope.NewRawAccount(addrmgrNs, account)
			if err != nil {
				return err
			}
		}

		// If this is the first startup with remote signing and wallet
		// migration turned on and the wallet wasn't previously
		// migrated, we can do that now that we made sure all accounts
		// that we need were derived correctly.
		if watchOnly {
			log.Infof("Migrating wallet to watch-only mode, " +
				"purging all private key material")

			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

			return w.Manager.ConvertToWatchingOnly(ns)
		}

		return nil
	})
}

// InitAccounts creates accounts numbered from one through num. This legacy
// range-based API is retained for callers that do not know their exact account
// set.
func (w *Wallet) InitAccounts(scope *waddrmgr.ScopedKeyManager,
	watchOnly bool, num uint32) error {

	accounts := make([]uint32, 0, num)
	for account := uint32(1); account <= num && account != 0; account++ {
		accounts = append(accounts, account)
	}

	return w.initAccounts(scope, watchOnly, accounts)
}

// NextExternalKey derives and persists the next external public key for an
// account, returning the allocated child index. Missing private accounts are
// created in the same transaction as the allocation.
func (w *Wallet) NextExternalKey(scope waddrmgr.KeyScope,
	account uint32) (*btcec.PublicKey, uint32, error) {

	scopedManager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, 0, err
	}

	w.newAddrMtx.Lock()
	defer w.newAddrMtx.Unlock()

	var managedAddress waddrmgr.ManagedAddress
	if w.db != nil {
		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			_, err := scopedManager.AccountName(addrmgrNs, account)
			if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) &&
				!w.WatchOnly() {

				err = scopedManager.NewRawAccount(addrmgrNs, account)
			}
			if err != nil {
				return err
			}

			addresses, err := scopedManager.NextExternalAddresses(
				addrmgrNs, account, 1,
			)
			if err != nil {
				return err
			}
			managedAddress = addresses[0]

			return nil
		})
	} else {
		err = w.store.UpdateOnce(
			context.Background(),
			func(tx walletstore.ReadWriteTx) error {
				_, err := tx.Addr().Account(scope, account)
				if waddrmgr.IsError(
					err, waddrmgr.ErrAccountNotFound,
				) && !w.WatchOnly() {

					err = scopedManager.NewRawAccountFromStore(
						tx.Addr(), account,
					)
				}
				if err != nil {
					return err
				}

				managedAddress, _, err =
					scopedManager.NextExternalAddressFromStore(
						tx.Addr(), account,
					)

				return err
			}, func() {
				managedAddress = nil
			},
		)
	}
	if err != nil {
		var ambiguous *walletstore.AmbiguousCommitError
		if errors.As(err, &ambiguous) {
			w.Manager.MarkAccountCacheStale(scope, account)
		}

		return nil, 0, err
	}

	pubKeyAddress, ok := managedAddress.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return nil, 0, fmt.Errorf("managed address %T has no public key",
			managedAddress)
	}
	_, path, _ := pubKeyAddress.DerivationInfo()

	return pubKeyAddress.PubKey(), path.Index, nil
}

// DeriveManagedPubKey derives an arbitrary managed public key. A missing
// account is created for a wallet with private key material, while watch-only
// callers must initialize or import the account first.
func (w *Wallet) DeriveManagedPubKey(scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) (*btcec.PublicKey, error) {

	scopedManager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var managedAddress waddrmgr.ManagedAddress
	if w.db != nil {
		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			managedAddress, err = scopedManager.DeriveFromKeyPath(
				addrmgrNs, path,
			)
			if !waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) ||
				w.WatchOnly() {

				return err
			}

			if err := scopedManager.NewRawAccount(
				addrmgrNs, path.InternalAccount,
			); err != nil {

				return err
			}

			managedAddress, err = scopedManager.DeriveFromKeyPath(
				addrmgrNs, path,
			)

			return err
		})
	} else {
		err = w.store.UpdateOnce(
			context.Background(),
			func(tx walletstore.ReadWriteTx) error {
				_, err := tx.Addr().Account(
					scope, path.InternalAccount,
				)
				if waddrmgr.IsError(
					err, waddrmgr.ErrAccountNotFound,
				) && !w.WatchOnly() {

					err = scopedManager.NewRawAccountFromStore(
						tx.Addr(), path.InternalAccount,
					)
				}
				if err != nil {
					return err
				}

				managedAddress, err =
					scopedManager.DeriveFromKeyPathFromStore(
						tx.Addr(), path,
					)

				return err
			}, func() {
				managedAddress = nil
			},
		)
	}
	if err != nil {
		return nil, err
	}

	pubKeyAddress, ok := managedAddress.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return nil, fmt.Errorf("managed address %T has no public key",
			managedAddress)
	}

	return pubKeyAddress.PubKey(), nil
}

// DeriveFromKeyPath derives a private key using the given derivation path.
func (w *Wallet) DeriveFromKeyPath(scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	scopedMgr, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, fmt.Errorf("error fetching manager for scope %v: "+
			"%w", scope, err)
	}

	// Let's see if we can hit the private key cache.
	privKey, err := scopedMgr.DeriveFromKeyPathCache(path)
	if err == nil {
		return privKey, nil
	}

	// The key wasn't in the cache, let's fully derive it now.
	derive := func(addrmgrNs walletdb.ReadBucket) error {
		addr, err := scopedMgr.DeriveFromKeyPath(addrmgrNs, path)
		if err != nil {
			return fmt.Errorf("error deriving private key: %w", err)
		}

		mpka, ok := addr.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			err := fmt.Errorf("managed address type for %v is "+
				"`%T` but want waddrmgr.ManagedPubKeyAddress",
				addr, addr)

			return err
		}
		privKey, err = mpka.PrivKey()

		return err
	}
	if w.db != nil {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			return derive(tx.ReadBucket(waddrmgrNamespaceKey))
		})
	} else {
		err = w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				addr, err := scopedMgr.DeriveFromKeyPathFromStore(
					tx.Addr(), path,
				)
				if err != nil {
					return fmt.Errorf(
						"error deriving private key: %w", err,
					)
				}
				mpka, ok := addr.(waddrmgr.ManagedPubKeyAddress)
				if !ok {
					return fmt.Errorf(
						"managed address type for %v is `%T` but want "+
							"waddrmgr.ManagedPubKeyAddress", addr, addr,
					)
				}
				privKey, err = mpka.PrivKey()

				return err
			}, func() {
				privKey = nil
			},
		)
	}
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// DeriveFromKeyPathAddAccount derives a private key using the given derivation
// path. The account will be created if it doesn't exist.
func (w *Wallet) DeriveFromKeyPathAddAccount(scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	scopedMgr, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, fmt.Errorf("error fetching manager for scope %v: "+
			"%w", scope, err)
	}

	// Let's see if we can hit the private key cache.
	privKey, err := scopedMgr.DeriveFromKeyPathCache(path)
	if err == nil {
		return privKey, nil
	}

	derivePrivKey := func(addrmgrNs walletdb.ReadWriteBucket) error {
		addr, err := scopedMgr.DeriveFromKeyPath(addrmgrNs, path)

		// Exit early if there's no error.
		if err == nil {
			key, ok := addr.(waddrmgr.ManagedPubKeyAddress)
			if !ok {
				return fmt.Errorf(
					"managed address %T has no private key", addr,
				)
			}

			// Overwrite the returned private key variable.
			privKey, err = key.PrivKey()

			return err
		}

		return err
	}

	// The key wasn't in the cache, let's fully derive it now.
	if w.db == nil {
		err = w.store.UpdateOnce(
			context.Background(),
			func(tx walletstore.ReadWriteTx) error {
				_, err := scopedMgr.AccountPropertiesFromStore(
					tx.Addr(), path.InternalAccount,
				)
				if err != nil && !waddrmgr.IsError(
					err, waddrmgr.ErrAccountNotFound,
				) {

					return err
				}
				if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
					if err := scopedMgr.NewRawAccountFromStore(
						tx.Addr(), path.InternalAccount,
					); err != nil {

						return err
					}
				}

				addr, err := scopedMgr.DeriveFromKeyPathFromStore(
					tx.Addr(), path,
				)
				if err != nil {
					return fmt.Errorf(
						"error deriving private key: %w", err,
					)
				}
				key, ok := addr.(waddrmgr.ManagedPubKeyAddress)
				if !ok {
					return fmt.Errorf(
						"managed address %T has no private key", addr,
					)
				}
				privKey, err = key.PrivKey()
				return err
			}, func() {
				privKey = nil
			},
		)
		return privKey, err
	}

	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := derivePrivKey(addrmgrNs)

		// Exit early if there's no error.
		if err == nil {
			return nil
		}

		// Exit with the error if it's not account not found.
		if !waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return fmt.Errorf("error deriving private key: %w", err)
		}

		// If we've reached this point, then the account doesn't yet
		// exist, so we'll create it now to ensure we can sign.
		err = scopedMgr.NewRawAccount(
			addrmgrNs, path.InternalAccount,
		)
		if err != nil {
			return err
		}

		// Now that we know the account exists, we'll attempt to
		// re-derive the private key.
		return derivePrivKey(addrmgrNs)
	})
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// SyncedTo calls the `SyncedTo` method on the wallet's manager.
func (w *Wallet) SyncedTo() waddrmgr.BlockStamp {
	return w.Manager.SyncedTo()
}

// AddrManager returns the internal address manager.
//
// TODO(yy): Refactor it in lnd and remove the method.
func (w *Wallet) AddrManager() *waddrmgr.Manager {
	return w.Manager
}

// NotificationServer returns the internal NotificationServer.
//
// TODO(yy): Refactor it in lnd and remove the method.
func (w *Wallet) NotificationServer() *NotificationServer {
	return w.NtfnServer
}

// CreateWithCallback is the same as Create with an added callback that will be
// called in the same transaction the wallet structure is initialized.
func CreateWithCallback(db walletdb.DB, pubPass, privPass []byte,
	rootKey *hdkeychain.ExtendedKey, params *chaincfg.Params,
	birthday time.Time, cb func(walletdb.ReadWriteTx) error) error {

	return create(
		db, pubPass, privPass, rootKey, params, birthday, false, cb,
	)
}

// CreateWatchingOnlyWithCallback is the same as CreateWatchingOnly with an
// added callback that will be called in the same transaction the wallet
// structure is initialized.
func CreateWatchingOnlyWithCallback(db walletdb.DB, pubPass []byte,
	params *chaincfg.Params, birthday time.Time,
	cb func(walletdb.ReadWriteTx) error) error {

	return create(
		db, pubPass, nil, nil, params, birthday, true, cb,
	)
}

// Create creates an new wallet, writing it to an empty database.  If the passed
// root key is non-nil, it is used.  Otherwise, a secure random seed of the
// recommended length is generated.
func Create(db walletdb.DB, pubPass, privPass []byte,
	rootKey *hdkeychain.ExtendedKey, params *chaincfg.Params,
	birthday time.Time) error {

	return create(
		db, pubPass, privPass, rootKey, params, birthday, false, nil,
	)
}

// CreateWatchingOnly creates an new watch-only wallet, writing it to
// an empty database. No root key can be provided as this wallet will be
// watching only.  Likewise no private passphrase may be provided
// either.
func CreateWatchingOnly(db walletdb.DB, pubPass []byte,
	params *chaincfg.Params, birthday time.Time) error {

	return create(
		db, pubPass, nil, nil, params, birthday, true, nil,
	)
}

// create initializes the wallet namespaces in an existing walletdb database.
func create(db walletdb.DB, pubPass, privPass []byte,
	rootKey *hdkeychain.ExtendedKey, params *chaincfg.Params,
	birthday time.Time, isWatchingOnly bool,
	cb func(walletdb.ReadWriteTx) error) error {

	// If no root key was provided, we create one now from a random seed.
	// But only if this is not a watching-only wallet where the accounts are
	// created individually from their xpubs.
	if !isWatchingOnly && rootKey == nil {
		hdSeed, err := hdkeychain.GenerateSeed(
			hdkeychain.RecommendedSeedLen,
		)
		if err != nil {
			return err
		}

		// Derive the master extended key from the seed.
		rootKey, err = hdkeychain.NewMaster(hdSeed, params)
		if err != nil {
			return fmt.Errorf("failed to derive master extended " +
				"key")
		}
	}

	// We need a private key if this isn't a watching only wallet.
	if !isWatchingOnly && rootKey != nil && !rootKey.IsPrivate() {
		return fmt.Errorf("need extended private key for wallet that " +
			"is not watching only")
	}

	return walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return err
		}
		txmgrNs, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if err != nil {
			return err
		}

		err = waddrmgr.Create(
			addrmgrNs, rootKey, pubPass, privPass, params, nil,
			birthday,
		)
		if err != nil {
			return err
		}

		err = wtxmgr.Create(txmgrNs)
		if err != nil {
			return err
		}

		if cb != nil {
			return cb(tx)
		}

		return nil
	})
}

// Open loads an already-created wallet from the passed database and namespaces.
func Open(db walletdb.DB, pubPass []byte, cbs *waddrmgr.OpenCallbacks,
	params *chaincfg.Params, recoveryWindow uint32) (*Wallet, error) {

	return OpenWithRetry(
		db, pubPass, cbs, params, recoveryWindow,
		defaultSyncRetryInterval,
	)
}

// OpenWithRetry loads an already-created wallet from the passed database and
// namespaces and re-tries on errors during initial sync.
func OpenWithRetry(db walletdb.DB, pubPass []byte, cbs *waddrmgr.OpenCallbacks,
	params *chaincfg.Params, recoveryWindow uint32,
	syncRetryInterval time.Duration) (*Wallet, error) {

	var (
		addrMgr *waddrmgr.Manager
		txMgr   *wtxmgr.Store
	)

	// Before attempting to open the wallet, we'll check if there are any
	// database upgrades for us to proceed. We'll also create our references
	// to the address and transaction managers, as they are backed by the
	// database.
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		addrMgrBucket := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if addrMgrBucket == nil {
			return errors.New("missing address manager namespace")
		}
		txMgrBucket := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if txMgrBucket == nil {
			return errors.New("missing transaction manager namespace")
		}

		addrMgrUpgrader := waddrmgr.NewMigrationManager(addrMgrBucket)
		txMgrUpgrader := wtxmgr.NewMigrationManager(txMgrBucket)
		err := migration.Upgrade(txMgrUpgrader, addrMgrUpgrader)
		if err != nil {
			return err
		}

		addrMgr, err = waddrmgr.Open(addrMgrBucket, pubPass, params)
		if err != nil {
			return err
		}
		txMgr, err = wtxmgr.Open(txMgrBucket, params)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	log.Infof("Opened wallet") // TODO: log balance? last sync height?

	w := newWallet(
		db, walletkvdb.NewStore(db, addrMgr, txMgr), addrMgr, txMgr,
		pubPass, params, recoveryWindow, syncRetryInterval,
	)

	return w, nil
}

// OpenFromStore loads an existing wallet around the real address manager and a
// backend-neutral Store without constructing a walletdb database.
func OpenFromStore(store walletstore.Store, pubPass []byte,
	params *chaincfg.Params, recoveryWindow uint32,
	syncRetryInterval time.Duration) (*Wallet, error) {

	var snapshot *waddrmgr.ManagerSnapshot
	err := store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			var err error
			snapshot, err = waddrmgr.ReadManagerSnapshot(tx.Addr())
			return err
		}, func() {
			snapshot = nil
		},
	)
	if err != nil {
		return nil, err
	}

	addrMgr, err := waddrmgr.OpenFromSnapshot(snapshot, pubPass, params)
	if err != nil {
		return nil, err
	}

	log.Infof("Opened wallet")

	return newWallet(
		nil, store, addrMgr, nil, pubPass, params, recoveryWindow,
		syncRetryInterval,
	), nil
}

// newWallet initializes the existing Wallet state machine around the supplied
// manager stores.
func newWallet(db walletdb.DB, store walletstore.Store,
	addrMgr *waddrmgr.Manager, txMgr *wtxmgr.Store, pubPass []byte,
	params *chaincfg.Params, recoveryWindow uint32,
	syncRetryInterval time.Duration) *Wallet {

	w := &Wallet{
		publicPassphrase:    pubPass,
		db:                  db,
		store:               store,
		Manager:             addrMgr,
		TxStore:             txMgr,
		lockedOutpoints:     map[wire.OutPoint]struct{}{},
		recoveryWindow:      recoveryWindow,
		rescanAddJob:        make(chan *RescanJob),
		rescanBatch:         make(chan *rescanBatch),
		rescanNotifications: make(chan interface{}),
		rescanProgress:      make(chan *RescanProgressMsg),
		rescanFinished:      make(chan *RescanFinishedMsg),
		createTxRequests:    make(chan createTxRequest),
		unlockRequests:      make(chan unlockRequest),
		lockRequests:        make(chan struct{}),
		holdUnlockRequests:  make(chan chan heldUnlock),
		lockState:           make(chan bool),
		changePassphrase:    make(chan changePassphraseRequest),
		changePassphrases:   make(chan changePassphrasesRequest),
		chainParams:         params,
		quit:                make(chan struct{}),
		syncRetryInterval:   syncRetryInterval,
	}

	w.NtfnServer = newNotificationServer(w)

	return w
}
