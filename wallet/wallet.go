// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wallet provides a bitcoin wallet that is capable of fulfilling all
// the duties of a typical bitcoin wallet such as creating and managing keys,
// creating and signing transactions, and customizing of transaction fees.
//
// TODO(yy): bring wrapcheck back when implementing the `Store` interface.
//
//nolint:wrapcheck,cyclop
package wallet

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/walletdb/migration"
	"github.com/btcsuite/btcwallet/wtxmgr"
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

	// ErrNoAssocPrivateKey is returned when a private key is requested for
	// an address that has no associated private key.
	ErrNoAssocPrivateKey = errors.New("address does not have an " +
		"associated private key")

	// Namespace bucket keys.
	waddrmgrNamespaceKey = []byte("waddrmgr")
	wtxmgrNamespaceKey   = []byte("wtxmgr")
)


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

// Wallet is a structure containing all the components for a
// complete wallet.  It contains the Armory-style key store
// addresses and keys),
// Wallet is a structure containing all the components for a complete wallet.
// It manages the cryptographic keys, transaction history, and synchronization
// with the blockchain.
type Wallet struct {
	// walletDeprecated embeds the legacy state and channels. Access to
	// these should be phased out as refactoring progresses.
	*walletDeprecated

	// publicPassphrase is the passphrase used to encrypt and decrypt public
	// data in the address manager.
	publicPassphrase []byte

	// db is the underlying key-value database where all wallet data is
	// persisted.
	db walletdb.DB

	// addrStore is the address and key manager responsible for hierarchical
	// deterministic (HD) derivation and storage of cryptographic keys.
	addrStore waddrmgr.AddrStore

	// txStore is the transaction manager responsible for storing and
	// querying the wallet's transaction history and unspent outputs.
	txStore wtxmgr.TxStore

	// recoveryWindow specifies the number of additional keys to derive
	// beyond the last used one to look for previously used addresses
	// during a rescan or recovery.
	recoveryWindow uint32

	// NtfnServer handles the delivery of wallet-related events (e.g., new
	// transactions, block connections) to connected clients.
	NtfnServer *NotificationServer

	// wg is a wait group used to track and wait for all long-running
	// background goroutines to finish during a graceful shutdown.
	wg sync.WaitGroup
}

// AccountAddresses returns the addresses for every created address for an
// account.


// ChainParams returns the network parameters for the blockchain the wallet
// belongs to.
func (w *Wallet) ChainParams() *chaincfg.Params {
	return w.chainParams
}

// Database returns the underlying walletdb database. This method is provided
// in order to allow applications wrapping btcwallet to store app-specific data
// with the wallet's database.
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

	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		wtxmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		return w.txStore.RemoveUnminedTx(wtxmgrNs, txRecord)
	})
}

// BirthdayBlock returns the birthday block of the wallet.
//
// NOTE: The wallet won't start until the backend is synced, thus the birthday
// block won't be set and `ErrBirthdayBlockNotSet` will be returned.
func (w *Wallet) BirthdayBlock() (*waddrmgr.BlockStamp, error) {
	var birthdayBlock waddrmgr.BlockStamp

	// Query the wallet's birthday block height from db.
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		bb, _, err := w.addrStore.BirthdayBlock(addrmgrNs)
		birthdayBlock = bb

		return err
	})
	if err != nil {
		return nil, err
	}

	return &birthdayBlock, nil
}

// SyncedTo calls the `SyncedTo` method on the wallet's manager.
func (w *Wallet) SyncedTo() waddrmgr.BlockStamp {
	return w.addrStore.SyncedTo()
}

// AddrManager returns the internal address manager.
//
// TODO(yy): Refactor it in lnd and remove the method.
func (w *Wallet) AddrManager() waddrmgr.AddrStore {
	return w.addrStore
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

// hasMinConfs checks whether a transaction at height txHeight has met minconf
// confirmations for a blockchain at height curHeight.
func hasMinConfs(minconf uint32, txHeight, curHeight int32) bool {
	confs := calcConf(txHeight, curHeight)
	if confs < 0 {
		return false
	}

	return uint32(confs) >= minconf
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

	deprecated := &walletDeprecated{
		lockedOutpoints:     map[wire.OutPoint]struct{}{},
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

	w := &Wallet{
		publicPassphrase: pubPass,
		db:               db,
		addrStore:        addrMgr,
		txStore:          txMgr,
		recoveryWindow:   recoveryWindow,
		walletDeprecated: deprecated,
	}

	w.NtfnServer = newNotificationServer(w)
	txMgr.NotifyUnspent = func(hash *chainhash.Hash, index uint32) {
		w.NtfnServer.notifyUnspentOutput(0, hash, index)
	}

	return w, nil
}
