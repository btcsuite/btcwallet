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
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
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

	// birthdayBlockDelta is the maximum time delta allowed between our
	// birthday timestamp and our birthday block's timestamp when searching
	// for a better birthday block candidate (if possible).
	birthdayBlockDelta = 2 * time.Hour

	// defaultLockDuration is the default duration for automatic wallet
	// locking.
	defaultLockDuration = 10 * time.Minute

	// MinRecoveryWindow is the minimum allowed value for the RecoveryWindow
	// configuration parameter. This value ensures that a sufficient number
	// of addresses are scanned during wallet recovery to avoid missing
	// funds due to gaps in the address chain.
	MinRecoveryWindow = 20
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

	// ErrInvalidAccountKey is returned when the provided extended public key
	// does not meet the requirements for an account key (e.g., wrong depth
	// or not hardened).
	ErrInvalidAccountKey = errors.New("invalid account key")

	// ErrMissingParam is returned when a required parameter is missing from
	// the configuration.
	ErrMissingParam = errors.New("missing config parameter")

	// ErrInvalidParam is returned when a parameter is invalid.
	ErrInvalidParam = errors.New("invalid config parameter")

	// Namespace bucket keys.
	waddrmgrNamespaceKey = []byte("waddrmgr")
	wtxmgrNamespaceKey   = []byte("wtxmgr")
)

// SyncMethod determines the strategy used to synchronize the wallet with the
// blockchain.
type SyncMethod uint8

const (
	// SyncMethodAuto defaults to CFilters if available (Neutrino/Bitcoind),
	// falling back to Full Block scan if not.
	//
	// Use Case: Default for most users.
	//
	// Logic:
	// 1. Checks if the number of watched items (Addresses + UTXOs) exceeds
	//    a heuristic threshold (100,000). If so, switches to Full Block
	//    scanning to avoid the CPU bottleneck of client-side filter
	//    matching.
	// 2. Attempts to fetch CFilters. If successful, uses CFilters.
	// 3. If CFilters are unavailable, falls back to Full Block scanning.
	SyncMethodAuto SyncMethod = iota

	// SyncMethodCFilters forces the use of Compact Filters (BIP 157/158).
	// The sync process will fail if the backend does not support filters.
	//
	// Use Case: Bandwidth-constrained environments (mobile) or when privacy
	// is paramount (Neutrino P2P).
	//
	// Pros:
	// - Minimal Bandwidth: Only downloads headers and filters (approx 4MB
	//   per 200 blocks) plus relevant blocks. Ideal for sparse wallets.
	//
	// Cons:
	// - CPU Intensive: Client-side matching is O(N*M) where N=Blocks,
	//   M=Addresses. Can be slow for massive wallets (>100k addresses).
	// - Slower if Match Rate is High: If the wallet has transactions in
	//   nearly every block, it downloads filters AND blocks, resulting in
	//   higher overhead than full block scanning.
	SyncMethodCFilters

	// SyncMethodFullBlocks forces the use of full block downloading and
	// scanning, bypassing filters entirely.
	//
	// Use Case: High-bandwidth/Local environments (Bitcoind on localhost)
	// or massive wallets (exchanges, heavy users).
	//
	// Pros:
	// - Low CPU: Block parsing and map lookup is extremely fast compared
	//   to filter matching. Scaling is O(1) or O(TxOutputs) for address
	//   lookups, independent of watchlist size.
	// - Faster for High Match Rates: Avoids the overhead of
	//   fetching/matching filters when most blocks are going to be
	//   downloaded anyway.
	//
	// Cons:
	// - High Bandwidth: Downloads all block data (approx 200MB per 200
	//   blocks). Slow on limited connections.
	SyncMethodFullBlocks
)

// Config holds the configuration options for creating a new
// WalletController.
type Config struct {
	// DB is the underlying database for the wallet.
	DB walletdb.DB

	// Chain is the interface to the blockchain (e.g. bitcoind,
	// neutrino). If set, the wallet will automatically synchronize with
	// the chain upon Start.
	Chain chain.Interface

	// ChainParams defines the network parameters (e.g. mainnet, testnet).
	ChainParams *chaincfg.Params

	// RecoveryWindow specifies the address lookahead for recovery.
	RecoveryWindow uint32

	// WalletSyncRetryInterval is the interval at which the wallet should
	// retry syncing to the chain if it encounters an error.
	WalletSyncRetryInterval time.Duration

	// SyncMethod specifies the synchronization strategy to use.
	SyncMethod SyncMethod

	// AutoLockDuration is the default duration after which the wallet will
	// automatically lock itself if no specific duration is provided during
	// unlock. If zero or negative, the wallet will default to a hardcoded
	// safe duration (e.g. 10m) unless explicitly overridden by the unlock
	// request.
	AutoLockDuration time.Duration

	// Name is the unique identifier for the wallet. It is used to track
	// active wallet instances within the Manager.
	Name string

	// PubPassphrase is the public passphrase for the wallet.
	PubPassphrase []byte

	// MaxCFilterItems is the threshold of watched items (addresses +
	// outpoints) above which the wallet will fallback to full block
	// scanning when SyncMethodAuto is used. This avoids the CPU bottleneck
	// of client-side filter matching for large watchlists. If 0, a default
	// of 100,000 is used.
	MaxCFilterItems int
}

// validate checks the configuration for consistency and completeness.
func (c *Config) validate() error {
	if c.DB == nil {
		return fmt.Errorf("%w: DB", ErrMissingParam)
	}

	if c.Chain == nil {
		return fmt.Errorf("%w: Chain", ErrMissingParam)
	}

	if c.ChainParams == nil {
		return fmt.Errorf("%w: ChainParams", ErrMissingParam)
	}

	if c.Name == "" {
		return fmt.Errorf("%w: Name", ErrMissingParam)
	}

	if c.RecoveryWindow < MinRecoveryWindow {
		return fmt.Errorf("%w: RecoveryWindow must be at least %d",
			ErrInvalidParam, MinRecoveryWindow)
	}

	return nil
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
		//
		//nolint:mnd // Division by 2 is standard for binary search.
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

// Wallet is a structure containing all the components for a complete wallet.
// It manages the cryptographic keys, transaction history, and synchronization
// with the blockchain.
type Wallet struct {
	// walletDeprecated embeds the legacy state and channels. Access to
	// these should be phased out as refactoring progresses.
	*walletDeprecated

	// addrStore is the address and key manager responsible for hierarchical
	// deterministic (HD) derivation and storage of cryptographic keys.
	addrStore waddrmgr.AddrStore

	// txStore is the transaction manager responsible for storing and
	// querying the wallet's transaction history and unspent outputs.
	txStore wtxmgr.TxStore

	// store provides access to database operations used by wallet managers.
	//
	// TODO(yy): Migrate UTXO-related callers behind db.UTXOStore.
	store db.Store

	// NtfnServer handles the delivery of wallet-related events (e.g., new
	// transactions, block connections) to connected clients.
	//
	// TODO(yy): Deprecate.
	NtfnServer *NotificationServer

	// wg is a wait group used to track and wait for all long-running
	// background goroutines to finish during a graceful shutdown.
	wg sync.WaitGroup

	// cfg holds the static configuration parameters provided when the
	// wallet was created or loaded.
	cfg Config

	// sync is the dedicated synchronization component that manages the
	// chain loop, scanning, and reorganization handling.
	sync chainSyncer

	// state maintains the wallet's atomic, three-dimensional status:
	// Lifecycle (System), Synchronization (Chain), and Authentication
	// (Security).
	state walletState

	// lifetimeCtx defines the runtime scope of the wallet. It is created
	// when the wallet starts and canceled when it stops, providing a
	// standard way to signal shutdown to all context-aware background
	// routines.
	//
	// Storing a context in a struct is generally considered an
	// anti-pattern because contexts are usually request-scoped. However,
	// for long-lived service objects that manage their own background
	// goroutines, maintaining a parent context for those routines is a
	// valid exception.
	//
	//nolint:containedctx
	lifetimeCtx context.Context

	// cancel is the cancellation function for lifetimeCtx.
	cancel context.CancelFunc

	// requestChan is the central communication channel for incoming
	// lifecycle and authentication requests.
	requestChan chan any

	// lockTimer is the timer used to automatically lock the wallet after a
	// timeout.
	lockTimer *time.Timer

	// birthdayBlock is the block from which the wallet started scanning.
	// It is loaded on startup and cached to avoid database lookups.
	birthdayBlock waddrmgr.BlockStamp
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
