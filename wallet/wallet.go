/*
 * Copyright (c) 2013-2015 The btcsuite developers
 * Copyright (c) 2015 The Decred developers
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
	"sort"
	"sync"
	"time"

	"github.com/decred/dcrd/blockchain"
	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/chain"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/walletdb"
	"github.com/decred/dcrwallet/wstakemgr"
	"github.com/decred/dcrwallet/wtxmgr"
)

const (
	walletDbWatchingOnlyName = "wowallet.db"

	// rollbackTestHeight is the height at which to begin doing the
	// rollback test on simnet.
	rollbackTestHeight = 200

	// rollbackTestDepth is the depth to rollback to when testing.
	rollbackTestDepth = 100
)

// ErrNotSynced describes an error where an operation cannot complete
// due wallet being out of sync (and perhaps currently syncing with)
// the remote chain server.
var ErrNotSynced = errors.New("wallet is not synchronized with the chain server")

// Namespace bucket keys.
var (
	waddrmgrNamespaceKey = []byte("waddrmgr")
	wtxmgrNamespaceKey   = []byte("wtxmgr")
)

// StakeDifficultyInfo is a container for stake difficulty information updates.
type StakeDifficultyInfo struct {
	BlockHash       *chainhash.Hash
	BlockHeight     int64
	StakeDifficulty int64
}

// CurrentVotingInfo is a container for the current height, hash, and list
// of eligible tickets.
type VotingInfo struct {
	BlockHash   *chainhash.Hash
	BlockHeight int64
	Tickets     []*chainhash.Hash
}

// Wallet is a structure containing all the components for a
// complete wallet.  It contains the Armory-style key store
// addresses and keys),
type Wallet struct {
	// Data stores
	db       walletdb.DB
	Manager  *waddrmgr.Manager
	TxStore  *wtxmgr.Store
	StakeMgr *wstakemgr.StakeStore

	// Handlers for stake system.
	stakeSettingsLock  sync.Mutex
	VoteBits           uint16
	StakeMiningEnabled bool
	CurrentStakeDiff   *StakeDifficultyInfo
	BalanceToMaintain  dcrutil.Amount
	CurrentVotingInfo  *VotingInfo
	TicketMaxPrice     dcrutil.Amount

	automaticRepair bool

	chainSvr        *chain.Client
	chainSvrLock    sync.Mutex
	chainSvrSynced  bool
	chainSvrSyncMtx sync.Mutex

	lockedOutpoints map[wire.OutPoint]struct{}

	feeIncrementLock sync.Mutex
	feeIncrement     dcrutil.Amount
	DisallowFree     bool

	// Channels for rescan processing.  Requests are added and merged with
	// any waiting requests, before being sent to another goroutine to
	// call the rescan RPC.
	rescanAddJob        chan *RescanJob
	rescanBatch         chan *rescanBatch
	rescanNotifications chan interface{} // From chain server
	rescanProgress      chan *RescanProgressMsg
	rescanFinished      chan *RescanFinishedMsg

	// Channel for transaction creation requests.
	createTxRequests         chan createTxRequest
	createMultisigTxRequests chan createMultisigTxRequest

	// Channels for stake tx creation requests.
	createSStxRequests     chan createSStxRequest
	createSSGenRequests    chan createSSGenRequest
	createSSRtxRequests    chan createSSRtxRequest
	purchaseTicketRequests chan purchaseTicketRequest

	// Internal address handling.
	internalPool  *addressPool
	externalPool  *addressPool
	addressReuse  bool
	ticketAddress dcrutil.Address

	// Live rollback testing for wtxmgr.
	rollbackTesting bool
	rollbackBlockDB map[uint32]*wtxmgr.DatabaseContents

	// Channels for the manager locker.
	unlockRequests     chan unlockRequest
	lockRequests       chan struct{}
	holdUnlockRequests chan chan HeldUnlock
	lockState          chan bool
	changePassphrase   chan changePassphraseRequest

	// Notification channels so other components can listen in on wallet
	// activity.  These are initialized as nil, and must be created by
	// calling one of the Listen* methods.
	connectedBlocks         chan wtxmgr.BlockMeta
	disconnectedBlocks      chan wtxmgr.BlockMeta
	ticketsPurchased        chan wstakemgr.StakeNotification
	votesCreated            chan wstakemgr.StakeNotification
	revocationsCreated      chan wstakemgr.StakeNotification
	relevantTxs             chan chain.RelevantTx
	lockStateChanges        chan bool // true when locked
	confirmedBalance        chan dcrutil.Amount
	unconfirmedBalance      chan dcrutil.Amount
	confirmedBalanceStake   chan dcrutil.Amount
	unconfirmedBalanceStake chan dcrutil.Amount
	notificationMu          sync.Mutex

	chainParams *chaincfg.Params

	wg sync.WaitGroup

	started bool
	quit    chan struct{}
	quitMu  sync.Mutex
}

// newWallet creates a new Wallet structure with the provided address manager
// and transaction store.
func newWallet(vb uint16, esm bool, btm dcrutil.Amount, addressReuse bool,
	rollbackTest bool, ticketAddress dcrutil.Address, tmp dcrutil.Amount,
	autoRepair bool, mgr *waddrmgr.Manager, txs *wtxmgr.Store,
	smgr *wstakemgr.StakeStore, db *walletdb.DB, params *chaincfg.Params) *Wallet {
	var rollbackBlockDB map[uint32]*wtxmgr.DatabaseContents
	if rollbackTest {
		rollbackBlockDB = make(map[uint32]*wtxmgr.DatabaseContents)
	}

	var feeIncrement dcrutil.Amount
	switch {
	case params == &chaincfg.MainNetParams:
		feeIncrement = FeeIncrementMainnet
	case params == &chaincfg.TestNetParams:
		feeIncrement = FeeIncrementTestnet
	default:
		feeIncrement = FeeIncrementTestnet
	}

	return &Wallet{
		db:                       *db,
		Manager:                  mgr,
		TxStore:                  txs,
		StakeMgr:                 smgr,
		StakeMiningEnabled:       esm,
		VoteBits:                 vb,
		BalanceToMaintain:        btm,
		CurrentStakeDiff:         &StakeDifficultyInfo{nil, -1, -1},
		lockedOutpoints:          map[wire.OutPoint]struct{}{},
		feeIncrement:             feeIncrement,
		rescanAddJob:             make(chan *RescanJob),
		rescanBatch:              make(chan *rescanBatch),
		rescanNotifications:      make(chan interface{}),
		rescanProgress:           make(chan *RescanProgressMsg),
		rescanFinished:           make(chan *RescanFinishedMsg),
		createTxRequests:         make(chan createTxRequest),
		createMultisigTxRequests: make(chan createMultisigTxRequest),
		createSStxRequests:       make(chan createSStxRequest),
		createSSGenRequests:      make(chan createSSGenRequest),
		createSSRtxRequests:      make(chan createSSRtxRequest),
		purchaseTicketRequests:   make(chan purchaseTicketRequest),
		internalPool:             new(addressPool),
		externalPool:             new(addressPool),
		addressReuse:             addressReuse,
		ticketAddress:            ticketAddress,
		TicketMaxPrice:           tmp,
		automaticRepair:          autoRepair,
		rollbackTesting:          rollbackTest,
		rollbackBlockDB:          rollbackBlockDB,
		unlockRequests:           make(chan unlockRequest),
		lockRequests:             make(chan struct{}),
		holdUnlockRequests:       make(chan chan HeldUnlock),
		lockState:                make(chan bool),
		changePassphrase:         make(chan changePassphraseRequest),
		chainParams:              params,
		quit:                     make(chan struct{}),
	}
}

// GetStakeDifficulty is used to get CurrentStakeDiff information in
// the wallet. It returns a pointer to a copy of the data.
func (w *Wallet) GetStakeDifficulty() *StakeDifficultyInfo {
	w.stakeSettingsLock.Lock()
	defer w.stakeSettingsLock.Unlock()

	if w.CurrentStakeDiff == nil {
		return nil
	}

	return &StakeDifficultyInfo{
		w.CurrentStakeDiff.BlockHash,
		w.CurrentStakeDiff.BlockHeight,
		w.CurrentStakeDiff.StakeDifficulty,
	}
}

// SetStakeDifficulty is used to set CurrentStakeDiff information in
// the wallet.
func (w *Wallet) SetStakeDifficulty(sdi *StakeDifficultyInfo) {
	w.stakeSettingsLock.Lock()
	defer w.stakeSettingsLock.Unlock()

	w.CurrentStakeDiff = sdi
}

// FeeIncrement is used to get the current feeIncrement for the wallet.
func (w *Wallet) FeeIncrement() dcrutil.Amount {
	w.feeIncrementLock.Lock()
	fee := w.feeIncrement
	w.feeIncrementLock.Unlock()

	return fee
}

// SetFeeIncrement is used to set the current w.FeeIncrement for the wallet.
// Uses non-exported mutex safe setFeeIncrement func
func (w *Wallet) SetFeeIncrement(fee dcrutil.Amount) {
	w.feeIncrementLock.Lock()
	w.feeIncrement = fee
	w.feeIncrementLock.Unlock()
}

// SetGenerate is used to enable or disable stake mining in the
// wallet.
func (w *Wallet) SetGenerate(flag bool) error {
	w.stakeSettingsLock.Lock()
	defer w.stakeSettingsLock.Unlock()

	isChanged := w.StakeMiningEnabled != flag
	w.StakeMiningEnabled = flag

	// If stake mining has been enabled again, make sure to
	// try to submit any possible votes on the current top
	// block.
	if w.StakeMiningEnabled && isChanged &&
		w.CurrentVotingInfo != nil {
		ntfns, err := w.StakeMgr.HandleWinningTicketsNtfn(
			w.CurrentVotingInfo.BlockHash,
			w.CurrentVotingInfo.BlockHeight,
			w.CurrentVotingInfo.Tickets,
			w.VoteBits)
		if err != nil {
			return err
		}

		if ntfns != nil {
			// Send notifications for newly created votes by the RPC.
			for _, ntfn := range ntfns {
				w.notifyVoteCreated(*ntfn)
			}
		}
	}

	if w.StakeMiningEnabled && isChanged {
		log.Infof("Stake mining enabled")
	} else if !w.StakeMiningEnabled && isChanged {
		log.Infof("Stake mining disabled")
	}

	return nil
}

// GetCurrentVotingInfo returns a copy of the current voting information.
func (w *Wallet) GetCurrentVotingInfo() *VotingInfo {
	if w.CurrentVotingInfo == nil {
		return nil
	}

	var tickets []*chainhash.Hash
	for _, ti := range w.CurrentVotingInfo.Tickets {
		tickets = append(tickets, ti)
	}
	return &VotingInfo{
		w.CurrentVotingInfo.BlockHash,
		w.CurrentVotingInfo.BlockHeight,
		w.CurrentVotingInfo.Tickets,
	}
}

// SetCurrentVotingInfo is used to set the current tickets eligible
// to vote on the top block, along with that block's hash and height.
func (w *Wallet) SetCurrentVotingInfo(blockHash *chainhash.Hash,
	blockHeight int64,
	tickets []*chainhash.Hash) {
	w.stakeSettingsLock.Lock()
	defer w.stakeSettingsLock.Unlock()

	w.CurrentVotingInfo = &VotingInfo{blockHash, blockHeight, tickets}
}

// GetTicketMaxPrice gets the current maximum price the user is willing to pay
// for a ticket.
func (w *Wallet) GetTicketMaxPrice() dcrutil.Amount {
	w.stakeSettingsLock.Lock()
	defer w.stakeSettingsLock.Unlock()

	return w.TicketMaxPrice
}

// SetTicketMaxPrice sets the current maximum price the user is willing to pay
// for a ticket.
func (w *Wallet) SetTicketMaxPrice(amt dcrutil.Amount) {
	w.stakeSettingsLock.Lock()
	defer w.stakeSettingsLock.Unlock()

	w.TicketMaxPrice = amt
}

func (w *Wallet) ChainParams() *chaincfg.Params {
	return w.chainParams
}

// ErrDuplicateListen is returned for any attempts to listen for the same
// notification more than once.  If callers must pass along a notifiation to
// multiple places, they must broadcast it themself.
var ErrDuplicateListen = errors.New("duplicate listen")

// ListenConnectedBlocks returns a channel that passes all blocks that a wallet
// has been marked in sync with. The channel must be read, or other wallet
// methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenConnectedBlocks() (<-chan wtxmgr.BlockMeta, error) {
	defer w.notificationMu.Unlock()
	w.notificationMu.Lock()

	if w.connectedBlocks != nil {
		return nil, ErrDuplicateListen
	}
	w.connectedBlocks = make(chan wtxmgr.BlockMeta)
	return w.connectedBlocks, nil
}

// ListenDisconnectedBlocks returns a channel that passes all blocks that a
// wallet has detached.  The channel must be read, or other wallet methods will
// block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenDisconnectedBlocks() (<-chan wtxmgr.BlockMeta, error) {
	defer w.notificationMu.Unlock()
	w.notificationMu.Lock()

	if w.disconnectedBlocks != nil {
		return nil, ErrDuplicateListen
	}
	w.disconnectedBlocks = make(chan wtxmgr.BlockMeta)
	return w.disconnectedBlocks, nil
}

// ListenTicketsPurchased returns a channel that passes all SStx generated by
// the wallet to the relevant ntfn channel. The channel must be read, or other
// wallet methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenTicketsPurchased() (<-chan wstakemgr.StakeNotification, error) {
	defer w.notificationMu.Unlock()
	w.notificationMu.Lock()

	if w.ticketsPurchased != nil {
		return nil, ErrDuplicateListen
	}
	w.ticketsPurchased = make(chan wstakemgr.StakeNotification)
	return w.ticketsPurchased, nil
}

// ListenVotesCreated returns a channel that passes all SSGen generated by
// the wallet to the relevant ntfn channel. The channel must be read, or other
// wallet methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenVotesCreated() (<-chan wstakemgr.StakeNotification, error) {
	defer w.notificationMu.Unlock()
	w.notificationMu.Lock()

	if w.votesCreated != nil {
		return nil, ErrDuplicateListen
	}
	w.votesCreated = make(chan wstakemgr.StakeNotification)
	return w.votesCreated, nil
}

// ListenRevocationsCreated returns a channel that passes all SSRtx generated by
// the wallet to the relevant ntfn channel. The channel must be read, or other
// wallet methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenRevocationsCreated() (<-chan wstakemgr.StakeNotification, error) {
	defer w.notificationMu.Unlock()
	w.notificationMu.Lock()

	if w.revocationsCreated != nil {
		return nil, ErrDuplicateListen
	}
	w.revocationsCreated = make(chan wstakemgr.StakeNotification)
	return w.revocationsCreated, nil
}

// ListenLockStatus returns a channel that passes the current lock state
// of the wallet whenever the lock state is changed.  The value is true for
// locked, and false for unlocked.  The channel must be read, or other wallet
// methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenLockStatus() (<-chan bool, error) {
	defer w.notificationMu.Unlock()
	w.notificationMu.Lock()

	if w.lockStateChanges != nil {
		return nil, ErrDuplicateListen
	}
	w.lockStateChanges = make(chan bool)
	return w.lockStateChanges, nil
}

// ListenConfirmedBalance returns a channel that passes the confirmed balance
// when any changes to the balance are made.  This channel must be read, or
// other wallet methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenConfirmedBalance() (<-chan dcrutil.Amount, error) {
	defer w.notificationMu.Unlock()
	w.notificationMu.Lock()

	if w.confirmedBalance != nil {
		return nil, ErrDuplicateListen
	}
	w.confirmedBalance = make(chan dcrutil.Amount)
	return w.confirmedBalance, nil
}

// ListenUnconfirmedBalance returns a channel that passes the unconfirmed
// balance when any changes to the balance are made.  This channel must be
// read, or other wallet methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenUnconfirmedBalance() (<-chan dcrutil.Amount, error) {
	defer w.notificationMu.Unlock()
	w.notificationMu.Lock()

	if w.unconfirmedBalance != nil {
		return nil, ErrDuplicateListen
	}
	w.unconfirmedBalance = make(chan dcrutil.Amount)
	return w.unconfirmedBalance, nil
}

// ListenRelevantTxs returns a channel that passes all transactions relevant to
// a wallet, optionally including metadata regarding the block they were mined
// in.  This channel must be read, or other wallet methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (w *Wallet) ListenRelevantTxs() (<-chan chain.RelevantTx, error) {
	defer w.notificationMu.Unlock()
	w.notificationMu.Lock()

	if w.relevantTxs != nil {
		return nil, ErrDuplicateListen
	}
	w.relevantTxs = make(chan chain.RelevantTx)
	return w.relevantTxs, nil
}

func (w *Wallet) notifyConnectedBlock(block wtxmgr.BlockMeta) {
	w.notificationMu.Lock()
	if w.connectedBlocks != nil {
		w.connectedBlocks <- block
	}
	w.notificationMu.Unlock()
}

func (w *Wallet) notifyDisconnectedBlock(block wtxmgr.BlockMeta) {
	w.notificationMu.Lock()
	if w.disconnectedBlocks != nil {
		w.disconnectedBlocks <- block
	}
	w.notificationMu.Unlock()
}

func (w *Wallet) notifyLockStateChange(locked bool) {
	w.notificationMu.Lock()
	if w.lockStateChanges != nil {
		w.lockStateChanges <- locked
	}
	w.notificationMu.Unlock()
}

func (w *Wallet) notifyConfirmedBalance(bal dcrutil.Amount) {
	w.notificationMu.Lock()
	if w.confirmedBalance != nil {
		w.confirmedBalance <- bal
	}
	w.notificationMu.Unlock()
}

func (w *Wallet) notifyUnconfirmedBalance(bal dcrutil.Amount) {
	w.notificationMu.Lock()
	if w.unconfirmedBalance != nil {
		w.unconfirmedBalance <- bal
	}
	w.notificationMu.Unlock()
}

func (w *Wallet) notifyConfirmedBalanceStake(bal dcrutil.Amount) {
	w.notificationMu.Lock()
	if w.confirmedBalanceStake != nil {
		w.confirmedBalanceStake <- bal
	}
	w.notificationMu.Unlock()
}

func (w *Wallet) notifyUnconfirmedBalanceStake(bal dcrutil.Amount) {
	w.notificationMu.Lock()
	if w.unconfirmedBalanceStake != nil {
		w.unconfirmedBalanceStake <- bal
	}
	w.notificationMu.Unlock()
}
func (w *Wallet) notifyTicketPurchase(sn wstakemgr.StakeNotification) {
	w.notificationMu.Lock()
	if w.ticketsPurchased != nil {
		w.ticketsPurchased <- sn
	}
	w.notificationMu.Unlock()
}

func (w *Wallet) notifyVoteCreated(sn wstakemgr.StakeNotification) {
	w.notificationMu.Lock()
	if w.votesCreated != nil {
		w.votesCreated <- sn
	}
	w.notificationMu.Unlock()
}

func (w *Wallet) notifyRevocationCreated(sn wstakemgr.StakeNotification) {
	w.notificationMu.Lock()
	if w.revocationsCreated != nil {
		w.revocationsCreated <- sn
	}
	w.notificationMu.Unlock()
}

func (w *Wallet) notifyRelevantTx(relevantTx chain.RelevantTx) {
	w.notificationMu.Lock()
	if w.relevantTxs != nil {
		w.relevantTxs <- relevantTx
	}
	w.notificationMu.Unlock()
}

// Start starts the goroutines necessary to manage a wallet.
func (w *Wallet) Start(chainServer *chain.Client) {
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

	w.chainSvrLock.Lock()
	defer w.chainSvrLock.Unlock()
	w.chainSvr = chainServer
	w.StakeMgr.SetChainSvr(chainServer)

	w.wg.Add(7)

	go w.handleChainNotifications()
	go w.handleChainVotingNotifications()
	go w.txCreator()
	go w.walletLocker()
	go w.rescanBatchHandler()
	go w.rescanProgressHandler()
	go w.rescanRPCHandler()

	// Request notifications for winning tickets.
	err := w.chainSvr.NotifyWinningTickets()
	if err != nil {
		log.Error("Unable to request transaction updates for "+
			"winning tickets. Error: ", err.Error())
	}

	// Request notifications for spent and missed tickets.
	err = w.chainSvr.NotifySpentAndMissedTickets()
	if err != nil {
		log.Error("Unable to request transaction updates for spent "+
			"and missed tickets. Error: ", err.Error())
	}

	// Request notifications for stake difficulty.
	err = w.chainSvr.NotifyStakeDifficulty()
	if err != nil {
		log.Error("Unable to request transaction updates for stake "+
			"difficulty. Error: ", err.Error())
	}

	if w.StakeMiningEnabled {
		log.Infof("Stake mining is enabled. Votebits: %v, minimum wallet "+
			"balance %v", w.VoteBits, w.BalanceToMaintain.ToCoin())
		log.Infof("PLEASE ENSURE YOUR WALLET IS UNLOCKED SO IT MAY " +
			"VOTE ON BLOCKS AND RECEIVE STAKE REWARDS")
	}

	// Spin up the address pools.
	w.internalPool.initialize(waddrmgr.InternalBranch, w)
	w.externalPool.initialize(waddrmgr.ExternalBranch, w)
}

// quitChan atomically reads the quit channel.
func (w *Wallet) quitChan() <-chan struct{} {
	w.quitMu.Lock()
	c := w.quit
	w.quitMu.Unlock()
	return c
}

// CloseDatabases triggers the wallet databases to shut down.
func (w *Wallet) CloseDatabases() {
	w.TxStore.Close()
	w.StakeMgr.Close()

	// Store the current address pool last addresses.
	w.CloseAddressPools()
}

// Stop signals all wallet goroutines to shutdown.
func (w *Wallet) Stop() {
	w.quitMu.Lock()
	quit := w.quit
	w.quitMu.Unlock()

	select {
	case <-quit:
	default:
		close(quit)
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
	case <-w.quitChan():
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
// NOTE: Due to an API limitation with dcrrpcclient, this may return true after
// the client disconnected (and is attempting a reconnect).  This will be unknown
// until the reconnect notification is received, at which point the wallet can be
// marked out of sync again until after the next rescan completes.
func (w *Wallet) SetChainSynced(synced bool) {
	w.chainSvrSyncMtx.Lock()
	w.chainSvrSynced = synced
	w.chainSvrSyncMtx.Unlock()
}

// finalScanLength is the final length of keys to scan for the recursive
// function below.
var finalScanLength int = 100

// addrSeekWidth is the number of new addresses to generate and add to the
// address manager when trying to sync up a wallet to the main chain. This
// is the maximum gap introduced by a resyncing as well, and should be less
// than finalScanLength above.
// TODO Optimize the scanning so that rather than overshooting the end address,
// you instead step through addresses incrementally until reaching idx so that
// you don't reach a gap. This can be done by keeping track of where the current
// cursor is and adding addresses in big chunks until you hit the end.
var addrSeekWidth uint32 = 20

// bisectLastIndex is a helper function for search through addresses.
func (w *Wallet) bisectLastIndex(hi, low int, account uint32, branch uint32) int {
	offset := low
	for i := hi - low - 1; i > 0; i /= 2 {
		if i+offset+int(addrSeekWidth) < waddrmgr.MaxAddressesPerAccount {
			for j := i + offset; j < i+offset+int(addrSeekWidth); j++ {
				addr, err := w.Manager.GetAddress(uint32(j), account, branch)
				// Skip erroneous keys, which happen rarely.
				if err != nil {
					continue
				}

				existsJson, err := w.chainSvr.ExistsAddress(addr)
				if err != nil {
					return 0
				}
				if existsJson.Exists {
					return i + offset
				}
			}
		} else {
			addr, err := w.Manager.GetAddress(uint32(i+offset), account, branch)
			// Skip erroneous keys, which happen rarely.
			if err != nil {
				continue
			}
			existsJson, err := w.chainSvr.ExistsAddress(addr)
			if err != nil {
				return 0
			}
			if existsJson.Exists {
				return i + offset
			}
		}
	}

	return 0
}

// findEnd is a helper function for searching for used addresses.
func (w *Wallet) findEnd(start, stop int, account uint32, branch uint32) int {
	indexStart := w.bisectLastIndex(stop, start, account, branch)
	indexLast := 0
	for {
		indexLastStored := indexStart
		low := indexLastStored
		hi := indexLast + ((indexStart - indexLast) * 2) + 1
		indexStart = w.bisectLastIndex(hi, low, account, branch)
		indexLast = indexLastStored

		if indexStart == 0 {
			break
		}
	}

	return indexLast
}

// scanAddressIndex identifies the last used address in an HD keychain of public
// keys. It returns the index of the last used key, along with the address of
// this key.
func (w *Wallet) scanAddressIndex(start int, end int, account uint32,
	branch uint32) (uint32, dcrutil.Address, error) {
	// Find the last used address. Scan from it to the end in case there was a
	// gap from that position, which is possible. Then, return the address
	// in that position.
	lastUsed := w.findEnd(start, end, account, branch)
	if lastUsed != 0 {
		for i := lastUsed + finalScanLength; i > lastUsed; i-- {
			addr, err := w.Manager.GetAddress(uint32(i), account, branch)
			// Skip erroneous keys.
			if err != nil {
				continue
			}

			existsJson, err := w.chainSvr.ExistsAddress(addr)
			if err != nil {
				return 0, nil, fmt.Errorf("failed to access chain server: %v",
					err.Error())
			}

			if existsJson.Exists {
				lastUsed = i
				break
			}
		}

		addr, err := w.Manager.GetAddress(uint32(lastUsed), account, branch)
		if err != nil {
			return 0, nil, err
		}
		return uint32(lastUsed), addr, nil
	}

	// We can't find any used addresses. The wallet is
	// unused.
	return 0, nil, nil
}

// doAddressResync resyncs the address manager to a given address.
func (w *Wallet) doAddressResync(addr dcrutil.Address, idx uint32,
	internal bool) error {
	isSynced := false
	addrFunction := w.Manager.NextExternalAddresses
	if internal {
		addrFunction = w.Manager.NextInternalAddresses
	}

	counter := uint32(0)
	for !isSynced {
		// Generate some new addresses and scan them to see
		// if any of the match the address to sync to.
		addrs, err :=
			addrFunction(waddrmgr.DefaultAccountNum,
				addrSeekWidth)
		if err != nil {
			return err
		}

		for _, newAddr := range addrs {
			if bytes.Compare(addr.ScriptAddress(),
				newAddr.Address().ScriptAddress()) == 0 {
				isSynced = true
			}
		}

		// Don't let this loop infinitely.
		if counter > waddrmgr.MaxAddressesPerAccount/addrSeekWidth {
			break
		}

		log.Debugf("Currently getting address %v", counter*addrSeekWidth)

		counter++
	}

	if isSynced {
		return nil
	}

	return fmt.Errorf("failed to sync to address %v during address rescan",
		addr.String())
}

// rescanActiveAddresses accesses the daemon to discover all the addresses that
// have been used by an HD keychain stemming from this wallet in the default
// account.
// TODO Discover and rescan all other active accounts.
func (w *Wallet) rescanActiveAddresses() error {
	min := 0
	max := waddrmgr.MaxAddressesPerAccount

	log.Infof("Beginning a rescan of active addresses using the daemon. " +
		"This may take a while.")

	// Do this for both external (0) and internal (1) branches.
	for i := uint32(0); i < 2; i++ {
		idx, addr, err := w.scanAddressIndex(min, max,
			waddrmgr.DefaultAccountNum, i)
		if err != nil {
			return err
		}

		branchString := "external"
		if i == 1 {
			branchString = "internal"
		}

		if addr == nil && err == nil {
			// Check if the zeroeth address is used. If it is, insert it.
			addr, err := w.Manager.GetAddress(uint32(i),
				waddrmgr.DefaultAccountNum, i)
			// Skip erroneous keys.
			if err != nil {
				continue
			}
			existsJson, err := w.chainSvr.ExistsAddress(addr)
			if err != nil {
				return fmt.Errorf("failed to access chain server: %v",
					err.Error())
			}

			if existsJson.Exists {
				addrFunction := w.Manager.NextExternalAddresses
				if i == 1 {
					addrFunction = w.Manager.NextInternalAddresses
				}
				addrFunction(waddrmgr.DefaultAccountNum, 1)

				log.Infof("Wallet has 1 used address for "+
					"default account %v branch", branchString)
				continue
			}

			log.Infof("Wallet has no used addresses for "+
				"default account %v branch", branchString)
			continue
		}

		// Exit out if we already have the address in question.
		exists, err := w.Manager.ExistsAddress(addr.ScriptAddress())
		if err != nil {
			return err
		}
		if exists {
			log.Debugf("Wallet is already synchronized to address %v"+
				" of default account %v branch", addr, branchString)
			continue
		}

		log.Infof("Wallet default account %v branch is desynced and must be "+
			"resynced. Doing this now...", branchString)

		if i == 0 { // External
			err := w.doAddressResync(addr, idx, false)
			if err != nil {
				return fmt.Errorf("couldn't sync external addresses in " +
					"address manager")
			}
			log.Infof("Successfully synchronized the address manager to "+
				"external address %v (key index %v)",
				addr.String(),
				idx)
		}
		if i == 1 { // Internal
			err := w.doAddressResync(addr, idx, true)
			if err != nil {
				return fmt.Errorf("couldn't sync internal addresses in " +
					"address manager")
			}
			log.Infof("Successfully synchronized the address manager to "+
				"internal address %v (key index %v)",
				addr.String(),
				idx)
		}
	}

	return nil
}

// activeData returns the currently-active receiving addresses and all unspent
// outputs.  This is primarely intended to provide the parameters for a
// rescan request.
func (w *Wallet) activeData() ([]dcrutil.Address, []*wire.OutPoint, error) {
	err := w.rescanActiveAddresses()
	if err != nil {
		return nil, nil, err
	}

	var addrs []dcrutil.Address
	err = w.Manager.ForEachActiveAddress(func(addr dcrutil.Address) error {
		addrs = append(addrs, addr)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	unspent, err := w.TxStore.UnspentOutpoints()
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
	// dcrrpcclient is modified to allow some notification request to not
	// automatically resent on reconnect, include the notifyblocks request
	// as well.  I am leaning towards allowing off all dcrrpcclient
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

	// Compare previously-seen blocks against the chain server.  If any of
	// these blocks no longer exist, rollback all of the missing blocks
	// before catching up with the rescan.
	rollback := false
	localBest := w.Manager.SyncedTo()
	var syncBlock waddrmgr.BlockStamp
	for i := localBest.Height; i > 0; i-- {
		// Get the block hash from the transaction store.
		blhLocal, err := w.TxStore.GetBlockHash(i)
		if err != nil {
			continue
		}

		// This block may not be on the main chain. Get the block at this
		// position on the main chain using getblockhash. If it fails to
		// match up, also initiate rollback.
		blhMainchain, err := w.chainSvr.GetBlockHash(int64(i))
		if err != nil {
			continue
		}
		if !blhMainchain.IsEqual(&blhLocal) {
			rollback = true
			continue
		}

		log.Debug("Found matching block %v at height %v. Rolling back "+
			"blockchain if necessary.", blhLocal, i)
		syncBlock.Hash = blhLocal
		syncBlock.Height = i
		break
	}
	if rollback {
		log.Debug("Rolling back blockchain to height %v.", syncBlock.Height)
		err = w.Manager.SetSyncedTo(&syncBlock)
		if err != nil {
			return err
		}
		// Rollback unconfirms transactions at and beyond the passed
		// height, so add one to the new synced-to height to prevent
		// unconfirming txs from the synced-to block.
		err = w.TxStore.Rollback(syncBlock.Height + 1)
		if err != nil {
			return err
		}
	}

	err = w.Rescan(addrs, unspent)
	if err != nil {
		return err
	}

	// Get a list of the most recent blocks from the chain server. Send these
	// to the wtxmgr so that the wtxmgr can insert the blocks if they do not
	// exist, so that it can properly handle rollbacks around this period.
	log.Infof("Syncing the transaction store blockchain to the most recent " +
		"blocks.")
	bestBlockHash, bestBlockHeight, err := w.chainSvr.GetBestBlock()
	if err != nil {
		return err
	}
	curBlock := bestBlockHash
	maxBlockDistToRestore := int32(512)

	if !curBlock.IsEqual(w.chainParams.GenesisHash) {
		// The default behaviour of the wtxmgr is to insert a block if
		// the block isn't already otherwise in the database. If it does
		// exist there, the function does nothing. Insertion ordering
		// itself is unimportant as long as the history itself is correct.
		for i := bestBlockHeight; i >
			(bestBlockHeight - maxBlockDistToRestore); i-- {
			bl, err := w.chainSvr.GetBlock(curBlock)
			if err != nil {
				return err
			}
			blHeight := bl.MsgBlock().Header.Height
			vb := bl.MsgBlock().Header.VoteBits
			wtxBm := wtxmgr.BlockMeta{
				wtxmgr.Block{*curBlock, int32(blHeight)},
				time.Now(),
				vb,
			}
			err = w.TxStore.InsertBlock(&wtxBm)
			if err != nil {
				return err
			}

			curBlock = &bl.MsgBlock().Header.PrevBlock

			// Break early if we hit the genesis block.
			if i == 1 {
				break
			}
		}
	}

	// Set the ticket price upon syncing to the main chain.
	bestBlock, err := w.chainSvr.GetBlock(bestBlockHash)
	if err != nil {
		return err
	}
	w.SetStakeDifficulty(&StakeDifficultyInfo{
		bestBlockHash,
		int64(bestBlockHeight),
		bestBlock.MsgBlock().Header.SBits,
	})

	return nil
}

type (
	createTxRequest struct {
		account uint32
		pairs   map[string]dcrutil.Amount
		minconf int32
		resp    chan createTxResponse
	}
	createMultisigTxRequest struct {
		account   uint32
		amount    dcrutil.Amount
		pubkeys   []*dcrutil.AddressSecpPubKey
		nrequired int8
		minconf   int32
		resp      chan createMultisigTxResponse
	}
	createSStxRequest struct {
		usedInputs []wtxmgr.Credit
		pair       map[string]dcrutil.Amount
		couts      []dcrjson.SStxCommitOut
		inputs     []dcrjson.SStxInput
		minconf    int32
		resp       chan createSStxResponse
	}
	createSSGenRequest struct {
		tickethash chainhash.Hash
		blockhash  chainhash.Hash
		height     int64
		votebits   uint16
		resp       chan createSSGenResponse
	}
	createSSRtxRequest struct {
		tickethash chainhash.Hash
		resp       chan createSSRtxResponse
	}
	purchaseTicketRequest struct {
		minBalance dcrutil.Amount
		spendLimit dcrutil.Amount
		minConf    int32
		ticketAddr dcrutil.Address
		resp       chan purchaseTicketResponse
	}

	createTxResponse struct {
		tx  *CreatedTx
		err error
	}
	createMultisigTxResponse struct {
		tx           *CreatedTx
		address      dcrutil.Address
		redeemScript []byte
		err          error
	}
	createSStxResponse struct {
		tx  *CreatedTx
		err error
	}
	createSSGenResponse struct {
		tx  *CreatedTx
		err error
	}
	createSSRtxResponse struct {
		tx  *CreatedTx
		err error
	}
	purchaseTicketResponse struct {
		data interface{}
		err  error
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
			// Initialize the address pool for use.
			pool := w.internalPool
			pool.mutex.Lock()
			addrFunc := pool.GetNewAddress

			tx, err := w.txToPairs(txr.pairs, txr.account, txr.minconf,
				addrFunc)
			if err == nil {
				pool.BatchFinish()
			} else {
				pool.BatchRollback()
			}
			pool.mutex.Unlock()

			txr.resp <- createTxResponse{tx, err}

		case txr := <-w.createMultisigTxRequests:
			tx, address, redeemScript, err := w.txToMultisig(txr.account,
				txr.amount, txr.pubkeys, txr.nrequired, txr.minconf)
			txr.resp <- createMultisigTxResponse{tx, address, redeemScript, err}

		case txr := <-w.createSStxRequests:
			// Initialize the address pool for use.
			pool := w.internalPool
			pool.mutex.Lock()
			addrFunc := pool.GetNewAddress

			tx, err := w.txToSStx(txr.pair,
				txr.usedInputs,
				txr.inputs,
				txr.couts,
				waddrmgr.DefaultAccountNum,
				addrFunc,
				txr.minconf)
			if err == nil {
				pool.BatchFinish()
			} else {
				pool.BatchRollback()
			}
			pool.mutex.Unlock()

			txr.resp <- createSStxResponse{tx, err}

		case txr := <-w.createSSGenRequests:
			tx, err := w.txToSSGen(txr.tickethash,
				txr.blockhash,
				txr.height,
				txr.votebits)
			txr.resp <- createSSGenResponse{tx, err}

		case txr := <-w.createSSRtxRequests:
			tx, err := w.txToSSRtx(txr.tickethash)
			txr.resp <- createSSRtxResponse{tx, err}

		case txr := <-w.purchaseTicketRequests:
			data, err := w.purchaseTicket(txr)
			txr.resp <- purchaseTicketResponse{data, err}

		case <-quit:
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
func (w *Wallet) CreateSimpleTx(account uint32, pairs map[string]dcrutil.Amount,
	minconf int32) (*CreatedTx, error) {

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

// CreateSStxTx receives a request from the RPC and ships it to txCreator to
// generate a new SStx.
func (w *Wallet) CreateMultisigTx(account uint32, amount dcrutil.Amount,
	pubkeys []*dcrutil.AddressSecpPubKey, nrequired int8,
	minconf int32) (*CreatedTx, dcrutil.Address, []byte, error) {

	req := createMultisigTxRequest{
		account:   account,
		amount:    amount,
		pubkeys:   pubkeys,
		nrequired: nrequired,
		minconf:   minconf,
		resp:      make(chan createMultisigTxResponse),
	}
	w.createMultisigTxRequests <- req
	resp := <-req.resp
	return resp.tx, resp.address, resp.redeemScript, resp.err
}

// CreateSStxTx receives a request from the RPC and ships it to txCreator to
// generate a new SStx.
func (w *Wallet) CreateSStxTx(pair map[string]dcrutil.Amount,
	usedInputs []wtxmgr.Credit,
	inputs []dcrjson.SStxInput,
	couts []dcrjson.SStxCommitOut,
	minconf int32) (*CreatedTx, error) {

	req := createSStxRequest{
		usedInputs: usedInputs,
		pair:       pair,
		inputs:     inputs,
		couts:      couts,
		minconf:    minconf,
		resp:       make(chan createSStxResponse),
	}
	w.createSStxRequests <- req
	resp := <-req.resp
	return resp.tx, resp.err
}

// CreateSSGenTx receives a request from the RPC and ships it to txCreator to
// generate a new SSGen.
func (w *Wallet) CreateSSGenTx(ticketHash chainhash.Hash,
	blockHash chainhash.Hash,
	height int64,
	voteBits uint16) (*CreatedTx, error) {

	req := createSSGenRequest{
		tickethash: ticketHash,
		blockhash:  blockHash,
		height:     height,
		votebits:   voteBits,
		resp:       make(chan createSSGenResponse),
	}
	w.createSSGenRequests <- req
	resp := <-req.resp
	return resp.tx, resp.err
}

// CreateSSGenTx receives a request from the RPC and ships it to txCreator to
// generate a new SSGen.
func (w *Wallet) CreateSSRtx(ticketHash chainhash.Hash) (*CreatedTx, error) {

	req := createSSRtxRequest{
		tickethash: ticketHash,
		resp:       make(chan createSSRtxResponse),
	}
	w.createSSRtxRequests <- req
	resp := <-req.resp
	return resp.tx, resp.err
}

// CreatePurchaseTicket receives a request from the RPC and ships it to txCreator
// to purchase a new ticket.
func (w *Wallet) CreatePurchaseTicket(minBalance, spendLimit dcrutil.Amount,
	minConf int32, ticketAddr dcrutil.Address) (interface{}, error) {

	req := purchaseTicketRequest{
		minBalance: minBalance,
		spendLimit: spendLimit,
		minConf:    minConf,
		ticketAddr: ticketAddr,
		resp:       make(chan purchaseTicketResponse),
	}
	w.purchaseTicketRequests <- req
	resp := <-req.resp
	return resp.data, resp.err
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
	quit := w.quitChan()
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
			err := w.Manager.ChangePassphrase(req.old, req.new, true,
				&waddrmgr.DefaultScryptOptions)
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
		timeout = nil
		err := w.Manager.Lock()
		if err != nil && !waddrmgr.IsError(err, waddrmgr.ErrLocked) {
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
	log.Infof("The wallet has been locked.")
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

// AccountUsed returns whether there are any recorded transactions spending to
// a given account. It returns true if atleast one address in the account was
// used and false if no address in the account was used.
func (w *Wallet) AccountUsed(account uint32) (bool, error) {
	var used bool
	var err error
	merr := w.Manager.ForEachAccountAddress(account,
		func(maddr waddrmgr.ManagedAddress) error {
			used, err = maddr.Used()
			if err != nil {
				return err
			}
			if used {
				return waddrmgr.Break
			}
			return nil
		})
	if merr == waddrmgr.Break {
		merr = nil
	}
	return used, merr
}

// CalculateBalance sums the amounts of all unspent transaction
// outputs to addresses of a wallet and returns the balance.
//
// If confirmations is 0, all UTXOs, even those not present in a
// block (height -1), will be used to get the balance.  Otherwise,
// a UTXO must be in a block.  If confirmations is 1 or greater,
// the balance will be calculated based on how many how many blocks
// include a UTXO.
func (w *Wallet) CalculateBalance(confirms int32, balanceType wtxmgr.BehaviorFlags) (dcrutil.Amount, error) {
	blk := w.Manager.SyncedTo()
	return w.TxStore.Balance(confirms, blk.Height, balanceType)
}

// CalculateAccountBalance sums the amounts of all unspent transaction
// outputs to the given account of a wallet and returns the balance.
func (w *Wallet) CalculateAccountBalance(account uint32,
	confirms int32) (dcrutil.Amount, error) {
	var bal dcrutil.Amount

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	syncBlock := w.Manager.SyncedTo()

	unspent, err := w.TxStore.UnspentOutputs()
	if err != nil {
		return 0, err
	}
	for i := range unspent {
		output := unspent[i]

		if !confirmed(confirms, output.Height, syncBlock.Height) {
			continue
		}
		if output.FromCoinBase {
			target := int32(w.ChainParams().CoinbaseMaturity)
			if !confirmed(target, output.Height, syncBlock.Height) {
				continue
			}
		}

		var outputAcct uint32
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txscript.DefaultScriptVersion, output.PkScript, w.chainParams)
		if err == nil && len(addrs) > 0 {
			outputAcct, err = w.Manager.AddrAccount(addrs[0])
		}
		if err == nil && outputAcct == account {
			bal += output.Amount
		}
	}
	return bal, nil
}

// CurrentAddress gets the most recently requested payment address from a wallet.
// If the address has already been used (there is at least one transaction
// spending to it in the blockchain or dcrd mempool), the next chained address
// is returned.
func (w *Wallet) CurrentAddress(account uint32) (dcrutil.Address, error) {
	addr, _, err := w.Manager.LastExternalAddress(account)
	if err != nil {
		// If no address exists yet, create the first external address
		if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
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

// existsAddressOnChain checks the chain on daemon to see if the given address
// has been used before on the main chain.
func (w *Wallet) existsAddressOnChain(address dcrutil.Address) (bool, error) {
	reply, err := w.chainSvr.ExistsAddress(address)
	if err != nil {
		return false, err
	}

	return reply.Exists, nil
}

// ExistsAddressOnChain is the exported version of existsAddressOnChain that is
// safe for concurrent access.
func (w *Wallet) ExistsAddressOnChain(address dcrutil.Address) (bool, error) {
	w.chainSvrLock.Lock()
	defer w.chainSvrLock.Unlock()

	return w.existsAddressOnChain(address)
}

// CreditCategory describes the type of wallet transaction output.  The category
// of "sent transactions" (debits) is always "send", and is not expressed by
// this type.
//
// TODO: This is a requirement of the RPC server and should be moved.
type CreditCategory byte

// These constants define the possible credit categories.
const (
	CreditReceive CreditCategory = iota
	CreditGenerate
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
	chainParams *chaincfg.Params) CreditCategory {
	if blockchain.IsCoinBaseTx(&details.MsgTx) {
		if confirmed(int32(chainParams.CoinbaseMaturity), details.Block.Height,
			syncHeight) {
			return CreditGenerate
		}
		return CreditImmature
	}
	return CreditReceive
}

// ListTransactions creates a object that may be marshalled to a response result
// for a listtransactions RPC.
//
// TODO: This should be moved to the legacyrpc package.
func ListTransactions(details *wtxmgr.TxDetails, addrMgr *waddrmgr.Manager,
	syncHeight int32, net *chaincfg.Params) []dcrjson.ListTransactionsResult {

	var (
		blockHashStr  string
		blockTime     int64
		confirmations int64
	)
	if details.Block.Height != -1 {
		blockHashStr = details.Block.Hash.String()
		blockTime = details.Block.Time.Unix()
		confirmations = int64(confirms(details.Block.Height, syncHeight))
	}

	results := []dcrjson.ListTransactionsResult{}
	txHashStr := details.Hash.String()
	received := details.Received.Unix()
	generated := blockchain.IsCoinBaseTx(&details.MsgTx)
	recvCat := RecvCategory(details, syncHeight, net).String()

	send := len(details.Debits) != 0

	// Fee can only be determined if every input is a debit.
	var feeF64 float64
	if len(details.Debits) == len(details.MsgTx.TxIn) {
		var debitTotal dcrutil.Amount
		for _, deb := range details.Debits {
			debitTotal += deb.Amount
		}
		var outputTotal dcrutil.Amount
		for _, output := range details.MsgTx.TxOut {
			outputTotal += dcrutil.Amount(output.Value)
		}
		// Note: The actual fee is debitTotal - outputTotal.  However,
		// this RPC reports negative numbers for fees, so the inverse
		// is calculated.
		feeF64 = (outputTotal - debitTotal).ToCoin()
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
		_, addrs, _, _ := txscript.ExtractPkScriptAddrs(output.Version,
			output.PkScript, net)
		if len(addrs) == 1 {
			addr := addrs[0]
			address = addr.EncodeAddress()
			account, err := addrMgr.AddrAccount(addrs[0])
			if err == nil {
				accountName, err = addrMgr.AccountName(account)
				if err != nil {
					accountName = ""
				}
			}
		}

		amountF64 := dcrutil.Amount(output.Value).ToCoin()
		result := dcrjson.ListTransactionsResult{
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
func (w *Wallet) ListSinceBlock(start, end, syncHeight int32) ([]dcrjson.ListTransactionsResult, error) {
	txList := []dcrjson.ListTransactionsResult{}
	err := w.TxStore.RangeTransactions(start, end, func(details []wtxmgr.TxDetails) (bool, error) {
		for _, detail := range details {
			jsonResults := ListTransactions(&detail, w.Manager,
				syncHeight, w.chainParams)
			txList = append(txList, jsonResults...)
		}
		return false, nil
	})
	return txList, err
}

// ListTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listtransactions RPC
// replies.
func (w *Wallet) ListTransactions(from, count int) ([]dcrjson.ListTransactionsResult, error) {
	txList := []dcrjson.ListTransactionsResult{}

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	syncBlock := w.Manager.SyncedTo()

	// Need to skip the first from transactions, and after those, only
	// include the next count transactions.
	skipped := 0
	n := 0

	// Return newer results first by starting at mempool height and working
	// down to the genesis block.
	err := w.TxStore.RangeTransactions(-1, 0, func(details []wtxmgr.TxDetails) (bool, error) {
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

			jsonResults := ListTransactions(&details[i],
				w.Manager, syncBlock.Height, w.chainParams)
			txList = append(txList, jsonResults...)
		}

		return false, nil
	})

	return txList, err
}

// ListAddressTransactions returns a slice of objects with details about
// recorded transactions to or from any address belonging to a set.  This is
// intended to be used for listaddresstransactions RPC replies.
func (w *Wallet) ListAddressTransactions(pkHashes map[string]struct{}) (
	[]dcrjson.ListTransactionsResult, error) {

	txList := []dcrjson.ListTransactionsResult{}

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	syncBlock := w.Manager.SyncedTo()

	err := w.TxStore.RangeTransactions(0, -1, func(details []wtxmgr.TxDetails) (bool, error) {
	loopDetails:
		for i := range details {
			detail := &details[i]

			for _, cred := range detail.Credits {
				pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(
					txscript.DefaultScriptVersion, pkScript, w.chainParams)
				if err != nil || len(addrs) != 1 {
					continue
				}
				apkh, ok := addrs[0].(*dcrutil.AddressPubKeyHash)
				if !ok {
					continue
				}
				_, ok = pkHashes[string(apkh.ScriptAddress())]
				if !ok {
					continue
				}

				jsonResults := ListTransactions(detail, w.Manager,
					syncBlock.Height, w.chainParams)
				if err != nil {
					return false, err
				}
				txList = append(txList, jsonResults...)
				continue loopDetails
			}
		}
		return false, nil
	})

	return txList, err
}

// ListAllTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listalltransactions RPC
// replies.
func (w *Wallet) ListAllTransactions() ([]dcrjson.ListTransactionsResult, error) {
	txList := []dcrjson.ListTransactionsResult{}

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	syncBlock := w.Manager.SyncedTo()

	// Return newer results first by starting at mempool height and working
	// down to the genesis block.
	err := w.TxStore.RangeTransactions(-1, 0, func(details []wtxmgr.TxDetails) (bool, error) {
		// Iterate over transactions at this height in reverse order.
		// This does nothing for unmined transactions, which are
		// unsorted, but it will process mined transactions in the
		// reverse order they were marked mined.
		for i := len(details) - 1; i >= 0; i-- {
			jsonResults := ListTransactions(&details[i], w.Manager,
				syncBlock.Height, w.chainParams)
			txList = append(txList, jsonResults...)
		}
		return false, nil
	})

	return txList, err
}

// creditSlice satisifies the sort.Interface interface to provide sorting
// transaction credits from oldest to newest.  Credits with the same receive
// time and mined in the same block are not guaranteed to be sorted by the order
// they appear in the block.  Credits from the same transaction are sorted by
// output index.
type creditSlice []*wtxmgr.Credit

func (s creditSlice) Len() int {
	return len(s)
}

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

func (s creditSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// ListUnspent returns a slice of objects representing the unspent wallet
// transactions fitting the given criteria. The confirmations will be more than
// minconf, less than maxconf and if addresses is populated only the addresses
// contained within it will be considered.  If we know nothing about a
// transaction an empty array will be returned.
func (w *Wallet) ListUnspent(minconf, maxconf int32,
	addresses map[string]struct{}) ([]*dcrjson.ListUnspentResult, error) {

	syncBlock := w.Manager.SyncedTo()

	filter := len(addresses) != 0
	unspent, err := w.TxStore.UnspentOutputs()
	if err != nil {
		return nil, err
	}
	sort.Sort(sort.Reverse(creditSlice(unspent)))

	defaultAccountName, err := w.Manager.AccountName(waddrmgr.DefaultAccountNum)
	if err != nil {
		return nil, err
	}

	results := make([]*dcrjson.ListUnspentResult, 0, len(unspent))
	for i := range unspent {
		output := unspent[i]

		details, err := w.TxStore.TxDetails(&output.Hash)
		if err != nil {
			return nil, fmt.Errorf("Couldn't get credit details")
		}

		// Outputs with fewer confirmations than the minimum or more
		// confs than the maximum are excluded.
		confs := confirms(output.Height, syncBlock.Height)
		if confs < minconf || confs > maxconf {
			continue
		}

		// Only mature coinbase outputs are included.
		if output.FromCoinBase {
			target := int32(w.ChainParams().CoinbaseMaturity)
			if !confirmed(target, output.Height, syncBlock.Height) {
				continue
			}
		}

		switch details.TxRecord.TxType {
		case stake.TxTypeSStx:
			// Ticket commitment, only spendable after ticket maturity.
			// You can only spent it after TM many blocks has gone past, so
			// ticket maturity + 1??? Check this DECRED TODO
			if output.Index == 0 {
				if !confirmed(int32(w.chainParams.TicketMaturity+1),
					details.Height(), syncBlock.Height) {
					continue
				}
			}
			// Change outputs.
			if (output.Index > 0) && (output.Index%2 == 0) {
				if !confirmed(int32(w.chainParams.SStxChangeMaturity),
					details.Height(), syncBlock.Height) {
					continue
				}
			}
		case stake.TxTypeSSGen:
			// All non-OP_RETURN outputs for SSGen tx are only spendable
			// after coinbase maturity many blocks.
			if !confirmed(int32(w.chainParams.CoinbaseMaturity),
				details.Height(), syncBlock.Height) {
				continue
			}
		case stake.TxTypeSSRtx:
			// All outputs for SSRtx tx are only spendable
			// after coinbase maturity many blocks.
			if !confirmed(int32(w.chainParams.CoinbaseMaturity),
				details.Height(), syncBlock.Height) {
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
		acctName := defaultAccountName
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txscript.DefaultScriptVersion, output.PkScript, w.chainParams)
		if err != nil {
			continue
		}
		if len(addrs) > 0 {
			acct, err := w.Manager.AddrAccount(addrs[0])
			if err == nil {
				s, err := w.Manager.AccountName(acct)
				if err == nil {
					acctName = s
				}
			}
		}

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
		result := &dcrjson.ListUnspentResult{
			TxID:          output.OutPoint.Hash.String(),
			Vout:          output.OutPoint.Index,
			Tree:          output.OutPoint.Tree,
			Account:       acctName,
			ScriptPubKey:  hex.EncodeToString(output.PkScript),
			TxType:        int(details.TxType),
			Amount:        output.Amount.ToCoin(),
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
	var privkeys []string
	// Iterate over each active address, appending the private key to
	// privkeys.
	err := w.Manager.ForEachActiveAddress(func(addr dcrutil.Address) error {
		ma, err := w.Manager.Address(addr)
		if err != nil {
			return err
		}

		// Only those addresses with keys needed.
		pka, ok := ma.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return nil
		}

		wif, err := pka.ExportPrivKey()
		if err != nil {
			// It would be nice to zero out the array here. However,
			// since strings in go are immutable, and we have no
			// control over the caller I don't think we can. :(
			return err
		}
		privkeys = append(privkeys, wif.String())
		return nil
	})
	return privkeys, err
}

// DumpWIFPrivateKey returns the WIF encoded private key for a
// single wallet address.
func (w *Wallet) DumpWIFPrivateKey(addr dcrutil.Address) (string, error) {
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
func (w *Wallet) ImportPrivateKey(wif *dcrutil.WIF, bs *waddrmgr.BlockStamp,
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
			Addrs:      []dcrutil.Address{addr.Address()},
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

// exportBase64 exports a wallet's serialized database as a base64-encoded
// string.
func (w *Wallet) exportBase64() (string, error) {
	var buf bytes.Buffer
	if err := w.db.Copy(&buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
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
func (w *Wallet) LockedOutpoints() []dcrjson.TransactionInput {
	locked := make([]dcrjson.TransactionInput, len(w.lockedOutpoints))
	i := 0
	for op := range w.lockedOutpoints {
		locked[i] = dcrjson.TransactionInput{
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
	txs, err := w.TxStore.UnminedTxs()
	if err != nil {
		log.Errorf("Cannot load unmined transactions for resending: %v", err)
		return
	}
	for _, tx := range txs {
		resp, err := w.chainSvr.SendRawTransaction(tx, false)
		if err != nil {
			// TODO(jrick): Check error for if this tx is a double spend,
			// remove it if so.
			log.Tracef("Could not resend transaction %v: %v",
				tx.TxSha(), err)
			continue
		}
		log.Tracef("Resent unmined transaction %v", resp)
	}
}

// SortedActivePaymentAddresses returns a slice of all active payment
// addresses in a wallet.
func (w *Wallet) SortedActivePaymentAddresses() ([]string, error) {
	var addrStrs []string
	err := w.Manager.ForEachActiveAddress(func(addr dcrutil.Address) error {
		addrStrs = append(addrStrs, addr.EncodeAddress())
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Sort(sort.StringSlice(addrStrs))
	return addrStrs, nil
}

// confirmed checks whether a transaction at height txHeight has met minconf
// confirmations for a blockchain at height curHeight.
func confirmed(minconf, txHeight, curHeight int32) bool {
	return confirms(txHeight, curHeight) >= minconf
}

// confirms returns the number of confirmations for a transaction in a block at
// height txHeight (or -1 for an unconfirmed tx) given the chain height
// curHeight.
func confirms(txHeight, curHeight int32) int32 {
	switch {
	case txHeight == -1, txHeight > curHeight:
		return 0
	default:
		return curHeight - txHeight + 1
	}
}

// TotalReceivedForAccount iterates through a wallet's transaction history,
// returning the total amount of decred received for a single wallet
// account.
func (w *Wallet) TotalReceivedForAccount(account uint32, minConf int32) (dcrutil.Amount, int32, error) {
	syncBlock := w.Manager.SyncedTo()

	var (
		amount     dcrutil.Amount
		lastConf   int32 // Confs of the last matching transaction.
		stopHeight int32
	)

	if minConf > 0 {
		stopHeight = syncBlock.Height - minConf + 1
	} else {
		stopHeight = -1
	}
	err := w.TxStore.RangeTransactions(0, stopHeight, func(details []wtxmgr.TxDetails) (bool, error) {
		for i := range details {
			detail := &details[i]
			for _, cred := range detail.Credits {
				pkVersion := detail.MsgTx.TxOut[cred.Index].Version
				pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
				var outputAcct uint32
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkVersion,
					pkScript, w.chainParams)
				if err == nil && len(addrs) > 0 {
					outputAcct, err = w.Manager.AddrAccount(addrs[0])
				}
				if err == nil && outputAcct == account {
					amount += cred.Amount
					lastConf = confirms(detail.Block.Height, syncBlock.Height)
				}
			}
		}
		return false, nil
	})

	return amount, lastConf, err
}

// TotalReceivedForAddr iterates through a wallet's transaction history,
// returning the total amount of decred received for a single wallet
// address.
func (w *Wallet) TotalReceivedForAddr(addr dcrutil.Address, minConf int32) (dcrutil.Amount, error) {
	syncBlock := w.Manager.SyncedTo()

	var (
		addrStr    = addr.EncodeAddress()
		amount     dcrutil.Amount
		stopHeight int32
	)

	if minConf > 0 {
		stopHeight = syncBlock.Height - minConf + 1
	} else {
		stopHeight = -1
	}
	err := w.TxStore.RangeTransactions(0, stopHeight, func(details []wtxmgr.TxDetails) (bool, error) {
		for i := range details {
			detail := &details[i]
			for _, cred := range detail.Credits {
				pkVersion := detail.MsgTx.TxOut[cred.Index].Version
				pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkVersion,
					pkScript, w.chainParams)
				// An error creating addresses from the output script only
				// indicates a non-standard script, so ignore this credit.
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
	})
	return amount, err
}

// SendPairs creates and sends payment transactions. It returns the transaction
// hash upon success
func (w *Wallet) SendPairs(amounts map[string]dcrutil.Amount, account uint32,
	minconf int32) (*CreatedTx, error) {

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := w.CreateSimpleTx(account, amounts, minconf)
	if err != nil {
		return nil, err
	}

	// TODO: The record already has the serialized tx, so no need to
	// serialize it again.
	return createdTx, nil
}

// Open loads an already-created wallet from the passed database and namespaces.
func Open(pubPass []byte, params *chaincfg.Params, db walletdb.DB, waddrmgrNS,
	wtxmgrNS, wstmgrNS walletdb.Namespace, cbs *waddrmgr.OpenCallbacks,
	voteBits uint16, stakeMiningEnabled bool, balanceToMaintain float64,
	addressReuse bool, rollbackTest bool, pruneTickets bool, ticketAddress string,
	ticketMaxPrice float64, autoRepair bool) (*Wallet, error) {
	addrMgr, err := waddrmgr.Open(waddrmgrNS, pubPass, params, cbs)
	if err != nil {
		return nil, err
	}
	txMgr, err := wtxmgr.Open(wtxmgrNS, pruneTickets, params)
	if err != nil {
		if !wtxmgr.IsNoExists(err) {
			return nil, err
		}
		log.Info("No recorded transaction history -- needs full rescan")
		err = addrMgr.SetSyncedTo(nil)
		if err != nil {
			return nil, err
		}
		txMgr, err = wtxmgr.Create(wtxmgrNS, params)
		if err != nil {
			return nil, err
		}
	}

	smgr, err := wstakemgr.Open(wstmgrNS, addrMgr, params)
	if err != nil {
		log.Info("No stake manager present, generating")
		smgr, err = wstakemgr.Create(wstmgrNS, addrMgr, params)
		if err != nil {
			return nil, err
		}
	}

	// XXX Should we check error here?  Right now error gives default (0).
	btm, err := dcrutil.NewAmount(balanceToMaintain)
	if err != nil {
		return nil, err
	}

	var ticketAddr dcrutil.Address
	if ticketAddress != "" {
		ticketAddr, err = dcrutil.DecodeAddress(ticketAddress, params)
		if err != nil {
			return nil, fmt.Errorf("ticket address could not parse: %v",
				err.Error())
		}
	}

	tmp, err := dcrutil.NewAmount(ticketMaxPrice)
	if err != nil {
		return nil, err
	}

	log.Infof("Opened wallet") // TODO: log balance? last sync height?

	w := newWallet(voteBits,
		stakeMiningEnabled,
		btm,
		addressReuse,
		rollbackTest,
		ticketAddr,
		tmp,
		autoRepair,
		addrMgr,
		txMgr,
		smgr,
		&db,
		params)

	return w, nil
}
