// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/blockchain"
	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrrpcclient"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrutil/hdkeychain"
	"github.com/decred/dcrwallet/chain"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/wallet/txauthor"
	"github.com/decred/dcrwallet/wallet/txrules"
	"github.com/decred/dcrwallet/walletdb"
	"github.com/decred/dcrwallet/wstakemgr"
	"github.com/decred/dcrwallet/wtxmgr"
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

	walletDbWatchingOnlyName = "wowallet.db"

	// rollbackTestHeight is the height at which to begin doing the
	// rollback test on simnet.
	rollbackTestHeight = 200

	// rollbackTestDepth is the depth to rollback to when testing.
	rollbackTestDepth = 100
)

var (
	// SimulationPassphrase is the password for a wallet created for simnet
	// with --createtemp.
	SimulationPassphrase = []byte("password")
)

// ErrNotSynced describes an error where an operation cannot complete
// due wallet being out of sync (and perhaps currently syncing with)
// the remote chain server.
var ErrNotSynced = errors.New("wallet is not synchronized with the chain server")

// Namespace bucket keys.
var (
	waddrmgrNamespaceKey  = []byte("waddrmgr")
	wtxmgrNamespaceKey    = []byte("wtxmgr")
	wstakemgrNamespaceKey = []byte("wstakemgr")
)

// StakeDifficultyInfo is a container for stake difficulty information updates.
type StakeDifficultyInfo struct {
	BlockHash       *chainhash.Hash
	BlockHeight     int64
	StakeDifficulty int64
}

// VotingInfo is a container for the current height, hash, and list
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
	publicPassphrase []byte

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
	CurrentVotingInfo  *VotingInfo
	TicketMaxPrice     dcrutil.Amount
	ticketBuyFreq      int
	balanceToMaintain  dcrutil.Amount
	poolAddress        dcrutil.Address
	poolFees           float64
	stakePoolEnabled   bool
	stakePoolColdAddrs map[string]struct{}

	// Start up flags/settings
	automaticRepair bool
	resyncAccounts  bool
	addrIdxScanLen  int

	chainClient        *chain.RPCClient
	chainClientLock    sync.Mutex
	chainClientSynced  bool
	chainClientSyncMtx sync.Mutex

	lockedOutpoints map[wire.OutPoint]struct{}

	relayFee               dcrutil.Amount
	relayFeeMu             sync.Mutex
	ticketFeeIncrementLock sync.Mutex
	ticketFeeIncrement     dcrutil.Amount
	DisallowFree           bool
	AllowHighFees          bool

	// Channels for rescan processing.  Requests are added and merged with
	// any waiting requests, before being sent to another goroutine to
	// call the rescan RPC.
	rescanAddJob        chan *RescanJob
	rescanBatch         chan *rescanBatch
	rescanNotifications chan interface{} // From chain server
	rescanProgress      chan *RescanProgressMsg
	rescanFinished      chan *RescanFinishedMsg

	// Channel for transaction creation requests.
	consolidateRequests      chan consolidateRequest
	createTxRequests         chan createTxRequest
	createMultisigTxRequests chan createMultisigTxRequest

	// Channels for stake tx creation requests.
	createSStxRequests     chan createSStxRequest
	createSSGenRequests    chan createSSGenRequest
	createSSRtxRequests    chan createSSRtxRequest
	purchaseTicketRequests chan purchaseTicketRequest

	// Internal address handling.
	addrPools     map[uint32]*addressPools
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

	NtfnServer *NotificationServer

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
	ticketBuyFreq int, poolAddress dcrutil.Address, pf float64,
	addrIdxScanLen int, stakePoolColdAddrs map[string]struct{},
	autoRepair, AllowHighFees bool, mgr *waddrmgr.Manager, txs *wtxmgr.Store,
	smgr *wstakemgr.StakeStore, db *walletdb.DB,
	params *chaincfg.Params) *Wallet {
	var rollbackBlockDB map[uint32]*wtxmgr.DatabaseContents
	if rollbackTest {
		rollbackBlockDB = make(map[uint32]*wtxmgr.DatabaseContents)
	}

	w := &Wallet{
		db:                       *db,
		Manager:                  mgr,
		TxStore:                  txs,
		StakeMgr:                 smgr,
		StakeMiningEnabled:       esm,
		VoteBits:                 vb,
		balanceToMaintain:        btm,
		CurrentStakeDiff:         &StakeDifficultyInfo{nil, -1, -1},
		lockedOutpoints:          map[wire.OutPoint]struct{}{},
		relayFee:                 txrules.DefaultRelayFeePerKb,
		ticketFeeIncrement:       TicketFeeIncrement,
		AllowHighFees:            AllowHighFees,
		rescanAddJob:             make(chan *RescanJob),
		rescanBatch:              make(chan *rescanBatch),
		rescanNotifications:      make(chan interface{}),
		rescanProgress:           make(chan *RescanProgressMsg),
		rescanFinished:           make(chan *RescanFinishedMsg),
		consolidateRequests:      make(chan consolidateRequest),
		createTxRequests:         make(chan createTxRequest),
		createMultisigTxRequests: make(chan createMultisigTxRequest),
		createSStxRequests:       make(chan createSStxRequest),
		createSSGenRequests:      make(chan createSSGenRequest),
		createSSRtxRequests:      make(chan createSSRtxRequest),
		purchaseTicketRequests:   make(chan purchaseTicketRequest),
		addrPools:                make(map[uint32]*addressPools),
		addressReuse:             addressReuse,
		ticketAddress:            ticketAddress,
		TicketMaxPrice:           tmp,
		ticketBuyFreq:            ticketBuyFreq,
		poolAddress:              poolAddress,
		poolFees:                 pf,
		addrIdxScanLen:           addrIdxScanLen,
		stakePoolEnabled:         len(stakePoolColdAddrs) > 0,
		stakePoolColdAddrs:       stakePoolColdAddrs,
		automaticRepair:          autoRepair,
		resyncAccounts:           false,
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

	w.NtfnServer = newNotificationServer(w)
	w.TxStore.NotifyUnspent = func(hash *chainhash.Hash, index uint32) {
		w.NtfnServer.notifyUnspentOutput(0, hash, index)
	}
	return w
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

// BalanceToMaintain is used to get the current balancetomaintain for the wallet.
func (w *Wallet) BalanceToMaintain() dcrutil.Amount {
	w.stakeSettingsLock.Lock()
	balance := w.balanceToMaintain
	w.stakeSettingsLock.Unlock()

	return balance
}

// SetBalanceToMaintain is used to set the current w.balancetomaintain for the wallet.
func (w *Wallet) SetBalanceToMaintain(balance dcrutil.Amount) {
	w.stakeSettingsLock.Lock()
	w.balanceToMaintain = balance
	w.stakeSettingsLock.Unlock()
}

// Generate returns the current status of the generation stake of the wallet.
func (w *Wallet) Generate() bool {
	w.stakeSettingsLock.Lock()
	defer w.stakeSettingsLock.Unlock()
	return w.StakeMiningEnabled
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
		_, err := w.StakeMgr.HandleWinningTicketsNtfn(
			w.CurrentVotingInfo.BlockHash,
			w.CurrentVotingInfo.BlockHeight,
			w.CurrentVotingInfo.Tickets,
			w.VoteBits,
			w.AllowHighFees,
		)
		if err != nil {
			return err
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

// TicketAddress gets the ticket address for the wallet to give the ticket
// voting rights to.
func (w *Wallet) TicketAddress() dcrutil.Address {
	return w.ticketAddress
}

// PoolAddress gets the pool address for the wallet to give ticket fees to.
func (w *Wallet) PoolAddress() dcrutil.Address {
	return w.poolAddress
}

// PoolFees gets the per-ticket pool fee for the wallet.
func (w *Wallet) PoolFees() float64 {
	return w.poolFees
}

// SetResyncAccounts sets whether or not the user needs to sync accounts,
// which dictates some of the start up syncing behaviour. It should only
// be called before the wallet RPC servers are accessible. It is not safe
// for concurrent access.
func (w *Wallet) SetResyncAccounts(set bool) {
	w.resyncAccounts = set
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
func (w *Wallet) SynchronizeRPC(chainClient *chain.RPCClient) {
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
	w.chainClientLock.Unlock()

	w.StakeMgr.SetChainSvr(chainClient)

	// TODO: It would be preferable to either run these goroutines
	// separately from the wallet (use wallet mutator functions to
	// make changes from the RPC client) and not have to stop and
	// restart them each time the client disconnects and reconnets.
	w.wg.Add(5)
	go w.handleChainNotifications()
	go w.handleChainVotingNotifications()
	go w.rescanBatchHandler()
	go w.rescanProgressHandler()
	go w.rescanRPCHandler()

	// Request notifications for winning tickets.
	err := chainClient.NotifyWinningTickets()
	if err != nil {
		log.Error("Unable to request transaction updates for "+
			"winning tickets. Error: ", err.Error())
	}

	// Request notifications for spent and missed tickets.
	err = chainClient.NotifySpentAndMissedTickets()
	if err != nil {
		log.Error("Unable to request transaction updates for spent "+
			"and missed tickets. Error: ", err.Error())
	}

	// Request notifications for stake difficulty.
	err = chainClient.NotifyStakeDifficulty()
	if err != nil {
		log.Error("Unable to request transaction updates for stake "+
			"difficulty. Error: ", err.Error())
	}

	if w.StakeMiningEnabled {
		log.Infof("Stake mining is enabled. Votebits: %v, minimum wallet "+
			"balance %v", w.VoteBits, w.BalanceToMaintain().ToCoin())
		log.Infof("PLEASE ENSURE YOUR WALLET REMAINS UNLOCKED SO IT MAY " +
			"VOTE ON BLOCKS AND RECEIVE STAKE REWARDS")
	}
}

// requireChainClient marks that a wallet method can only be completed when the
// consensus RPC server is set.  This function and all functions that call it
// are unstable and will need to be moved when the syncing code is moved out of
// the wallet.
func (w *Wallet) requireChainClient() (*chain.RPCClient, error) {
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
func (w *Wallet) ChainClient() *chain.RPCClient {
	w.chainClientLock.Lock()
	chainClient := w.chainClient
	w.chainClientLock.Unlock()
	return chainClient
}

// RelayFee returns the current minimum relay fee (per kB of serialized
// transaction) used when constructing transactions.
func (w *Wallet) RelayFee() dcrutil.Amount {
	w.relayFeeMu.Lock()
	relayFee := w.relayFee
	w.relayFeeMu.Unlock()
	return relayFee
}

// SetRelayFee sets a new minimum relay fee (per kB of serialized
// transaction) used when constructing transactions.
func (w *Wallet) SetRelayFee(relayFee dcrutil.Amount) {
	w.relayFeeMu.Lock()
	w.relayFee = relayFee
	w.relayFeeMu.Unlock()
}

// TicketFeeIncrement is used to get the current feeIncrement for the wallet.
func (w *Wallet) TicketFeeIncrement() dcrutil.Amount {
	w.ticketFeeIncrementLock.Lock()
	fee := w.ticketFeeIncrement
	w.ticketFeeIncrementLock.Unlock()

	return fee
}

// SetTicketFeeIncrement is used to set the current w.ticketFeeIncrement for the wallet.
func (w *Wallet) SetTicketFeeIncrement(fee dcrutil.Amount) {
	w.ticketFeeIncrementLock.Lock()
	w.ticketFeeIncrement = fee
	w.ticketFeeIncrementLock.Unlock()
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
	// Store the current address pool last addresses.
	w.CloseAddressPools()
	w.TxStore.Close()
	w.StakeMgr.Close()
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
// NOTE: Due to an API limitation with dcrrpcclient, this may return true after
// the client disconnected (and is attempting a reconnect).  This will be unknown
// until the reconnect notification is received, at which point the wallet can be
// marked out of sync again until after the next rescan completes.
func (w *Wallet) SetChainSynced(synced bool) {
	w.chainClientSyncMtx.Lock()
	w.chainClientSynced = synced
	w.chainClientSyncMtx.Unlock()
}

// activeData returns the currently-active receiving addresses and all unspent
// outputs.  This is primarely intended to provide the parameters for a
// rescan request.
func (w *Wallet) activeData() ([]dcrutil.Address, []*wire.OutPoint, error) {
	var err error
	var addrs []dcrutil.Address
	err = w.Manager.ForEachActiveAddress(func(addr dcrutil.Address) error {
		addrs = append(addrs, addr)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	unspent, err := w.TxStore.UnspentOutpoints()
	if err != nil {
		return nil, nil, err
	}

	return addrs, unspent, err
}

// syncWithChain brings the wallet up to date with the current chain server
// connection.  It creates a rescan request and blocks until the rescan has
// finished.
func (w *Wallet) syncWithChain() error {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return err
	}

	// Request notifications for connected and disconnected blocks.
	//
	// TODO(jrick): Either request this notification only once, or when
	// dcrrpcclient is modified to allow some notification request to not
	// automatically resent on reconnect, include the notifyblocks request
	// as well.  I am leaning towards allowing off all dcrrpcclient
	// notification re-registrations, in which case the code here should be
	// left as is.
	err = chainClient.NotifyBlocks()
	if err != nil {
		return err
	}

	// Rescan to the newest used addresses. This also initializes the
	// address pools.
	err = w.rescanActiveAddresses()
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
		blhMainchain, err := chainClient.GetBlockHash(int64(i))
		if err != nil {
			continue
		}
		if !blhMainchain.IsEqual(&blhLocal) {
			rollback = true
			continue
		}

		log.Debugf("Found matching block %v at height %v. Rolling back "+
			"blockchain if necessary.", blhLocal, i)
		syncBlock.Hash = blhLocal
		syncBlock.Height = i
		break
	}
	if rollback {
		log.Debugf("Rolling back blockchain to height %v.", syncBlock.Height)
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
	bestBlockHash, bestBlockHeight, err := chainClient.GetBestBlock()
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
			bl, err := chainClient.GetBlock(curBlock)
			if err != nil {
				return err
			}
			blHeight := bl.MsgBlock().Header.Height
			vb := bl.MsgBlock().Header.VoteBits
			wtxBm := wtxmgr.BlockMeta{
				Block: wtxmgr.Block{
					Hash:   *curBlock,
					Height: int32(blHeight),
				},
				Time:     bl.MsgBlock().Header.Timestamp,
				VoteBits: vb,
			}
			err = w.TxStore.InsertBlock(&wtxBm)
			if err != nil {
				return err
			}

			curBlock = &bl.MsgBlock().Header.PrevBlock

			// Break early if we hit the genesis block.
			if i == 0 {
				break
			}
		}
	}

	// Set the ticket price upon syncing to the main chain.
	bestBlock, err := chainClient.GetBlock(bestBlockHash)
	if err != nil {
		return err
	}
	w.SetStakeDifficulty(&StakeDifficultyInfo{
		bestBlockHash,
		int64(bestBlockHeight),
		bestBlock.MsgBlock().Header.SBits,
	})

	log.Infof("Blockchain sync completed, wallet ready for general usage.")

	return nil
}

type (
	consolidateRequest struct {
		inputs  int
		account uint32
		resp    chan consolidateResponse
	}
	createTxRequest struct {
		account uint32
		outputs []*wire.TxOut
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
		minBalance  dcrutil.Amount
		spendLimit  dcrutil.Amount
		minConf     int32
		ticketAddr  dcrutil.Address
		account     uint32
		numTickets  int
		poolAddress dcrutil.Address
		poolFees    float64
		expiry      int32
		resp        chan purchaseTicketResponse
	}

	consolidateResponse struct {
		txHash *chainhash.Hash
		err    error
	}
	createTxResponse struct {
		tx  *txauthor.AuthoredTx
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
		case txr := <-w.consolidateRequests:
			txh, err := w.compressWallet(txr.inputs, txr.account)
			txr.resp <- consolidateResponse{txh, err}

		case txr := <-w.createTxRequests:
			tx, err := w.TxToOutputs(txr.outputs, txr.account, txr.minconf, true)
			txr.resp <- createTxResponse{tx, err}

		case txr := <-w.createMultisigTxRequests:
			tx, address, redeemScript, err := w.txToMultisig(txr.account,
				txr.amount, txr.pubkeys, txr.nrequired, txr.minconf)
			txr.resp <- createMultisigTxResponse{tx, address, redeemScript, err}

		case txr := <-w.createSStxRequests:
			// Initialize the address pool for use.
			pool := w.addrPools[waddrmgr.DefaultAccountNum].internal
			pool.mutex.Lock()
			addrFunc := pool.getNewAddress

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

// Consolidate consolidates as many UTXOs as are passed in the inputs argument.
// If that many UTXOs can not be found, it will use the maximum it finds. This
// will only compress UTXOs in the default account
func (w *Wallet) Consolidate(inputs int, account uint32) (*chainhash.Hash, error) {
	req := consolidateRequest{
		inputs:  inputs,
		account: account,
		resp:    make(chan consolidateResponse),
	}
	w.consolidateRequests <- req
	resp := <-req.resp
	return resp.txHash, resp.err
}

// CreateSimpleTx creates a new signed transaction spending unspent P2PKH
// outputs with at laest minconf confirmations spending to any number of
// address/amount pairs.  Change and an appropriate transaction fee are
// automatically included, if necessary.  All transaction creation through this
// function is serialized to prevent the creation of many transactions which
// spend the same outputs.
func (w *Wallet) CreateSimpleTx(account uint32, outputs []*wire.TxOut,
	minconf int32) (*txauthor.AuthoredTx, error) {

	req := createTxRequest{
		account: account,
		outputs: outputs,
		minconf: minconf,
		resp:    make(chan createTxResponse),
	}
	w.createTxRequests <- req
	resp := <-req.resp
	return resp.tx, resp.err
}

// CreateMultisigTx receives a request from the RPC and ships it to txCreator to
// generate a new multisigtx.
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

// CreateSSRtx receives a request from the RPC and ships it to txCreator to
// generate a new SSRtx.
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
	minConf int32, ticketAddr dcrutil.Address, account uint32,
	numTickets int, poolAddress dcrutil.Address,
	poolFees float64, expiry int32) (interface{}, error) {

	req := purchaseTicketRequest{
		minBalance:  minBalance,
		spendLimit:  spendLimit,
		minConf:     minConf,
		ticketAddr:  ticketAddr,
		account:     account,
		numTickets:  numTickets,
		poolAddress: poolAddress,
		poolFees:    poolFees,
		expiry:      expiry,
		resp:        make(chan purchaseTicketResponse),
	}
	w.purchaseTicketRequests <- req
	resp := <-req.resp
	return resp.data, resp.err
}

type (
	unlockRequest struct {
		passphrase []byte
		lockAfter  <-chan time.Time // nil prevents the timeout.
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
			timeout = req.lockAfter
			if timeout == nil {
				log.Info("The wallet has been unlocked without a time limit")
			} else {
				log.Info("The wallet has been temporarily unlocked")
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
			timeout = nil
		case <-timeout:
		}

		// Select statement fell through by an explicit lock or the
		// timer expiring.  Lock the manager here.
		timeout = nil
		err := w.Manager.Lock()
		if err != nil && !waddrmgr.IsError(err, waddrmgr.ErrLocked) {
			log.Errorf("Could not lock wallet: %v", err)
		} else {
			log.Info("The wallet has been locked.")
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
	return w.TxStore.Balance(confirms, blk.Height, balanceType, true, 0)
}

// CalculateAccountBalance sums the amounts of all unspent transaction
// outputs to the given account of a wallet and returns the balance.
func (w *Wallet) CalculateAccountBalance(account uint32, confirms int32,
	balanceType wtxmgr.BehaviorFlags) (dcrutil.Amount, error) {
	var bal dcrutil.Amount
	var err error

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	syncBlock := w.Manager.SyncedTo()

	bal, err = w.TxStore.Balance(confirms, syncBlock.Height,
		balanceType, false, account)
	if err != nil {
		return 0, err
	}

	return bal, nil
}

// CalculateAccountBalances calculates the values for the wtxmgr struct Balance,
// which includes the total balance, the spendable balance, and the balance
// which has yet to mature.
func (w *Wallet) CalculateAccountBalances(account uint32,
	confirms int32) (wtxmgr.Balances, error) {
	syncBlock := w.Manager.SyncedTo()

	bals, err := w.TxStore.AccountBalances(syncBlock.Height, confirms, account)
	if err != nil {
		return wtxmgr.Balances{}, err
	}

	return bals, nil
}

// CurrentAddress gets the most recently requested payment address from a wallet.
// If the address has already been used (there is at least one transaction
// spending to it in the blockchain or dcrd mempool), the next chained address
// is returned.
func (w *Wallet) CurrentAddress(account uint32) (dcrutil.Address, error) {
	// Access the address index to get the next to use
	// address.
	nextToUseIdx, err := w.AddressPoolIndex(account, waddrmgr.ExternalBranch)
	if err != nil {
		return nil, err
	}
	lastUsedIdx := nextToUseIdx - 1

	addr, err := w.Manager.AddressDerivedFromDbAcct(lastUsedIdx, account,
		waddrmgr.ExternalBranch)
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// existsAddressOnChain checks the chain on daemon to see if the given address
// has been used before on the main chain.
func (w *Wallet) existsAddressOnChain(address dcrutil.Address) (bool, error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return false, err
	}
	exists, err := chainClient.ExistsAddress(address)
	if err != nil {
		return false, err
	}

	return exists, nil
}

// ExistsAddressOnChain is the exported version of existsAddressOnChain that is
// safe for concurrent access.
func (w *Wallet) ExistsAddressOnChain(address dcrutil.Address) (bool, error) {
	return w.existsAddressOnChain(address)
}

// RenameAccount sets the name for an account number to newName.
func (w *Wallet) RenameAccount(account uint32, newName string) error {
	err := w.Manager.RenameAccount(account, newName)
	if err != nil {
		return err
	}

	props, err := w.Manager.AccountProperties(account)
	if err != nil {
		log.Errorf("Cannot fetch new account properties for notification "+
			"during account rename: %v", err)
	} else {
		w.NtfnServer.notifyAccountProperties(props)
	}

	return nil
}

// NextAccount creates the next account and returns its account number.  The
// name must be unique to the account.
func (w *Wallet) NextAccount(name string) (uint32, error) {
	account, err := w.Manager.NewAccount(name)
	if err != nil {
		return 0, err
	}

	props, err := w.Manager.AccountProperties(account)
	if err != nil {
		log.Errorf("Cannot fetch new account properties for notification "+
			"after account creation: %v", err)
	} else {
		w.NtfnServer.notifyAccountProperties(props)
	}

	// Start an address buffer for this account in the address
	// manager for both the internal and external branches.
	_, err = w.Manager.SyncAccountToAddrIndex(account,
		addressPoolBuffer, waddrmgr.ExternalBranch)
	if err != nil {
		return 0, fmt.Errorf("failed to create initial waddrmgr "+
			"external address buffer for the address pool, "+
			"account %v during createnewaccount: %s",
			account, err.Error())
	}
	_, err = w.Manager.SyncAccountToAddrIndex(account,
		addressPoolBuffer, waddrmgr.InternalBranch)
	if err != nil {
		return 0, fmt.Errorf("failed to create initial waddrmgr "+
			"internal address buffer for the address pool, "+
			"account %v during createnewaccount: %s",
			account, err.Error())
	}

	// Initialize a new address pool for this account.
	w.addrPools[account], err = newAddressPools(account, 0, 0, w)
	if err != nil {
		return 0, err
	}

	return account, nil
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

	txTypeStr := dcrjson.LTTTRegular
	switch details.TxType {
	case stake.TxTypeSStx:
		txTypeStr = dcrjson.LTTTTicket
	case stake.TxTypeSSGen:
		txTypeStr = dcrjson.LTTTVote
	case stake.TxTypeSSRtx:
		txTypeStr = dcrjson.LTTTRevocation
	}

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
			TxType:          &txTypeStr,
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
	MinedTransactions   []Block
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
func (w *Wallet) GetTransactions(startBlock, endBlock *BlockIdentifier, cancel <-chan struct{}) (*GetTransactionsResult, error) {
	var start, end int32 = 0, -1

	w.chainClientLock.Lock()
	chainClient := w.chainClient
	w.chainClientLock.Unlock()

	// TODO: Fetching block heights by their hashes is inherently racy
	// because not all block headers are saved but when they are for SPV the
	// db can be queried directly without this.
	var startResp, endResp dcrrpcclient.FutureGetBlockVerboseResult
	if startBlock != nil {
		if startBlock.hash == nil {
			start = startBlock.height
		} else {
			if chainClient == nil {
				return nil, errors.New("no chain server client")
			}
			startResp = chainClient.GetBlockVerboseAsync(startBlock.hash, false)
		}
	}
	if endBlock != nil {
		if endBlock.hash == nil {
			end = endBlock.height
		} else {
			if chainClient == nil {
				return nil, errors.New("no chain server client")
			}
			endResp = chainClient.GetBlockVerboseAsync(endBlock.hash, false)
		}
	}
	if startResp != nil {
		resp, err := startResp.Receive()
		if err != nil {
			return nil, err
		}
		start = int32(resp.Height)
	}
	if endResp != nil {
		resp, err := endResp.Receive()
		if err != nil {
			return nil, err
		}
		end = int32(resp.Height)
	}

	var res GetTransactionsResult
	err := w.TxStore.RangeTransactions(start, end, func(details []wtxmgr.TxDetails) (bool, error) {
		// TODO: probably should make RangeTransactions not reuse the
		// details backing array memory.
		dets := make([]wtxmgr.TxDetails, len(details))
		copy(dets, details)
		details = dets

		txs := make([]TransactionSummary, 0, len(details))
		for i := range details {
			txs = append(txs, makeTxSummary(w, &details[i]))
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
	})
	return &res, err
}

// AccountResult is a single account result for the AccountsResult type.
type AccountResult struct {
	waddrmgr.AccountProperties
	TotalBalance dcrutil.Amount
}

// AccountsResult is the resutl of the wallet's Accounts method.  See that
// method for more details.
type AccountsResult struct {
	Accounts           []AccountResult
	CurrentBlockHash   *chainhash.Hash
	CurrentBlockHeight int32
}

// Accounts returns the current names, numbers, and total balances of all
// accounts in the wallet.  The current chain tip is included in the result for
// atomicity reasons.
//
// TODO(jrick): Is the chain tip really needed, since only the total balances
// are included?
func (w *Wallet) Accounts() (*AccountsResult, error) {
	var accounts []AccountResult
	syncBlock := w.Manager.SyncedTo()
	unspent, err := w.TxStore.UnspentOutputs()
	if err != nil {
		return nil, err
	}
	err = w.Manager.ForEachAccount(func(acct uint32) error {
		props, err := w.Manager.AccountProperties(acct)
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
		return nil, err
	}
	m := make(map[uint32]*dcrutil.Amount)
	for i := range accounts {
		a := &accounts[i]
		m[a.AccountNumber] = &a.TotalBalance
	}
	for i := range unspent {
		output := unspent[i]
		var outputAcct uint32
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txscript.DefaultScriptVersion, output.PkScript, w.chainParams)
		if err == nil && len(addrs) > 0 {
			outputAcct, err = w.Manager.AddrAccount(addrs[0])
		}
		if err == nil {
			amt, ok := m[outputAcct]
			if ok {
				*amt += output.Amount
			}
		}
	}
	return &AccountsResult{
		Accounts:           accounts,
		CurrentBlockHash:   &syncBlock.Hash,
		CurrentBlockHeight: syncBlock.Height,
	}, nil
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
		sc, addrs, _, err := txscript.ExtractPkScriptAddrs(
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
		case txscript.ScriptHashTy:
			spendable = true
		case txscript.StakeGenTy:
			spendable = true
		case txscript.StakeRevocationTy:
			spendable = true
		case txscript.StakeSubChangeTy:
			spendable = true
		case txscript.MultiSigTy:
			for _, a := range addrs {
				_, err := w.Manager.Address(a)
				if err == nil {
					continue
				}
				if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
					break scSwitch
				}
				return nil, err
			}
			spendable = true
		}

		result := &dcrjson.ListUnspentResult{
			TxID:          output.OutPoint.Hash.String(),
			Vout:          output.OutPoint.Index,
			Tree:          output.OutPoint.Tree,
			Account:       acctName,
			ScriptPubKey:  hex.EncodeToString(output.PkScript),
			TxType:        int(details.TxType),
			Amount:        output.Amount.ToCoin(),
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

	props, err := w.Manager.AccountProperties(waddrmgr.ImportedAddrAccount)
	if err != nil {
		log.Errorf("Cannot fetch account properties for imported "+
			"account after importing key: %v", err)
	} else {
		w.NtfnServer.notifyAccountProperties(props)
	}

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
	chainClient, err := w.requireChainClient()
	if err != nil {
		log.Errorf("No chain server available to resend unmined transactions")
		return
	}

	txs, err := w.TxStore.UnminedTxs()
	if err != nil {
		log.Errorf("Cannot load unmined transactions for resending: %v", err)
		return
	}
	for _, tx := range txs {
		resp, err := chainClient.SendRawTransaction(tx, w.AllowHighFees)
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

// SendOutputs creates and sends payment transactions. It returns the
// transaction hash upon success
func (w *Wallet) SendOutputs(outputs []*wire.TxOut, account uint32,
	minconf int32) (*chainhash.Hash, error) {

	relayFee := w.RelayFee()
	for _, output := range outputs {
		err := txrules.CheckOutput(output, relayFee)
		if err != nil {
			return nil, err
		}
	}

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := w.CreateSimpleTx(account, outputs, minconf)
	if err != nil {
		return nil, err
	}

	// TODO: The record already has the serialized tx, so no need to
	// serialize it again.
	hash := createdTx.Tx.TxSha()
	return &hash, nil
}

// SignatureError records the underlying error when validating a transaction
// input signature.
type SignatureError struct {
	InputIndex uint32
	Error      error
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
	additionalKeysByAddress map[string]*dcrutil.WIF,
	p2shRedeemScriptsByAddress map[string][]byte) ([]SignatureError, error) {

	var signErrors []SignatureError
	for i, txIn := range tx.TxIn {
		// For an SSGen tx, skip the first input as it is a stake base
		// and doesn't need to be signed.
		if i == 0 {
			isSSGen, err := stake.IsSSGen(dcrutil.NewTx(tx))
			if err == nil && isSSGen {
				// Put some garbage in the signature script.
				txIn.SignatureScript = []byte{0xDE, 0xAD, 0xBE, 0xEF}
				continue
			}
		}

		prevOutScript, ok := additionalPrevScripts[txIn.PreviousOutPoint]
		if !ok {
			prevHash := &txIn.PreviousOutPoint.Hash
			prevIndex := txIn.PreviousOutPoint.Index
			txDetails, err := w.TxStore.TxDetails(prevHash)
			if err != nil {
				return nil, fmt.Errorf("Cannot query previous transaction "+
					"details for %v: %v", txIn.PreviousOutPoint, err)
			}
			if txDetails == nil {
				return nil, fmt.Errorf("%v not found",
					txIn.PreviousOutPoint)
			}
			prevOutScript = txDetails.MsgTx.TxOut[prevIndex].PkScript
		}

		// Set up our callbacks that we pass to txscript so it can
		// look up the appropriate keys and scripts by address.
		getKey := txscript.KeyClosure(func(addr dcrutil.Address) (
			chainec.PrivateKey, bool, error) {
			if len(additionalKeysByAddress) != 0 {
				addrStr := addr.EncodeAddress()
				wif, ok := additionalKeysByAddress[addrStr]
				if !ok {
					return nil, false,
						fmt.Errorf("no key for address (needed: %v, have %v)",
							addr.EncodeAddress(), additionalKeysByAddress)
				}
				return wif.PrivKey, true, nil
			}
			address, err := w.Manager.Address(addr)
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
			addr dcrutil.Address) ([]byte, error) {
			// If keys were provided then we can only use the
			// redeem scripts provided with our inputs, too.
			if len(additionalKeysByAddress) != 0 {
				addrStr := addr.EncodeAddress()
				script, ok := p2shRedeemScriptsByAddress[addrStr]
				if !ok {
					return nil, errors.New("no script for " +
						"address")
				}
				return script, nil
			}

			// First check tx manager script store.
			scrTxStore, err :=
				w.TxStore.GetTxScript(addr.ScriptAddress())
			if err != nil {
				return nil, err
			}
			if scrTxStore != nil {
				return scrTxStore, nil
			}

			// Then check the address manager.
			address, err := w.Manager.Address(addr)
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
			// Check for alternative checksig scripts and
			// set the signature suite accordingly.
			ecType := chainec.ECTypeSecp256k1
			class := txscript.GetScriptClass(txscript.DefaultScriptVersion, prevOutScript)
			if class == txscript.PubkeyAltTy ||
				class == txscript.PubkeyHashAltTy {
				var err error
				ecType, err = txscript.ExtractPkScriptAltSigType(prevOutScript)
				if err != nil {
					return nil, errors.New("unknown checksigalt signature " +
						"suite specified")
				}
			}

			script, err := txscript.SignTxOutput(w.ChainParams(),
				tx, i, prevOutScript, hashType, getKey,
				getScript, txIn.SignatureScript, ecType)
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
		vm, err := txscript.NewEngine(prevOutScript, tx, i,
			txscript.StandardVerifyFlags, txscript.DefaultScriptVersion)
		if err == nil {
			err = vm.Execute()
		}
		if err != nil {
			multisigNotEnoughSigs := false
			class, addr, _, _ := txscript.ExtractPkScriptAddrs(
				txscript.DefaultScriptVersion,
				additionalPrevScripts[txIn.PreviousOutPoint],
				w.ChainParams())

			if err == txscript.ErrStackUnderflow &&
				class == txscript.ScriptHashTy {
				redeemScript, _ := getScript(addr[0])
				redeemClass := txscript.GetScriptClass(
					txscript.DefaultScriptVersion, redeemScript)
				if redeemClass == txscript.MultiSigTy {
					multisigNotEnoughSigs = true
				}
			}
			// Only report an error for the script engine in the event
			// that it's not a multisignature underflow, indicating that
			// we didn't have enough signatures in front of the
			// redeemScript rather than an actual error.
			if !multisigNotEnoughSigs {
				signErrors = append(signErrors, SignatureError{
					InputIndex: uint32(i),
					Error:      err,
				})
			}
		}
	}

	return signErrors, nil
}

// PublishTransaction sends the transaction to the consensus RPC server so it
// can be propigated to other nodes and eventually mined.
//
// This function is unstable and will be removed once syncing code is moved out
// of the wallet.
func (w *Wallet) PublishTransaction(tx *wire.MsgTx) error {
	server, err := w.requireChainClient()
	if err != nil {
		return err
	}

	_, err = server.SendRawTransaction(tx, w.AllowHighFees)
	return err
}

// ChainParams returns the network parameters for the blockchain the wallet
// belongs to.
func (w *Wallet) ChainParams() *chaincfg.Params {
	return w.chainParams
}

// Create creates an new wallet, writing it to an empty database.  If the passed
// seed is non-nil, it is used.  Otherwise, a secure random seed of the
// recommended length is generated.
func Create(db walletdb.DB, pubPass, privPass, seed []byte, params *chaincfg.Params, unsafeMainNet bool) error {
	// If a seed was provided, ensure that it is of valid length. Otherwise,
	// we generate a random seed for the wallet with the recommended seed
	// length.
	if seed == nil {
		hdSeed, err := hdkeychain.GenerateSeed(
			hdkeychain.RecommendedSeedLen)
		if err != nil {
			return err
		}
		seed = hdSeed
	}
	if len(seed) < hdkeychain.MinSeedBytes ||
		len(seed) > hdkeychain.MaxSeedBytes {
		return hdkeychain.ErrInvalidSeedLen
	}

	// Create the address manager.
	addrMgrNamespace, err := db.Namespace(waddrmgrNamespaceKey)
	if err != nil {
		return err
	}
	err = waddrmgr.Create(addrMgrNamespace, seed, pubPass, privPass,
		params, nil, unsafeMainNet)
	if err != nil {
		return err
	}

	// Create empty stake manager.
	stakeMgrNamespace, err := db.Namespace([]byte("wstakemgr"))
	if err != nil {
		return err
	}
	return wstakemgr.Create(stakeMgrNamespace)
}

// CreateWatchOnly creates a watchonly wallet on the provided db.
func CreateWatchOnly(db walletdb.DB, extendedPubKey string, pubPass []byte, params *chaincfg.Params) error {
	// Create the address manager.
	waddrmgrNamespace, err := db.Namespace(waddrmgrNamespaceKey)
	if err != nil {
		return err
	}

	err = waddrmgr.CreateWatchOnly(waddrmgrNamespace, extendedPubKey,
		pubPass, params, nil)
	if err != nil {
		return err
	}

	// Create the stake manager/store.
	wstakemgrNamespace, err := db.Namespace(wstakemgrNamespaceKey)
	if err != nil {
		return err
	}
	err = wstakemgr.Create(wstakemgrNamespace)
	if err != nil {
		return err
	}

	return nil
}

// decodeStakePoolColdExtKey decodes the string of stake pool addresses
// to search incoming tickets for. The format for the passed string is:
//   "xpub...:end"
// where xpub... is the extended public key and end is the last
// address index to scan to, exclusive. Effectively, it returns the derived
// addresses for this public key for the address indexes [0,end). The branch
// used for the derivation is always the external branch.
func decodeStakePoolColdExtKey(encStr string,
	params *chaincfg.Params) (map[string]struct{}, error) {
	// Default option; stake pool is disabled.
	if encStr == "" {
		return nil, nil
	}

	// Split the string.
	splStrs := strings.Split(encStr, ":")
	if len(splStrs) != 2 {
		return nil, fmt.Errorf("failed to correctly parse passed stakepool " +
			"address public key and index")
	}

	// Parse the extended public key and ensure it's the right network.
	key, err := hdkeychain.NewKeyFromString(splStrs[0])
	if err != nil {
		return nil, err
	}
	if !key.IsForNet(params) {
		return nil, fmt.Errorf("extended public key is for wrong network")
	}

	// Parse the ending index and ensure it's valid.
	end, err := strconv.Atoi(splStrs[1])
	if err != nil {
		return nil, err
	}
	if end < 0 || end > waddrmgr.MaxAddressesPerAccount {
		return nil, fmt.Errorf("pool address index is invalid (got %v)",
			end)
	}

	log.Infof("Please wait, deriving %v stake pool fees addresses "+
		"for extended public key %s", end, splStrs[0])

	// Derive the addresses from [0, end) for this extended public key.
	addrs, err := waddrmgr.AddressesDerivedFromExtPub(0, uint32(end),
		key, waddrmgr.ExternalBranch, params)
	if err != nil {
		return nil, err
	}

	addrMap := make(map[string]struct{})
	for i := range addrs {
		addrMap[addrs[i].EncodeAddress()] = struct{}{}
	}

	return addrMap, nil
}

// Open loads an already-created wallet from the passed database and namespaces.
func Open(db walletdb.DB, pubPass []byte, cbs *waddrmgr.OpenCallbacks,
	voteBits uint16, stakeMiningEnabled bool, balanceToMaintain float64,
	addressReuse bool, rollbackTest bool, pruneTickets bool, ticketAddress string,
	ticketMaxPrice float64, ticketBuyFreq int, poolAddress string,
	poolFees float64, addrIdxScanLen int, stakePoolColdExtKey string,
	autoRepair, allowHighFees bool, params *chaincfg.Params) (*Wallet, error) {
	addrMgrNS, err := db.Namespace(waddrmgrNamespaceKey)
	if err != nil {
		return nil, err
	}
	txMgrNS, err := db.Namespace(wtxmgrNamespaceKey)
	if err != nil {
		return nil, err
	}
	stakeMgrNS, err := db.Namespace(wstakemgrNamespaceKey)
	if err != nil {
		return nil, err
	}
	addrMgr, err := waddrmgr.Open(addrMgrNS, pubPass, params, cbs)
	if err != nil {
		return nil, err
	}
	noTxMgr, err := walletdb.NamespaceIsEmpty(txMgrNS)
	if err != nil {
		return nil, err
	}
	if noTxMgr {
		log.Info("No recorded transaction history -- needs full rescan")
		err = addrMgr.SetSyncedTo(nil)
		if err != nil {
			return nil, err
		}
		err = wtxmgr.Create(txMgrNS)
		if err != nil {
			return nil, err
		}
	}
	// Create a callback for account lookup from waddrmgr.
	accountCallback := addrMgr.AddrAccount
	txMgr, err := wtxmgr.Open(txMgrNS, pruneTickets, params, accountCallback)
	if err != nil {
		return nil, err
	}

	smgr, err := wstakemgr.Open(stakeMgrNS, addrMgr, params)
	if err != nil {
		return nil, err
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

	var poolAddr dcrutil.Address
	if poolAddress != "" {
		poolAddr, err = dcrutil.DecodeAddress(poolAddress, params)
		if err != nil {
			return nil, fmt.Errorf("pool address could not parse: %v",
				err.Error())
		}
	}
	stakePoolColdAddrs, err := decodeStakePoolColdExtKey(stakePoolColdExtKey,
		params)
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
		ticketBuyFreq,
		poolAddr,
		poolFees,
		addrIdxScanLen,
		stakePoolColdAddrs,
		autoRepair,
		allowHighFees,
		addrMgr,
		txMgr,
		smgr,
		&db,
		params)

	return w, nil
}
