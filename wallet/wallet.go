// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

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
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
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

	walletDbWatchingOnlyName = "wowallet.db"
)

// ErrNotSynced describes an error where an operation cannot complete
// due wallet being out of sync (and perhaps currently syncing with)
// the remote chain server.
var ErrNotSynced = errors.New("wallet is not synchronized with the chain server")

var ErrNotificationsClosed = errors.New("Notification stream has closed.")

// Namespace bucket keys.
var (
	waddrmgrNamespaceKey = []byte("waddrmgr")
	wtxmgrNamespaceKey   = []byte("wtxmgr")
)

// Wallet is a structure containing all the components for a
// complete wallet.  It contains the Armory-style key store
// addresses and keys),
//
// Wallet is stateless. In other words, it is inert. It is not
// responsible for opening and closing the database, and
type Wallet struct {
	publicPassphrase []byte

	// Data stores
	db      walletdb.DB
	Manager *waddrmgr.Manager
	TxStore *wtxmgr.Store

	lockedOutpoints map[wire.OutPoint]struct{}
	relayFee        btcutil.Amount
	relayFeeMu      sync.Mutex

	// Channels for rescan processing.  Requests are added and merged with
	// any waiting requests, before being sent to another goroutine to
	// call the rescan RPC.
	//
	// These channels are never closed.
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

	NtfnServer *NotificationServer

	chainParams *chaincfg.Params

	started bool

	quitMu sync.Mutex
	quit   chan struct{}

	wg sync.WaitGroup
}

// Start starts the goroutines necessary to manage a wallet.
func (w *Wallet) start() {
	w.quitMu.Lock()
	defer w.quitMu.Unlock()
	if w.started {
		return
	}
	w.started = true

	w.wg.Add(1)
	go w.walletLocker(w.quit)
}

// SynchronizeRPC associates the wallet with the consensus RPC client,
// synchronizes the wallet with the latest changes to the blockchain, and
// continuously updates the wallet through RPC notifications.
//
// This method is unstable and will be removed when all syncing logic is moved
// outside of the wallet package.
func (w *Wallet) synchronizeRPC(chainClient *chain.RPCClient,
	lifecycle func(session *Session) error) error {

	// Only one session is allowed to run at a time.
	defer w.quitMu.Unlock()
	w.quitMu.Lock()

	// TODO: Ignoring the new client when one is already set breaks callers
	// who are replacing the client, perhaps after a disconnect.
	//
	// SOLUTION: A Session struct cannot be restarted. It is disposable.
	// If you want another one, you recreate the object.
	//
	// Create the session.
	s := Session{
		Wallet:      w,
		chainClient: chainClient,
		quit:        w.quit,
	}

	// TODO: It would be preferable to either run these goroutines
	// separately from the wallet (use wallet mutator functions to
	// make changes from the RPC client) and not have to stop and
	// restart them each time the client disconnects and reconnets.
	w.wg.Add(5)
	go s.handleChainNotifications()
	go s.txCreator()
	go s.rescanBatchHandler()
	go s.rescanProgressHandler()
	go s.rescanRPCHandler()

	// Run the session through its lifecycle.
	err := lifecycle(&s)

	// Make sure the session is stopping.
	s.Stop()

	if err != nil {
		return err
	}

	return nil
}

// RelayFee returns the current minimum relay fee (per kB of serialized
// transaction) used when constructing transactions.
func (w *Wallet) RelayFee() btcutil.Amount {
	w.relayFeeMu.Lock()
	relayFee := w.relayFee
	w.relayFeeMu.Unlock()
	return relayFee
}

// SetRelayFee sets a new minimum relay fee (per kB of serialized
// transaction) used when constructing transactions.
func (w *Wallet) SetRelayFee(relayFee btcutil.Amount) {
	w.relayFeeMu.Lock()
	w.relayFee = relayFee
	w.relayFeeMu.Unlock()
}

// WaitForShutdown blocks until all wallet goroutines have finished executing.
func (w *Wallet) WaitForShutdown() error {
	w.wg.Wait()
	return nil
}

// activeData returns the currently-active receiving addresses and all unspent
// outputs.  This is primarely intended to provide the parameters for a
// rescan request.
func (w *Wallet) activeData() ([]btcutil.Address, []wtxmgr.Credit, error) {
	var addrs []btcutil.Address
	err := w.Manager.ForEachActiveAddress(func(addr btcutil.Address) error {
		addrs = append(addrs, addr)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	unspent, err := w.TxStore.UnspentOutputs()
	return addrs, unspent, err
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
func (w *Wallet) walletLocker(quit chan struct{}) {
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
		case <-timeout:
		}

		// Select statement fell through by an explicit lock or the
		// timer expiring.  Lock the manager here.
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
func (w *Wallet) CalculateBalance(confirms int32) (btcutil.Amount, error) {
	blk := w.Manager.SyncedTo()
	return w.TxStore.Balance(confirms, blk.Height)
}

// Balances records total, spendable (by policy), and immature coinbase
// reward balance amounts.
type Balances struct {
	Total          btcutil.Amount
	Spendable      btcutil.Amount
	ImmatureReward btcutil.Amount
}

// CalculateAccountBalances sums the amounts of all unspent transaction
// outputs to the given account of a wallet and returns the balance.
//
// This function is much slower than it needs to be since transactions outputs
// are not indexed by the accounts they credit to, and all unspent transaction
// outputs must be iterated.
func (w *Wallet) CalculateAccountBalances(account uint32, confirms int32) (Balances, error) {
	var bals Balances

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	syncBlock := w.Manager.SyncedTo()

	unspent, err := w.TxStore.UnspentOutputs()
	if err != nil {
		return bals, err
	}
	for i := range unspent {
		output := &unspent[i]

		var outputAcct uint32
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams)
		if err == nil && len(addrs) > 0 {
			outputAcct, err = w.Manager.AddrAccount(addrs[0])
		}
		if err != nil || outputAcct != account {
			continue
		}

		bals.Total += output.Amount
		if output.FromCoinBase && !confirmed(int32(w.chainParams.CoinbaseMaturity),
			output.Height, syncBlock.Height) {
			bals.ImmatureReward += output.Amount
		} else if confirmed(confirms, output.Height, syncBlock.Height) {
			bals.Spendable += output.Amount
		}
	}
	return bals, nil
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
func RecvCategory(details *wtxmgr.TxDetails, syncHeight int32, net *chaincfg.Params) CreditCategory {
	if blockchain.IsCoinBaseTx(&details.MsgTx) {
		if confirmed(int32(net.CoinbaseMaturity), details.Block.Height,
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
	syncHeight int32, net *chaincfg.Params) []btcjson.ListTransactionsResult {

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
			account, err := addrMgr.AddrAccount(addrs[0])
			if err == nil {
				accountName, err = addrMgr.AccountName(account)
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
func (w *Wallet) ListSinceBlock(start, end, syncHeight int32) ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}
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
func (w *Wallet) ListTransactions(from, count int) ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}

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
	[]btcjson.ListTransactionsResult, error) {

	txList := []btcjson.ListTransactionsResult{}

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
					pkScript, w.chainParams)
				if err != nil || len(addrs) != 1 {
					continue
				}
				apkh, ok := addrs[0].(*btcutil.AddressPubKeyHash)
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
func (w *Wallet) ListAllTransactions() ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}

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

// AccountResult is a single account result for the AccountsResult type.
type AccountResult struct {
	waddrmgr.AccountProperties
	TotalBalance btcutil.Amount
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
	m := make(map[uint32]*btcutil.Amount)
	for i := range accounts {
		a := &accounts[i]
		m[a.AccountNumber] = &a.TotalBalance
	}
	for i := range unspent {
		output := &unspent[i]
		var outputAcct uint32
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams)
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
type creditSlice []wtxmgr.Credit

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
	addresses map[string]struct{}) ([]*btcjson.ListUnspentResult, error) {

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

	results := make([]*btcjson.ListUnspentResult, 0, len(unspent))
	for i := range unspent {
		output := &unspent[i]

		// Outputs with fewer confirmations than the minimum or more
		// confs than the maximum are excluded.
		confs := confirms(output.Height, syncBlock.Height)
		if confs < minconf || confs > maxconf {
			continue
		}

		// Only mature coinbase outputs are included.
		if output.FromCoinBase {
			target := int32(w.chainParams.CoinbaseMaturity)
			if !confirmed(target, output.Height, syncBlock.Height) {
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
			output.PkScript, w.chainParams)
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

		result := &btcjson.ListUnspentResult{
			TxID:          output.OutPoint.Hash.String(),
			Vout:          output.OutPoint.Index,
			Account:       acctName,
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

	return results, nil
}

// DumpPrivKeys returns the WIF-encoded private keys for all addresses with
// private keys in a wallet.
func (w *Wallet) DumpPrivKeys() ([]string, error) {
	var privkeys []string
	// Iterate over each active address, appending the private key to
	// privkeys.
	err := w.Manager.ForEachActiveAddress(func(addr btcutil.Address) error {
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

// ExportWatchingWallet returns a watching-only version of the wallet serialized
// database as a base64-encoded string.
func (w *Wallet) ExportWatchingWallet() (string, error) {
	tmpDir, err := ioutil.TempDir("", "btcwallet")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	// Create a new file and write a copy of the current database into it.
	woDbPath := filepath.Join(tmpDir, walletDbWatchingOnlyName)
	fi, err := os.OpenFile(woDbPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	if err := w.db.Copy(fi); err != nil {
		fi.Close()
		return "", err
	}
	fi.Close()
	defer os.Remove(woDbPath)

	// Open the new database, get the address manager namespace, and open
	// it.
	woDb, err := walletdb.Open("bdb", woDbPath)
	if err != nil {
		_ = os.Remove(woDbPath)
		return "", err
	}
	defer woDb.Close()

	namespace, err := woDb.Namespace(waddrmgrNamespaceKey)
	if err != nil {
		return "", err
	}
	woMgr, err := waddrmgr.Open(namespace, w.publicPassphrase,
		w.chainParams, nil)
	if err != nil {
		return "", err
	}
	defer woMgr.Close()

	// Convert the namespace to watching only if needed.
	if err := woMgr.ConvertToWatchingOnly(); err != nil {
		// Only return the error is it's not because it's already
		// watching-only.  When it is already watching-only, the code
		// just falls through to the export below.
		if !waddrmgr.IsError(err, waddrmgr.ErrWatchingOnly) {
			return "", err
		}
	}

	// Export the watching only wallet's serialized data.
	return exportBase64DB(woDb)
}

// exportBase64DB exports a wallet's serialized database as a base64-encoded
// string.
func exportBase64DB(db walletdb.DB) (string, error) {
	var buf bytes.Buffer
	if err := db.Copy(&buf); err != nil {
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

// SortedActivePaymentAddresses returns a slice of all active payment
// addresses in a wallet.
func (w *Wallet) SortedActivePaymentAddresses() ([]string, error) {
	var addrStrs []string
	err := w.Manager.ForEachActiveAddress(func(addr btcutil.Address) error {
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
// returning the total amount of bitcoins received for a single wallet
// account.
func (w *Wallet) TotalReceivedForAccount(account uint32, minConf int32) (btcutil.Amount, int32, error) {
	syncBlock := w.Manager.SyncedTo()

	var (
		amount     btcutil.Amount
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
				pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
				var outputAcct uint32
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(
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
// returning the total amount of bitcoins received for a single wallet
// address.
func (w *Wallet) TotalReceivedForAddr(addr btcutil.Address, minConf int32) (btcutil.Amount, error) {
	syncBlock := w.Manager.SyncedTo()

	var (
		addrStr    = addr.EncodeAddress()
		amount     btcutil.Amount
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
				pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(
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
	additionalKeysByAddress map[string]*btcutil.WIF,
	p2shRedeemScriptsByAddress map[string][]byte) ([]SignatureError, error) {

	var signErrors []SignatureError
	for i, txIn := range tx.TxIn {
		var prevAmount int64
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
		getKey := txscript.KeyClosure(func(addr btcutil.Address) (
			*btcec.PrivateKey, bool, error) {
			if len(additionalKeysByAddress) != 0 {
				addrStr := addr.EncodeAddress()
				wif, ok := additionalKeysByAddress[addrStr]
				if !ok {
					return nil, false,
						errors.New("no key for address")
				}
				return wif.PrivKey, wif.CompressPubKey, nil
			}
			address, err := w.Manager.Address(addr)
			if err != nil {
				return nil, false, err
			}

			pka, ok := address.(waddrmgr.ManagedPubKeyAddress)
			if !ok {
				return nil, false, errors.New("address is not " +
					"a pubkey address")
			}

			key, err := pka.PrivKey()
			if err != nil {
				return nil, false, err
			}

			return key, pka.Compressed(), nil
		})
		getScript := txscript.ScriptClosure(func(
			addr btcutil.Address) ([]byte, error) {
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
		vm, err := txscript.NewEngine(prevOutScript, tx, i,
			txscript.StandardVerifyFlags, nil, nil, prevAmount)
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

	return signErrors, nil
}

// ChainParams returns the network parameters for the blockchain the wallet
// belongs to.
func (w *Wallet) ChainParams() *chaincfg.Params {
	return w.chainParams
}

// Create creates an new wallet, writing it to an empty database.  If the passed
// seed is non-nil, it is used.  Otherwise, a secure random seed of the
// recommended length is generated.
func Create(db walletdb.DB, pubPass, privPass, seed []byte, params *chaincfg.Params) error {
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
		params, nil)
	if err != nil {
		return err
	}

	// Create empty transaction manager.
	txMgrNamespace, err := db.Namespace(wtxmgrNamespaceKey)
	if err != nil {
		return err
	}
	return wtxmgr.Create(txMgrNamespace)
}

// Open loads an already-created wallet from the passed database and namespaces.
func Open(db walletdb.DB, pubPass []byte, cbs *waddrmgr.OpenCallbacks, params *chaincfg.Params) (*Wallet, error) {
	addrMgrNS, err := db.Namespace(waddrmgrNamespaceKey)
	if err != nil {
		return nil, err
	}
	txMgrNS, err := db.Namespace(wtxmgrNamespaceKey)
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
	txMgr, err := wtxmgr.Open(txMgrNS, params)
	if err != nil {
		return nil, err
	}

	log.Infof("Opened wallet") // TODO: log balance? last sync height?
	w := &Wallet{
		publicPassphrase:    pubPass,
		db:                  db,
		Manager:             addrMgr,
		TxStore:             txMgr,
		lockedOutpoints:     map[wire.OutPoint]struct{}{},
		relayFee:            txrules.DefaultRelayFeePerKb,
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
		chainParams:         params,
		quit:                make(chan struct{}),
	}
	w.start()
	w.NtfnServer = newNotificationServer()
	w.TxStore.NotifyUnspent = func(hash *chainhash.Hash, index uint32) {
		w.NtfnServer.notifyUnspentOutput(0, hash, index)
	}
	return w, nil
}
