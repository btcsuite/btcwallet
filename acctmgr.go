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

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/conformal/btcchain"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/txstore"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
)

// Errors relating to accounts.
var (
	ErrAccountExists = errors.New("account already exists")
	ErrWalletExists  = errors.New("wallet already exists")
	ErrNotFound      = errors.New("not found")
	ErrNoAccounts    = errors.New("no accounts")
)

// AcctMgr is the global account manager for all opened accounts.
var AcctMgr = NewAccountManager()

type (
	openAccountsCmd struct{}

	accessAccountRequest struct {
		name string
		resp chan *Account
	}

	accessAllRequest struct {
		resp chan []*Account
	}

	accessAccountByAddressRequest struct {
		address string
		resp    chan *Account
	}

	markAddressForAccountCmd struct {
		address string
		account *Account
	}

	addAccountCmd struct {
		a *Account
	}

	removeAccountCmd struct {
		a *Account
	}

	quitCmd struct{}
)

type unlockRequest struct {
	passphrase []byte
	timeout    time.Duration // Zero value prevents the timeout.
	err        chan error
}

// AccountManager manages a collection of accounts.
type AccountManager struct {
	// The accounts accessed through the account manager are not safe for
	// concurrent access.  The account manager therefore contains a
	// binary semaphore channel to prevent incorrect access.
	bsem           chan struct{}
	cmdChan        chan interface{}
	rescanMsgs     chan RescanMsg
	unlockRequests chan unlockRequest
	lockRequests   chan struct{}
	unlockedState  chan bool

	ds *DiskSyncer
	rm *RescanManager

	wg   sync.WaitGroup
	quit chan struct{}
}

// NewAccountManager returns a new AccountManager.
func NewAccountManager() *AccountManager {
	am := &AccountManager{
		bsem:           make(chan struct{}, 1),
		cmdChan:        make(chan interface{}),
		rescanMsgs:     make(chan RescanMsg, 1),
		unlockRequests: make(chan unlockRequest),
		lockRequests:   make(chan struct{}),
		unlockedState:  make(chan bool),

		quit: make(chan struct{}),
	}
	am.ds = NewDiskSyncer(am)
	am.rm = NewRescanManager(am.rescanMsgs)
	return am
}

// Start starts the goroutines required to run the AccountManager.
func (am *AccountManager) Start() {
	// Ready the semaphore - can't grab unless the manager has started.
	am.bsem <- struct{}{}

	am.wg.Add(3)
	go am.accountHandler()
	go am.keystoreLocker()
	go am.rescanListener()

	go am.ds.Start()
	go am.rm.Start()
}

// Stop shuts down the account manager by stoping all signaling all goroutines
// started by Start to close.
func (am *AccountManager) Stop() {
	am.rm.Stop()
	am.ds.Stop()
	close(am.quit)
}

// WaitForShutdown blocks until all goroutines started by Start and stopped
// with Stop have finished.
func (am *AccountManager) WaitForShutdown() {
	am.rm.WaitForShutdown()
	am.ds.WaitForShutdown()
	am.wg.Wait()
}

// accountData is a helper structure to let us centralise logic for adding
// and removing accounts.
type accountData struct {
	// maps name to account struct. We could keep a list here for iteration
	// but iteration over the small amounts we have is likely not worth
	// the extra complexity.
	nameToAccount    map[string]*Account
	addressToAccount map[string]*Account
}

func newAccountData() *accountData {
	return &accountData{
		nameToAccount:    make(map[string]*Account),
		addressToAccount: make(map[string]*Account),
	}
}

func (ad *accountData) addAccount(a *Account) {
	if _, ok := ad.nameToAccount[a.name]; ok {
		return
	}
	ad.nameToAccount[a.name] = a
	for addr := range a.ActivePaymentAddresses() {
		ad.addressToAccount[addr] = a
	}
}

func (ad *accountData) removeAccount(a *Account) {
	a, ok := ad.nameToAccount[a.name]
	if !ok {
		return
	}

	delete(ad.nameToAccount, a.name)
	for addr := range a.ActivePaymentAddresses() {
		delete(ad.addressToAccount, addr)
	}
}

// walletOpenError is a special error type so problems opening wallet
// files can be differentiated (by a type assertion) from other errors.
type walletOpenError struct {
	Err string
}

// Error satisifies the builtin error interface.
func (e *walletOpenError) Error() string {
	return e.Err
}

var (
	// errNoWallet describes an error where a wallet does not exist and
	// must be created first.
	errNoWallet = &walletOpenError{
		Err: "wallet file does not exist",
	}
)

// openSavedAccount opens a named account from disk.  If the wallet does not
// exist, errNoWallet is returned as an error.
func openSavedAccount(name string, cfg *config) (*Account, error) {
	netdir := networkDir(activeNet.Params)
	if err := checkCreateDir(netdir); err != nil {
		return nil, &walletOpenError{
			Err: err.Error(),
		}
	}

	wlt := new(wallet.Wallet)
	txs := txstore.New()
	a := &Account{
		name:            name,
		Wallet:          wlt,
		TxStore:         txs,
		lockedOutpoints: map[btcwire.OutPoint]struct{}{},
	}

	walletPath := accountFilename("wallet.bin", name, netdir)
	txstorePath := accountFilename("tx.bin", name, netdir)

	// Read wallet file.
	walletFi, err := os.Open(walletPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Must create and save wallet first.
			return nil, errNoWallet
		}
		msg := fmt.Sprintf("cannot open wallet file: %s", err)
		return nil, &walletOpenError{msg}
	}
	if _, err = wlt.ReadFrom(walletFi); err != nil {
		if err := walletFi.Close(); err != nil {
			log.Warnf("Cannot close wallet file: %v", err)
		}
		msg := fmt.Sprintf("Cannot read wallet: %s", err)
		return nil, &walletOpenError{msg}
	}

	// Read txstore file.  If this fails, write a new empty transaction
	// store to disk, mark the wallet as unsynced, and write the unsynced
	// wallet to disk.
	//
	// This file is opened read/write so it may be truncated if a new empty
	// transaction store must be written.
	txstoreFi, err := os.OpenFile(txstorePath, os.O_RDWR, 0)
	if err != nil {
		if err := walletFi.Close(); err != nil {
			log.Warnf("Cannot close wallet file: %v", err)
		}
		if err := writeUnsyncedWallet(a, walletPath); err != nil {
			return nil, err
		}

		// Create and write empty txstore, if it doesn't exist.
		if !fileExists(txstorePath) {
			log.Warn("Transaction store file missing")
			if txstoreFi, err = os.Create(txstorePath); err != nil {
				return nil, fmt.Errorf("cannot create new "+
					"txstore file: %v", err)
			}
			defer func() {
				if err := txstoreFi.Close(); err != nil {
					log.Warnf("Cannot close transaction "+
						"store file: %v", err)
				}
			}()
		} else {
			return nil, fmt.Errorf("transaction store file "+
				"exists but cannot be opened: %v", err)
		}

		if _, err := txs.WriteTo(txstoreFi); err != nil {
			log.Warn(err)
		}
		return a, nil
	}
	if _, err = txs.ReadFrom(txstoreFi); err != nil {
		if err := walletFi.Close(); err != nil {
			log.Warnf("Cannot close wallet file: %v", err)
		}
		if err := writeUnsyncedWallet(a, walletPath); err != nil {
			return nil, err
		}

		defer func() {
			if err := txstoreFi.Close(); err != nil {
				log.Warnf("Cannot close transaction store "+
					"file: %v", err)
			}
		}()
		log.Warnf("Cannot read transaction store: %s", err)
		if _, err := txstoreFi.Seek(0, os.SEEK_SET); err != nil {
			return nil, err
		}
		if err := txstoreFi.Truncate(0); err != nil {
			return nil, err
		}
		if _, err := txs.WriteTo(txstoreFi); err != nil {
			log.Warn("Cannot write new transaction store: %v", err)
		}
		log.Infof("Wrote empty transaction store file")
		return a, nil
	}

	if err := walletFi.Close(); err != nil {
		log.Warnf("Cannot close wallet file: %v", err)
	}
	if err := txstoreFi.Close(); err != nil {
		log.Warnf("Cannot close transaction store file: %v", err)
	}
	return a, nil
}

// writeUnsyncedWallet sets the wallet unsynced (to handle the case
// where the transaction store was unreadable) and atomically writes
// the new wallet file back to disk.  The current wallet file on disk
// should be already closed, or this will error on Windows for ovewriting
// an open file.
func writeUnsyncedWallet(a *Account, path string) error {
	// Mark wallet as unsynced and write back to disk.  Later calls
	// to SyncHeight will use the wallet creation height, or possibly
	// an earlier height for imported keys.
	netdir, _ := filepath.Split(path)
	a.SetSyncedWith(nil)
	tmpwallet, err := ioutil.TempFile(netdir, "wallet.bin")
	if err != nil {
		return fmt.Errorf("cannot create temporary wallet: %v", err)
	}
	if _, err := a.Wallet.WriteTo(tmpwallet); err != nil {
		return fmt.Errorf("cannot write back unsynced wallet: %v", err)
	}
	tmpwalletpath := tmpwallet.Name()
	if err := tmpwallet.Close(); err != nil {
		return fmt.Errorf("cannot close temporary wallet file: %v", err)
	}
	if err := Rename(tmpwalletpath, path); err != nil {
		return fmt.Errorf("cannot move temporary wallet file: %v", err)
	}
	return nil
}

// openAccounts attempts to open all saved accounts.
func openAccounts() *accountData {
	ad := newAccountData()

	// If the network (account) directory is missing, but the temporary
	// directory exists, move it.  This is unlikely to happen, but possible,
	// if writing out every account file at once to a tmp directory (as is
	// done for changing a wallet passphrase) and btcwallet closes after
	// removing the network directory but before renaming the temporary
	// directory.
	netDir := networkDir(activeNet.Params)
	tmpNetDir := tmpNetworkDir(activeNet.Params)
	if !fileExists(netDir) && fileExists(tmpNetDir) {
		if err := Rename(tmpNetDir, netDir); err != nil {
			log.Errorf("Cannot move temporary network dir: %v", err)
			return ad
		}
	}

	// The default account must exist, or btcwallet acts as if no
	// wallets/accounts have been created yet.
	a, err := openSavedAccount("", cfg)
	if err != nil {
		log.Errorf("Cannot open default account: %v", err)
		return ad
	}

	ad.addAccount(a)

	// Read all filenames in the account directory, and look for any
	// filenames matching '*-wallet.bin'.  These are wallets for
	// additional saved accounts.
	accountDir, err := os.Open(netDir)
	if err != nil {
		// Can't continue.
		log.Errorf("Unable to open account directory: %v", err)
		return ad
	}
	defer func() {
		if err := accountDir.Close(); err != nil {
			log.Warnf("Cannot close account directory")
		}
	}()
	fileNames, err := accountDir.Readdirnames(0)
	if err != nil {
		// fileNames might be partially set, so log an error and
		// at least try to open some accounts.
		log.Errorf("Unable to read all account files: %v", err)
	}
	var accountNames []string
	for _, file := range fileNames {
		if strings.HasSuffix(file, "-wallet.bin") {
			name := strings.TrimSuffix(file, "-wallet.bin")
			accountNames = append(accountNames, name)
		}
	}

	// Open all additional accounts.
	for _, acctName := range accountNames {
		// Log txstore/utxostore errors as these will be recovered
		// from with a rescan, but wallet errors must be returned
		// to the caller.
		a, err := openSavedAccount(acctName, cfg)
		if err != nil {
			switch err.(type) {
			case *walletOpenError:
				log.Errorf("Error opening account's wallet: %v", err)

			default:
				log.Warnf("Non-critical error opening an account file: %v", err)
			}
		} else {
			ad.addAccount(a)
		}
	}
	return ad
}

// accountHandler maintains accounts and structures for quick lookups for
// account information.  Access to these structures must be requested via
// cmdChan. cmdChan is a single channel for multiple command types since there
// is ordering inherent in the commands and ordering between multipl goroutine
// reads via select{} is very much undefined. This function never returns and
// should be called as a new goroutine.
func (am *AccountManager) accountHandler() {
	ad := openAccounts()

out:
	for {
		select {
		case c := <-am.cmdChan:
			switch cmd := c.(type) {
			case *openAccountsCmd:
				// Write all old accounts before proceeding.
				for _, a := range ad.nameToAccount {
					if err := am.ds.FlushAccount(a); err != nil {
						log.Errorf("Cannot write previously "+
							"scheduled account file: %v", err)
					}
				}

				ad = openAccounts()
			case *accessAccountRequest:
				a, ok := ad.nameToAccount[cmd.name]
				if !ok {
					a = nil
				}
				cmd.resp <- a

			case *accessAccountByAddressRequest:
				a, ok := ad.addressToAccount[cmd.address]
				if !ok {
					a = nil
				}
				cmd.resp <- a

			case *accessAllRequest:
				s := make([]*Account, 0, len(ad.nameToAccount))
				for _, a := range ad.nameToAccount {
					s = append(s, a)
				}
				cmd.resp <- s

			case *addAccountCmd:
				ad.addAccount(cmd.a)
			case *removeAccountCmd:
				ad.removeAccount(cmd.a)

			case *markAddressForAccountCmd:
				// TODO(oga) make sure we own account
				ad.addressToAccount[cmd.address] = cmd.account
			}

		case <-am.quit:
			break out
		}
	}
	am.wg.Done()
}

// keystoreLocker manages the lockedness state of all account keystores.
func (am *AccountManager) keystoreLocker() {
	unlocked := false
	var timeout <-chan time.Time
out:
	for {
		select {
		case req := <-am.unlockRequests:
			for _, a := range am.AllAccounts() {
				if err := a.Unlock(req.passphrase); err != nil {
					req.err <- err
					continue out
				}
			}
			unlocked = true
			if req.timeout == 0 {
				timeout = nil
			} else {
				timeout = time.After(req.timeout)
			}
			req.err <- nil
			continue

		case am.unlockedState <- unlocked:
			continue

		case <-am.quit:
			break out

		case <-am.lockRequests:
		case <-timeout:
		}

		// Select statement fell through by an explicit lock or the
		// timer expiring.  Lock the keystores here.
		timeout = nil
		for _, a := range am.AllAccounts() {
			if err := a.Lock(); err != nil {
				log.Errorf("Could not lock wallet for account '%s': %v",
					a.name, err)
			}
		}
		unlocked = false
	}
	am.wg.Done()
}

// rescanListener listens for messages from the rescan manager and marks
// accounts and addresses as synced.
func (am *AccountManager) rescanListener() {
	for msg := range am.rescanMsgs {
		AcctMgr.Grab()
		switch e := msg.(type) {
		case *RescanStartedMsg:
			// Log the newly-started rescan.
			n := 0
			for _, addrs := range e.Addresses {
				n += len(addrs)
			}
			noun := pickNoun(n, "address", "addresses")
			log.Infof("Started rescan at height %d for %d %s", e.StartHeight, n, noun)

		case *RescanProgressMsg:
			for acct, addrs := range e.Addresses {
				for i := range addrs {
					err := acct.SetSyncStatus(addrs[i], wallet.PartialSync(e.Height))
					if err != nil {
						log.Errorf("Error marking address partially synced: %v", err)
						continue
					}
				}
				am.ds.ScheduleWalletWrite(acct)
				err := am.ds.FlushAccount(acct)
				if err != nil {
					log.Errorf("Could not write rescan progress: %v", err)
				}
			}

			log.Infof("Rescanned through block height %d", e.Height)

		case *RescanFinishedMsg:
			if e.Error != nil {
				log.Errorf("Rescan failed: %v", e.Error)
				break
			}

			n := 0
			for acct, addrs := range e.Addresses {
				n += len(addrs)
				for i := range addrs {
					err := acct.SetSyncStatus(addrs[i], wallet.FullSync{})
					if err != nil {
						log.Errorf("Error marking address synced: %v", err)
						continue
					}
				}
				am.ds.ScheduleWalletWrite(acct)
				err := am.ds.FlushAccount(acct)
				if err != nil {
					log.Errorf("Could not write rescan progress: %v", err)
				}
			}

			noun := pickNoun(n, "address", "addresses")
			log.Infof("Finished rescan for %d %s", n, noun)

		default:
			// Unexpected rescan message type.
			panic(e)
		}
		AcctMgr.Release()
	}
	am.wg.Done()
}

// Grab grabs the account manager's binary semaphore.  A custom semaphore
// is used instead of a sync.Mutex so the account manager's disk syncer
// can grab the semaphore from a select statement.
func (am *AccountManager) Grab() {
	<-am.bsem
}

// Release releases exclusive ownership of the AccountManager.
func (am *AccountManager) Release() {
	am.bsem <- struct{}{}
}

// OpenAccounts triggers the manager to reopen all known accounts.
func (am *AccountManager) OpenAccounts() {
	am.cmdChan <- &openAccountsCmd{}
}

// Account returns the account specified by name, or ErrNotFound
// as an error if the account is not found.
func (am *AccountManager) Account(name string) (*Account, error) {
	respChan := make(chan *Account)
	am.cmdChan <- &accessAccountRequest{
		name: name,
		resp: respChan,
	}
	resp := <-respChan
	if resp == nil {
		return nil, ErrNotFound
	}
	return resp, nil
}

// AccountByAddress returns the account specified by address, or
// ErrNotFound as an error if the account is not found.
func (am *AccountManager) AccountByAddress(addr btcutil.Address) (*Account, error) {
	respChan := make(chan *Account)
	req := accessAccountByAddressRequest{
		address: addr.EncodeAddress(),
		resp:    respChan,
	}
	select {
	case am.cmdChan <- &req:
		resp := <-respChan
		if resp == nil {
			return nil, ErrNotFound
		}
		return resp, nil
	case <-am.quit:
		return nil, ErrNoAccounts
	}
}

// MarkAddressForAccount labels the given account as containing the provided
// address.
func (am *AccountManager) MarkAddressForAccount(address btcutil.Address,
	account *Account) {
	// TODO(oga) really this entire dance should be carried out implicitly
	// instead of requiring explicit messaging from the account to the
	// manager.
	req := markAddressForAccountCmd{
		address: address.EncodeAddress(),
		account: account,
	}
	select {
	case am.cmdChan <- &req:
	case <-am.quit:
	}
}

// Address looks up an address if it is known to wallet at all.
func (am *AccountManager) Address(addr btcutil.Address) (wallet.WalletAddress, error) {
	a, err := am.AccountByAddress(addr)
	if err != nil {
		return nil, err
	}

	return a.Address(addr)
}

// AllAccounts returns a slice of all managed accounts.
func (am *AccountManager) AllAccounts() []*Account {
	respChan := make(chan []*Account)
	req := accessAllRequest{
		resp: respChan,
	}
	select {
	case am.cmdChan <- &req:
		return <-respChan
	case <-am.quit:
		return nil
	}
}

// AddAccount adds an account to the collection managed by an AccountManager.
func (am *AccountManager) AddAccount(a *Account) {
	req := addAccountCmd{
		a: a,
	}
	select {
	case am.cmdChan <- &req:
	case <-am.quit:
	}
}

// RemoveAccount removes an account to the collection managed by an
// AccountManager.
func (am *AccountManager) RemoveAccount(a *Account) {
	req := removeAccountCmd{
		a: a,
	}
	select {
	case am.cmdChan <- &req:
	case <-am.quit:
	}
}

// RegisterNewAccount adds a new memory account to the account manager,
// and immediately writes the account to disk.
func (am *AccountManager) RegisterNewAccount(a *Account) error {
	am.AddAccount(a)

	// Ensure that the new account is written out to disk.
	am.ds.ScheduleWalletWrite(a)
	am.ds.ScheduleTxStoreWrite(a)
	if err := am.ds.FlushAccount(a); err != nil {
		am.RemoveAccount(a)
		return err
	}
	return nil
}

// Rollback rolls back each managed Account to the state before the block
// specified by height and hash was connected to the main chain.
func (am *AccountManager) Rollback(height int32, hash *btcwire.ShaHash) error {
	for _, a := range am.AllAccounts() {
		if err := a.TxStore.Rollback(height); err != nil {
			return err
		}
		am.ds.ScheduleTxStoreWrite(a)
	}
	return nil
}

// BlockNotify notifies all wallet clients of any changes from the new block,
// including changed balances.  Each account is then set to be synced
// with the latest block.
func (am *AccountManager) BlockNotify(bs *wallet.BlockStamp) {
	for _, a := range am.AllAccounts() {
		// TODO: need a flag or check that the utxo store was actually
		// modified, or this will notify even if there are no balance
		// changes, or sending these notifications as the utxos are added.
		confirmed, err := a.CalculateBalance(1)
		var unconfirmed btcutil.Amount
		if err == nil {
			unconfirmed, err = a.CalculateBalance(0)
		}
		if err == nil {
			unconfirmed -= confirmed
			server.NotifyWalletBalance(a.name, confirmed)
			server.NotifyWalletBalanceUnconfirmed(a.name, unconfirmed)
		}

		// If this is the default account, update the block all accounts
		// are synced with, and schedule a wallet write.
		if a.Name() == "" {
			a.Wallet.SetSyncedWith(bs)
			am.ds.ScheduleWalletWrite(a)
		}
	}
}

// RecordMinedTx searches through each account's TxStore, searching for a
// sent transaction with the same txid as from a txmined notification.  If
// the transaction IDs match, the record in the TxStore is updated with
// the full information about the newly-mined tx, and the TxStore is
// scheduled to be written to disk..
func (am *AccountManager) RecordSpendingTx(tx *btcutil.Tx, block *txstore.Block) error {
	for _, a := range am.AllAccounts() {
		// TODO(jrick): This needs to iterate through each txout's
		// addresses and find whether this account's keystore contains
		// any of the addresses this tx sends to.
		txr, err := a.TxStore.InsertTx(tx, block)
		if err != nil {
			return err
		}
		// When received as a notification, we don't know what the inputs are.
		if _, err := txr.AddDebits(nil); err != nil {
			return err
		}
		am.ds.ScheduleTxStoreWrite(a)
	}
	return nil
}

// CalculateBalance returns the balance, calculated using minconf block
// confirmations, of an account.
func (am *AccountManager) CalculateBalance(account string, minconf int) (btcutil.Amount, error) {
	a, err := am.Account(account)
	if err != nil {
		return 0, err
	}

	return a.CalculateBalance(minconf)
}

// CreateEncryptedWallet creates a new default account with a wallet file
// encrypted with passphrase.
func (am *AccountManager) CreateEncryptedWallet(passphrase []byte) error {
	if len(am.AllAccounts()) != 0 {
		return ErrWalletExists
	}

	// Get current block's height and hash.
	rpcc, err := accessClient()
	if err != nil {
		return err
	}
	bs, err := rpcc.BlockStamp()
	if err != nil {
		return err
	}

	// Create new wallet in memory.
	wlt, err := wallet.NewWallet("", "Default acccount", passphrase,
		activeNet.Params, &bs, cfg.KeypoolSize)
	if err != nil {
		return err
	}

	// Create new account and begin managing with the global account
	// manager.  Registering will fail if the new account can not be
	// written immediately to disk.
	a := &Account{
		Wallet:          wlt,
		TxStore:         txstore.New(),
		lockedOutpoints: map[btcwire.OutPoint]struct{}{},
	}
	if err := am.RegisterNewAccount(a); err != nil {
		return err
	}

	// Begin tracking account against a connected btcd.
	a.Track()

	return nil
}

// ChangePassphrase unlocks all account wallets with the old
// passphrase, and re-encrypts each using the new passphrase.
func (am *AccountManager) ChangePassphrase(old, new []byte) error {
	// Keystores must be unlocked to change their passphrase.
	err := am.UnlockWallets(old, 0)
	if err != nil {
		return err
	}

	accts := am.AllAccounts()

	// Change passphrase for each unlocked wallet.
	for _, a := range accts {
		err = a.Wallet.ChangePassphrase(new)
		if err != nil {
			return err
		}
	}

	am.LockWallets()

	// Immediately write out to disk.
	return am.ds.WriteBatch(accts)
}

// LockWallets locks all managed account wallets.
func (am *AccountManager) LockWallets() {
	am.lockRequests <- struct{}{}
}

// UnlockWallets unlocks all managed account's wallets, locking them again after
// the timeout expires, or resetting a previous timeout if one is still running.
func (am *AccountManager) UnlockWallets(passphrase []byte, timeout time.Duration) error {
	req := unlockRequest{
		passphrase: passphrase,
		timeout:    timeout,
		err:        make(chan error, 1),
	}
	am.unlockRequests <- req
	return <-req.err
}

// DumpKeys returns all WIF-encoded private keys associated with all
// accounts. All wallets must be unlocked for this operation to succeed.
func (am *AccountManager) DumpKeys() ([]string, error) {
	keys := []string{}
	for _, a := range am.AllAccounts() {
		switch walletKeys, err := a.DumpPrivKeys(); err {
		case wallet.ErrWalletLocked:
			return nil, err

		case nil:
			keys = append(keys, walletKeys...)

		default: // any other non-nil error
			return nil, err
		}

	}
	return keys, nil
}

// DumpWIFPrivateKey searches through all accounts for the bitcoin
// payment address addr and returns the WIF-encdoded private key.
func (am *AccountManager) DumpWIFPrivateKey(addr btcutil.Address) (string, error) {
	a, err := am.AccountByAddress(addr)
	if err != nil {
		return "", err
	}
	return a.DumpWIFPrivateKey(addr)
}

// ListAccounts returns a map of account names to their current account
// balances.  The balances are calculated using minconf confirmations.
func (am *AccountManager) ListAccounts(minconf int) (map[string]btcutil.Amount, error) {
	// Create and fill a map of account names and their balances.
	accts := am.AllAccounts()
	pairs := make(map[string]btcutil.Amount, len(accts))
	for _, a := range accts {
		bal, err := a.CalculateBalance(minconf)
		if err != nil {
			return nil, err
		}
		pairs[a.name] = bal
	}
	return pairs, nil
}

// ListAccountsF64 returns a map of account names to their current account
// balances.  The balances are calculated using minconf confirmations.
//
// The amounts are converted to float64 so this result may be marshaled
// as a JSON object for the listaccounts RPC.
func (am *AccountManager) ListAccountsF64(minconf int) (map[string]float64, error) {
	// Create and fill a map of account names and their balances.
	accts := am.AllAccounts()
	pairs := make(map[string]float64, len(accts))
	for _, a := range accts {
		bal, err := a.CalculateBalance(minconf)
		if err != nil {
			return nil, err
		}
		pairs[a.name] = bal.ToUnit(btcutil.AmountBTC)
	}
	return pairs, nil
}

// ListSinceBlock returns a slice of objects representing all transactions in
// the wallets since the given block.
// To be used for the listsinceblock command.
func (am *AccountManager) ListSinceBlock(since, curBlockHeight int32,
	minconf int) ([]btcjson.ListTransactionsResult, error) {

	// Create and fill a map of account names and their balances.
	txList := []btcjson.ListTransactionsResult{}
	for _, a := range am.AllAccounts() {
		txTmp, err := a.ListSinceBlock(since, curBlockHeight, minconf)
		if err != nil {
			return nil, err
		}
		txList = append(txList, txTmp...)
	}
	return txList, nil
}

// accountTx represents an account/transaction pair to be used by
// GetTransaction.
type accountTx struct {
	Account string
	Tx      *txstore.TxRecord
}

// GetTransaction returns an array of accountTx to fully represent the effect of
// a transaction on locally known wallets. If we know nothing about a
// transaction an empty array will be returned.
func (am *AccountManager) GetTransaction(txSha *btcwire.ShaHash) []accountTx {
	accumulatedTxen := []accountTx{}

	for _, a := range am.AllAccounts() {
		for _, record := range a.TxStore.Records() {
			if *record.Tx().Sha() != *txSha {
				continue
			}

			atx := accountTx{
				Account: a.name,
				Tx:      record,
			}
			accumulatedTxen = append(accumulatedTxen, atx)
		}
	}

	return accumulatedTxen
}

// ListUnspent returns a slice of objects representing the unspent wallet
// transactions fitting the given criteria. The confirmations will be more than
// minconf, less than maxconf and if addresses is populated only the addresses
// contained within it will be considered.  If we know nothing about a
// transaction an empty array will be returned.
func (am *AccountManager) ListUnspent(minconf, maxconf int,
	addresses map[string]bool) ([]*btcjson.ListUnspentResult, error) {

	results := []*btcjson.ListUnspentResult{}

	rpcc, err := accessClient()
	if err != nil {
		return results, err
	}
	bs, err := rpcc.BlockStamp()
	if err != nil {
		return results, err
	}

	filter := len(addresses) != 0

	for _, a := range am.AllAccounts() {
		unspent, err := a.TxStore.SortedUnspentOutputs()
		if err != nil {
			return nil, err
		}

		for _, credit := range unspent {
			confs := credit.Confirmations(bs.Height)
			if int(confs) < minconf || int(confs) > maxconf {
				continue
			}
			if credit.IsCoinbase() {
				if !credit.Confirmed(btcchain.CoinbaseMaturity, bs.Height) {
					continue
				}
			}
			if a.LockedOutpoint(*credit.OutPoint()) {
				continue
			}

			_, addrs, _, _ := credit.Addresses(activeNet.Params)
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
				Account:       a.Name(),
				ScriptPubKey:  hex.EncodeToString(credit.TxOut().PkScript),
				Amount:        credit.Amount().ToUnit(btcutil.AmountBTC),
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
	}

	return results, nil
}

// RescanActiveAddresses begins a rescan for all active addresses for
// each account.  If markBestBlock is non-nil, the block described by
// the blockstamp is used to mark the synced-with height of the wallet
// just before the rescan is submitted and started.  This allows the
// caller to mark the progress that the rescan is expected to complete
// through, if the account otherwise does not contain any recently
// seen blocks.
func (am *AccountManager) RescanActiveAddresses(markBestBlock *wallet.BlockStamp) error {
	var job *RescanJob
	var defaultAcct *Account
	for _, a := range am.AllAccounts() {
		acctJob, err := a.RescanActiveJob()
		if err != nil {
			return err
		}
		if job == nil {
			job = acctJob
		} else {
			job.Merge(acctJob)
		}

		if a.name == "" {
			defaultAcct = a
		}
	}
	if job != nil {
		if markBestBlock != nil {
			defaultAcct.SetSyncedWith(markBestBlock)
		}

		// Submit merged job and block until rescan completes.
		jobFinished := am.rm.SubmitJob(job)
		<-jobFinished
	}

	return nil
}

func (am *AccountManager) ResendUnminedTxs() {
	for _, a := range am.AllAccounts() {
		a.ResendUnminedTxs()
	}
}

// Track begins tracking all addresses in all accounts for updates from
// btcd.
func (am *AccountManager) Track() {
	for _, a := range am.AllAccounts() {
		a.Track()
	}
}
