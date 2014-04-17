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
	"github.com/conformal/btcjson"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"os"
	"strings"
)

// Errors relating to accounts.
var (
	ErrAccountExists = errors.New("account already exists")
	ErrWalletExists  = errors.New("wallet already exists")
	ErrNotFound      = errors.New("not found")
)

// AcctMgr is the global account manager for all opened accounts.
var AcctMgr = NewAccountManager()

type openAccountsCmd struct{}

type accessAccountRequest struct {
	name string
	resp chan *Account
}

type accessAllRequest struct {
	resp chan []*Account
}

type accessAccountByAddressRequest struct {
	address string
	resp    chan *Account
}

type markAddressForAccountCmd struct {
	address string
	account *Account
}

type addAccountCmd struct {
	a *Account
}

type removeAccountCmd struct {
	a *Account
}

// AccountManager manages a collection of accounts.
type AccountManager struct {
	// The accounts accessed through the account manager are not safe for
	// concurrent access.  The account manager therefore contains a
	// binary semaphore channel to prevent incorrect access.
	bsem       chan struct{}
	cmdChan    chan interface{}
	rescanMsgs chan RescanMsg

	ds *DiskSyncer
	rm *RescanManager
}

// NewAccountManager returns a new AccountManager.
func NewAccountManager() *AccountManager {
	am := &AccountManager{
		bsem:       make(chan struct{}, 1),
		cmdChan:    make(chan interface{}),
		rescanMsgs: make(chan RescanMsg, 1),
	}
	am.ds = NewDiskSyncer(am)
	am.rm = NewRescanManager(am.rescanMsgs)
	return am
}

// Start starts the goroutines required to run the AccountManager.
func (am *AccountManager) Start() {
	// Ready the semaphore - can't grab unless the manager has started.
	am.bsem <- struct{}{}

	go am.accountHandler()
	go am.rescanListener()
	go am.ds.Start()
	go am.rm.Start()
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

	// errNoTxs describes an error where the wallet and UTXO files were
	// successfully read, but the TX history file was not.  It is up to
	// the caller whether this necessitates a rescan or not.
	errNoTxs = errors.New("tx file cannot be read")
)

// openSavedAccount opens a named account from disk.  If the wallet does not
// exist, errNoWallet is returned as an error.
func openSavedAccount(name string, cfg *config) (*Account, error) {
	netdir := networkDir(cfg.Net())
	if err := checkCreateDir(netdir); err != nil {
		return nil, &walletOpenError{
			Err: err.Error(),
		}
	}

	wlt := new(wallet.Wallet)
	txs := tx.NewStore()
	a := &Account{
		name:    name,
		Wallet:  wlt,
		TxStore: txs,
	}

	wfilepath := accountFilename("wallet.bin", name, netdir)
	txfilepath := accountFilename("tx.bin", name, netdir)
	var wfile, txfile *os.File

	// Read wallet file.
	wfile, err := os.Open(wfilepath)
	if err != nil {
		if os.IsNotExist(err) {
			// Must create and save wallet first.
			return nil, errNoWallet
		}
		msg := fmt.Sprintf("cannot open wallet file: %s", err)
		return nil, &walletOpenError{msg}
	}
	defer wfile.Close()

	if _, err = wlt.ReadFrom(wfile); err != nil {
		msg := fmt.Sprintf("cannot read wallet: %s", err)
		return nil, &walletOpenError{msg}
	}

	// Read tx file.  If this fails, return a errNoTxs error and let
	// the caller decide if a rescan is necessary.
	var finalErr error
	if txfile, err = os.Open(txfilepath); err != nil {
		log.Errorf("cannot open tx file: %s", err)
		// This is not a error we should immediately return with,
		// but other errors can be more important, so only return
		// this if none of the others are hit.
		finalErr = errNoTxs
		a.fullRescan = true
	} else {
		defer txfile.Close()
		if _, err = txs.ReadFrom(txfile); err != nil {
			log.Errorf("cannot read tx file: %s", err)
			a.fullRescan = true
			finalErr = errNoTxs
		}
	}

	return a, finalErr
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
	netDir := networkDir(cfg.Net())
	tmpNetDir := tmpNetworkDir(cfg.Net())
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
		switch err.(type) {
		case *walletOpenError:
			log.Errorf("Default account wallet file unreadable: %v", err)
			return ad

		default:
			log.Warnf("Non-critical problem opening an account file: %v", err)
		}
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
	defer accountDir.Close()
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

	for c := range am.cmdChan {
		switch cmd := c.(type) {
		case *openAccountsCmd:
			// Write all old accounts before proceeding.
			for _, a := range ad.nameToAccount {
				am.ds.FlushAccount(a)
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
	}
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
				log.Errorf("Rescan failed: %v", e.Error.Message)
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
		}
		AcctMgr.Release()
	}
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
func (am *AccountManager) AccountByAddress(addr btcutil.Address) (*Account,
	error) {
	respChan := make(chan *Account)
	am.cmdChan <- &accessAccountByAddressRequest{
		address: addr.EncodeAddress(),
		resp:    respChan,
	}
	resp := <-respChan
	if resp == nil {
		return nil, ErrNotFound
	}
	return resp, nil
}

// MarkAddressForAccount labels the given account as containing the provided
// address.
func (am *AccountManager) MarkAddressForAccount(address btcutil.Address,
	account *Account) {
	// TODO(oga) really this entire dance should be carried out implicitly
	// instead of requiring explicit messaging from the account to the
	// manager.
	am.cmdChan <- &markAddressForAccountCmd{
		address: address.EncodeAddress(),
		account: account,
	}
}

// Address looks up an address if it is known to wallet at all.
func (am *AccountManager) Address(addr btcutil.Address) (wallet.WalletAddress,
	error) {
	a, err := am.AccountByAddress(addr)
	if err != nil {
		return nil, err
	}

	return a.Address(addr)
}

// AllAccounts returns a slice of all managed accounts.
func (am *AccountManager) AllAccounts() []*Account {
	respChan := make(chan []*Account)
	am.cmdChan <- &accessAllRequest{
		resp: respChan,
	}
	return <-respChan
}

// AddAccount adds an account to the collection managed by an AccountManager.
func (am *AccountManager) AddAccount(a *Account) {
	am.cmdChan <- &addAccountCmd{
		a: a,
	}
}

// RemoveAccount removes an account to the collection managed by an
// AccountManager.
func (am *AccountManager) RemoveAccount(a *Account) {
	am.cmdChan <- &removeAccountCmd{
		a: a,
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
func (am *AccountManager) Rollback(height int32, hash *btcwire.ShaHash) {
	log.Infof("Rolling back tx history since block height %v", height)

	for _, a := range am.AllAccounts() {
		a.TxStore.Rollback(height)
		am.ds.ScheduleTxStoreWrite(a)
	}
}

// BlockNotify notifies all frontends of any changes from the new block,
// including changed balances.  Each account is then set to be synced
// with the latest block.
func (am *AccountManager) BlockNotify(bs *wallet.BlockStamp) {
	for _, a := range am.AllAccounts() {
		// TODO: need a flag or check that the utxo store was actually
		// modified, or this will notify even if there are no balance
		// changes, or sending these notifications as the utxos are added.
		confirmed := a.CalculateBalance(1)
		unconfirmed := a.CalculateBalance(0) - confirmed
		NotifyWalletBalance(allClients, a.name, confirmed)
		NotifyWalletBalanceUnconfirmed(allClients, a.name,
			unconfirmed)

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
func (am *AccountManager) RecordSpendingTx(tx_ *btcutil.Tx, block *tx.Block) error {
	for _, a := range am.AllAccounts() {
		// TODO(jrick): This needs to iterate through each txout's
		// addresses and find whether this account's keystore contains
		// any of the addresses this tx sends to.
		txr, err := a.TxStore.InsertTx(tx_, block)
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
func (am *AccountManager) CalculateBalance(account string, minconf int) (float64, error) {
	a, err := am.Account(account)
	if err != nil {
		return 0, err
	}

	return a.CalculateBalance(minconf), nil
}

// CreateEncryptedWallet creates a new default account with a wallet file
// encrypted with passphrase.
func (am *AccountManager) CreateEncryptedWallet(passphrase []byte) error {
	if len(am.AllAccounts()) != 0 {
		return ErrWalletExists
	}

	// Get current block's height and hash.
	bs, err := GetCurBlock()
	if err != nil {
		return err
	}

	// Create new wallet in memory.
	wlt, err := wallet.NewWallet("", "Default acccount", passphrase,
		cfg.Net(), &bs, cfg.KeypoolSize)
	if err != nil {
		return err
	}

	// Create new account and begin managing with the global account
	// manager.  Registering will fail if the new account can not be
	// written immediately to disk.
	a := &Account{
		Wallet:  wlt,
		TxStore: tx.NewStore(),
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
	accts := am.AllAccounts()

	for _, a := range accts {
		if locked := a.Wallet.IsLocked(); !locked {
			if err := a.Wallet.Lock(); err != nil {
				return err
			}
		}

		if err := a.Wallet.Unlock(old); err != nil {
			return err
		}
		defer a.Wallet.Lock()
	}

	// Change passphrase for each unlocked wallet.
	for _, a := range accts {
		if err := a.Wallet.ChangePassphrase(new); err != nil {
			return err
		}
	}

	// Immediately write out to disk.
	return am.ds.WriteBatch(accts)
}

// LockWallets locks all managed account wallets.
func (am *AccountManager) LockWallets() error {
	for _, a := range am.AllAccounts() {
		if err := a.Lock(); err != nil {
			return err
		}
	}

	return nil
}

// UnlockWallets unlocks all managed account's wallets.  If any wallet unlocks
// fail, all successfully unlocked wallets are locked again.
func (am *AccountManager) UnlockWallets(passphrase string) error {
	accts := am.AllAccounts()
	unlockedAccts := make([]*Account, 0, len(accts))

	for _, a := range accts {
		if err := a.Unlock([]byte(passphrase)); err != nil {
			for _, ua := range unlockedAccts {
				ua.Lock()
			}
			return fmt.Errorf("cannot unlock account %v: %v",
				a.name, err)
		}
		unlockedAccts = append(unlockedAccts, a)
	}

	return nil
}

// DumpKeys returns all WIF-encoded private keys associated with all
// accounts. All wallets must be unlocked for this operation to succeed.
func (am *AccountManager) DumpKeys() ([]string, error) {
	var keys []string
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

// NotifyBalances notifies a wallet frontend of all confirmed and unconfirmed
// account balances.
func (am *AccountManager) NotifyBalances(frontend chan []byte) {
	for _, a := range am.AllAccounts() {
		balance := a.CalculateBalance(1)
		unconfirmed := a.CalculateBalance(0) - balance
		NotifyWalletBalance(frontend, a.name, balance)
		NotifyWalletBalanceUnconfirmed(frontend, a.name, unconfirmed)
	}
}

// ListAccounts returns a map of account names to their current account
// balances.  The balances are calculated using minconf confirmations.
func (am *AccountManager) ListAccounts(minconf int) map[string]float64 {
	// Create and fill a map of account names and their balances.
	pairs := make(map[string]float64)
	for _, a := range am.AllAccounts() {
		pairs[a.name] = a.CalculateBalance(minconf)
	}
	return pairs
}

// ListSinceBlock returns a slice of objects representing all transactions in
// the wallets since the given block.
// To be used for the listsinceblock command.
func (am *AccountManager) ListSinceBlock(since, curBlockHeight int32,
	minconf int) ([]btcjson.ListTransactionsResult, error) {

	// Create and fill a map of account names and their balances.
	var txList []btcjson.ListTransactionsResult
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
	Tx      *tx.TxRecord
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
	addresses map[string]bool) ([]*btcjson.ListUnSpentResult, error) {

	bs, err := GetCurBlock()
	if err != nil {
		return nil, err
	}

	filter := len(addresses) != 0

	var results []*btcjson.ListUnSpentResult
	for _, a := range am.AllAccounts() {
		unspent, err := a.TxStore.UnspentOutputs()
		if err != nil {
			return nil, err
		}
		for _, credit := range unspent {
			confs := credit.Confirmations(bs.Height)
			if int(confs) < minconf || int(confs) > maxconf {
				continue
			}

			_, addrs, _, _ := credit.Addresses(cfg.Net())
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
			result := &btcjson.ListUnSpentResult{
				TxId:          credit.Tx().Sha().String(),
				Vout:          float64(credit.OutputIndex),
				Account:       a.Name(),
				ScriptPubKey:  hex.EncodeToString(credit.TxOut().PkScript),
				Amount:        credit.Amount().ToUnit(btcutil.AmountBTC),
				Confirmations: float64(confs),
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
// each account.
func (am *AccountManager) RescanActiveAddresses() error {
	var job *RescanJob
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
	}
	if job != nil {
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
