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
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
)

// Errors relating to accounts.
var (
	ErrAccountExists = errors.New("account already exists")
	ErrWalletExists  = errors.New("wallet already exists")
	ErrNotFound      = errors.New("not found")
)

// AcctMgr is the global account manager for all opened accounts.
var AcctMgr = NewAccountManager()

// AccountManager manages a collection of accounts.
type AccountManager struct {
	// The accounts accessed through the account manager are not safe for
	// concurrent access.  The account manager therefore contains a
	// binary semaphore channel to prevent incorrect access.
	bsem chan struct{}

	accessAccount chan *accessAccountRequest
	accessAll     chan *accessAllRequest
	add           chan *Account
	remove        chan *Account

	ds *DiskSyncer // might move to inside Start
}

// NewAccountManager returns a new AccountManager.
func NewAccountManager() *AccountManager {
	am := &AccountManager{
		bsem:          make(chan struct{}, 1),
		accessAccount: make(chan *accessAccountRequest),
		accessAll:     make(chan *accessAllRequest),
		add:           make(chan *Account),
		remove:        make(chan *Account),
	}
	am.ds = NewDiskSyncer(am)
	return am
}

// Start maintains accounts and structures for quick lookups for account
// information.  Access to these structures must be done through with the
// channels in the AccountManger struct fields.  This function never returns
// and should be called as a new goroutine.
func (am *AccountManager) Start() {
	// Ready the semaphore - can't grab unless the manager has started.
	am.bsem <- struct{}{}

	// Start the account manager's disk syncer.
	go am.ds.Start()

	// List and map of all accounts.
	l := list.New()
	m := make(map[string]*Account)

	for {
		select {
		case access := <-am.accessAccount:
			a, ok := m[access.name]
			access.resp <- &accessAccountResponse{
				a:  a,
				ok: ok,
			}

		case access := <-am.accessAll:
			s := make([]*Account, 0, l.Len())
			for e := l.Front(); e != nil; e = e.Next() {
				s = append(s, e.Value.(*Account))
			}
			access.resp <- s

		case a := <-am.add:
			if _, ok := m[a.name]; ok {
				break
			}
			m[a.name] = a
			l.PushBack(a)

		case a := <-am.remove:
			if _, ok := m[a.name]; ok {
				delete(m, a.name)
				for e := l.Front(); e != nil; e = e.Next() {
					v := e.Value.(*Account)
					if v == a {
						l.Remove(e)
						break
					}
				}
			}
		}
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

type accessAccountRequest struct {
	name string
	resp chan *accessAccountResponse
}

type accessAccountResponse struct {
	a  *Account
	ok bool
}

// Account returns the account specified by name, or ErrNotFound
// as an error if the account is not found.
func (am *AccountManager) Account(name string) (*Account, error) {
	req := &accessAccountRequest{
		name: name,
		resp: make(chan *accessAccountResponse),
	}
	am.accessAccount <- req
	resp := <-req.resp
	if !resp.ok {
		return nil, ErrNotFound
	}
	return resp.a, nil
}

type accessAllRequest struct {
	resp chan []*Account
}

// AllAccounts returns a slice of all managed accounts.
func (am *AccountManager) AllAccounts() []*Account {
	req := &accessAllRequest{
		resp: make(chan []*Account),
	}
	am.accessAll <- req
	return <-req.resp
}

// AddAccount adds an account to the collection managed by an AccountManager.
func (am *AccountManager) AddAccount(a *Account) {
	am.add <- a
}

// RemoveAccount removes an account to the collection managed by an
// AccountManager.
func (am *AccountManager) RemoveAccount(a *Account) {
	am.remove <- a
}

// RegisterNewAccount adds a new memory account to the account manager,
// and immediately writes the account to disk.
func (am *AccountManager) RegisterNewAccount(a *Account) error {
	am.AddAccount(a)

	// Ensure that the new account is written out to disk.
	am.ds.ScheduleWalletWrite(a)
	am.ds.ScheduleTxStoreWrite(a)
	am.ds.ScheduleUtxoStoreWrite(a)
	if err := am.ds.FlushAccount(a); err != nil {
		am.RemoveAccount(a)
		return err
	}
	return nil
}

// Rollback rolls back each managed Account to the state before the block
// specified by height and hash was connected to the main chain.
func (am *AccountManager) Rollback(height int32, hash *btcwire.ShaHash) {
	log.Debugf("Rolling back tx history since block height %v hash %v",
		height, hash)

	for _, a := range am.AllAccounts() {
		if a.UtxoStore.Rollback(height, hash) {
			am.ds.ScheduleUtxoStoreWrite(a)
		}

		if a.TxStore.Rollback(height, hash) {
			am.ds.ScheduleTxStoreWrite(a)
		}
	}
}

// Rollback reverts each stored Account to a state before the block
// with the passed chainheight and block hash was connected to the main
// chain.  This is used to remove transactions and utxos for each wallet
// that occured on a chain no longer considered to be the main chain.
func (a *Account) Rollback(height int32, hash *btcwire.ShaHash) {
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
		NotifyWalletBalance(frontendNotificationMaster, a.name, confirmed)
		NotifyWalletBalanceUnconfirmed(frontendNotificationMaster, a.name,
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
func (am *AccountManager) RecordMinedTx(txid *btcwire.ShaHash,
	blkhash *btcwire.ShaHash, blkheight int32, blkindex int,
	blktime int64) error {

	for _, a := range am.AllAccounts() {
		// Search in reverse order.  Since more recently-created
		// transactions are appended to the end of the store, it's
		// more likely to find it when searching from the end.
		for i := len(a.TxStore) - 1; i >= 0; i-- {
			sendtx, ok := a.TxStore[i].(*tx.SendTx)
			if ok {
				if bytes.Equal(txid.Bytes(), sendtx.TxID[:]) {
					copy(sendtx.BlockHash[:], blkhash.Bytes())
					sendtx.BlockHeight = blkheight
					sendtx.BlockIndex = int32(blkindex)
					sendtx.BlockTime = blktime

					am.ds.ScheduleTxStoreWrite(a)

					return nil
				}
			}
		}
	}

	return errors.New("txid does not match any recorded sent transaction")
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
		Wallet: wlt,
	}
	if err := am.RegisterNewAccount(a); err != nil {
		return err
	}

	// Mark all active payment addresses as belonging to this account.
	//
	// TODO(jrick) move this to the account manager
	for addr := range a.ActivePaymentAddresses() {
		MarkAddressForAccount(addr, "")
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
	for _, a := range am.AllAccounts() {
		switch wif, err := a.DumpWIFPrivateKey(addr); err {
		case wallet.ErrAddressNotFound:
			// Move on to the next account.
			continue

		case nil:
			return wif, nil

		default: // all other non-nil errors
			return "", err
		}
	}

	return "", errors.New("address does not refer to a key")
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

// ListSinceBlock returns a slice of maps of strings to interface containing
// structures defining all transactions in the wallets since the given block.
// To be used for the listsinceblock command.
func (am *AccountManager) ListSinceBlock(since, curBlockHeight int32, minconf int) ([]map[string]interface{}, error) {
	// Create and fill a map of account names and their balances.
	txInfoList := []map[string]interface{}{}
	for _, a := range am.AllAccounts() {
		txTmp, err := a.ListSinceBlock(since, curBlockHeight, minconf)
		if err != nil {
			return nil, err
		}
		txInfoList = append(txInfoList, txTmp...)
	}
	return txInfoList, nil
}

// accountTx represents an account/transaction pair to be used by
// GetTransaction().
type accountTx struct {
	Account string
	Tx      tx.Tx
}

// GetTransaction returns an array of accountTx to fully represent the effect of
// a transaction on locally known wallets. If we know nothing about a
// transaction an empty array will be returned.
func (am *AccountManager) GetTransaction(txid string) []accountTx {
	accumulatedTxen := []accountTx{}

	for _, a := range am.AllAccounts() {
		for _, t := range a.TxStore {
			if t.GetTxID().String() != txid {
				continue
			}
			accumulatedTxen = append(accumulatedTxen,
				accountTx{
					Account: a.name,
					Tx:      t.Copy(),
				})
		}
	}

	return accumulatedTxen
}

// ListUnspent returns an array of objects representing the unspent
// wallet transactions fitting the given criteria. The confirmations will be
// more then minconf, less than maxconf and if addresses is populated only the
// addresses contained within it will be considered.
// a transaction on locally known wallets. If we know nothing about a
// transaction an empty array will be returned.
func (am *AccountManager) ListUnspent(minconf, maxconf int,
	addresses map[string]bool) ([]map[string]interface{}, error) {
	bs, err := GetCurBlock()
	if err != nil {
		return nil, err
	}

	replies := []map[string]interface{}{}
	for _, a := range am.AllAccounts() {
		for _, u := range a.UtxoStore {
			confirmations := 0
			if u.Height != -1 {
				confirmations = int(bs.Height - u.Height + 1)
			}
			if minconf != 0 && (u.Height == -1 ||
				confirmations < minconf) {
				continue
			}
			// check maxconf - doesn't apply if not confirmed.
			if u.Height != -1 && confirmations > maxconf {
				continue
			}

			addr, err := btcutil.NewAddressPubKeyHash(u.AddrHash[:],
				cfg.Net())
			if err != nil {
				continue
			}

			// if we hve addresses, limit to that list.
			if len(addresses) > 0 {
				if _, ok := addresses[addr.EncodeAddress()]; !ok {
					continue
				}
			}
			entry := map[string]interface{}{
				// check minconf/maxconf
				"txid":          u.Out.Hash.String(),
				"vout":          u.Out.Index,
				"address":       addr.EncodeAddress(),
				"account":       a.name,
				"scriptPubKey":  u.Subscript,
				"amount":        float64(u.Amt) / float64(btcutil.SatoshiPerBitcoin),
				"confirmations": confirmations,
				// TODO(oga) if the object is
				// pay-to-script-hash we need to add the
				// redeemscript.
			}

			replies = append(replies, entry)
		}

	}
	return replies, nil
}

// RescanActiveAddresses begins a rescan for all active addresses for
// each account.
//
// TODO(jrick): batch addresses for all accounts together so multiple
// rescan commands can be avoided.
func (am *AccountManager) RescanActiveAddresses() {
	for _, account := range am.AllAccounts() {
		account.RescanActiveAddresses()
	}
}

// Track begins tracking all addresses in all accounts for updates from
// btcd.
func (am *AccountManager) Track() {
	for _, a := range am.AllAccounts() {
		a.Track()
	}
}
