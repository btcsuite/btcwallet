/*
 * Copyright (c) 2013 Conformal Systems LLC <info@conformal.com>
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
	"errors"
	"fmt"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"os"
	"path/filepath"
	"sync"
)

// Errors relating to accounts.
var (
	ErrAcctExists   = errors.New("account already exists")
	ErrAcctNotExist = errors.New("account does not exist")
)

var accountstore = NewAccountStore()

// AccountStore stores all wallets currently being handled by
// btcwallet.  Wallet are stored in a map with the account name as the
// key.  A RWMutex is used to protect against incorrect concurrent
// access.
type AccountStore struct {
	sync.Mutex
	accounts map[string]*Account
}

// NewAccountStore returns an initialized and empty AccountStore.
func NewAccountStore() *AccountStore {
	return &AccountStore{
		accounts: make(map[string]*Account),
	}
}

// Account returns the account specified by name, or ErrAcctNotExist
// as an error if the account is not found.
func (store *AccountStore) Account(name string) (*Account, error) {
	store.Lock()
	defer store.Unlock()

	account, ok := store.accounts[name]
	if !ok {
		return nil, ErrAcctNotExist
	}
	return account, nil
}

// Rollback rolls back each Account saved in the store.
//
// TODO(jrick): This must also roll back the UTXO and TX stores, and notify
// all wallets of new account balances.
func (store *AccountStore) Rollback(height int32, hash *btcwire.ShaHash) {
	store.Lock()
	defer store.Unlock()

	for _, account := range store.accounts {
		account.Rollback(height, hash)
	}
}

// BlockNotify runs after btcwallet is notified of a new block connected to
// the best chain.  It notifies all frontends of any changes from the new
// block, including changed balances.  Each account is then set to be synced
// with the latest block.
func (store *AccountStore) BlockNotify(bs *wallet.BlockStamp) {
	store.Lock()
	defer store.Unlock()

	for _, a := range store.accounts {
		// The UTXO store will be dirty if it was modified
		// from a tx notification.
		if a.UtxoStore.dirty {
			// Notify all frontends of account's new unconfirmed
			// and confirmed balance.
			confirmed := a.CalculateBalance(1)
			unconfirmed := a.CalculateBalance(0) - confirmed
			NotifyWalletBalance(frontendNotificationMaster,
				a.name, confirmed)
			NotifyWalletBalanceUnconfirmed(frontendNotificationMaster,
				a.name, unconfirmed)
		}

		// The account is intentionaly not immediately synced to disk.
		// If btcd is performing an IBD, writing the wallet file for
		// each newly-connected block would result in too many
		// unnecessary disk writes.  The UTXO and transaction stores
		// could be written, but in the case of btcwallet closing
		// before writing the dirty wallet, both would have to be
		// pruned anyways.
		//
		// Instead, the wallet is queued to be written to disk at the
		// next scheduled disk sync.
		a.mtx.Lock()
		a.Wallet.SetSyncedWith(bs)
		a.dirty = true
		a.mtx.Unlock()
		dirtyAccounts.Lock()
		dirtyAccounts.m[a] = true
		dirtyAccounts.Unlock()
	}
}

// RecordMinedTx searches through each account's TxStore, searching for a
// sent transaction with the same txid as from a txmined notification.  If
// the transaction IDs match, the record in the TxStore is updated with
// the full information about the newly-mined tx, and the TxStore is
// marked as dirty.
func (store *AccountStore) RecordMinedTx(txid *btcwire.ShaHash,
	blkhash *btcwire.ShaHash, blkheight int32, blkindex int,
	blktime int64) error {

	store.Lock()
	defer store.Unlock()

	for _, account := range store.accounts {
		account.TxStore.Lock()

		// Search in reverse order.  Since more recently-created
		// transactions are appended to the end of the store, it's
		// more likely to find it when searching from the end.
		for i := len(account.TxStore.s) - 1; i >= 0; i-- {
			sendtx, ok := account.TxStore.s[i].(*tx.SendTx)
			if ok {
				if bytes.Equal(txid.Bytes(), sendtx.TxID[:]) {
					copy(sendtx.BlockHash[:], blkhash.Bytes())
					sendtx.BlockHeight = blkheight
					sendtx.BlockIndex = int32(blkindex)
					sendtx.BlockTime = blktime
					account.TxStore.dirty = true
					account.TxStore.Unlock()
					return nil
				}
			}
		}

		account.TxStore.Unlock()
	}

	return errors.New("txid does not match any recorded sent transaction")
}

// CalculateBalance returns the balance, calculated using minconf
// block confirmations, of an account.
func (store *AccountStore) CalculateBalance(account string,
	minconf int) (float64, error) {

	a, err := store.Account(account)
	if err != nil {
		return 0, err
	}

	return a.CalculateBalance(minconf), nil
}

// CreateEncryptedWallet creates a new account with a wallet file
// encrypted with passphrase.
//
// TODO(jrick): different passphrases on different accounts in the
// same wallet is a bad idea.  Switch this to use one passphrase for all
// account wallet files.
func (store *AccountStore) CreateEncryptedWallet(name, desc string, passphrase []byte) error {
	store.Lock()
	defer store.Unlock()

	_, ok := store.accounts[name]
	if ok {
		return ErrAcctExists
	}

	// Decide which Bitcoin network must be used.
	var net btcwire.BitcoinNet
	if cfg.MainNet {
		net = btcwire.MainNet
	} else {
		net = btcwire.TestNet3
	}

	// Get current block's height and hash.
	bs, err := GetCurBlock()
	if err != nil {
		return err
	}

	// Create new wallet in memory.
	wlt, err := wallet.NewWallet(name, desc, passphrase, net, &bs)
	if err != nil {
		return err
	}

	// Create new account with the wallet.  A new JSON ID is set for
	// transaction notifications.
	account := &Account{
		Wallet:           wlt,
		name:             name,
		dirty:            true,
		NewBlockTxJSONID: <-NewJSONID,
	}

	// Save the account in the global account map.  The mutex is
	// already held at this point, and will be unlocked when this
	// func returns.
	store.accounts[name] = account

	// Begin tracking account against a connected btcd.
	//
	// TODO(jrick): this should *only* happen if btcd is connected.
	account.Track()

	// Write new wallet to disk.
	if err := account.writeDirtyToDisk(); err != nil {
		log.Errorf("cannot sync dirty wallet: %v", err)
		return nil
	}

	return nil
}

// DumpKeys returns all WIF-encoded private keys associated with all
// accounts. All wallets must be unlocked for this operation to succeed.
func (store *AccountStore) DumpKeys() ([]string, error) {
	store.Lock()
	defer store.Unlock()

	var keys []string
	for _, a := range store.accounts {
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
func (store *AccountStore) DumpWIFPrivateKey(addr string) (string, error) {
	store.Lock()
	defer store.Unlock()

	for _, a := range store.accounts {
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
func (store *AccountStore) NotifyBalances(frontend chan []byte) {
	store.Lock()
	defer store.Unlock()

	for _, account := range store.accounts {
		balance := account.CalculateBalance(1)
		unconfirmed := account.CalculateBalance(0) - balance
		NotifyWalletBalance(frontend, account.name, balance)
		NotifyWalletBalanceUnconfirmed(frontend, account.name, unconfirmed)
	}
}

// ListAccounts returns a map of account names to their current account
// balances.  The balances are calculated using minconf confirmations.
func (store *AccountStore) ListAccounts(minconf int) map[string]float64 {
	store.Lock()
	defer store.Unlock()

	// Create and fill a map of account names and their balances.
	pairs := make(map[string]float64)
	for name, a := range store.accounts {
		pairs[name] = a.CalculateBalance(minconf)
	}
	return pairs
}

// RescanActiveAddresses begins a rescan for all active addresses for
// each account.
//
// TODO(jrick): batch addresses for all accounts together so multiple
// rescan commands can be avoided.
func (store *AccountStore) RescanActiveAddresses() {
	store.Lock()
	defer store.Unlock()

	for _, account := range store.accounts {
		account.RescanActiveAddresses()
	}
}

// Track begins tracking all addresses in all accounts for updates from
// btcd.
func (store *AccountStore) Track() {
	store.Lock()
	defer store.Unlock()

	for _, account := range store.accounts {
		account.Track()
	}
}

// OpenAccount opens an account described by account in the data
// directory specified by cfg.  If the wallet does not exist, ErrNoWallet
// is returned as an error.
//
// Wallets opened from this function are not set to track against a
// btcd connection.
func (store *AccountStore) OpenAccount(name string, cfg *config) error {
	store.Lock()
	defer store.Unlock()

	wlt := new(wallet.Wallet)

	account := &Account{
		Wallet: wlt,
		name:   name,
	}

	var finalErr error
	adir := account.accountdir(cfg)
	if err := account.checkCreateAccountDir(adir); err != nil {
		return err
	}

	wfilepath := filepath.Join(adir, "wallet.bin")
	utxofilepath := filepath.Join(adir, "utxo.bin")
	txfilepath := filepath.Join(adir, "tx.bin")
	var wfile, utxofile, txfile *os.File

	// Read wallet file.
	wfile, err := os.Open(wfilepath)
	if err != nil {
		if os.IsNotExist(err) {
			// Must create and save wallet first.
			return ErrNoWallet
		}
		return fmt.Errorf("cannot open wallet file: %s", err)
	}
	defer wfile.Close()

	if _, err = wlt.ReadFrom(wfile); err != nil {
		return fmt.Errorf("cannot read wallet: %s", err)
	}

	// Read tx file.  If this fails, return a ErrNoTxs error and let
	// the caller decide if a rescan is necessary.
	if txfile, err = os.Open(txfilepath); err != nil {
		log.Errorf("cannot open tx file: %s", err)
		// This is not a error we should immediately return with,
		// but other errors can be more important, so only return
		// this if none of the others are hit.
		finalErr = ErrNoTxs
	} else {
		defer txfile.Close()
		var txs tx.TxStore
		if _, err = txs.ReadFrom(txfile); err != nil {
			log.Errorf("cannot read tx file: %s", err)
			finalErr = ErrNoTxs
		} else {
			account.TxStore.s = txs
		}
	}

	// Read utxo file.  If this fails, return a ErrNoUtxos error so a
	// rescan can be done since the wallet creation block.
	var utxos tx.UtxoStore
	utxofile, err = os.Open(utxofilepath)
	if err != nil {
		log.Errorf("cannot open utxo file: %s", err)
		finalErr = ErrNoUtxos
	} else {
		defer utxofile.Close()
		if _, err = utxos.ReadFrom(utxofile); err != nil {
			log.Errorf("cannot read utxo file: %s", err)
			finalErr = ErrNoUtxos
		} else {
			account.UtxoStore.s = utxos
		}
	}

	switch finalErr {
	case ErrNoTxs:
		// Do nothing special for now.  This will be implemented when
		// the tx history file is properly written.
		store.accounts[name] = account

	case ErrNoUtxos:
		// Add wallet, but mark wallet as needing a full rescan since
		// the wallet creation block.  This will take place when btcd
		// connects.
		account.fullRescan = true
		store.accounts[name] = account
	case nil:
		store.accounts[name] = account

	default:
		log.Warnf("cannot open wallet: %v", err)
	}
	return nil
}

func (store *AccountStore) handleSendRawTxReply(frontend chan []byte, icmd btcjson.Cmd,
	result interface{}, e *btcjson.Error, a *Account,
	txInfo *CreatedTx) bool {

	store.Lock()
	defer store.Unlock()

	if e != nil {
		ReplyError(frontend, icmd.Id(), e)
		return true
	}

	txIDStr, ok := result.(string)
	if !ok {
		e := &btcjson.Error{
			Code:    btcjson.ErrInternal.Code,
			Message: "Unexpected type from btcd reply",
		}
		ReplyError(frontend, icmd.Id(), e)
		return true
	}
	txID, err := btcwire.NewShaHashFromStr(txIDStr)
	if err != nil {
		e := &btcjson.Error{
			Code:    btcjson.ErrInternal.Code,
			Message: "Invalid hash string from btcd reply",
		}
		ReplyError(frontend, icmd.Id(), e)
		return true
	}

	// Add to transaction store.
	sendtx := &tx.SendTx{
		TxID:        *txID,
		Time:        txInfo.time.Unix(),
		BlockHeight: -1,
		Fee:         txInfo.fee,
		Receivers:   txInfo.outputs,
	}
	a.TxStore.Lock()
	a.TxStore.s = append(a.TxStore.s, sendtx)
	a.TxStore.dirty = true
	a.TxStore.Unlock()

	// Remove previous unspent outputs now spent by the tx.
	a.UtxoStore.Lock()
	modified := a.UtxoStore.s.Remove(txInfo.inputs)
	a.UtxoStore.dirty = a.UtxoStore.dirty || modified

	// Add unconfirmed change utxo (if any) to UtxoStore.
	if txInfo.changeUtxo != nil {
		a.UtxoStore.s = append(a.UtxoStore.s, txInfo.changeUtxo)
		a.ReqSpentUtxoNtfn(txInfo.changeUtxo)
		a.UtxoStore.dirty = true
	}
	a.UtxoStore.Unlock()

	// Disk sync tx and utxo stores.
	if err := a.writeDirtyToDisk(); err != nil {
		log.Errorf("cannot sync dirty wallet: %v", err)
	}

	// Notify all frontends of account's new unconfirmed and
	// confirmed balance.
	confirmed := a.CalculateBalance(1)
	unconfirmed := a.CalculateBalance(0) - confirmed
	NotifyWalletBalance(frontendNotificationMaster, a.name, confirmed)
	NotifyWalletBalanceUnconfirmed(frontendNotificationMaster, a.name, unconfirmed)

	// btcd cannot be trusted to successfully relay the tx to the
	// Bitcoin network.  Even if this succeeds, the rawtx must be
	// saved and checked for an appearence in a later block. btcd
	// will make a best try effort, but ultimately it's btcwallet's
	// responsibility.
	//
	// Add hex string of raw tx to sent tx pool.  If btcd disconnects
	// and is reconnected, these txs are resent.
	UnminedTxs.Lock()
	UnminedTxs.m[TXID(*txID)] = txInfo
	UnminedTxs.Unlock()
	log.Infof("Successfully sent transaction %v", result)
	ReplySuccess(frontend, icmd.Id(), result)

	// The comments to be saved differ based on the underlying type
	// of the cmd, so switch on the type to check whether it is a
	// SendFromCmd or SendManyCmd.
	//
	// TODO(jrick): If message succeeded in being sent, save the
	// transaction details with comments.
	switch cmd := icmd.(type) {
	case *btcjson.SendFromCmd:
		_ = cmd.Comment
		_ = cmd.CommentTo

	case *btcjson.SendManyCmd:
		_ = cmd.Comment
	}

	return true
}
