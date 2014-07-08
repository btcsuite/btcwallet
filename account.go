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
	"encoding/base64"
	"fmt"
	"path/filepath"

	"github.com/conformal/btcjson"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/keystore"
	"github.com/conformal/btcwallet/txstore"
	"github.com/conformal/btcwire"
)

// Account is a structure containing all the components for a
// complete wallet.  It contains the Armory-style wallet (to store
// addresses and keys), and tx and utxo stores, and a mutex to prevent
// incorrect multiple access.
type Account struct {
	name            string
	KeyStore        *keystore.Store
	TxStore         *txstore.Store
	lockedOutpoints map[btcwire.OutPoint]struct{}
	FeeIncrement    btcutil.Amount
}

func newAccount(name string, keys *keystore.Store, txs *txstore.Store) *Account {
	return &Account{
		name:            name,
		KeyStore:        keys,
		TxStore:         txs,
		lockedOutpoints: map[btcwire.OutPoint]struct{}{},
		FeeIncrement:    defaultFeeIncrement,
	}
}

// Lock locks the underlying wallet for an account.
func (a *Account) Lock() error {
	switch err := a.KeyStore.Lock(); err {
	case nil:
		server.NotifyWalletLockStateChange(a.KeyStore.Name(), true)
		return nil

	case keystore.ErrLocked:
		// Do not pass wallet already locked errors to the caller.
		return nil

	default:
		return err
	}
}

// Unlock unlocks the underlying wallet for an account.
func (a *Account) Unlock(passphrase []byte) error {
	if err := a.KeyStore.Unlock(passphrase); err != nil {
		return err
	}

	server.NotifyWalletLockStateChange(a.KeyStore.Name(), false)
	return nil
}

// AddressUsed returns whether there are any recorded transactions spending to
// a given address.  Assumming correct TxStore usage, this will return true iff
// there are any transactions with outputs to this address in the blockchain or
// the btcd mempool.
func (a *Account) AddressUsed(addr btcutil.Address) bool {
	// This not only can be optimized by recording this data as it is
	// read when opening an account, and keeping it up to date each time a
	// new received tx arrives, but it probably should in case an address is
	// used in a tx (made public) but the tx is eventually removed from the
	// store (consider a chain reorg).

	pkHash := addr.ScriptAddress()

	for _, r := range a.TxStore.Records() {
		credits := r.Credits()
		for _, c := range credits {
			// Errors don't matter here.  If addrs is nil, the
			// range below does nothing.
			_, addrs, _, _ := c.Addresses(activeNet.Params)
			for _, a := range addrs {
				if bytes.Equal(a.ScriptAddress(), pkHash) {
					return true
				}
			}
		}
	}
	return false
}

// CalculateBalance sums the amounts of all unspent transaction
// outputs to addresses of a wallet and returns the balance as a
// float64.
//
// If confirmations is 0, all UTXOs, even those not present in a
// block (height -1), will be used to get the balance.  Otherwise,
// a UTXO must be in a block.  If confirmations is 1 or greater,
// the balance will be calculated based on how many how many blocks
// include a UTXO.
func (a *Account) CalculateBalance(confirms int) (btcutil.Amount, error) {
	rpcc, err := accessClient()
	if err != nil {
		return 0, err
	}
	bs, err := rpcc.BlockStamp()
	if err != nil {
		return 0, err
	}

	return a.TxStore.Balance(confirms, bs.Height)
}

// CalculateAddressBalance sums the amounts of all unspent transaction
// outputs to a single address's pubkey hash and returns the balance
// as a float64.
//
// If confirmations is 0, all UTXOs, even those not present in a
// block (height -1), will be used to get the balance.  Otherwise,
// a UTXO must be in a block.  If confirmations is 1 or greater,
// the balance will be calculated based on how many how many blocks
// include a UTXO.
func (a *Account) CalculateAddressBalance(addr btcutil.Address, confirms int) (btcutil.Amount, error) {
	rpcc, err := accessClient()
	if err != nil {
		return 0, err
	}
	bs, err := rpcc.BlockStamp()
	if err != nil {
		return 0, err
	}

	var bal btcutil.Amount
	unspent, err := a.TxStore.UnspentOutputs()
	if err != nil {
		return 0, err
	}
	for _, credit := range unspent {
		if credit.Confirmed(confirms, bs.Height) {
			// We only care about the case where len(addrs) == 1, and err
			// will never be non-nil in that case
			_, addrs, _, _ := credit.Addresses(activeNet.Params)
			if len(addrs) != 1 {
				continue
			}
			if addrs[0].EncodeAddress() == addr.EncodeAddress() {
				bal += credit.Amount()
			}
		}
	}
	return bal, nil
}

// CurrentAddress gets the most recently requested Bitcoin payment address
// from an account.  If the address has already been used (there is at least
// one transaction spending to it in the blockchain or btcd mempool), the next
// chained address is returned.
func (a *Account) CurrentAddress() (btcutil.Address, error) {
	addr := a.KeyStore.LastChainedAddress()

	// Get next chained address if the last one has already been used.
	if a.AddressUsed(addr) {
		return a.NewAddress()
	}

	return addr, nil
}

// ListSinceBlock returns a slice of objects with details about transactions
// since the given block. If the block is -1 then all transactions are included.
// This is intended to be used for listsinceblock RPC replies.
func (a *Account) ListSinceBlock(since, curBlockHeight int32,
	minconf int) ([]btcjson.ListTransactionsResult, error) {

	txList := []btcjson.ListTransactionsResult{}
	for _, txRecord := range a.TxStore.Records() {
		// Transaction records must only be considered if they occur
		// after the block height since.
		if since != -1 && txRecord.BlockHeight <= since {
			continue
		}

		// Transactions that have not met minconf confirmations are to
		// be ignored.
		if !txRecord.Confirmed(minconf, curBlockHeight) {
			continue
		}

		jsonResults, err := txRecord.ToJSON(a.name, curBlockHeight,
			a.KeyStore.Net())
		if err != nil {
			return nil, err
		}
		txList = append(txList, jsonResults...)
	}

	return txList, nil
}

// ListTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listtransactions RPC
// replies.
func (a *Account) ListTransactions(from, count int) ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	rpcc, err := accessClient()
	if err != nil {
		return txList, err
	}
	bs, err := rpcc.BlockStamp()
	if err != nil {
		return txList, err
	}

	records := a.TxStore.Records()
	lastLookupIdx := len(records) - count
	// Search in reverse order: lookup most recently-added first.
	for i := len(records) - 1; i >= from && i >= lastLookupIdx; i-- {
		jsonResults, err := records[i].ToJSON(a.name, bs.Height,
			a.KeyStore.Net())
		if err != nil {
			return nil, err
		}
		txList = append(txList, jsonResults...)
	}

	return txList, nil
}

// ListAddressTransactions returns a slice of objects with details about
// recorded transactions to or from any address belonging to a set.  This is
// intended to be used for listaddresstransactions RPC replies.
func (a *Account) ListAddressTransactions(pkHashes map[string]struct{}) (
	[]btcjson.ListTransactionsResult, error) {

	txList := []btcjson.ListTransactionsResult{}

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	rpcc, err := accessClient()
	if err != nil {
		return txList, err
	}
	bs, err := rpcc.BlockStamp()
	if err != nil {
		return txList, err
	}

	for _, r := range a.TxStore.Records() {
		for _, c := range r.Credits() {
			// We only care about the case where len(addrs) == 1,
			// and err will never be non-nil in that case.
			_, addrs, _, _ := c.Addresses(activeNet.Params)
			if len(addrs) != 1 {
				continue
			}
			apkh, ok := addrs[0].(*btcutil.AddressPubKeyHash)
			if !ok {
				continue
			}

			if _, ok := pkHashes[string(apkh.ScriptAddress())]; !ok {
				continue
			}
			jsonResult, err := c.ToJSON(a.name, bs.Height,
				a.KeyStore.Net())
			if err != nil {
				return nil, err
			}
			txList = append(txList, jsonResult)
		}
	}

	return txList, nil
}

// ListAllTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listalltransactions RPC
// replies.
func (a *Account) ListAllTransactions() ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	rpcc, err := accessClient()
	if err != nil {
		return txList, err
	}
	bs, err := rpcc.BlockStamp()
	if err != nil {
		return txList, err
	}

	// Search in reverse order: lookup most recently-added first.
	records := a.TxStore.Records()
	for i := len(records) - 1; i >= 0; i-- {
		jsonResults, err := records[i].ToJSON(a.name, bs.Height,
			a.KeyStore.Net())
		if err != nil {
			return nil, err
		}
		txList = append(txList, jsonResults...)
	}

	return txList, nil
}

// DumpPrivKeys returns the WIF-encoded private keys for all addresses with
// private keys in a wallet.
func (a *Account) DumpPrivKeys() ([]string, error) {
	// Iterate over each active address, appending the private
	// key to privkeys.
	privkeys := []string{}
	for _, info := range a.KeyStore.ActiveAddresses() {
		// Only those addresses with keys needed.
		pka, ok := info.(keystore.PubKeyAddress)
		if !ok {
			continue
		}
		wif, err := pka.ExportPrivKey()
		if err != nil {
			// It would be nice to zero out the array here. However,
			// since strings in go are immutable, and we have no
			// control over the caller I don't think we can. :(
			return nil, err
		}
		privkeys = append(privkeys, wif.String())
	}

	return privkeys, nil
}

// DumpWIFPrivateKey returns the WIF encoded private key for a
// single wallet address.
func (a *Account) DumpWIFPrivateKey(addr btcutil.Address) (string, error) {
	// Get private key from wallet if it exists.
	address, err := a.KeyStore.Address(addr)
	if err != nil {
		return "", err
	}

	pka, ok := address.(keystore.PubKeyAddress)
	if !ok {
		return "", fmt.Errorf("address %s is not a key type", addr)
	}

	wif, err := pka.ExportPrivKey()
	if err != nil {
		return "", err
	}
	return wif.String(), nil
}

// ImportPrivateKey imports a private key to the account's wallet and
// writes the new wallet to disk.
func (a *Account) ImportPrivateKey(wif *btcutil.WIF, bs *keystore.BlockStamp,
	rescan bool) (string, error) {

	// Attempt to import private key into wallet.
	addr, err := a.KeyStore.ImportPrivateKey(wif, bs)
	if err != nil {
		return "", err
	}

	// Immediately write wallet to disk.
	AcctMgr.ds.ScheduleWalletWrite(a)
	if err := AcctMgr.ds.FlushAccount(a); err != nil {
		return "", fmt.Errorf("cannot write account: %v", err)
	}

	addrStr := addr.EncodeAddress()

	// Rescan blockchain for transactions with txout scripts paying to the
	// imported address.
	if rescan {
		addrs := []btcutil.Address{addr}
		job := &RescanJob{
			Addresses:   map[*Account][]btcutil.Address{a: addrs},
			OutPoints:   nil,
			StartHeight: 0,
		}

		// Submit rescan job and log when the import has completed.
		// Do not block on finishing the rescan.
		doneChan := AcctMgr.rm.SubmitJob(job)
		go func() {
			<-doneChan
			log.Infof("Finished import for address %s", addrStr)
		}()
	}

	// Associate the imported address with this account.
	AcctMgr.MarkAddressForAccount(addr, a)

	log.Infof("Imported payment address %s", addrStr)

	// Return the payment address string of the imported private key.
	return addrStr, nil
}

// ExportToDirectory writes an account to a special export directory.  Any
// previous files are overwritten.
func (a *Account) ExportToDirectory(dirBaseName string) error {
	dir := filepath.Join(networkDir(activeNet.Params), dirBaseName)
	if err := checkCreateDir(dir); err != nil {
		return err
	}

	return AcctMgr.ds.ExportAccount(a, dir)
}

// ExportWatchingWallet returns a new account with a watching wallet
// exported by this a's wallet.  Both wallets share the same tx and utxo
// stores, so locking one will lock the other as well.  The returned account
// should be exported quickly, either to file or to an rpc caller, and then
// dropped from scope.
func (a *Account) ExportWatchingWallet() (*Account, error) {
	ww, err := a.KeyStore.ExportWatchingWallet()
	if err != nil {
		return nil, err
	}

	wa := *a
	wa.KeyStore = ww
	return &wa, nil
}

// exportBase64 exports an account's serialized wallet, tx, and utxo
// stores as base64-encoded values in a map.
func (a *Account) exportBase64() (map[string]string, error) {
	buf := bytes.Buffer{}
	m := make(map[string]string)

	_, err := a.KeyStore.WriteTo(&buf)
	if err != nil {
		return nil, err
	}
	m["wallet"] = base64.StdEncoding.EncodeToString(buf.Bytes())
	buf.Reset()

	if _, err = a.TxStore.WriteTo(&buf); err != nil {
		return nil, err
	}
	m["tx"] = base64.StdEncoding.EncodeToString(buf.Bytes())
	buf.Reset()

	return m, nil
}

// LockedOutpoint returns whether an outpoint has been marked as locked and
// should not be used as an input for created transactions.
func (a *Account) LockedOutpoint(op btcwire.OutPoint) bool {
	_, locked := a.lockedOutpoints[op]
	return locked
}

// LockOutpoint marks an outpoint as locked, that is, it should not be used as
// an input for newly created transactions.
func (a *Account) LockOutpoint(op btcwire.OutPoint) {
	a.lockedOutpoints[op] = struct{}{}
}

// UnlockOutpoint marks an outpoint as unlocked, that is, it may be used as an
// input for newly created transactions.
func (a *Account) UnlockOutpoint(op btcwire.OutPoint) {
	delete(a.lockedOutpoints, op)
}

// ResetLockedOutpoints resets the set of locked outpoints so all may be used
// as inputs for new transactions.
func (a *Account) ResetLockedOutpoints() {
	a.lockedOutpoints = map[btcwire.OutPoint]struct{}{}
}

// LockedOutpoints returns a slice of currently locked outpoints.  This is
// intended to be used by marshaling the result as a JSON array for
// listlockunspent RPC results.
func (a *Account) LockedOutpoints() []btcjson.TransactionInput {
	locked := make([]btcjson.TransactionInput, len(a.lockedOutpoints))
	i := 0
	for op := range a.lockedOutpoints {
		locked[i] = btcjson.TransactionInput{
			Txid: op.Hash.String(),
			Vout: op.Index,
		}
		i++
	}
	return locked
}

// Track requests btcd to send notifications of new transactions for
// each address stored in a wallet.
func (a *Account) Track() {
	rpcc, err := accessClient()
	if err != nil {
		log.Errorf("No chain server client to track addresses.")
		return
	}

	// Request notifications for transactions sending to all wallet
	// addresses.
	//
	// TODO: return as slice? (doesn't have to be ordered, or
	// SortedActiveAddresses would be fine.)
	addrMap := a.KeyStore.ActiveAddresses()
	addrs := make([]btcutil.Address, 0, len(addrMap))
	for addr := range addrMap {
		addrs = append(addrs, addr)
	}

	if err := rpcc.NotifyReceived(addrs); err != nil {
		log.Error("Unable to request transaction updates for address.")
	}

	unspent, err := a.TxStore.UnspentOutputs()
	if err != nil {
		log.Errorf("Unable to access unspent outputs: %v", err)
		return
	}
	ReqSpentUtxoNtfns(unspent)
}

// RescanActiveJob creates a RescanJob for all active addresses in the
// account.  This is needed for catching btcwallet up to a long-running
// btcd process, as otherwise it would have missed notifications as
// blocks are attached to the main chain.
func (a *Account) RescanActiveJob() (*RescanJob, error) {
	// Determine the block necesary to start the rescan for all active
	// addresses.
	height := a.KeyStore.SyncHeight()

	actives := a.KeyStore.SortedActiveAddresses()
	addrs := make([]btcutil.Address, 0, len(actives))
	for i := range actives {
		addrs = append(addrs, actives[i].Address())
	}

	unspents, err := a.TxStore.UnspentOutputs()
	if err != nil {
		return nil, err
	}
	outpoints := make([]*btcwire.OutPoint, 0, len(unspents))
	for _, c := range unspents {
		outpoints = append(outpoints, c.OutPoint())
	}

	job := &RescanJob{
		Addresses:   map[*Account][]btcutil.Address{a: addrs},
		OutPoints:   outpoints,
		StartHeight: height,
	}
	return job, nil
}

// ResendUnminedTxs iterates through all transactions that spend from wallet
// credits that are not known to have been mined into a block, and attempts
// to send each to the chain server for relay.
func (a *Account) ResendUnminedTxs() {
	rpcc, err := accessClient()
	if err != nil {
		log.Errorf("No chain server client to resend txs.")
		return
	}

	txs := a.TxStore.UnminedDebitTxs()
	for _, tx := range txs {
		_, err := rpcc.SendRawTransaction(tx.MsgTx(), false)
		if err != nil {
			// TODO(jrick): Check error for if this tx is a double spend,
			// remove it if so.
			log.Warnf("Could not resend transaction %v: %v",
				tx.Sha(), err)
			continue
		}
		log.Debugf("Resent unmined transaction %v", tx.Sha())
	}
}

// SortedActivePaymentAddresses returns a slice of all active payment
// addresses in an account.
func (a *Account) SortedActivePaymentAddresses() []string {
	infos := a.KeyStore.SortedActiveAddresses()

	addrs := make([]string, len(infos))
	for i, info := range infos {
		addrs[i] = info.Address().EncodeAddress()
	}

	return addrs
}

// ActivePaymentAddresses returns a set of all active pubkey hashes
// in an account.
func (a *Account) ActivePaymentAddresses() map[string]struct{} {
	infos := a.KeyStore.ActiveAddresses()

	addrs := make(map[string]struct{}, len(infos))
	for _, info := range infos {
		addrs[info.Address().EncodeAddress()] = struct{}{}
	}

	return addrs
}

// NewAddress returns a new payment address for an account.
func (a *Account) NewAddress() (btcutil.Address, error) {
	// Get current block's height and hash.
	rpcc, err := accessClient()
	if err != nil {
		return nil, err
	}
	bs, err := rpcc.BlockStamp()
	if err != nil {
		return nil, err
	}

	// Get next address from wallet.
	addr, err := a.KeyStore.NextChainedAddress(&bs, cfg.KeypoolSize)
	if err != nil {
		return nil, err
	}

	// Immediately write updated wallet to disk.
	AcctMgr.ds.ScheduleWalletWrite(a)
	if err := AcctMgr.ds.FlushAccount(a); err != nil {
		return nil, fmt.Errorf("account write failed: %v", err)
	}

	// Mark this new address as belonging to this account.
	AcctMgr.MarkAddressForAccount(addr, a)

	// Request updates from btcd for new transactions sent to this address.
	if err := rpcc.NotifyReceived([]btcutil.Address{addr}); err != nil {
		return nil, err
	}

	return addr, nil
}

// NewChangeAddress returns a new change address for an account.
func (a *Account) NewChangeAddress() (btcutil.Address, error) {
	// Get current block's height and hash.
	rpcc, err := accessClient()
	if err != nil {
		return nil, err
	}
	bs, err := rpcc.BlockStamp()
	if err != nil {
		return nil, err
	}

	// Get next chained change address from wallet.
	addr, err := a.KeyStore.ChangeAddress(&bs, cfg.KeypoolSize)
	if err != nil {
		return nil, err
	}

	// Immediately write updated wallet to disk.
	AcctMgr.ds.ScheduleWalletWrite(a)
	if err := AcctMgr.ds.FlushAccount(a); err != nil {
		return nil, fmt.Errorf("account write failed: %v", err)
	}

	// Mark this new address as belonging to this account.
	AcctMgr.MarkAddressForAccount(addr, a)

	// Request updates from btcd for new transactions sent to this address.
	if err := rpcc.NotifyReceived([]btcutil.Address{addr}); err != nil {
		return nil, err
	}

	return addr, nil
}

// RecoverAddresses recovers the next n chained addresses of a wallet.
func (a *Account) RecoverAddresses(n int) error {
	// Get info on the last chained address.  The rescan starts at the
	// earliest block height the last chained address might appear at.
	last := a.KeyStore.LastChainedAddress()
	lastInfo, err := a.KeyStore.Address(last)
	if err != nil {
		return err
	}

	addrs, err := a.KeyStore.ExtendActiveAddresses(n, cfg.KeypoolSize)
	if err != nil {
		return err
	}

	// Run a goroutine to rescan blockchain for recovered addresses.
	go func() {
		rpcc, err := accessClient()
		if err != nil {
			log.Errorf("Cannot access chain server client to " +
				"rescan recovered addresses.")
			return
		}
		err = rpcc.Rescan(lastInfo.FirstBlock(), addrs, nil)
		if err != nil {
			log.Errorf("Rescanning for recovered addresses "+
				"failed: %v", err)
		}
	}()

	return nil
}

// ReqSpentUtxoNtfns sends a message to btcd to request updates for when
// a stored UTXO has been spent.
func ReqSpentUtxoNtfns(credits []txstore.Credit) {
	ops := make([]*btcwire.OutPoint, 0, len(credits))
	for _, c := range credits {
		op := c.OutPoint()
		log.Debugf("Requesting spent UTXO notifications for Outpoint "+
			"hash %s index %d", op.Hash, op.Index)
		ops = append(ops, op)
	}

	rpcc, err := accessClient()
	if err != nil {
		log.Errorf("Cannot access chain server client to " +
			"request spent output notifications.")
		return
	}
	if err := rpcc.NotifySpent(ops); err != nil {
		log.Errorf("Cannot request notifications for spent outputs: %v",
			err)
	}
}

// TotalReceived iterates through an account's transaction history, returning the
// total amount of bitcoins received for any account address.  Amounts received
// through multisig transactions are ignored.
func (a *Account) TotalReceived(confirms int) (btcutil.Amount, error) {
	rpcc, err := accessClient()
	if err != nil {
		return 0, err
	}
	bs, err := rpcc.BlockStamp()
	if err != nil {
		return 0, err
	}

	var amount btcutil.Amount
	for _, r := range a.TxStore.Records() {
		for _, c := range r.Credits() {
			// Ignore change.
			if c.Change() {
				continue
			}

			// Tally if the appropiate number of block confirmations have passed.
			if c.Confirmed(confirms, bs.Height) {
				amount += c.Amount()
			}
		}
	}
	return amount, nil
}
