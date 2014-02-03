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
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"path/filepath"
	"sync"
)

// addressAccountMap holds a map of addresses to names of the
// accounts that hold each address.
//
// TODO: move this to AccountManager
var addressAccountMap = struct {
	sync.RWMutex
	m map[string]string
}{
	m: make(map[string]string),
}

// MarkAddressForAccount marks an address as belonging to an account.
func MarkAddressForAccount(address, account string) {
	addressAccountMap.Lock()
	addressAccountMap.m[address] = account
	addressAccountMap.Unlock()
}

// LookupAccountByAddress returns the account name for address.  error
// will be set to ErrNotFound if the address has not been marked as
// associated with any account.
func LookupAccountByAddress(address string) (string, error) {
	addressAccountMap.RLock()
	defer addressAccountMap.RUnlock()
	account, ok := addressAccountMap.m[address]
	if !ok {
		return "", ErrNotFound
	}
	return account, nil
}

// Account is a structure containing all the components for a
// complete wallet.  It contains the Armory-style wallet (to store
// addresses and keys), and tx and utxo stores, and a mutex to prevent
// incorrect multiple access.
type Account struct {
	name       string
	fullRescan bool
	*wallet.Wallet
	tx.UtxoStore
	tx.TxStore
}

// Lock locks the underlying wallet for an account.
func (a *Account) Lock() error {
	switch err := a.Wallet.Lock(); err {
	case nil:
		NotifyWalletLockStateChange(a.Name(), true)
		return nil

	case wallet.ErrWalletLocked:
		// Do not pass wallet already locked errors to the caller.
		return nil

	default:
		return err
	}
}

// Unlock unlocks the underlying wallet for an account.
func (a *Account) Unlock(passphrase []byte) error {
	if err := a.Wallet.Unlock(passphrase); err != nil {
		return err
	}

	NotifyWalletLockStateChange(a.Name(), false)
	return nil
}

// AddressUsed returns whether there are any recorded transactions spending to
// a given address.  Assumming correct TxStore usage, this will return true iff
// there are any transactions with outputs to this address in the blockchain or
// the btcd mempool.
func (a *Account) AddressUsed(addr btcutil.Address) bool {
	// This can be optimized by recording this data as it is read when
	// opening an account, and keeping it up to date each time a new
	// received tx arrives.

	pkHash := addr.ScriptAddress()

	for i := range a.TxStore {
		rtx, ok := a.TxStore[i].(*tx.RecvTx)
		if !ok {
			continue
		}

		if bytes.Equal(rtx.ReceiverHash, pkHash) {
			return true
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
func (a *Account) CalculateBalance(confirms int) float64 {
	bs, err := GetCurBlock()
	if bs.Height == int32(btcutil.BlockHeightUnknown) || err != nil {
		return 0.
	}

	var bal uint64 // Measured in satoshi
	for _, u := range a.UtxoStore {
		// Utxos not yet in blocks (height -1) should only be
		// added if confirmations is 0.
		if confirmed(confirms, u.Height, bs.Height) {
			bal += u.Amt
		}
	}
	return float64(bal) / float64(btcutil.SatoshiPerBitcoin)
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
func (a *Account) CalculateAddressBalance(addr *btcutil.AddressPubKeyHash, confirms int) float64 {
	bs, err := GetCurBlock()
	if bs.Height == int32(btcutil.BlockHeightUnknown) || err != nil {
		return 0.
	}

	var bal uint64 // Measured in satoshi
	for _, u := range a.UtxoStore {
		// Utxos not yet in blocks (height -1) should only be
		// added if confirmations is 0.
		if confirmed(confirms, u.Height, bs.Height) {
			if bytes.Equal(addr.ScriptAddress(), u.AddrHash[:]) {
				bal += u.Amt
			}
		}
	}
	return float64(bal) / float64(btcutil.SatoshiPerBitcoin)
}

// CurrentAddress gets the most recently requested Bitcoin payment address
// from an account.  If the address has already been used (there is at least
// one transaction spending to it in the blockchain or btcd mempool), the next
// chained address is returned.
func (a *Account) CurrentAddress() (btcutil.Address, error) {
	addr := a.Wallet.LastChainedAddress()

	// Get next chained address if the last one has already been used.
	if a.AddressUsed(addr) {
		return a.NewAddress()
	}

	return addr, nil
}

// ListSinceBlock returns a slice of maps with details about transactions since
// the given block. If the block is -1 then all transactions are included.
// transaction.  This is intended to be used for listsinceblock RPC
// replies.
func (a *Account) ListSinceBlock(since, curBlockHeight int32, minconf int) ([]map[string]interface{}, error) {
	var txInfoList []map[string]interface{}
	for _, tx := range a.TxStore {
		// check block number.
		if since != -1 && tx.GetBlockHeight() <= since {
			continue
		}

		txInfoList = append(txInfoList,
			tx.TxInfo(a.name, curBlockHeight, a.Net())...)
	}

	return txInfoList, nil
}

// ListTransactions returns a slice of maps with details about a recorded
// transaction.  This is intended to be used for listtransactions RPC
// replies.
func (a *Account) ListTransactions(from, count int) ([]map[string]interface{}, error) {
	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	bs, err := GetCurBlock()
	if err != nil {
		return nil, err
	}

	var txInfoList []map[string]interface{}

	lastLookupIdx := len(a.TxStore) - count
	// Search in reverse order: lookup most recently-added first.
	for i := len(a.TxStore) - 1; i >= from && i >= lastLookupIdx; i-- {
		txInfoList = append(txInfoList,
			a.TxStore[i].TxInfo(a.name, bs.Height, a.Net())...)
	}

	return txInfoList, nil
}

// ListAddressTransactions returns a slice of maps with details about a
// recorded transactions to or from any address belonging to a set.  This is
// intended to be used for listaddresstransactions RPC replies.
func (a *Account) ListAddressTransactions(pkHashes map[string]struct{}) (
	[]map[string]interface{}, error) {

	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	bs, err := GetCurBlock()
	if err != nil {
		return nil, err
	}

	var txInfoList []map[string]interface{}
	for i := range a.TxStore {
		rtx, ok := a.TxStore[i].(*tx.RecvTx)
		if !ok {
			continue
		}
		if _, ok := pkHashes[string(rtx.ReceiverHash[:])]; ok {
			info := rtx.TxInfo(a.name, bs.Height, a.Net())
			txInfoList = append(txInfoList, info...)
		}
	}

	return txInfoList, nil
}

// ListAllTransactions returns a slice of maps with details about a recorded
// transaction.  This is intended to be used for listalltransactions RPC
// replies.
func (a *Account) ListAllTransactions() ([]map[string]interface{}, error) {
	// Get current block.  The block height used for calculating
	// the number of tx confirmations.
	bs, err := GetCurBlock()
	if err != nil {
		return nil, err
	}

	// Search in reverse order: lookup most recently-added first.
	var txInfoList []map[string]interface{}
	for i := len(a.TxStore) - 1; i >= 0; i-- {
		txInfoList = append(txInfoList,
			a.TxStore[i].TxInfo(a.name, bs.Height, a.Net())...)
	}

	return txInfoList, nil
}

// DumpPrivKeys returns the WIF-encoded private keys for all addresses with
// private keys in a wallet.
func (a *Account) DumpPrivKeys() ([]string, error) {
	// Iterate over each active address, appending the private
	// key to privkeys.
	var privkeys []string
	for addr, info := range a.Wallet.ActiveAddresses() {
		key, err := a.Wallet.AddressKey(addr)
		if err != nil {
			return nil, err
		}
		encKey, err := btcutil.EncodePrivateKey(key.D.Bytes(),
			a.Wallet.Net(), info.Compressed)
		if err != nil {
			return nil, err
		}
		privkeys = append(privkeys, encKey)
	}

	return privkeys, nil
}

// DumpWIFPrivateKey returns the WIF encoded private key for a
// single wallet address.
func (a *Account) DumpWIFPrivateKey(addr btcutil.Address) (string, error) {
	// Get private key from wallet if it exists.
	key, err := a.Wallet.AddressKey(addr)
	if err != nil {
		return "", err
	}

	// Get address info.  This is needed to determine whether
	// the pubkey is compressed or not.
	info, err := a.Wallet.AddressInfo(addr)
	if err != nil {
		return "", err
	}

	// Return WIF-encoding of the private key.
	return btcutil.EncodePrivateKey(key.D.Bytes(), a.Net(), info.Compressed)
}

// ImportPrivateKey imports a private key to the account's wallet and
// writes the new wallet to disk.
func (a *Account) ImportPrivateKey(pk []byte, compressed bool, bs *wallet.BlockStamp) (string, error) {
	// Attempt to import private key into wallet.
	addr, err := a.Wallet.ImportPrivateKey(pk, compressed, bs)
	if err != nil {
		return "", err
	}
	addrStr := addr.String()

	// Immediately write wallet to disk.
	AcctMgr.ds.ScheduleWalletWrite(a)
	if err := AcctMgr.ds.FlushAccount(a); err != nil {
		return "", fmt.Errorf("cannot write account: %v", err)
	}

	// Associate the imported address with this account.
	MarkAddressForAccount(addrStr, a.Name())

	log.Infof("Imported payment address %v", addrStr)

	// Return the payment address string of the imported private key.
	return addrStr, nil
}

// ExportToDirectory writes an account to a special export directory.  Any
// previous files are overwritten.
func (a *Account) ExportToDirectory(dirBaseName string) error {
	dir := filepath.Join(networkDir(cfg.Net()), dirBaseName)
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
	ww, err := a.Wallet.ExportWatchingWallet()
	if err != nil {
		return nil, err
	}

	wa := *a
	wa.Wallet = ww
	return &wa, nil
}

// exportBase64 exports an account's serialized wallet, tx, and utxo
// stores as base64-encoded values in a map.
func (a *Account) exportBase64() (map[string]string, error) {
	buf := &bytes.Buffer{}
	m := make(map[string]string)

	_, err := a.Wallet.WriteTo(buf)
	if err != nil {
		return nil, err
	}
	m["wallet"] = base64.StdEncoding.EncodeToString(buf.Bytes())
	buf.Reset()

	if _, err = a.TxStore.WriteTo(buf); err != nil {
		return nil, err
	}
	m["tx"] = base64.StdEncoding.EncodeToString(buf.Bytes())
	buf.Reset()

	_, err = a.UtxoStore.WriteTo(buf)
	if err != nil {
		return nil, err
	}
	m["utxo"] = base64.StdEncoding.EncodeToString(buf.Bytes())
	buf.Reset()

	return m, nil
}

// Track requests btcd to send notifications of new transactions for
// each address stored in a wallet.
func (a *Account) Track() {
	// Request notifications for transactions sending to all wallet
	// addresses.
	addrs := a.ActiveAddresses()
	addrstrs := make([]string, len(addrs))
	i := 0
	for addr := range addrs {
		addrstrs[i] = addr.EncodeAddress()
		i++
	}

	err := NotifyNewTXs(CurrentServerConn(), addrstrs)
	if err != nil {
		log.Error("Unable to request transaction updates for address.")
	}

	for _, utxo := range a.UtxoStore {
		ReqSpentUtxoNtfn(utxo)
	}
}

// RescanActiveAddresses requests btcd to rescan the blockchain for new
// transactions to all active wallet addresses.  This is needed for
// catching btcwallet up to a long-running btcd process, as otherwise
// it would have missed notifications as blocks are attached to the
// main chain.
func (a *Account) RescanActiveAddresses() {
	// Determine the block to begin the rescan from.
	beginBlock := int32(0)
	if a.fullRescan {
		// Need to perform a complete rescan since the wallet creation
		// block.
		beginBlock = a.EarliestBlockHeight()
		log.Debugf("Rescanning account '%v' for new transactions since block height %v",
			a.name, beginBlock)
	} else {
		// The last synced block height should be used the starting
		// point for block rescanning.  Grab the block stamp here.
		bs := a.SyncedWith()

		log.Debugf("Rescanning account '%v' for new transactions after block height %v hash %v",
			a.name, bs.Height, bs.Hash)

		// If we're synced with block x, must scan the blocks x+1 to best block.
		beginBlock = bs.Height + 1
	}

	// Rescan active addresses starting at the determined block height.
	Rescan(CurrentServerConn(), beginBlock, a.ActivePaymentAddresses())
	AcctMgr.ds.FlushAccount(a)
}

// SortedActivePaymentAddresses returns a slice of all active payment
// addresses in an account.
func (a *Account) SortedActivePaymentAddresses() []string {
	infos := a.Wallet.SortedActiveAddresses()

	addrs := make([]string, len(infos))
	for i, info := range infos {
		addrs[i] = info.Address.EncodeAddress()
	}

	return addrs
}

// ActivePaymentAddresses returns a set of all active pubkey hashes
// in an account.
func (a *Account) ActivePaymentAddresses() map[string]struct{} {
	infos := a.ActiveAddresses()

	addrs := make(map[string]struct{}, len(infos))
	for _, info := range infos {
		addrs[info.Address.EncodeAddress()] = struct{}{}
	}

	return addrs
}

// NewAddress returns a new payment address for an account.
func (a *Account) NewAddress() (btcutil.Address, error) {
	// Get current block's height and hash.
	bs, err := GetCurBlock()
	if err != nil {
		return nil, err
	}

	// Get next address from wallet.
	addr, err := a.Wallet.NextChainedAddress(&bs, cfg.KeypoolSize)
	if err != nil {
		return nil, err
	}

	// Immediately write updated wallet to disk.
	AcctMgr.ds.ScheduleWalletWrite(a)
	if err := AcctMgr.ds.FlushAccount(a); err != nil {
		return nil, fmt.Errorf("account write failed: %v", err)
	}

	// Mark this new address as belonging to this account.
	MarkAddressForAccount(addr.EncodeAddress(), a.Name())

	// Request updates from btcd for new transactions sent to this address.
	a.ReqNewTxsForAddress(addr)

	return addr, nil
}

// NewChangeAddress returns a new change address for an account.
func (a *Account) NewChangeAddress() (btcutil.Address, error) {
	// Get current block's height and hash.
	bs, err := GetCurBlock()
	if err != nil {
		return nil, err
	}

	// Get next chained change address from wallet.
	addr, err := a.Wallet.ChangeAddress(&bs, cfg.KeypoolSize)
	if err != nil {
		return nil, err
	}

	// Immediately write updated wallet to disk.
	AcctMgr.ds.ScheduleWalletWrite(a)
	if err := AcctMgr.ds.FlushAccount(a); err != nil {
		return nil, fmt.Errorf("account write failed: %v", err)
	}

	// Mark this new address as belonging to this account.
	MarkAddressForAccount(addr.EncodeAddress(), a.Name())

	// Request updates from btcd for new transactions sent to this address.
	a.ReqNewTxsForAddress(addr)

	return addr, nil
}

// RecoverAddresses recovers the next n chained addresses of a wallet.
func (a *Account) RecoverAddresses(n int) error {
	// Get info on the last chained address.  The rescan starts at the
	// earliest block height the last chained address might appear at.
	last := a.Wallet.LastChainedAddress()
	lastInfo, err := a.Wallet.AddressInfo(last)
	if err != nil {
		return err
	}

	addrs, err := a.Wallet.ExtendActiveAddresses(n, cfg.KeypoolSize)
	if err != nil {
		return err
	}

	// Run a goroutine to rescan blockchain for recovered addresses.
	m := make(map[string]struct{})
	for i := range addrs {
		m[addrs[i].EncodeAddress()] = struct{}{}
	}
	go func(addrs map[string]struct{}) {
		jsonErr := Rescan(CurrentServerConn(), lastInfo.FirstBlock, addrs)
		if jsonErr != nil {
			log.Errorf("Rescanning for recovered addresses failed: %v",
				jsonErr.Message)
		}
	}(m)

	return nil
}

// ReqNewTxsForAddress sends a message to btcd to request tx updates
// for addr for each new block that is added to the blockchain.
func (a *Account) ReqNewTxsForAddress(addr btcutil.Address) {
	// Only support P2PKH addresses currently.
	apkh, ok := addr.(*btcutil.AddressPubKeyHash)
	if !ok {
		return
	}

	log.Debugf("Requesting notifications of TXs sending to address %v", apkh)

	err := NotifyNewTXs(CurrentServerConn(), []string{apkh.EncodeAddress()})
	if err != nil {
		log.Error("Unable to request transaction updates for address.")
	}
}

// ReqSpentUtxoNtfn sends a message to btcd to request updates for when
// a stored UTXO has been spent.
func ReqSpentUtxoNtfn(u *tx.Utxo) {
	log.Debugf("Requesting spent UTXO notifications for Outpoint hash %s index %d",
		u.Out.Hash, u.Out.Index)

	NotifySpent(CurrentServerConn(), (*btcwire.OutPoint)(&u.Out))
}

// TotalReceived iterates through an account's transaction history, returning the
// total amount of bitcoins received for any account address.  Amounts received
// through multisig transactions are ignored.
func (a *Account) TotalReceived(confirms int) (float64, error) {
	bs, err := GetCurBlock()
	if err != nil {
		return 0, err
	}

	var totalSatoshis int64
	for _, e := range a.TxStore {
		recvtx, ok := e.(*tx.RecvTx)
		if !ok {
			continue
		}

		// Ignore change.
		addr, err := btcutil.NewAddressPubKeyHash(recvtx.ReceiverHash, cfg.Net())
		if err != nil {
			continue
		}
		info, err := a.Wallet.AddressInfo(addr)
		if err != nil {
			continue
		}
		if info.Change {
			continue
		}

		// Tally if the appropiate number of block confirmations have passed.
		if confirmed(confirms, recvtx.GetBlockHeight(), bs.Height) {
			totalSatoshis += recvtx.Amount
		}
	}

	return float64(totalSatoshis) / float64(btcutil.SatoshiPerBitcoin), nil
}

// confirmed checks whether a transaction at height txHeight has met
// minconf confirmations for a blockchain at height curHeight.
func confirmed(minconf int, txHeight, curHeight int32) bool {
	if minconf == 0 {
		return true
	}
	if txHeight != -1 && int(curHeight-txHeight+1) >= minconf {
		return true
	}
	return false
}
