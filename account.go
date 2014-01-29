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
	"errors"
	"fmt"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"path/filepath"
	"sync"
)

// ErrNotFound describes an error where a map lookup failed due to a
// key not being in the map.
var ErrNotFound = errors.New("not found")

// addressAccountMap holds a map of addresses to names of the
// accounts that hold each address.
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
// addresses and keys), and tx and utxo data stores, along with locks
// to prevent against incorrect multiple access.
type Account struct {
	*wallet.Wallet
	mtx        sync.RWMutex
	name       string
	fullRescan bool
	UtxoStore  struct {
		sync.RWMutex
		s tx.UtxoStore
	}
	TxStore struct {
		sync.RWMutex
		s tx.TxStore
	}
}

// Lock locks the underlying wallet for an account.
func (a *Account) Lock() error {
	a.mtx.Lock()
	defer a.mtx.Unlock()

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
	a.mtx.Lock()
	defer a.mtx.Unlock()

	if err := a.Wallet.Unlock(passphrase); err != nil {
		return err
	}

	NotifyWalletLockStateChange(a.Name(), false)
	return nil
}

// Rollback reverts each stored Account to a state before the block
// with the passed chainheight and block hash was connected to the main
// chain.  This is used to remove transactions and utxos for each wallet
// that occured on a chain no longer considered to be the main chain.
func (a *Account) Rollback(height int32, hash *btcwire.ShaHash) {
	a.UtxoStore.Lock()
	modified := a.UtxoStore.s.Rollback(height, hash)
	a.UtxoStore.Unlock()
	if modified {
		a.ScheduleUtxoStoreWrite()
	}

	a.TxStore.Lock()
	modified = a.TxStore.s.Rollback(height, hash)
	a.TxStore.Unlock()
	if modified {
		a.ScheduleTxStoreWrite()
	}
}

// AddressUsed returns whether there are any recorded transactions spending to
// a given address.  Assumming correct TxStore usage, this will return true iff
// there are any transactions with outputs to this address in the blockchain or
// the btcd mempool.
func (a *Account) AddressUsed(addr btcutil.Address) bool {
	// This can be optimized by recording this data as it is read when
	// opening an account, and keeping it up to date each time a new
	// received tx arrives.

	a.TxStore.RLock()
	defer a.TxStore.RUnlock()

	pkHash := addr.ScriptAddress()

	for i := range a.TxStore.s {
		rtx, ok := a.TxStore.s[i].(*tx.RecvTx)
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
	var bal uint64 // Measured in satoshi

	bs, err := GetCurBlock()
	if bs.Height == int32(btcutil.BlockHeightUnknown) || err != nil {
		return 0.
	}

	a.UtxoStore.RLock()
	for _, u := range a.UtxoStore.s {
		// Utxos not yet in blocks (height -1) should only be
		// added if confirmations is 0.
		if confirms == 0 || (u.Height != -1 && int(bs.Height-u.Height+1) >= confirms) {
			bal += u.Amt
		}
	}
	a.UtxoStore.RUnlock()
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
	var bal uint64 // Measured in satoshi

	bs, err := GetCurBlock()
	if bs.Height == int32(btcutil.BlockHeightUnknown) || err != nil {
		return 0.
	}

	a.UtxoStore.RLock()
	for _, u := range a.UtxoStore.s {
		// Utxos not yet in blocks (height -1) should only be
		// added if confirmations is 0.
		if confirms == 0 || (u.Height != -1 && int(bs.Height-u.Height+1) >= confirms) {
			if bytes.Equal(addr.ScriptAddress(), u.AddrHash[:]) {
				bal += u.Amt
			}
		}
	}
	a.UtxoStore.RUnlock()
	return float64(bal) / float64(btcutil.SatoshiPerBitcoin)
}

// CurrentAddress gets the most recently requested Bitcoin payment address
// from an account.  If the address has already been used (there is at least
// one transaction spending to it in the blockchain or btcd mempool), the next
// chained address is returned.
func (a *Account) CurrentAddress() (btcutil.Address, error) {
	a.mtx.RLock()
	addr := a.Wallet.LastChainedAddress()
	a.mtx.RUnlock()

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
	a.TxStore.RLock()
	defer a.TxStore.RUnlock()

	for _, tx := range a.TxStore.s {
		// check block number.
		if since != -1 && tx.Height() <= since {
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
	a.TxStore.RLock()

	lastLookupIdx := len(a.TxStore.s) - count
	// Search in reverse order: lookup most recently-added first.
	for i := len(a.TxStore.s) - 1; i >= from && i >= lastLookupIdx; i-- {
		txInfoList = append(txInfoList,
			a.TxStore.s[i].TxInfo(a.name, bs.Height, a.Net())...)
	}
	a.TxStore.RUnlock()

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
	a.TxStore.RLock()

	for i := range a.TxStore.s {
		rtx, ok := a.TxStore.s[i].(*tx.RecvTx)
		if !ok {
			continue
		}
		if _, ok := pkHashes[string(rtx.ReceiverHash[:])]; ok {
			info := rtx.TxInfo(a.name, bs.Height, a.Net())
			txInfoList = append(txInfoList, info...)
		}
	}
	a.TxStore.RUnlock()

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

	var txInfoList []map[string]interface{}
	a.TxStore.RLock()

	// Search in reverse order: lookup most recently-added first.
	for i := len(a.TxStore.s) - 1; i >= 0; i-- {
		txInfoList = append(txInfoList,
			a.TxStore.s[i].TxInfo(a.name, bs.Height, a.Net())...)
	}
	a.TxStore.RUnlock()

	return txInfoList, nil
}

// DumpPrivKeys returns the WIF-encoded private keys for all addresses with
// private keys in a wallet.
func (a *Account) DumpPrivKeys() ([]string, error) {
	a.mtx.RLock()
	defer a.mtx.RUnlock()

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
	a.mtx.RLock()
	defer a.mtx.RUnlock()

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

// ImportPrivKey imports a WIF-encoded private key into an account's wallet.
// This function is not recommended, as it gives no hints as to when the
// address first appeared (not just in the blockchain, but since the address
// was first generated, or made public), and will cause all future rescans to
// start from the genesis block.
func (a *Account) ImportPrivKey(wif string, rescan bool) error {
	bs := &wallet.BlockStamp{}
	addr, err := a.ImportWIFPrivateKey(wif, bs)
	if err != nil {
		return err
	}

	if rescan {
		// Do not wait for rescan to finish before returning to the
		// caller.
		go func() {
			addrs := map[string]struct{}{
				addr: struct{}{},
			}

			Rescan(CurrentRPCConn(), bs.Height, addrs)
			a.WriteScheduledToDisk()
		}()
	}
	return nil
}

// ImportWIFPrivateKey takes a WIF-encoded private key and adds it to the
// wallet.  If the import is successful, the payment address string is
// returned.
func (a *Account) ImportWIFPrivateKey(wif string, bs *wallet.BlockStamp) (string, error) {
	// Decode WIF private key and perform sanity checking.
	privkey, net, compressed, err := btcutil.DecodePrivateKey(wif)
	if err != nil {
		return "", err
	}
	if net != a.Net() {
		return "", errors.New("wrong network")
	}

	// Attempt to import private key into wallet.
	a.mtx.Lock()
	addr, err := a.Wallet.ImportPrivateKey(privkey, compressed, bs)
	a.mtx.Unlock()
	if err != nil {
		return "", err
	}
	addrStr := addr.String()

	// Immediately write wallet to disk.
	a.ScheduleWalletWrite()
	if err := a.WriteScheduledToDisk(); err != nil {
		return "", fmt.Errorf("cannot write account: %v", err)
	}

	// Associate the imported address with this account.
	MarkAddressForAccount(addrStr, a.Name())

	log.Infof("Imported payment address %v", addrStr)

	// Return the payment address string of the imported private key.
	return addrStr, nil
}

// ExportWatchingWallet returns a new account with a watching wallet
// exported by this a's wallet.  Both wallets share the same tx and utxo
// stores, so locking one will lock the other as well.  The returned account
// should be exported quickly, either to file or to an rpc caller, and then
// dropped from scope.
func (a *Account) ExportWatchingWallet() (*Account, error) {
	a.mtx.RLock()
	ww, err := a.Wallet.ExportWatchingWallet()
	a.mtx.RUnlock()
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

	a.mtx.RLock()
	_, err := a.Wallet.WriteTo(buf)
	a.mtx.RUnlock()
	if err != nil {
		return nil, err
	}
	m["wallet"] = base64.StdEncoding.EncodeToString(buf.Bytes())
	buf.Reset()

	a.TxStore.RLock()
	_, err = a.TxStore.s.WriteTo(buf)
	a.TxStore.RUnlock()
	if err != nil {
		return nil, err
	}
	m["tx"] = base64.StdEncoding.EncodeToString(buf.Bytes())
	buf.Reset()

	a.UtxoStore.RLock()
	_, err = a.UtxoStore.s.WriteTo(buf)
	a.UtxoStore.RUnlock()
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

	err := NotifyNewTXs(CurrentRPCConn(), addrstrs)
	if err != nil {
		log.Error("Unable to request transaction updates for address.")
	}

	a.UtxoStore.RLock()
	for _, utxo := range a.UtxoStore.s {
		ReqSpentUtxoNtfn(utxo)
	}
	a.UtxoStore.RUnlock()
}

// RescanActiveAddresses requests btcd to rescan the blockchain for new
// transactions to all active wallet addresses.  This is needed for
// catching btcwallet up to a long-running btcd process, as otherwise
// it would have missed notifications as blocks are attached to the
// main chain.
func (a *Account) RescanActiveAddresses() {
	// Determine the block to begin the rescan from.
	beginBlock := int32(0)
	a.mtx.RLock()
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
	a.mtx.RUnlock()

	// Rescan active addresses starting at the determined block height.
	Rescan(CurrentRPCConn(), beginBlock, a.ActivePaymentAddresses())
	a.WriteScheduledToDisk()
}

// SortedActivePaymentAddresses returns a slice of all active payment
// addresses in an account.
func (a *Account) SortedActivePaymentAddresses() []string {
	a.mtx.RLock()
	infos := a.Wallet.SortedActiveAddresses()
	a.mtx.RUnlock()

	addrs := make([]string, len(infos))
	for i, info := range infos {
		addrs[i] = info.Address.EncodeAddress()
	}

	return addrs
}

// ActivePaymentAddresses returns a set of all active pubkey hashes
// in an account.
func (a *Account) ActivePaymentAddresses() map[string]struct{} {
	a.mtx.RLock()
	infos := a.ActiveAddresses()
	a.mtx.RUnlock()

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
	a.mtx.Lock()
	addr, err := a.Wallet.NextChainedAddress(&bs, cfg.KeypoolSize)
	a.mtx.Unlock()
	if err != nil {
		return nil, err
	}

	// Immediately write updated wallet to disk.
	a.ScheduleWalletWrite()
	if err := a.WriteScheduledToDisk(); err != nil {
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
	a.mtx.RLock()
	last := a.Wallet.LastChainedAddress()
	lastInfo, err := a.Wallet.AddressInfo(last)
	a.mtx.RUnlock()
	if err != nil {
		return err
	}

	a.mtx.Lock()
	addrs, err := a.Wallet.ExtendActiveAddresses(n, cfg.KeypoolSize)
	a.mtx.Unlock()
	if err != nil {
		return err
	}

	// Run a goroutine to rescan blockchain for recovered addresses.
	m := make(map[string]struct{})
	for i := range addrs {
		m[addrs[i].EncodeAddress()] = struct{}{}
	}
	go func(addrs map[string]struct{}) {
		jsonErr := Rescan(CurrentRPCConn(), lastInfo.FirstBlock, addrs)
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

	err := NotifyNewTXs(CurrentRPCConn(), []string{apkh.EncodeAddress()})
	if err != nil {
		log.Error("Unable to request transaction updates for address.")
	}
}

// ReqSpentUtxoNtfn sends a message to btcd to request updates for when
// a stored UTXO has been spent.
func ReqSpentUtxoNtfn(u *tx.Utxo) {
	log.Debugf("Requesting spent UTXO notifications for Outpoint hash %s index %d",
		u.Out.Hash, u.Out.Index)

	NotifySpent(CurrentRPCConn(), (*btcwire.OutPoint)(&u.Out))
}

// accountdir returns the directory containing an account's wallet, utxo,
// and tx files.
//
// This function is deprecated and should only be used when looking up
// old (before version 0.1.1) account directories so they may be updated
// to the new directory structure.
func accountdir(name string, cfg *config) string {
	var adir string
	if name == "" { // default account
		adir = "btcwallet"
	} else {
		adir = fmt.Sprintf("btcwallet-%s", name)
	}

	return filepath.Join(cfg.DataDir, adir)
}
