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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"github.com/conformal/btcws"
	"time"
)

var (
	// ErrBtcdDisconnected describes an error where an operation cannot
	// successfully complete due to btcd not being connected to
	// btcwallet.
	ErrBtcdDisconnected = errors.New("btcd disconnected")
)

type cmdHandler func(chan []byte, btcjson.Cmd)

var handlers = map[string]cmdHandler{
	// Standard bitcoind methods
	"getaddressesbyaccount": GetAddressesByAccount,
	"getbalance":            GetBalance,
	"getnewaddress":         GetNewAddress,
	"listaccounts":          ListAccounts,
	"sendfrom":              SendFrom,
	"sendmany":              SendMany,
	"settxfee":              SetTxFee,
	"walletlock":            WalletLock,
	"walletpassphrase":      WalletPassphrase,

	// btcwallet extensions
	"createencryptedwallet": CreateEncryptedWallet,
	"getbalances":           GetBalances,
	"walletislocked":        WalletIsLocked,
}

// ProcessFrontendMsg checks the message sent from a frontend.  If the
// message method is one that must be handled by btcwallet, the request
// is processed here.  Otherwise, the message is sent to btcd.
func ProcessFrontendMsg(frontend chan []byte, msg []byte) {
	// Parse marshaled command and check
	cmd, err := btcjson.ParseMarshaledCmd(msg)
	if err != nil {
		// Check that msg is valid JSON-RPC.  Reply to frontend
		// with error if invalid.
		if cmd == nil {
			ReplyError(frontend, nil, &btcjson.ErrInvalidRequest)
			return
		}

		// btcwallet cannot handle this command, so defer handling
		// to btcd.
		fmt.Printf("deferring %v with error %v\n", string(msg), err)
		DeferToBTCD(frontend, msg)
		return
	}

	// Check for a handler to reply to cmd.  If none exist, defer to btcd.
	if f, ok := handlers[cmd.Method()]; ok {
		f(frontend, cmd)
	} else {
		// btcwallet does not have a handler for the command.  Pass
		// to btcd and route replies back to the appropiate frontend.
		DeferToBTCD(frontend, msg)
	}
}

// DeferToBTCD sends an unmarshaled command to btcd, modifying the id
// and setting up a reply route to route the reply from btcd back to
// the frontend reply channel with the original id.
func DeferToBTCD(frontend chan []byte, msg []byte) {
	// msg cannot be sent to btcd directly, but the ID must instead be
	// changed to include additonal routing information so replies can
	// be routed back to the correct frontend.  Unmarshal msg into a
	// generic btcjson.Message struct so the ID can be modified and the
	// whole thing re-marshaled.
	var m btcjson.Message
	json.Unmarshal(msg, &m)

	// Create a new ID so replies can be routed correctly.
	n := <-NewJSONID
	var id interface{} = RouteID(m.Id, n)
	m.Id = &id

	// Marshal the request with modified ID.
	newMsg, err := json.Marshal(m)
	if err != nil {
		log.Errorf("DeferToBTCD: Cannot marshal message: %v", err)
		return
	}

	// If marshaling suceeded, save the id and frontend reply channel
	// so the reply can be sent to the correct frontend.
	replyRouter.Lock()
	replyRouter.m[n] = frontend
	replyRouter.Unlock()

	// Send message with modified ID to btcd.
	btcdMsgs <- newMsg
}

// RouteID creates a JSON-RPC id for a frontend request that was deferred
// to btcd.
func RouteID(origID, routeID interface{}) string {
	return fmt.Sprintf("btcwallet(%v)-%v", routeID, origID)
}

// ReplyError creates and marshalls a btcjson.Reply with the error e,
// sending the reply to a frontend reply channel.
func ReplyError(frontend chan []byte, id interface{}, e *btcjson.Error) {
	// Create a Reply with a non-nil error to marshal.
	r := btcjson.Reply{
		Error: e,
		Id:    &id,
	}

	// Marshal reply and send to frontend if marshaling suceeded.
	if mr, err := json.Marshal(r); err == nil {
		frontend <- mr
	}
}

// ReplySuccess creates and marshalls a btcjson.Reply with the result r,
// sending the reply to a frontend reply channel.
func ReplySuccess(frontend chan []byte, id interface{}, result interface{}) {
	// Create a Reply with a non-nil result to marshal.
	r := btcjson.Reply{
		Result: result,
		Id:     &id,
	}

	// Marshal reply and send to frontend if marshaling suceeded.
	if mr, err := json.Marshal(r); err == nil {
		frontend <- mr
	}
}

// GetAddressesByAccount replies to a getaddressesbyaccount request with
// all addresses for an account, or an error if the requested account does
// not exist.
func GetAddressesByAccount(frontend chan []byte, icmd btcjson.Cmd) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetAddressesByAccountCmd)
	if !ok {
		ReplyError(frontend, icmd.Id(), &btcjson.ErrInternal)
		return
	}

	// Check that the account specified in the request exists.
	w, ok := wallets.m[cmd.Account]
	if !ok {
		ReplyError(frontend, cmd.Id(),
			&btcjson.ErrWalletInvalidAccountName)
		return
	}

	// Reply with sorted active payment addresses.
	ReplySuccess(frontend, cmd.Id(), w.SortedActivePaymentAddresses())
}

// GetBalance replies to a getbalance request with the balance for an
// account (wallet), or an error if the requested account does not
// exist.
func GetBalance(frontend chan []byte, icmd btcjson.Cmd) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetBalanceCmd)
	if !ok {
		ReplyError(frontend, icmd.Id(), &btcjson.ErrInternal)
		return
	}

	// Check that the account specified in the request exists.
	w, ok := wallets.m[cmd.Account]
	if !ok {
		ReplyError(frontend, cmd.Id(),
			&btcjson.ErrWalletInvalidAccountName)
		return
	}

	// Reply with calculated balance.
	ReplySuccess(frontend, cmd.Id(), w.CalculateBalance(cmd.MinConf))
}

// GetBalances replies to a getbalances extension request by notifying
// the frontend of all balances for each opened account.
func GetBalances(frontend chan []byte, cmd btcjson.Cmd) {
	NotifyBalances(frontend)
}

// NotifyBalances notifies an attached wallet of the current confirmed
// and unconfirmed account balances.
//
// TODO(jrick): Switch this to return a JSON object (map) of all accounts
// and their balances, instead of separate notifications for each account.
func NotifyBalances(reply chan []byte) {
	for _, w := range wallets.m {
		balance := w.CalculateBalance(1)
		unconfirmed := w.CalculateBalance(0) - balance
		NotifyWalletBalance(reply, w.name, balance)
		NotifyWalletBalanceUnconfirmed(reply, w.name, unconfirmed)
	}
}

// GetNewAddress responds to a getnewaddress request by getting a new
// address for an account.  If the account does not exist, an appropiate
// error is returned to the frontend.
func GetNewAddress(frontend chan []byte, icmd btcjson.Cmd) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetAddressesByAccountCmd)
	if !ok {
		ReplyError(frontend, icmd.Id(), &btcjson.ErrInternal)
		return
	}

	// Check that the account specified in the request exists.
	w, ok := wallets.m[cmd.Account]
	if !ok {
		ReplyError(frontend, cmd.Id(),
			&btcjson.ErrWalletInvalidAccountName)
		return
	}

	// Get next address from wallet.
	addr, err := w.NextUnusedAddress()
	if err != nil {
		// TODO(jrick): generate new addresses if the address pool is
		// empty.
		e := btcjson.ErrInternal
		e.Message = fmt.Sprintf("New address generation not implemented yet")
		ReplyError(frontend, cmd.Id(), &e)
		return
	}

	// Write updated wallet to disk.
	w.dirty = true
	if err = w.writeDirtyToDisk(); err != nil {
		log.Errorf("cannot sync dirty wallet: %v", err)
	}

	// Request updates from btcd for new transactions sent to this address.
	w.ReqNewTxsForAddress(addr)

	// Reply with the new payment address string.
	ReplySuccess(frontend, cmd.Id(), addr)
}

// ListAccounts replies to a listaccounts request by returning a JSON
// object mapping account names with their balances.
func ListAccounts(frontend chan []byte, icmd btcjson.Cmd) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.ListAccountsCmd)
	if !ok {
		ReplyError(frontend, icmd.Id(), &btcjson.ErrInternal)
		return
	}

	// Create and fill a map of account names and their balances.
	pairs := make(map[string]float64)
	for account, w := range wallets.m {
		pairs[account] = w.CalculateBalance(cmd.MinConf)
	}

	// Reply with the map.  This will be marshaled into a JSON object.
	ReplySuccess(frontend, cmd.Id(), pairs)
}

// SendFrom creates a new transaction spending unspent transaction
// outputs for a wallet to another payment address.  Leftover inputs
// not sent to the payment address or a fee for the miner are sent
// back to a new address in the wallet.  Upon success, the TxID
// for the created transaction is sent to the frontend.
func SendFrom(frontend chan []byte, icmd btcjson.Cmd) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.SendFromCmd)
	if !ok {
		ReplyError(frontend, icmd.Id(), &btcjson.ErrInternal)
		return
	}

	// Check that signed integer parameters are positive.
	if cmd.Amount < 0 {
		e := &btcjson.Error{
			Code:    btcjson.ErrInvalidParameter.Code,
			Message: "amount must be positive",
		}
		ReplyError(frontend, cmd.Id(), e)
		return
	}
	if cmd.MinConf < 0 {
		e := &btcjson.Error{
			Code:    btcjson.ErrInvalidParameter.Code,
			Message: "minconf must be positive",
		}
		ReplyError(frontend, cmd.Id(), e)
		return
	}

	// Check that the account specified in the request exists.
	w, ok := wallets.m[cmd.FromAccount]
	if !ok {
		ReplyError(frontend, cmd.Id(),
			&btcjson.ErrWalletInvalidAccountName)
		return
	}

	// Create map of address and amount pairs.
	pairs := map[string]int64{
		cmd.ToAddress: cmd.Amount,
	}

	// Get fee to add to tx.
	// TODO(jrick): this needs to be fee per kB.
	TxFee.Lock()
	fee := TxFee.i
	TxFee.Unlock()

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := w.txToPairs(pairs, fee, cmd.MinConf)
	switch {
	case err == ErrNonPositiveAmount:
		e := &btcjson.Error{
			Code:    btcjson.ErrInvalidParameter.Code,
			Message: "amount must be positive",
		}
		ReplyError(frontend, cmd.Id(), e)
		return

	case err == wallet.ErrWalletLocked:
		ReplyError(frontend, cmd.Id(), &btcjson.ErrWalletUnlockNeeded)
		return

	case err != nil:
		e := &btcjson.Error{
			Code:    btcjson.ErrInternal.Code,
			Message: err.Error(),
		}
		ReplyError(frontend, cmd.Id(), e)
		return
	}

	// If a change address was added, mark wallet as dirty, sync to disk,
	// and Request updates for change address.
	if len(createdTx.changeAddr) != 0 {
		w.dirty = true
		if err := w.writeDirtyToDisk(); err != nil {
			log.Errorf("cannot write dirty wallet: %v", err)
		}
		w.ReqNewTxsForAddress(createdTx.changeAddr)
	}

	// Create sendrawtransaction request with hexstring of the raw tx.
	n := <-NewJSONID
	var id interface{} = fmt.Sprintf("btcwallet(%v)", n)
	m, err := btcjson.CreateMessageWithId("sendrawtransaction", id,
		hex.EncodeToString(createdTx.rawTx))
	if err != nil {
		e := &btcjson.Error{
			Code:    btcjson.ErrInternal.Code,
			Message: err.Error(),
		}
		ReplyError(frontend, cmd.Id(), e)
		return
	}

	// Set up a reply handler to respond to the btcd reply.
	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}, err *btcjson.Error) bool {
		return handleSendRawTxReply(frontend, cmd, result, err, w,
			createdTx)
	}
	replyHandlers.Unlock()

	// Send sendrawtransaction request to btcd.
	btcdMsgs <- m
}

// SendMany creates a new transaction spending unspent transaction
// outputs for a wallet to any number of  payment addresses.  Leftover
// inputs not sent to the payment address or a fee for the miner are
// sent back to a new address in the wallet.  Upon success, the TxID
// for the created transaction is sent to the frontend.
func SendMany(frontend chan []byte, icmd btcjson.Cmd) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.SendManyCmd)
	if !ok {
		ReplyError(frontend, icmd.Id(), &btcjson.ErrInternal)
		return
	}

	// Check that minconf is positive.
	if cmd.MinConf < 0 {
		e := &btcjson.Error{
			Code:    btcjson.ErrInvalidParameter.Code,
			Message: "minconf must be positive",
		}
		ReplyError(frontend, cmd.Id(), e)
		return
	}

	// Check that the account specified in the request exists.
	w, ok := wallets.m[cmd.FromAccount]
	if !ok {
		ReplyError(frontend, cmd.Id(),
			&btcjson.ErrWalletInvalidAccountName)
		return
	}

	// Get fee to add to tx.
	// TODO(jrick): this needs to be fee per kB.
	TxFee.Lock()
	fee := TxFee.i
	TxFee.Unlock()

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := w.txToPairs(cmd.Amounts, fee, cmd.MinConf)
	switch {
	case err == ErrNonPositiveAmount:
		e := &btcjson.Error{
			Code:    btcjson.ErrInvalidParameter.Code,
			Message: "amount must be positive",
		}
		ReplyError(frontend, cmd.Id(), e)
		return

	case err == wallet.ErrWalletLocked:
		ReplyError(frontend, cmd.Id(), &btcjson.ErrWalletUnlockNeeded)
		return

	case err != nil:
		e := &btcjson.Error{
			Code:    btcjson.ErrInternal.Code,
			Message: err.Error(),
		}
		ReplyError(frontend, cmd.Id(), e)
		return
	}

	// If a change address was added, mark wallet as dirty, sync to disk,
	// and request updates for change address.
	if len(createdTx.changeAddr) != 0 {
		w.dirty = true
		if err := w.writeDirtyToDisk(); err != nil {
			log.Errorf("cannot write dirty wallet: %v", err)
		}
		w.ReqNewTxsForAddress(createdTx.changeAddr)
	}

	// Create sendrawtransaction request with hexstring of the raw tx.
	n := <-NewJSONID
	var id interface{} = fmt.Sprintf("btcwallet(%v)", n)
	m, err := btcjson.CreateMessageWithId("sendrawtransaction", id,
		hex.EncodeToString(createdTx.rawTx))
	if err != nil {
		e := &btcjson.Error{
			Code:    btcjson.ErrInternal.Code,
			Message: err.Error(),
		}
		ReplyError(frontend, cmd.Id(), e)
		return
	}

	// Set up a reply handler to respond to the btcd reply.
	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}, err *btcjson.Error) bool {
		return handleSendRawTxReply(frontend, cmd, result, err, w,
			createdTx)
	}
	replyHandlers.Unlock()

	// Send sendrawtransaction request to btcd.
	btcdMsgs <- m
}

func handleSendRawTxReply(frontend chan []byte, icmd btcjson.Cmd,
	result interface{}, err *btcjson.Error, w *BtcWallet,
	txInfo *CreatedTx) bool {

	if err != nil {
		ReplyError(frontend, icmd.Id(), err)
		return true
	}

	// Remove previous unspent outputs now spent by the tx.
	w.UtxoStore.Lock()
	modified := w.UtxoStore.s.Remove(txInfo.inputs)

	// Add unconfirmed change utxo (if any) to UtxoStore.
	if txInfo.changeUtxo != nil {
		w.UtxoStore.s = append(w.UtxoStore.s, txInfo.changeUtxo)
		w.ReqSpentUtxoNtfn(txInfo.changeUtxo)
		modified = true
	}

	if modified {
		w.UtxoStore.dirty = true
		w.UtxoStore.Unlock()
		if err := w.writeDirtyToDisk(); err != nil {
			log.Errorf("cannot sync dirty wallet: %v", err)
		}

		// Notify all frontends of new account balances.
		confirmed := w.CalculateBalance(1)
		unconfirmed := w.CalculateBalance(0) - confirmed
		NotifyWalletBalance(frontendNotificationMaster, w.name, confirmed)
		NotifyWalletBalanceUnconfirmed(frontendNotificationMaster, w.name, unconfirmed)
	} else {
		w.UtxoStore.Unlock()
	}

	// btcd cannot be trusted to successfully relay the tx to the
	// Bitcoin network.  Even if this succeeds, the rawtx must be
	// saved and checked for an appearence in a later block. btcd
	// will make a best try effort, but ultimately it's btcwallet's
	// responsibility.
	//
	// Add hex string of raw tx to sent tx pool.  If btcd disconnects
	// and is reconnected, these txs are resent.
	UnminedTxs.Lock()
	UnminedTxs.m[TXID(result.(string))] = txInfo
	UnminedTxs.Unlock()

	log.Debugf("successfully sent transaction %v", result)
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

// SetTxFee sets the global transaction fee added to transactions.
func SetTxFee(frontend chan []byte, icmd btcjson.Cmd) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.SetTxFeeCmd)
	if !ok {
		ReplyError(frontend, icmd.Id(), &btcjson.ErrInternal)
		return
	}

	// Check that amount is not negative.
	if cmd.Amount < 0 {
		e := &btcjson.Error{
			Code:    btcjson.ErrInvalidParams.Code,
			Message: "amount cannot be negative",
		}
		ReplyError(frontend, cmd.Id(), e)
		return
	}

	// Set global tx fee.
	//
	// TODO(jrick): this must be a fee per kB.
	// TODO(jrick): need to notify all frontends of new tx fee.
	TxFee.Lock()
	TxFee.i = cmd.Amount
	TxFee.Unlock()

	// A boolean true result is returned upon success.
	ReplySuccess(frontend, cmd.Id(), true)
}

// CreateEncryptedWallet creates a new account with an encrypted
// wallet.  If an account with the same name as the requested account
// name already exists, an invalid account name error is returned to
// the client.
//
// Wallets will be created on TestNet3, or MainNet if btcwallet is run with
// the --mainnet option.
func CreateEncryptedWallet(frontend chan []byte, icmd btcjson.Cmd) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.CreateEncryptedWalletCmd)
	if !ok {
		ReplyError(frontend, icmd.Id(), &btcjson.ErrInternal)
		return
	}

	// Grab the account map lock and defer the unlock.  If an
	// account is successfully created, it will be added to the
	// map while the lock is held.
	wallets.Lock()
	defer wallets.Unlock()

	// Does this wallet already exist?
	if _, ok = wallets.m[cmd.Account]; ok {
		ReplyError(frontend, cmd.Id(),
			&btcjson.ErrWalletInvalidAccountName)
		return
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
		e := &btcjson.Error{
			Code:    btcjson.ErrInternal.Code,
			Message: "btcd disconnected",
		}
		ReplyError(frontend, cmd.Id(), e)
		return
	}

	// Create new wallet in memory.
	wlt, err := wallet.NewWallet(cmd.Account, cmd.Description,
		[]byte(cmd.Passphrase), net, &bs)
	if err != nil {
		log.Error("Error creating wallet: " + err.Error())
		ReplyError(frontend, cmd.Id(), &btcjson.ErrInternal)
		return
	}

	// Create new account with the wallet.  A new JSON ID is set for
	// transaction notifications.
	bw := &BtcWallet{
		Wallet:         wlt,
		name:           cmd.Account,
		dirty:          true,
		NewBlockTxSeqN: <-NewJSONID,
	}

	// Begin tracking account against a connected btcd.
	//
	// TODO(jrick): this should *only* happen if btcd is connected.
	bw.Track()

	// Save the account in the global account map.  The mutex is
	// already held at this point, and will be unlocked when this
	// func returns.
	wallets.m[cmd.Account] = bw

	// Write new wallet to disk.
	if err := bw.writeDirtyToDisk(); err != nil {
		log.Errorf("cannot sync dirty wallet: %v", err)
	}

	// Notify all frontends of this new account, and its balance.
	NotifyBalances(frontendNotificationMaster)

	// A nil reply is sent upon successful wallet creation.
	ReplySuccess(frontend, cmd.Id(), nil)
}

// WalletIsLocked responds to the walletislocked extension request by
// replying with the current lock state (false for unlocked, true for
// locked) of an account.  An error is returned if the requested account
// does not exist.
func WalletIsLocked(frontend chan []byte, icmd btcjson.Cmd) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.WalletIsLockedCmd)
	if !ok {
		ReplyError(frontend, icmd.Id(), &btcjson.ErrInternal)
		return
	}

	// Check that the account specified in the request exists.
	w, ok := wallets.m[cmd.Account]
	if !ok {
		ReplyError(frontend, cmd.Id(),
			&btcjson.ErrWalletInvalidAccountName)
		return
	}

	// Reply with true for a locked wallet, and false for unlocked.
	ReplySuccess(frontend, cmd.Id(), w.IsLocked())
}

// WalletLock responds to walletlock request by locking the wallet,
// replying with an error if the wallet is already locked.
//
// TODO(jrick): figure out how multiple wallets/accounts will work
// with this.  Lock all the wallets, like if all accounts are locked
// for one bitcoind wallet?
func WalletLock(frontend chan []byte, icmd btcjson.Cmd) {
	if w, ok := wallets.m[""]; ok {
		if err := w.Lock(); err != nil {
			ReplyError(frontend, icmd.Id(),
				&btcjson.ErrWalletWrongEncState)
			return
		}
		ReplySuccess(frontend, icmd.Id(), nil)
		NotifyWalletLockStateChange("", true)
	}
}

// WalletPassphrase responds to the walletpassphrase request by unlocking
// the wallet.  The decryption key is saved in the wallet until timeout
// seconds expires, after which the wallet is locked.
//
// TODO(jrick): figure out how to do this for non-default accounts.
func WalletPassphrase(frontend chan []byte, icmd btcjson.Cmd) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.WalletPassphraseCmd)
	if !ok {
		ReplyError(frontend, icmd.Id(), &btcjson.ErrInternal)
		return
	}

	if w, ok := wallets.m[""]; ok {
		if err := w.Unlock([]byte(cmd.Passphrase)); err != nil {
			ReplyError(frontend, cmd.Id(),
				&btcjson.ErrWalletPassphraseIncorrect)
			return
		}
		ReplySuccess(frontend, cmd.Id(), nil)
		NotifyWalletLockStateChange("", false)
		go func() {
			time.Sleep(time.Second * time.Duration(int64(cmd.Timeout)))
			w.Lock()
			NotifyWalletLockStateChange("", true)
		}()
	}
}

// AccountNtfn is a struct for marshalling any generic notification
// about a account for a wallet frontend.
//
// TODO(jrick): move to btcjson so it can be shared with frontends?
type AccountNtfn struct {
	Account      string      `json:"account"`
	Notification interface{} `json:"notification"`
}

// NotifyWalletLockStateChange sends a notification to all frontends
// that the wallet has just been locked or unlocked.
func NotifyWalletLockStateChange(account string, locked bool) {
	var id interface{} = "btcwallet:newwalletlockstate"
	m := btcjson.Reply{
		Result: &AccountNtfn{
			Account:      account,
			Notification: locked,
		},
		Id: &id,
	}
	msg, _ := json.Marshal(&m)
	frontendNotificationMaster <- msg
}

// NotifyWalletBalance sends a confirmed account balance notification
// to a frontend.
func NotifyWalletBalance(frontend chan []byte, account string, balance float64) {
	var id interface{} = "btcwallet:accountbalance"
	m := btcjson.Reply{
		Result: &AccountNtfn{
			Account:      account,
			Notification: balance,
		},
		Id: &id,
	}
	msg, _ := json.Marshal(&m)
	frontend <- msg
}

// NotifyWalletBalanceUnconfirmed  sends a confirmed account balance
// notification to a frontend.
func NotifyWalletBalanceUnconfirmed(frontend chan []byte, account string, balance float64) {
	var id interface{} = "btcwallet:accountbalanceunconfirmed"
	m := btcjson.Reply{
		Result: &AccountNtfn{
			Account:      account,
			Notification: balance,
		},
		Id: &id,
	}
	msg, _ := json.Marshal(&m)
	frontend <- msg
}
