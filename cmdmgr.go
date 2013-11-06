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
	"time"
)

var (
	// ErrBtcdDisconnected describes an error where an operation cannot
	// successfully complete due to btcd not being connected to
	// btcwallet.
	ErrBtcdDisconnected = errors.New("btcd disconnected")
)

// ProcessFrontendMsg checks the message sent from a frontend.  If the
// message method is one that must be handled by btcwallet, the request
// is processed here.  Otherwise, the message is sent to btcd.
func ProcessFrontendMsg(reply chan []byte, msg []byte) {
	var jsonMsg btcjson.Message
	if err := json.Unmarshal(msg, &jsonMsg); err != nil {
		log.Errorf("ProcessFrontendMsg: Cannot unmarshal message: %v",
			err)
		return
	}

	switch jsonMsg.Method {
	// Standard bitcoind methods
	case "getaddressesbyaccount":
		GetAddressesByAccount(reply, &jsonMsg)
	case "getbalance":
		GetBalance(reply, &jsonMsg)
	case "getnewaddress":
		GetNewAddress(reply, &jsonMsg)
	case "listaccounts":
		ListAccounts(reply, &jsonMsg)
	case "sendfrom":
		SendFrom(reply, &jsonMsg)
	case "sendmany":
		SendMany(reply, &jsonMsg)
	case "settxfee":
		SetTxFee(reply, &jsonMsg)
	case "walletlock":
		WalletLock(reply, &jsonMsg)
	case "walletpassphrase":
		WalletPassphrase(reply, &jsonMsg)

	// btcwallet extensions
	case "createencryptedwallet":
		CreateEncryptedWallet(reply, &jsonMsg)
	case "getbalances":
		GetBalances(reply, &jsonMsg)
	case "walletislocked":
		WalletIsLocked(reply, &jsonMsg)

	default:
		// btcwallet does not understand method.  Pass to btcd.
		n := <-NewJSONID
		var id interface{} = fmt.Sprintf("btcwallet(%v)-%v", n,
			jsonMsg.Id)
		jsonMsg.Id = &id
		newMsg, err := json.Marshal(jsonMsg)
		if err != nil {
			log.Errorf("ProcessFrontendMsg: Cannot marshal message: %v",
				err)
			return
		}
		replyRouter.Lock()
		replyRouter.m[n] = reply
		replyRouter.Unlock()
		btcdMsgs <- newMsg
	}
}

// ReplyError creates and marshalls a btcjson.Reply with the error e,
// sending the reply to a reply channel.
func ReplyError(reply chan []byte, id interface{}, e *btcjson.Error) {
	r := btcjson.Reply{
		Error: e,
		Id:    &id,
	}
	if mr, err := json.Marshal(r); err == nil {
		reply <- mr
	} else {
		log.Errorf("Cannot marshal json reply: %v", err)
	}
}

// ReplySuccess creates and marshalls a btcjson.Reply with the result r,
// sending the reply to a reply channel.
func ReplySuccess(reply chan []byte, id interface{}, result interface{}) {
	r := btcjson.Reply{
		Result: result,
		Id:     &id,
	}
	if mr, err := json.Marshal(r); err == nil {
		reply <- mr
	}
}

// GetAddressesByAccount replies with all addresses for an account.
func GetAddressesByAccount(reply chan []byte, msg *btcjson.Message) {
	e := btcjson.ErrInvalidParams

	// TODO(jrick): check if we can make btcjson.Message.Params
	// a []interface{} to avoid this.
	params, ok := msg.Params.([]interface{})
	if !ok {
		ReplyError(reply, msg.Id, &e)
		return
	}
	account, ok := params[0].(string)
	if !ok {
		e.Message = "account is not a string"
		ReplyError(reply, msg.Id, &e)
		return
	}

	var result []string
	if w := wallets.m[account]; w != nil {
		result = w.SortedActivePaymentAddresses()
	} else {
		ReplyError(reply, msg.Id, &btcjson.ErrWalletInvalidAccountName)
		return
	}

	ReplySuccess(reply, msg.Id, result)
}

// GetBalance replies with the balance for an account (wallet).  If
// the requested wallet does not exist, a JSON error will be returned to
// the client.
func GetBalance(reply chan []byte, msg *btcjson.Message) {
	params, ok := msg.Params.([]interface{})
	if !ok {
		log.Error("GetBalance: Cannot parse parameters.")
		return
	}
	var wname string
	conf := 1
	if len(params) > 0 {
		if s, ok := params[0].(string); ok {
			wname = s
		} else {
			ReplyError(reply, msg.Id, &btcjson.ErrInvalidParams)
		}
	}
	if len(params) > 1 {
		if f, ok := params[1].(float64); ok {
			conf = int(f)
		} else {
			ReplyError(reply, msg.Id, &btcjson.ErrInvalidParams)
		}
	}

	var result interface{}
	if w := wallets.m[wname]; w != nil {
		result = w.CalculateBalance(conf)
		ReplySuccess(reply, msg.Id, result)
	} else {
		e := btcjson.ErrWalletInvalidAccountName
		e.Message = fmt.Sprintf("Wallet for account '%s' does not exist.", wname)
		ReplyError(reply, msg.Id, &e)
	}
}

// GetBalances responds to the extension 'getbalances' command,
// replying with account balances for a single wallet request.
func GetBalances(reply chan []byte, msg *btcjson.Message) {
	NotifyBalances(reply)
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

// GetNewAddress gets or generates a new address for an account.  If
// the requested wallet does not exist, a JSON error will be returned to
// the client.
func GetNewAddress(reply chan []byte, msg *btcjson.Message) {
	e := btcjson.ErrInvalidParams
	params, ok := msg.Params.([]interface{})
	if !ok {
		ReplyError(reply, msg.Id, &e)
		return
	}
	var wname string
	if len(params) > 0 {
		var ok bool
		if wname, ok = params[0].(string); !ok {
			e.Message = "account is not a string"
			ReplyError(reply, msg.Id, &e)
			return
		}
	}

	if w := wallets.m[wname]; w != nil {
		// TODO(jrick): generate new addresses if the address pool is empty.
		addr, err := w.NextUnusedAddress()
		if err != nil {
			e := btcjson.ErrInternal
			e.Message = fmt.Sprintf("New address generation not implemented yet")
			ReplyError(reply, msg.Id, &e)
			return
		}
		w.dirty = true
		if err = w.writeDirtyToDisk(); err != nil {
			log.Errorf("cannot sync dirty wallet: %v", err)
		}
		w.ReqNewTxsForAddress(addr)
		ReplySuccess(reply, msg.Id, addr)
	} else {
		e := btcjson.ErrWalletInvalidAccountName
		e.Message = fmt.Sprintf("Wallet for account '%s' does not exist.", wname)
		ReplyError(reply, msg.Id, &e)
	}
}

// ListAccounts returns a JSON object filled with account names as
// keys and their balances as values.
func ListAccounts(reply chan []byte, msg *btcjson.Message) {
	minconf := 1
	e := btcjson.ErrInvalidParams
	params, ok := msg.Params.([]interface{})
	if ok && len(params) != 0 {
		fnum, ok := params[0].(float64)
		if !ok {
			e.Message = "minconf is not a number"
			ReplyError(reply, msg.Id, &e)
			return
		}
		minconf = int(fnum)
	}

	pairs := make(map[string]float64)

	for account, w := range wallets.m {
		pairs[account] = w.CalculateBalance(minconf)
	}

	ReplySuccess(reply, msg.Id, pairs)
}

// SendFrom creates a new transaction spending unspent transaction
// outputs for a wallet to another payment address.  Leftover inputs
// not sent to the payment address or a fee for the miner are sent
// back to a new address in the wallet.
func SendFrom(reply chan []byte, msg *btcjson.Message) {
	e := btcjson.ErrInvalidParams
	params, ok := msg.Params.([]interface{})
	if !ok {
		e.Message = "Cannot parse parameters."
		ReplyError(reply, msg.Id, &e)
		return
	}
	var fromaccount, toaddr58, comment, commentto string
	var famt, minconf float64
	if len(params) < 3 {
		e.Message = "Too few parameters."
		ReplyError(reply, msg.Id, &e)
		return
	}
	if fromaccount, ok = params[0].(string); !ok {
		e.Message = "fromaccount is not a string"
		ReplyError(reply, msg.Id, &e)
		return
	}
	if toaddr58, ok = params[1].(string); !ok {
		e.Message = "tobitcoinaddress is not a string"
		ReplyError(reply, msg.Id, &e)
		return
	}
	if famt, ok = params[2].(float64); !ok {
		e.Message = "amount is not a number"
		ReplyError(reply, msg.Id, &e)
		return
	}
	if famt < 0 {
		e.Message = "amount cannot be negative"
		ReplyError(reply, msg.Id, &e)
		return
	}
	amt, err := btcjson.JSONToAmount(famt)
	if err != nil {
		e.Message = "amount cannot be converted to integer"
		ReplyError(reply, msg.Id, &e)
		return
	}
	if len(params) > 3 {
		if minconf, ok = params[3].(float64); !ok {
			e.Message = "minconf is not a number"
			ReplyError(reply, msg.Id, &e)
			return
		}
		if minconf < 0 {
			e.Message = "minconf cannot be negative"
			ReplyError(reply, msg.Id, &e)
		}
	}
	if len(params) > 4 {
		if comment, ok = params[4].(string); !ok {
			e.Message = "comment is not a string"
			ReplyError(reply, msg.Id, &e)
			return
		}
	}
	if len(params) > 5 {
		if commentto, ok = params[5].(string); !ok {
			e.Message = "comment-to is not a string"
			ReplyError(reply, msg.Id, &e)
			return
		}
	}

	// Is wallet for this account unlocked?
	w, ok := wallets.m[fromaccount]
	if !ok {
		ReplyError(reply, msg.Id, &btcjson.ErrWalletInvalidAccountName)
		return
	}
	if w.IsLocked() {
		ReplyError(reply, msg.Id, &btcjson.ErrWalletUnlockNeeded)
		return
	}

	TxFee.Lock()
	fee := TxFee.i
	TxFee.Unlock()
	pairs := map[string]uint64{
		toaddr58: uint64(amt),
	}
	createdTx, err := w.txToPairs(pairs, uint64(fee), int(minconf))
	if err != nil {
		e := btcjson.ErrInternal
		e.Message = err.Error()
		ReplyError(reply, msg.Id, &e)
		return
	}

	// Request updates for change address.
	w.ReqNewTxsForAddress(createdTx.changeAddr)

	// Send rawtx off to btcd
	n := <-NewJSONID
	var id interface{} = fmt.Sprintf("btcwallet(%v)", n)
	m, err := btcjson.CreateMessageWithId("sendrawtransaction", id,
		hex.EncodeToString(createdTx.rawTx))
	if err != nil {
		e := btcjson.ErrInternal
		e.Message = err.Error()
		ReplyError(reply, msg.Id, &e)
		return
	}
	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}, err *btcjson.Error) bool {
		if err != nil {
			ReplyError(reply, msg.Id, err)
			return true
		}

		// TODO(jrick): btcd cannot be trusted to successfully relay the
		// tx to the Bitcoin network.  Even if this succeeds, the rawtx
		// must be saved and checked for if it exists in a later block.
		// btcd will make a best try effort, but ultimately it's
		// btcwallet's responsibility.

		// Remove previous unspent outputs now spent by the tx.
		w.UtxoStore.Lock()
		modified := w.UtxoStore.s.Remove(createdTx.inputs)

		// Add unconfirmed change utxo (if any) to UtxoStore.
		if createdTx.changeUtxo != nil {
			w.UtxoStore.s = append(w.UtxoStore.s, createdTx.changeUtxo)
			w.ReqSpentUtxoNtfn(createdTx.changeUtxo)
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

		ReplySuccess(reply, msg.Id, result)

		// TODO(jrick): If message succeeded in being sent, save the
		// transaction details with comments.
		_, _ = comment, commentto

		return true
	}
	replyHandlers.Unlock()
	btcdMsgs <- m
}

// SendMany creates a new transaction spending unspent transaction
// outputs for a wallet to any number of  payment addresses.  Leftover
// inputs not sent to the payment address or a fee for the miner are
// sent back to a new address in the wallet.
func SendMany(reply chan []byte, msg *btcjson.Message) {
	e := btcjson.ErrInvalidParams
	params, ok := msg.Params.([]interface{})
	if !ok {
		e.Message = "Cannot parse parameters."
		ReplyError(reply, msg.Id, &e)
		return
	}
	var fromaccount, comment string
	var minconf float64
	var jsonPairs map[string]interface{}
	if len(params) < 2 {
		e.Message = "Too few parameters."
		ReplyError(reply, msg.Id, &e)
		return
	}
	if fromaccount, ok = params[0].(string); !ok {
		e.Message = "fromaccount is not a string"
		ReplyError(reply, msg.Id, &e)
		return
	}
	if jsonPairs, ok = params[1].(map[string]interface{}); !ok {
		e.Message = "address and amount pairs is not a JSON object"
		ReplyError(reply, msg.Id, &e)
		return
	}
	pairs := make(map[string]uint64)
	for toaddr58, iamt := range jsonPairs {
		famt, ok := iamt.(float64)
		if !ok {
			e.Message = "amount is not a number"
			ReplyError(reply, msg.Id, &e)
			return
		}
		if famt < 0 {
			e.Message = "amount cannot be negative"
			ReplyError(reply, msg.Id, &e)
			return
		}
		amt, err := btcjson.JSONToAmount(famt)
		if err != nil {
			e.Message = "amount cannot be converted to integer"
			ReplyError(reply, msg.Id, &e)
			return
		}
		pairs[toaddr58] = uint64(amt)
	}

	if len(params) > 2 {
		if minconf, ok = params[2].(float64); !ok {
			e.Message = "minconf is not a number"
			ReplyError(reply, msg.Id, &e)
			return
		}
		if minconf < 0 {
			e.Message = "minconf cannot be negative"
			ReplyError(reply, msg.Id, &e)
			return
		}
	}
	if len(params) > 3 {
		if comment, ok = params[3].(string); !ok {
			e.Message = "comment is not a string"
			ReplyError(reply, msg.Id, &e)
			return
		}
	}

	// Is wallet for this account unlocked?
	w, ok := wallets.m[fromaccount]
	if !ok {
		ReplyError(reply, msg.Id, &btcjson.ErrWalletInvalidAccountName)
		return
	}
	if w.IsLocked() {
		ReplyError(reply, msg.Id, &btcjson.ErrWalletUnlockNeeded)
		return
	}

	TxFee.Lock()
	fee := TxFee.i
	TxFee.Unlock()
	createdTx, err := w.txToPairs(pairs, uint64(fee), int(minconf))
	if err != nil {
		e := btcjson.ErrInternal
		e.Message = err.Error()
		ReplyError(reply, msg.Id, &e)
		return
	}

	// Request updates for change address.
	w.ReqNewTxsForAddress(createdTx.changeAddr)

	// Send rawtx off to btcd
	n := <-NewJSONID
	var id interface{} = fmt.Sprintf("btcwallet(%v)", n)
	m, err := btcjson.CreateMessageWithId("sendrawtransaction", id,
		hex.EncodeToString(createdTx.rawTx))
	if err != nil {
		e := btcjson.ErrInternal
		e.Message = err.Error()
		ReplyError(reply, msg.Id, &e)
		return
	}
	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}, err *btcjson.Error) bool {
		if err != nil {
			ReplyError(reply, msg.Id, err)
			return true
		}

		// TODO(jrick): btcd cannot be trusted to successfully relay the
		// tx to the Bitcoin network.  Even if this succeeds, the rawtx
		// must be saved and checked for if it exists in a later block.
		// btcd will make a best try effort, but ultimately it's
		// btcwallet's responsibility.

		// Remove previous unspent outputs now spent by the tx.
		w.UtxoStore.Lock()
		modified := w.UtxoStore.s.Remove(createdTx.inputs)

		// Add unconfirmed change utxo (if any) to UtxoStore.
		if createdTx.changeUtxo != nil {
			w.UtxoStore.s = append(w.UtxoStore.s, createdTx.changeUtxo)
			w.ReqSpentUtxoNtfn(createdTx.changeUtxo)
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

		// Add hex string of raw tx to sent tx pool.  If future blocks
		// do not contain a tx, a resend is attempted.
		UnminedTxs.Lock()
		UnminedTxs.m[result.(string)] = hex.EncodeToString(createdTx.rawTx)
		UnminedTxs.Unlock()

		ReplySuccess(reply, msg.Id, result)

		// TODO(jrick): If message succeeded in being sent, save the
		// transaction details with comments.
		_ = comment

		return true
	}
	replyHandlers.Unlock()
	btcdMsgs <- m
}

// SetTxFee sets the global transaction fee added to transactions.
func SetTxFee(reply chan []byte, msg *btcjson.Message) {
	e := btcjson.ErrInvalidParams
	params, ok := msg.Params.([]interface{})
	if !ok {
		ReplyError(reply, msg.Id, &e)
		return
	}
	if len(params) != 1 {
		e.Message = "Incorrect number of parameters"
		ReplyError(reply, msg.Id, &e)
		return
	}
	jsonFee, ok := params[0].(float64)
	if !ok {
		e.Message = "Amount is not a number"
		ReplyError(reply, msg.Id, &e)
		return
	}
	if jsonFee < 0 {
		e.Message = "Amount cannot be negative"
		ReplyError(reply, msg.Id, &e)
		return
	}
	fee, err := btcjson.JSONToAmount(jsonFee)
	if err != nil {
		e.Message = fmt.Sprintf("Cannot convert JSON number to int64: %v", err)
		ReplyError(reply, msg.Id, &e)
		return
	}

	// TODO(jrick): need to notify all frontends of new tx fee.
	TxFee.Lock()
	TxFee.i = fee
	TxFee.Unlock()

	ReplySuccess(reply, msg.Id, true)
}

// CreateEncryptedWallet creates a new encrypted wallet.  The form of the command is:
//
//  createencryptedwallet [account] [description] [passphrase]
//
// All three parameters are required, and must be of type string.  If
// the wallet specified by account already exists, an invalid account
// name error is returned to the client.
//
// Wallets will be created on TestNet3, or MainNet if btcwallet is run with
// the --mainnet option.
func CreateEncryptedWallet(reply chan []byte, msg *btcjson.Message) {
	e := btcjson.ErrInvalidParams
	params, ok := msg.Params.([]interface{})
	if !ok {
		ReplyError(reply, msg.Id, &e)
		return
	}
	if len(params) != 3 {
		e.Message = "Incorrect number of parameters"
		ReplyError(reply, msg.Id, &e)
		return
	}
	wname, ok := params[0].(string)
	if !ok {
		e.Message = "Account is not a string"
		ReplyError(reply, msg.Id, &e)
		return
	}
	desc, ok := params[1].(string)
	if !ok {
		e.Message = "Description is not a string"
		ReplyError(reply, msg.Id, &e)
		return
	}
	pass, ok := params[2].(string)
	if !ok {
		e.Message = "Passphrase is not a string"
		ReplyError(reply, msg.Id, &e)
		return
	}

	// Prevent two wallets with the same account name from being added.
	wallets.Lock()
	defer wallets.Unlock()

	// Does this wallet already exist?
	if w := wallets.m[wname]; w != nil {
		e := btcjson.ErrWalletInvalidAccountName
		ReplyError(reply, msg.Id, &e)
		return
	}

	var net btcwire.BitcoinNet
	if cfg.MainNet {
		net = btcwire.MainNet
	} else {
		net = btcwire.TestNet3
	}

	bs, err := GetCurBlock()
	if err != nil {
		e := btcjson.ErrInternal
		e.Message = "btcd disconnected"
		ReplyError(reply, msg.Id, &e)
		return
	}
	wlt, err := wallet.NewWallet(wname, desc, []byte(pass), net, &bs)
	if err != nil {
		log.Error("Error creating wallet: " + err.Error())
		ReplyError(reply, msg.Id, &btcjson.ErrInternal)
		return
	}

	// Create a new account, with a new JSON ID for transaction
	// notifications.
	bw := &BtcWallet{
		Wallet:         wlt,
		name:           wname,
		dirty:          true,
		NewBlockTxSeqN: <-NewJSONID,
	}
	// TODO(jrick): only begin tracking wallet if btcwallet is already
	// connected to btcd.
	bw.Track()

	wallets.m[wname] = bw

	// Write new wallet to disk.
	if err := bw.writeDirtyToDisk(); err != nil {
		log.Errorf("cannot sync dirty wallet: %v", err)
	}

	// Notify all frontends of this new account, and its balance.
	NotifyBalances(frontendNotificationMaster)

	ReplySuccess(reply, msg.Id, nil)
}

// WalletIsLocked returns whether the wallet used by the specified
// account, or default account, is locked.
func WalletIsLocked(reply chan []byte, msg *btcjson.Message) {
	params, ok := msg.Params.([]interface{})
	if !ok {
		log.Error("WalletIsLocked: Cannot parse parameters.")
	}
	account := ""
	if len(params) > 0 {
		if acct, ok := params[0].(string); ok {
			account = acct
		} else {
			ReplyError(reply, msg.Id, &btcjson.ErrInvalidParams)
			return
		}
	}

	if w := wallets.m[account]; w != nil {
		result := w.IsLocked()
		ReplySuccess(reply, msg.Id, result)
	} else {
		ReplyError(reply, msg.Id, &btcjson.ErrWalletInvalidAccountName)
	}
}

// WalletLock locks the wallet.
//
// TODO(jrick): figure out how multiple wallets/accounts will work
// with this.  Lock all the wallets, like if all accounts are locked
// for one bitcoind wallet?
func WalletLock(reply chan []byte, msg *btcjson.Message) {
	if w := wallets.m[""]; w != nil {
		if err := w.Lock(); err != nil {
			ReplyError(reply, msg.Id, &btcjson.ErrWalletWrongEncState)
		} else {
			ReplySuccess(reply, msg.Id, nil)
			NotifyWalletLockStateChange("", true)
		}
	}
}

// WalletPassphrase stores the decryption key for the default account,
// unlocking the wallet.
//
// TODO(jrick): figure out how to do this for non-default accounts.
func WalletPassphrase(reply chan []byte, msg *btcjson.Message) {
	params, ok := msg.Params.([]interface{})
	if !ok {
		log.Error("WalletPassphrase: Cannot parse parameters.")
		return
	}
	if len(params) != 2 {
		ReplyError(reply, msg.Id, &btcjson.ErrInvalidParams)
		return
	}
	passphrase, ok1 := params[0].(string)
	timeout, ok2 := params[1].(float64)
	if !ok1 || !ok2 {
		ReplyError(reply, msg.Id, &btcjson.ErrInvalidParams)
		return
	}

	if w := wallets.m[""]; w != nil {
		if err := w.Unlock([]byte(passphrase)); err != nil {
			ReplyError(reply, msg.Id, &btcjson.ErrWalletPassphraseIncorrect)
			return
		}
		ReplySuccess(reply, msg.Id, nil)
		NotifyWalletLockStateChange("", false)
		go func() {
			time.Sleep(time.Second * time.Duration(int64(timeout)))
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
