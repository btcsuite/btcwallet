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
	"encoding/json"
	"fmt"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcwallet/wallet"
	"sync"
	"time"
)

// Errors
var (
	// Standard JSON-RPC 2.0 errors
	InvalidRequest = btcjson.Error{
		Code:    -32600,
		Message: "Invalid request",
	}
	MethodNotFound = btcjson.Error{
		Code:    -32601,
		Message: "Method not found",
	}
	InvalidParams = btcjson.Error{
		Code:    -32602,
		Message: "Invalid paramaters",
	}
	InternalError = btcjson.Error{
		Code:    -32603,
		Message: "Internal error",
	}
	ParseError = btcjson.Error{
		Code:    -32700,
		Message: "Parse error",
	}

	// General application defined errors
	MiscError = btcjson.Error{
		Code:    -1,
		Message: "Miscellaneous error",
	}
	ForbiddenBySafeMode = btcjson.Error{
		Code:    -2,
		Message: "Server is in safe mode, and command is not allowed in safe mode",
	}
	TypeError = btcjson.Error{
		Code:    -3,
		Message: "Unexpected type was passed as parameter",
	}
	InvalidAddressOrKey = btcjson.Error{
		Code:    -5,
		Message: "Invalid address or key",
	}
	OutOfMemory = btcjson.Error{
		Code:    -7,
		Message: "Ran out of memory during operation",
	}
	InvalidParameter = btcjson.Error{
		Code:    -8,
		Message: "Invalid, missing or duplicate parameter",
	}
	DatabaseError = btcjson.Error{
		Code:    -20,
		Message: "Database error",
	}
	DeserializationError = btcjson.Error{
		Code:    -22,
		Message: "Error parsing or validating structure in raw format",
	}

	// Wallet errors
	WalletError = btcjson.Error{
		Code:    -4,
		Message: "Unspecified problem with wallet",
	}
	WalletInsufficientFunds = btcjson.Error{
		Code:    -6,
		Message: "Not enough funds in wallet or account",
	}
	WalletInvalidAccountName = btcjson.Error{
		Code:    -11,
		Message: "Invalid account name",
	}
	WalletKeypoolRanOut = btcjson.Error{
		Code:    -12,
		Message: "Keypool ran out, call keypoolrefill first",
	}
	WalletUnlockNeeded = btcjson.Error{
		Code:    -13,
		Message: "Enter the wallet passphrase with walletpassphrase first",
	}
	WalletPassphraseIncorrect = btcjson.Error{
		Code:    -14,
		Message: "The wallet passphrase entered was incorrect",
	}
	WalletWrongEncState = btcjson.Error{
		Code:    -15,
		Message: "Command given in wrong wallet encryption state",
	}
	WalletEncryptionFailed = btcjson.Error{
		Code:    -16,
		Message: "Failed to encrypt the wallet",
	}
	WalletAlreadyUnlocked = btcjson.Error{
		Code:    -17,
		Message: "Wallet is already unlocked",
	}
)

var (
	// seq holds the btcwallet sequence number for frontend messages
	// which must be sent to and received from btcd.  A Mutex protects
	// against concurrent access.
	seq = struct {
		sync.Mutex
		n uint64
	}{}

	// replyRouter maps uint64 ids to reply channels, so btcd replies can
	// be routed to the correct frontend.
	replyRouter = struct {
		sync.Mutex
		m map[uint64]chan []byte
	}{
		m: make(map[uint64]chan []byte),
	}
)

// ProcessFrontendMsg checks the message sent from a frontend.  If the
// message method is one that must be handled by btcwallet, the request
// is processed here.  Otherwise, the message is sent to btcd.
func ProcessFrontendMsg(reply chan []byte, msg []byte) {
	cmd, err := btcjson.JSONGetMethod(msg)
	if err != nil {
		log.Error("Unable to parse JSON method from message.")
		return
	}

	switch cmd {
	// Standard bitcoind methods
	case "getaddressesbyaccount":
		GetAddressesByAccount(reply, msg)
	case "getbalance":
		GetBalance(reply, msg)
	case "getnewaddress":
		GetNewAddress(reply, msg)
	case "walletlock":
		WalletLock(reply, msg)
	case "walletpassphrase":
		WalletPassphrase(reply, msg)

	// btcwallet extensions
	case "createencryptedwallet":
		CreateEncryptedWallet(reply, msg)
	case "walletislocked":
		WalletIsLocked(reply, msg)

	default:
		// btcwallet does not understand method.  Pass to btcd.
		log.Info("Unknown btcwallet method ", cmd)

		seq.Lock()
		n := seq.n
		seq.n++
		seq.Unlock()

		var m map[string]interface{}
		json.Unmarshal(msg, &m)
		m["id"] = fmt.Sprintf("btcwallet(%v)-%v", n, m["id"])
		newMsg, err := json.Marshal(m)
		if err != nil {
			log.Info("Error marshalling json: " + err.Error())
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
func GetAddressesByAccount(reply chan []byte, msg []byte) {
	var v map[string]interface{}
	json.Unmarshal(msg, &v)
	params := v["params"].([]interface{})

	var result interface{}
	wallets.RLock()
	w := wallets.m[params[0].(string)]
	wallets.RUnlock()
	if w != nil {
		result = w.Wallet.GetActiveAddresses()
	} else {
		result = []interface{}{}
	}
	ReplySuccess(reply, v["id"], result)
}

// GetBalance replies with the balance for an account (wallet).  If
// the requested wallet does not exist, a JSON error will be returned to
// the client.
//
// TODO(jrick): Actually calculate correct balance.
func GetBalance(reply chan []byte, msg []byte) {
	var v map[string]interface{}
	json.Unmarshal(msg, &v)
	params := v["params"].([]interface{})
	var wname string
	conf := 1
	if len(params) > 0 {
		if s, ok := params[0].(string); ok {
			wname = s
		} else {
			ReplyError(reply, v["id"], &InvalidParams)
		}
	}
	if len(params) > 1 {
		if f, ok := params[1].(float64); ok {
			conf = int(f)
		} else {
			ReplyError(reply, v["id"], &InvalidParams)
		}
	}

	wallets.RLock()
	w := wallets.m[wname]
	wallets.RUnlock()
	var result interface{}
	if w != nil {
		result = w.CalculateBalance(conf)
		ReplySuccess(reply, v["id"], result)
	} else {
		e := WalletInvalidAccountName
		e.Message = fmt.Sprintf("Wallet for account '%s' does not exist.", wname)
		ReplyError(reply, v["id"], &e)
	}
}

// GetNewAddress gets or generates a new address for an account.  If
// the requested wallet does not exist, a JSON error will be returned to
// the client.
func GetNewAddress(reply chan []byte, msg []byte) {
	var v map[string]interface{}
	json.Unmarshal(msg, &v)
	params := v["params"].([]interface{})
	var wname string
	if len(params) == 0 || params[0].(string) == "" {
		wname = ""
	} else {
		wname = "params[0].(string)"
	}

	wallets.RLock()
	w := wallets.m[wname]
	wallets.RUnlock()
	if w != nil {
		// TODO(jrick): generate new addresses if the address pool is empty.
		addr := w.NextUnusedAddress()
		ReplySuccess(reply, v["id"], addr)
	} else {
		e := WalletInvalidAccountName
		e.Message = fmt.Sprintf("Wallet for account '%s' does not exist.", wname)
		ReplyError(reply, v["id"], &e)
	}
}

// CreateEncryptedWallet creates a new encrypted wallet.  The form of the command is:
//
//  createencryptedwallet [account] [description] [passphrase]
//
// All three parameters are required, and must be of type string.  If
// the wallet specified by account already exists, an invalid account
// name error is returned to the client.
func CreateEncryptedWallet(reply chan []byte, msg []byte) {
	var v map[string]interface{}
	json.Unmarshal(msg, &v)
	params := v["params"].([]interface{})
	var wname string
	if len(params) != 3 {
		ReplyError(reply, v["id"], &InvalidParams)
		return
	}
	wname, ok1 := params[0].(string)
	desc, ok2 := params[1].(string)
	pass, ok3 := params[2].(string)
	if !ok1 || !ok2 || !ok3 {
		ReplyError(reply, v["id"], &InvalidParams)
		return
	}

	// Does this wallet already exist?
	wallets.RLock()
	if w := wallets.m[wname]; w != nil {
		e := WalletInvalidAccountName
		e.Message = "Wallet already exists."
		ReplyError(reply, v["id"], &e)
		return
	}
	wallets.RUnlock()

	w, err := wallet.NewWallet(wname, desc, []byte(pass))
	if err != nil {
		log.Error("Error creating wallet: " + err.Error())
		ReplyError(reply, v["id"], &InternalError)
		return
	}

	// Grab a new unique sequence number for tx notifications in new blocks.
	seq.Lock()
	n := seq.n
	seq.n++
	seq.Unlock()

	bw := &BtcWallet{
		Wallet:         w,
		NewBlockTxSeqN: n,
	}
	// TODO(jrick): only begin tracking wallet if btcwallet is already
	// connected to btcd.
	bw.Track()

	wallets.Lock()
	wallets.m[wname] = bw
	wallets.Unlock()
	ReplySuccess(reply, v["id"], nil)
}

// WalletIsLocked returns whether the wallet used by the specified
// account, or default account, is locked.
func WalletIsLocked(reply chan []byte, msg []byte) {
	var v map[string]interface{}
	json.Unmarshal(msg, &v)
	params := v["params"].([]interface{})
	account := ""
	if len(params) > 0 {
		if acct, ok := params[0].(string); ok {
			account = acct
		} else {
			ReplyError(reply, v["id"], &InvalidParams)
			return
		}
	}
	wallets.RLock()
	w := wallets.m[account]
	wallets.RUnlock()
	if w != nil {
		result := w.IsLocked()
		ReplySuccess(reply, v["id"], result)
	} else {
		ReplyError(reply, v["id"], &WalletInvalidAccountName)
	}
}

// WalletLock locks the wallet.
//
// TODO(jrick): figure out how multiple wallets/accounts will work
// with this.
func WalletLock(reply chan []byte, msg []byte) {
	var v map[string]interface{}
	json.Unmarshal(msg, &v)
	wallets.RLock()
	w := wallets.m[""]
	wallets.RUnlock()
	if w != nil {
		if err := w.Lock(); err != nil {
			ReplyError(reply, v["id"], &WalletWrongEncState)
		} else {
			ReplySuccess(reply, v["id"], nil)
			NotifyWalletLockStateChange(reply, true)
		}
	}
}

// WalletPassphrase stores the decryption key for the default account,
// unlocking the wallet.
//
// TODO(jrick): figure out how multiple wallets/accounts will work
// with this.
func WalletPassphrase(reply chan []byte, msg []byte) {
	var v map[string]interface{}
	json.Unmarshal(msg, &v)
	params := v["params"].([]interface{})
	if len(params) != 2 {
		ReplyError(reply, v["id"], &InvalidParams)
		return
	}
	passphrase, ok1 := params[0].(string)
	timeout, ok2 := params[1].(float64)
	if !ok1 || !ok2 {
		ReplyError(reply, v["id"], &InvalidParams)
		return
	}

	wallets.RLock()
	w := wallets.m[""]
	wallets.RUnlock()
	if w != nil {
		if err := w.Unlock([]byte(passphrase)); err != nil {
			ReplyError(reply, v["id"], &WalletPassphraseIncorrect)
			return
		}
		ReplySuccess(reply, v["id"], nil)
		NotifyWalletLockStateChange(reply, false)
		go func() {
			time.Sleep(time.Second * time.Duration(int64(timeout)))
			w.Lock()
			NotifyWalletLockStateChange(reply, true)
		}()
	}
}

// NotifyWalletLockStateChange sends a notification to all frontends
// that the wallet has just been locked or unlocked.
func NotifyWalletLockStateChange(reply chan []byte, locked bool) {
	var id interface{} = "btcwallet:newwalletlockstate"
	m := btcjson.Reply{
		Result: locked,
		Id:     &id,
	}
	msg, _ := json.Marshal(&m)
	frontendNotificationMaster <- msg
}
