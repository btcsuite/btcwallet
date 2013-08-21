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
	"time"
	"sync"
)

// Errors
var (
	// Standard JSON-RPC 2.0 errors
	InvalidRequest = btcjson.Error{
		Code: -32600,
		Message: "Invalid request",
	}
	MethodNotFound = btcjson.Error{
		Code: -32601,
		Message: "Method not found",
	}
	InvalidParams = btcjson.Error{
		Code: -32602,
		Message: "Invalid paramaters",
	}
	InternalError = btcjson.Error{
		Code: -32603,
		Message: "Internal error",
	}
	ParseError = btcjson.Error{
		Code: -32700,
		Message: "Parse error",
	}

	// General application defined errors
	MiscError = btcjson.Error{
		Code: -1,
		Message: "Miscellaneous error",
	}
	ForbiddenBySafeMode = btcjson.Error{
		Code: -2,
		Message: "Server is in safe mode, and command is not allowed in safe mode",
	}
	TypeError = btcjson.Error{
		Code: -3,
		Message: "Unexpected type was passed as parameter",
	}
	InvalidAddressOrKey = btcjson.Error{
		Code: -5,
		Message: "Invalid address or key",
	}
	OutOfMemory = btcjson.Error{
		Code: -7,
		Message: "Ran out of memory during operation",
	}
	InvalidParameter = btcjson.Error{
		Code: -8,
		Message: "Invalid, missing or duplicate parameter",
	}
	DatabaseError = btcjson.Error{
		Code: -20,
		Message: "Database error",
	}
	DeserializationError = btcjson.Error{
		Code: -22,
		Message: "Error parsing or validating structure in raw format",
	}

	// Wallet errors
	WalletError = btcjson.Error{
		Code: -4,
		Message: "Unspecified problem with wallet",
	}
	WalletInsufficientFunds = btcjson.Error{
		Code: -6,
		Message: "Not enough funds in wallet or account",
	}
	WalletInvalidAccountName = btcjson.Error{
		Code: -11,
		Message: "Invalid account name",
	}
	WalletKeypoolRanOut = btcjson.Error{
		Code: -12,
		Message: "Keypool ran out, call keypoolrefill first",
	}
	WalletUnlockNeeded = btcjson.Error{
		Code: -13,
		Message: "Enter the wallet passphrase with walletpassphrase first",
	}
	WalletPassphraseIncorrect = btcjson.Error{
		Code: -14,
		Message: "The wallet passphrase entered was incorrect",
	}
	WalletWrongEncState = btcjson.Error{
		Code: -15,
		Message: "Command given in wrong wallet encryption state",
	}
	WalletEncryptionFailed = btcjson.Error{
		Code: -16,
		Message: "Failed to encrypt the wallet",
	}
	WalletAlreadyUnlocked = btcjson.Error{
		Code: -17,
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
	case "getaddressesbyaccount":
		GetAddressesByAccount(reply, msg)
	case "getnewaddress":
		GetNewAddress(reply, msg)
	case "walletlock":
		WalletLock(reply, msg)
	case "walletpassphrase":
		WalletPassphrase(reply, msg)
	default:
		// btcwallet does not understand method.  Pass to btcd.
		log.Info("Unknown btcwallet method", cmd)

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
		Id: &id,
	}
	if mr, err := json.Marshal(r); err != nil {
		reply <- mr
	}
}

// GetAddressesByAccount Gets all addresses for an account.
func GetAddressesByAccount(reply chan []byte, msg []byte) {
	var v map[string]interface{}
	json.Unmarshal(msg, &v)
	params := v["params"].([]interface{})
	id := v["id"]
	r := btcjson.Reply{
		Id: &id,
	}
	if w := wallets[params[0].(string)]; w != nil {
		r.Result = w.GetActiveAddresses()
	} else {
		r.Result = []interface{}{}
	}
	mr, err := json.Marshal(r)
	if err != nil {
		log.Info("Error marshalling reply: %v", err)
		return
	}
	reply <- mr
}

// GetNewAddress gets or generates a new address for an account.
//
// TODO(jrick): support non-default account wallets.
func GetNewAddress(reply chan []byte, msg []byte) {
	var v map[string]interface{}
	json.Unmarshal(msg, &v)
	params := v["params"].([]interface{})
	if len(params) == 0 || params[0].(string) == "" {
		if w := wallets[""]; w != nil {
			addr := w.NextUnusedAddress()
			id := v["id"]
			r := btcjson.Reply{
				Result: addr,
				Id:     &id,
			}
			mr, err := json.Marshal(r)
			if err != nil {
				log.Info("Error marshalling reply: %v", err)
				return
			}
			reply <- mr
		}
	}
}

// WalletLock locks the wallet.
//
// TODO(jrick): figure out how multiple wallets/accounts will work
// with this.
func WalletLock(reply chan []byte, msg []byte) {
	// TODO(jrick)
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

	if w := wallets[""]; w != nil {
		if err := w.Unlock([]byte(passphrase)); err != nil {
			ReplyError(reply, v["id"], &WalletPassphraseIncorrect)
			return
		}
		go func() {
			time.Sleep(time.Second * time.Duration(int64(timeout)))
			w.Lock()
		}()
	}
}
