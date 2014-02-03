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
	"github.com/conformal/btcjson"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"github.com/conformal/btcws"
	"sync"
	"time"
)

type cmdHandler func(btcjson.Cmd) (interface{}, *btcjson.Error)

var rpcHandlers = map[string]cmdHandler{
	// Standard bitcoind methods (implemented)
	"dumpprivkey":            DumpPrivKey,
	"getaccount":             GetAccount,
	"getaccountaddress":      GetAccountAddress,
	"getaddressesbyaccount":  GetAddressesByAccount,
	"getbalance":             GetBalance,
	"getinfo":                GetInfo,
	"getnewaddress":          GetNewAddress,
	"getrawchangeaddress":    GetRawChangeAddress,
	"getreceivedbyaccount":   GetReceivedByAccount,
	"importprivkey":          ImportPrivKey,
	"keypoolrefill":          KeypoolRefill,
	"listaccounts":           ListAccounts,
	"listsinceblock":         ListSinceBlock,
	"listtransactions":       ListTransactions,
	"sendfrom":               SendFrom,
	"sendmany":               SendMany,
	"settxfee":               SetTxFee,
	"walletlock":             WalletLock,
	"walletpassphrase":       WalletPassphrase,
	"walletpassphrasechange": WalletPassphraseChange,

	// Standard bitcoind methods (currently unimplemented)
	"addmultisigaddress":    Unimplemented,
	"backupwallet":          Unimplemented,
	"createmultisig":        Unimplemented,
	"dumpwallet":            Unimplemented,
	"getblocktemplate":      Unimplemented,
	"getreceivedbyaddress":  Unimplemented,
	"gettransaction":        Unimplemented,
	"gettxout":              Unimplemented,
	"gettxoutsetinfo":       Unimplemented,
	"getwork":               Unimplemented,
	"importwallet":          Unimplemented,
	"listaddressgroupings":  Unimplemented,
	"listlockunspent":       Unimplemented,
	"listreceivedbyaccount": Unimplemented,
	"listreceivedbyaddress": Unimplemented,
	"listunspent":           Unimplemented,
	"lockunspent":           Unimplemented,
	"move":                  Unimplemented,
	"sendtoaddress":         Unimplemented,
	"setaccount":            Unimplemented,
	"signmessage":           Unimplemented,
	"signrawtransaction":    Unimplemented,
	"validateaddress":       Unimplemented,
	"verifymessage":         Unimplemented,

	// Standard bitcoind methods which won't be implemented by btcwallet.
	"encryptwallet": Unsupported,

	// Extensions not exclusive to websocket connections.
	"createencryptedwallet": CreateEncryptedWallet,
}

// Extensions exclusive to websocket connections.
var wsHandlers = map[string]cmdHandler{
	"exportwatchingwallet":    ExportWatchingWallet,
	"getaddressbalance":       GetAddressBalance,
	"getunconfirmedbalance":   GetUnconfirmedBalance,
	"listaddresstransactions": ListAddressTransactions,
	"listalltransactions":     ListAllTransactions,
	"recoveraddresses":        RecoverAddresses,
	"walletislocked":          WalletIsLocked,
}

// Channels to control RPCGateway
var (
	// Incoming requests from frontends
	clientRequests = make(chan *ClientRequest)

	// Incoming notifications from a bitcoin server (btcd)
	svrNtfns = make(chan btcjson.Cmd)
)

// ErrServerBusy is a custom JSON-RPC error for when a client's request
// could not be added to the server request queue for handling.
var ErrServerBusy = btcjson.Error{
	Code:    -32000,
	Message: "Server busy",
}

// RPCGateway is the common entry point for all client RPC requests and
// server notifications.  If a request needs to be handled by btcwallet,
// it is sent to WalletRequestProcessor's request queue, or dropped if the
// queue is full.  If a request is unhandled, it is recreated with a new
// JSON-RPC id and sent to btcd for handling.  Notifications are also queued
// if they cannot be immediately handled, but are never dropped (queue may
// grow infinitely large).
func RPCGateway() {
	var ntfnQueue []btcjson.Cmd
	unreadChan := make(chan btcjson.Cmd)

	for {
		var ntfnOut chan btcjson.Cmd
		var oldestNtfn btcjson.Cmd
		if len(ntfnQueue) > 0 {
			ntfnOut = handleNtfn
			oldestNtfn = ntfnQueue[0]
		} else {
			ntfnOut = unreadChan
		}

		select {
		case r := <-clientRequests:
			// Check whether to handle request or send to btcd.
			_, std := rpcHandlers[r.request.Method()]
			_, ext := wsHandlers[r.request.Method()]
			if std || ext {
				select {
				case requestQueue <- r:
				default:
					// Server busy with too many requests.
					resp := ClientResponse{
						err: &ErrServerBusy,
					}
					r.response <- &resp
				}
			} else {
				r.request.SetId(<-NewJSONID)
				request := &ServerRequest{
					request:  r.request,
					result:   nil,
					response: r.response,
				}
				CurrentServerConn().SendRequest(request)
			}

		case n := <-svrNtfns:
			ntfnQueue = append(ntfnQueue, n)

		case ntfnOut <- oldestNtfn:
			ntfnQueue = ntfnQueue[1:]
		}
	}
}

// Channels to control WalletRequestProcessor
var (
	requestQueue = make(chan *ClientRequest, 100)
	handleNtfn   = make(chan btcjson.Cmd)
)

// WalletRequestProcessor processes client requests and btcd notifications.
// Notifications are preferred over client requests.
func WalletRequestProcessor() {
	for {
		select {
		case r := <-requestQueue:
			var result interface{}
			var jsonErr *btcjson.Error
			if f, ok := rpcHandlers[r.request.Method()]; ok {
				AcctMgr.Grab()
				result, jsonErr = f(r.request)
				AcctMgr.Release()
			} else if f, ok := wsHandlers[r.request.Method()]; r.ws && ok {
				AcctMgr.Grab()
				result, jsonErr = f(r.request)
				AcctMgr.Release()
			} else {
				result, jsonErr = Unimplemented(r.request)
			}
			resp := &ClientResponse{
				result: result,
				err:    jsonErr,
			}
			r.response <- resp

		case n := <-handleNtfn:
			if f, ok := notificationHandlers[n.Method()]; ok {
				AcctMgr.Grab()
				f(n)
				AcctMgr.Release()
			}
		}
	}
}

// Unimplemented handles an unimplemented RPC request with the
// appropiate error.
func Unimplemented(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	return nil, &btcjson.ErrUnimplemented
}

// Unsupported handles a standard bitcoind RPC request which is
// unsupported by btcwallet due to design differences.
func Unsupported(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	e := btcjson.Error{
		Code:    -1,
		Message: "Request unsupported by btcwallet",
	}
	return nil, &e
}

// DumpPrivKey handles a dumpprivkey request with the private key
// for a single address, or an appropiate error if the wallet
// is locked.
func DumpPrivKey(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.DumpPrivKeyCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	addr, err := btcutil.DecodeAddr(cmd.Address)
	if err != nil {
		return nil, &btcjson.ErrInvalidAddressOrKey
	}

	switch key, err := AcctMgr.DumpWIFPrivateKey(addr); err {
	case nil:
		// Key was found.
		return key, nil

	case wallet.ErrWalletLocked:
		// Address was found, but the private key isn't
		// accessible.
		return nil, &btcjson.ErrWalletUnlockNeeded

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}
}

// DumpWallet handles a dumpwallet request by returning  all private
// keys in a wallet, or an appropiate error if the wallet is locked.
// TODO: finish this to match bitcoind by writing the dump to a file.
func DumpWallet(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	_, ok := icmd.(*btcjson.DumpWalletCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	switch keys, err := AcctMgr.DumpKeys(); err {
	case nil:
		// Reply with sorted WIF encoded private keys
		return keys, nil

	case wallet.ErrWalletLocked:
		return nil, &btcjson.ErrWalletUnlockNeeded

	default: // any other non-nil error
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}
}

// ExportWatchingWallet handles an exportwatchingwallet request by exporting
// the current account wallet as a watching wallet (with no private keys), and
// either writing the exported wallet to disk, or base64-encoding serialized
// account files and sending them back in the response.
func ExportWatchingWallet(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.ExportWatchingWalletCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	switch err {
	case nil:
		break

	case ErrNotFound:
		return nil, &btcjson.ErrWalletInvalidAccountName

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	wa, err := a.ExportWatchingWallet()
	if err != nil {
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	if cmd.Download {
		switch m, err := wa.exportBase64(); err {
		case nil:
			return m, nil

		default:
			e := btcjson.Error{
				Code:    btcjson.ErrWallet.Code,
				Message: err.Error(),
			}
			return nil, &e
		}
	}

	// Create export directory, write files there.
	if err = wa.ExportToDirectory("watchingwallet"); err != nil {
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	return nil, nil
}

// GetAddressesByAccount handles a getaddressesbyaccount request by returning
// all addresses for an account, or an error if the requested account does
// not exist.
func GetAddressesByAccount(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetAddressesByAccountCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	switch a, err := AcctMgr.Account(cmd.Account); err {
	case nil:
		// Return sorted active payment addresses.
		return a.SortedActivePaymentAddresses(), nil

	case ErrNotFound:
		return nil, &btcjson.ErrWalletInvalidAccountName

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}
}

// GetBalance handles a getbalance request by returning the balance for an
// account (wallet), or an error if the requested account does not
// exist.
func GetBalance(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetBalanceCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	balance, err := AcctMgr.CalculateBalance(cmd.Account, cmd.MinConf)
	if err != nil {
		return nil, &btcjson.ErrWalletInvalidAccountName
	}

	// Return calculated balance.
	return balance, nil
}

// GetInfo handles a getinfo request by returning the a structure containing
// information about the current state of btcwallet.
// exist.
func GetInfo(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Call down to btcd for all of the information in this command known
	// by them.  This call can not realistically ever fail.
	gicmd, _ := btcjson.NewGetInfoCmd(<-NewJSONID)
	req := NewServerRequest(gicmd, make(map[string]interface{}))
	response := <-CurrentServerConn().SendRequest(req)
	if response.Error() != nil {
		return nil, response.Error()
	}
	ret := response.Result().(map[string]interface{})

	balance := float64(0.0)
	accounts := AcctMgr.ListAccounts(1)
	for _, v := range accounts {
		balance += v
	}
	ret["walletversion"] = wallet.VersCurrent.Uint32()
	ret["balance"] = balance
	// Keypool times are not tracked. set to current time.
	ret["keypoololdest"] = time.Now().Unix()
	ret["keypoolsize"] = cfg.KeypoolSize
	TxFeeIncrement.Lock()
	ret["paytxfee"] = TxFeeIncrement.i
	TxFeeIncrement.Unlock()
	/*
	 * We don't set the following since they don't make much sense in the
	 * wallet architecture:
	 * ret["unlocked_until"]
	 * ret["errors"]
	 */

	return ret, nil
}

// GetAccount handles a getaccount request by returning the account name
// associated with a single address.
func GetAccount(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetAccountCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	// Is address valid?
	addr, err := btcutil.DecodeAddr(cmd.Address)
	if err != nil {
		return nil, &btcjson.ErrInvalidAddressOrKey
	}
	var net btcwire.BitcoinNet
	switch a := addr.(type) {
	case *btcutil.AddressPubKeyHash:
		net = a.Net()

	case *btcutil.AddressScriptHash:
		net = a.Net()

	default:
		return nil, &btcjson.ErrInvalidAddressOrKey
	}
	if net != cfg.Net() {
		return nil, &btcjson.ErrInvalidAddressOrKey
	}

	// Look up account which holds this address.
	aname, err := LookupAccountByAddress(cmd.Address)
	if err == ErrNotFound {
		e := btcjson.Error{
			Code:    btcjson.ErrInvalidAddressOrKey.Code,
			Message: "Address not found in wallet",
		}
		return nil, &e
	}

	return aname, nil
}

// GetAccountAddress handles a getaccountaddress by returning the most
// recently-created chained address that has not yet been used (does not yet
// appear in the blockchain, or any tx that has arrived in the btcd mempool).
// If the most recently-requested address has been used, a new address (the
// next chained address in the keypool) is used.  This can fail if the keypool
// runs out (and will return btcjson.ErrWalletKeypoolRanOut if that happens).
func GetAccountAddress(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetAccountAddressCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	// Lookup account for this request.
	a, err := AcctMgr.Account(cmd.Account)
	switch err {
	case nil:
		break

	case ErrNotFound:
		return nil, &btcjson.ErrWalletInvalidAccountName

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	switch addr, err := a.CurrentAddress(); err {
	case nil:
		return addr.EncodeAddress(), nil

	case wallet.ErrWalletLocked:
		return nil, &btcjson.ErrWalletKeypoolRanOut

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}
}

// GetAddressBalance handles a getaddressbalance extension request by
// returning the current balance (sum of unspent transaction output amounts)
// for a single address.
func GetAddressBalance(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.GetAddressBalanceCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	// Is address valid?
	addr, err := btcutil.DecodeAddr(cmd.Address)
	if err != nil {
		return nil, &btcjson.ErrInvalidAddressOrKey
	}
	apkh, ok := addr.(*btcutil.AddressPubKeyHash)
	if !ok || apkh.Net() != cfg.Net() {
		return nil, &btcjson.ErrInvalidAddressOrKey
	}

	// Look up account which holds this address.
	aname, err := LookupAccountByAddress(cmd.Address)
	if err == ErrNotFound {
		e := btcjson.Error{
			Code:    btcjson.ErrInvalidAddressOrKey.Code,
			Message: "Address not found in wallet",
		}
		return nil, &e
	}

	// Get the account which holds the address in the request.
	// This should not fail, so if it does, return an internal
	// error to the frontend.
	a, err := AcctMgr.Account(aname)
	if err != nil {
		return nil, &btcjson.ErrInternal
	}

	bal := a.CalculateAddressBalance(apkh, int(cmd.Minconf))
	return bal, nil
}

// GetUnconfirmedBalance handles a getunconfirmedbalance extension request
// by returning the current unconfirmed balance of an account.
func GetUnconfirmedBalance(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.GetUnconfirmedBalanceCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	// Get the account included in the request.
	a, err := AcctMgr.Account(cmd.Account)
	switch err {
	case nil:
		break

	case ErrNotFound:
		return nil, &btcjson.ErrWalletInvalidAccountName

	default:
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	confirmed := a.CalculateBalance(1)
	unconfirmed := a.CalculateBalance(0) - confirmed
	return unconfirmed, nil
}

// ImportPrivKey handles an importprivkey request by parsing
// a WIF-encoded private key and adding it to an account.
func ImportPrivKey(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.ImportPrivKeyCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	// Get the acount included in the request. Yes, Label is the
	// account name...
	a, err := AcctMgr.Account(cmd.Label)
	switch err {
	case nil:
		break

	case ErrNotFound:
		return nil, &btcjson.ErrWalletInvalidAccountName

	default:
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	pk, net, compressed, err := btcutil.DecodePrivateKey(cmd.PrivKey)
	if err != nil || net != a.Net() {
		return nil, &btcjson.ErrInvalidAddressOrKey
	}

	// Import the private key, handling any errors.
	bs := &wallet.BlockStamp{}
	switch _, err := a.ImportPrivateKey(pk, compressed, bs); err {
	case nil:
		// If the import was successful, reply with nil.
		return nil, nil

	case wallet.ErrDuplicate:
		// Do not return duplicate key errors to the client.
		return nil, nil

	case wallet.ErrWalletLocked:
		return nil, &btcjson.ErrWalletUnlockNeeded

	default:
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}
}

// KeypoolRefill handles the keypoolrefill command. Since we handle the keypool
// automatically this does nothing since refilling is never manually required.
func KeypoolRefill(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	return nil, nil
}

// NotifyBalances notifies an attached frontend of the current confirmed
// and unconfirmed account balances.
//
// TODO(jrick): Switch this to return a single JSON object
// (map[string]interface{}) of all accounts and their balances, instead of
// separate notifications for each account.
func NotifyBalances(frontend chan []byte) {
	AcctMgr.NotifyBalances(frontend)
}

// GetNewAddress handlesa getnewaddress request by returning a new
// address for an account.  If the account does not exist or the keypool
// ran out with a locked wallet, an appropiate error is returned.
func GetNewAddress(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetNewAddressCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	switch err {
	case nil:
		break

	case ErrNotFound:
		return nil, &btcjson.ErrWalletInvalidAccountName

	case ErrBtcdDisconnected:
		return nil, &ErrBtcdDisconnected

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	addr, err := a.NewAddress()
	if err != nil {
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	// Return the new payment address string.
	return addr.EncodeAddress(), nil
}

// GetRawChangeAddress handles a getrawchangeaddress request by creating
// and returning a new change address for an account.
//
// Note: bitcoind allows specifying the account as an optional parameter,
// but ignores the parameter.
func GetRawChangeAddress(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	cmd, ok := icmd.(*btcjson.GetRawChangeAddressCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	switch err {
	case nil:
		break

	case ErrNotFound:
		return nil, &btcjson.ErrWalletInvalidAccountName

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	addr, err := a.NewChangeAddress()
	if err != nil {
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	// Return the new payment address string.
	return addr.EncodeAddress(), nil
}

// GetReceivedByAccount handles a getreceivedbyaccount request by returning
// the total amount received by addresses of an account.
func GetReceivedByAccount(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	cmd, ok := icmd.(*btcjson.GetReceivedByAccountCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	switch err {
	case nil:
		break

	case ErrNotFound:
		return nil, &btcjson.ErrWalletInvalidAccountName

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	amt, err := a.TotalReceived(cmd.MinConf)
	if err != nil {
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	return amt, nil
}

// ListAccounts handles a listaccounts request by returning a map of account
// names to their balances.
func ListAccounts(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.ListAccountsCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	// Return the map.  This will be marshaled into a JSON object.
	return AcctMgr.ListAccounts(cmd.MinConf), nil
}

// ListSinceBlock handles a listsinceblock request by returning an array of maps
// with details of sent and received wallet transactions since the given block.
func ListSinceBlock(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	cmd, ok := icmd.(*btcjson.ListSinceBlockCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	height := int32(-1)
	if cmd.BlockHash != "" {
		br, err := GetBlock(CurrentServerConn(), cmd.BlockHash)
		if err != nil {
			return nil, err
		}
		height = int32(br.Height)
	}

	bs, err := GetCurBlock()
	if err != nil {
		return nil, &btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
	}

	// For the result we need the block hash for the last block counted
	// in the blockchain due to confirmations. We send this off now so that
	// it can arrive asynchronously while we figure out the rest.
	gbh, err := btcjson.NewGetBlockHashCmd(<-NewJSONID,
		int64(bs.Height)+1-int64(cmd.TargetConfirmations))
	if err != nil {
		return nil, &btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
	}

	req := NewServerRequest(gbh, new(string))
	bhChan := CurrentServerConn().SendRequest(req)

	txInfoList, err := AcctMgr.ListSinceBlock(height, bs.Height,
		cmd.TargetConfirmations)
	if err != nil {
		return nil, &btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
	}

	// Done with work, get the response.
	response := <-bhChan
	if response.Error() != nil {
		return nil, response.Error()
	}

	hash := response.Result().(*string)

	res := make(map[string]interface{})
	res["transactions"] = txInfoList
	res["lastblock"] = *hash

	return res, nil
}

// ListTransactions handles a listtransactions request by returning an
// array of maps with details of sent and recevied wallet transactions.
func ListTransactions(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.ListTransactionsCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	switch err {
	case nil:
		break

	case ErrNotFound:
		return nil, &btcjson.ErrWalletInvalidAccountName

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	switch txList, err := a.ListTransactions(cmd.From, cmd.Count); err {
	case nil:
		// Return the list of tx information.
		return txList, nil

	case ErrBtcdDisconnected:
		e := btcjson.Error{
			Code:    btcjson.ErrInternal.Code,
			Message: "btcd disconnected",
		}
		return nil, &e

	default:
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}
}

// ListAddressTransactions handles a listaddresstransactions request by
// returning an array of maps with details of spent and received wallet
// transactions.  The form of the reply is identical to listtransactions,
// but the array elements are limited to transaction details which are
// about the addresess included in the request.
func ListAddressTransactions(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.ListAddressTransactionsCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	switch err {
	case nil:
		break

	case ErrNotFound:
		return nil, &btcjson.ErrWalletInvalidAccountName

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	// Decode addresses.
	pkHashMap := make(map[string]struct{})
	for _, addrStr := range cmd.Addresses {
		addr, err := btcutil.DecodeAddr(addrStr)
		if err != nil {
			return nil, &btcjson.ErrInvalidAddressOrKey
		}
		apkh, ok := addr.(*btcutil.AddressPubKeyHash)
		if !ok || apkh.Net() != cfg.Net() {
			return nil, &btcjson.ErrInvalidAddressOrKey
		}
		pkHashMap[string(addr.ScriptAddress())] = struct{}{}
	}

	txList, err := a.ListAddressTransactions(pkHashMap)
	if err != nil {
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}
	return txList, nil
}

// ListAllTransactions handles a listalltransactions request by returning
// a map with details of sent and recevied wallet transactions.  This is
// similar to ListTransactions, except it takes only a single optional
// argument for the account name and replies with all transactions.
func ListAllTransactions(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.ListAllTransactionsCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	switch err {
	case nil:
		break

	case ErrNotFound:
		return nil, &btcjson.ErrWalletInvalidAccountName

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	switch txList, err := a.ListAllTransactions(); err {
	case nil:
		// Return the list of tx information.
		return txList, nil

	case ErrBtcdDisconnected:
		e := btcjson.Error{
			Code:    btcjson.ErrInternal.Code,
			Message: "btcd disconnected",
		}
		return nil, &e

	default:
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}
}

// SendFrom handles a sendfrom RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to another payment
// address.  Leftover inputs not sent to the payment address or a fee for
// the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func SendFrom(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.SendFromCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	// Check that signed integer parameters are positive.
	if cmd.Amount < 0 {
		e := btcjson.Error{
			Code:    btcjson.ErrInvalidParameter.Code,
			Message: "amount must be positive",
		}
		return nil, &e
	}
	if cmd.MinConf < 0 {
		e := btcjson.Error{
			Code:    btcjson.ErrInvalidParameter.Code,
			Message: "minconf must be positive",
		}
		return nil, &e
	}

	// Check that the account specified in the request exists.
	a, err := AcctMgr.Account(cmd.FromAccount)
	if err != nil {
		return nil, &btcjson.ErrWalletInvalidAccountName
	}

	// Create map of address and amount pairs.
	pairs := map[string]int64{
		cmd.ToAddress: cmd.Amount,
	}

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := a.txToPairs(pairs, cmd.MinConf)
	switch {
	case err == ErrNonPositiveAmount:
		e := btcjson.Error{
			Code:    btcjson.ErrInvalidParameter.Code,
			Message: "amount must be positive",
		}
		return nil, &e

	case err == wallet.ErrWalletLocked:
		return nil, &btcjson.ErrWalletUnlockNeeded

	case err != nil:
		e := btcjson.Error{
			Code:    btcjson.ErrInternal.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	// Mark txid as having send history so handlers adding receive history
	// wait until all send history has been written.
	SendTxHistSyncChans.add <- createdTx.txid

	// If a change address was added, sync wallet to disk and request
	// transaction notifications to the change address.
	if createdTx.changeAddr != nil {
		AcctMgr.ds.ScheduleWalletWrite(a)
		if err := AcctMgr.ds.FlushAccount(a); err != nil {
			e := btcjson.Error{
				Code:    btcjson.ErrWallet.Code,
				Message: "Cannot write account: " + err.Error(),
			}
			return nil, &e
		}
		a.ReqNewTxsForAddress(createdTx.changeAddr)
	}

	hextx := hex.EncodeToString(createdTx.rawTx)
	// NewSendRawTransactionCmd will never fail so don't check error.
	sendtx, _ := btcjson.NewSendRawTransactionCmd(<-NewJSONID, hextx)
	request := NewServerRequest(sendtx, new(string))
	response := <-CurrentServerConn().SendRequest(request)
	txid := *response.Result().(*string)

	if response.Error() != nil {
		SendTxHistSyncChans.remove <- createdTx.txid
		return nil, response.Error()
	}

	return handleSendRawTxReply(cmd, txid, a, createdTx)
}

// SendMany handles a sendmany RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to any number of
// payment addresses.  Leftover inputs not sent to the payment address
// or a fee for the miner are sent back to a new address in the wallet.
// Upon success, the TxID for the created transaction is returned.
func SendMany(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.SendManyCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	// Check that minconf is positive.
	if cmd.MinConf < 0 {
		e := btcjson.Error{
			Code:    btcjson.ErrInvalidParameter.Code,
			Message: "minconf must be positive",
		}
		return nil, &e
	}

	// Check that the account specified in the request exists.
	a, err := AcctMgr.Account(cmd.FromAccount)
	if err != nil {
		return nil, &btcjson.ErrWalletInvalidAccountName
	}

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := a.txToPairs(cmd.Amounts, cmd.MinConf)
	switch {
	case err == ErrNonPositiveAmount:
		e := btcjson.Error{
			Code:    btcjson.ErrInvalidParameter.Code,
			Message: "amount must be positive",
		}
		return nil, &e

	case err == wallet.ErrWalletLocked:
		return nil, &btcjson.ErrWalletUnlockNeeded

	case err != nil: // any other non-nil error
		e := btcjson.Error{
			Code:    btcjson.ErrInternal.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	// Mark txid as having send history so handlers adding receive history
	// wait until all send history has been written.
	SendTxHistSyncChans.add <- createdTx.txid

	// If a change address was added, sync wallet to disk and request
	// transaction notifications to the change address.
	if createdTx.changeAddr != nil {
		AcctMgr.ds.ScheduleWalletWrite(a)
		if err := AcctMgr.ds.FlushAccount(a); err != nil {
			e := btcjson.Error{
				Code:    btcjson.ErrWallet.Code,
				Message: "Cannot write account: " + err.Error(),
			}
			return nil, &e
		}
		a.ReqNewTxsForAddress(createdTx.changeAddr)
	}

	hextx := hex.EncodeToString(createdTx.rawTx)
	// NewSendRawTransactionCmd will never fail so don't check error.
	sendtx, _ := btcjson.NewSendRawTransactionCmd(<-NewJSONID, hextx)
	request := NewServerRequest(sendtx, new(string))
	response := <-CurrentServerConn().SendRequest(request)
	txid := *response.Result().(*string)

	if response.Error() != nil {
		SendTxHistSyncChans.remove <- createdTx.txid
		return nil, response.Error()
	}

	return handleSendRawTxReply(cmd, txid, a, createdTx)
}

// Channels to manage SendBeforeReceiveHistorySync.
var SendTxHistSyncChans = struct {
	add, done, remove chan btcwire.ShaHash
	access            chan SendTxHistSyncRequest
}{
	add:    make(chan btcwire.ShaHash),
	remove: make(chan btcwire.ShaHash),
	done:   make(chan btcwire.ShaHash),
	access: make(chan SendTxHistSyncRequest),
}

// SendTxHistSyncRequest requests a SendTxHistSyncResponse from
// SendBeforeReceiveHistorySync.
type SendTxHistSyncRequest struct {
	txid     btcwire.ShaHash
	response chan SendTxHistSyncResponse
}

// SendTxHistSyncResponse is the response
type SendTxHistSyncResponse struct {
	c  chan struct{}
	ok bool
}

// SendBeforeReceiveHistorySync manages a set of transaction hashes
// created by this wallet.  For each newly added txid, a channel is
// created.  Once the send history has been recorded, the txid should
// be messaged across done, causing the internal channel to be closed.
// Before receive history is recorded, access should be used to check
// if there are or were any goroutines writing send history, and if
// so, wait until the channel is closed after a done message.
func SendBeforeReceiveHistorySync(add, done, remove chan btcwire.ShaHash,
	access chan SendTxHistSyncRequest) {

	m := make(map[btcwire.ShaHash]chan struct{})
	for {
		select {
		case txid := <-add:
			m[txid] = make(chan struct{})

		case txid := <-remove:
			delete(m, txid)

		case txid := <-done:
			if c, ok := m[txid]; ok {
				close(c)
			}

		case req := <-access:
			c, ok := m[req.txid]
			req.response <- SendTxHistSyncResponse{c: c, ok: ok}
		}
	}
}

func handleSendRawTxReply(icmd btcjson.Cmd, txIDStr string, a *Account, txInfo *CreatedTx) (interface{}, *btcjson.Error) {
	txID, err := btcwire.NewShaHashFromStr(txIDStr)
	if err != nil {
		e := btcjson.Error{
			Code:    btcjson.ErrInternal.Code,
			Message: "Invalid hash string from btcd reply",
		}
		return nil, &e
	}

	// Add to transaction store.
	sendtx := &tx.SendTx{
		TxID:        *txID,
		Time:        txInfo.time.Unix(),
		BlockHeight: -1,
		Fee:         txInfo.fee,
		Receivers:   txInfo.outputs,
	}
	a.TxStore = append(a.TxStore, sendtx)
	AcctMgr.ds.ScheduleTxStoreWrite(a)

	// Notify frontends of new SendTx.
	bs, err := GetCurBlock()
	if err == nil {
		for _, details := range sendtx.TxInfo(a.Name(), bs.Height, a.Net()) {
			NotifyNewTxDetails(frontendNotificationMaster, a.Name(),
				details)
		}
	}

	// Signal that received notifiations are ok to add now.
	SendTxHistSyncChans.done <- txInfo.txid

	// Remove previous unspent outputs now spent by the tx.
	if a.UtxoStore.Remove(txInfo.inputs) {
		AcctMgr.ds.ScheduleUtxoStoreWrite(a)
	}

	// Disk sync tx and utxo stores.
	if err := AcctMgr.ds.FlushAccount(a); err != nil {
		log.Errorf("cannot write account: %v", err)
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

	log.Infof("Successfully sent transaction %v", txIDStr)
	return txIDStr, nil
}

// SetTxFee sets the transaction fee per kilobyte added to transactions.
func SetTxFee(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.SetTxFeeCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	// Check that amount is not negative.
	if cmd.Amount < 0 {
		e := btcjson.Error{
			Code:    btcjson.ErrInvalidParams.Code,
			Message: "amount cannot be negative",
		}
		return nil, &e
	}

	// Set global tx fee.
	TxFeeIncrement.Lock()
	TxFeeIncrement.i = cmd.Amount
	TxFeeIncrement.Unlock()

	// A boolean true result is returned upon success.
	return true, nil
}

// CreateEncryptedWallet creates a new account with an encrypted
// wallet.  If an account with the same name as the requested account
// name already exists, an invalid account name error is returned to
// the client.
//
// Wallets will be created on TestNet3, or MainNet if btcwallet is run with
// the --mainnet option.
func CreateEncryptedWallet(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.CreateEncryptedWalletCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	err := AcctMgr.CreateEncryptedWallet([]byte(cmd.Passphrase))
	switch err {
	case nil:
		// A nil reply is sent upon successful wallet creation.
		return nil, nil

	case ErrWalletExists:
		return nil, &btcjson.ErrWalletInvalidAccountName

	case ErrBtcdDisconnected:
		return nil, &ErrBtcdDisconnected

	default: // all other non-nil errors
		return nil, &btcjson.ErrInternal
	}
}

// RecoverAddresses recovers the next n addresses from an account's wallet.
func RecoverAddresses(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	cmd, ok := icmd.(*btcws.RecoverAddressesCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	switch err {
	case nil:
		break

	case ErrNotFound:
		return nil, &btcjson.ErrWalletInvalidAccountName

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	if err := a.RecoverAddresses(cmd.N); err != nil {
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	return nil, nil
}

// WalletIsLocked handles the walletislocked extension request by
// returning the current lock state (false for unlocked, true for locked)
// of an account.  An error is returned if the requested account does not
// exist.
func WalletIsLocked(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.WalletIsLockedCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	switch err {
	case nil:
		break

	case ErrNotFound:
		return nil, &btcjson.ErrWalletInvalidAccountName

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	return a.Wallet.IsLocked(), nil
}

// WalletLock handles a walletlock request by locking the all account
// wallets, returning an error if any wallet is not encrypted (for example,
// a watching-only wallet).
func WalletLock(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	if err := AcctMgr.LockWallets(); err != nil {
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	return nil, nil
}

// WalletPassphrase responds to the walletpassphrase request by unlocking
// the wallet.  The decryption key is saved in the wallet until timeout
// seconds expires, after which the wallet is locked.
func WalletPassphrase(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.WalletPassphraseCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	if err := AcctMgr.UnlockWallets(cmd.Passphrase); err != nil {
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
	}

	go func(timeout int64) {
		time.Sleep(time.Second * time.Duration(timeout))
		_ = AcctMgr.LockWallets()
	}(cmd.Timeout)

	return nil, nil
}

// WalletPassphraseChange responds to the walletpassphrasechange request
// by unlocking all accounts with the provided old passphrase, and
// re-encrypting each private key with an AES key derived from the new
// passphrase.
//
// If the old passphrase is correct and the passphrase is changed, all
// wallets will be immediately locked.
func WalletPassphraseChange(icmd btcjson.Cmd) (interface{}, *btcjson.Error) {
	cmd, ok := icmd.(*btcjson.WalletPassphraseChangeCmd)
	if !ok {
		return nil, &btcjson.ErrInternal
	}

	err := AcctMgr.ChangePassphrase([]byte(cmd.OldPassphrase),
		[]byte(cmd.NewPassphrase))
	switch err {
	case nil:
		return nil, nil

	case wallet.ErrWrongPassphrase:
		return nil, &btcjson.ErrWalletPassphraseIncorrect

	default: // all other non-nil errors
		e := btcjson.Error{
			Code:    btcjson.ErrWallet.Code,
			Message: err.Error(),
		}
		return nil, &e
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
	ntfn := btcws.NewWalletLockStateNtfn(account, locked)
	mntfn, _ := ntfn.MarshalJSON()
	frontendNotificationMaster <- mntfn
}

// NotifyWalletBalance sends a confirmed account balance notification
// to a frontend.
func NotifyWalletBalance(frontend chan []byte, account string, balance float64) {
	ntfn := btcws.NewAccountBalanceNtfn(account, balance, true)
	mntfn, _ := ntfn.MarshalJSON()
	frontend <- mntfn
}

// NotifyWalletBalanceUnconfirmed sends a confirmed account balance
// notification to a frontend.
func NotifyWalletBalanceUnconfirmed(frontend chan []byte, account string, balance float64) {
	ntfn := btcws.NewAccountBalanceNtfn(account, balance, false)
	mntfn, _ := ntfn.MarshalJSON()
	frontend <- mntfn
}

// NotifyNewTxDetails sends details of a new transaction to a frontend.
func NotifyNewTxDetails(frontend chan []byte, account string,
	details map[string]interface{}) {

	ntfn := btcws.NewTxNtfn(account, details)
	mntfn, _ := ntfn.MarshalJSON()
	frontend <- mntfn
}

// NotifiedRecvTxRequest is used to check whether the outpoint of
// a received transaction has already been notified due to
// arriving first in the btcd mempool.
type NotifiedRecvTxRequest struct {
	op       btcwire.OutPoint
	response chan NotifiedRecvTxResponse
}

// NotifiedRecvTxResponse is the response of a NotifiedRecvTxRequest
// request.
type NotifiedRecvTxResponse bool

// NotifiedRecvTxChans holds the channels to manage
// StoreNotifiedMempoolTxs.
var NotifiedRecvTxChans = struct {
	add, remove chan btcwire.OutPoint
	access      chan NotifiedRecvTxRequest
}{
	add:    make(chan btcwire.OutPoint),
	remove: make(chan btcwire.OutPoint),
	access: make(chan NotifiedRecvTxRequest),
}

// StoreNotifiedMempoolRecvTxs maintains a set of previously-sent
// received transaction notifications originating from the btcd
// mempool. This is used to prevent duplicate frontend transaction
// notifications once a mempool tx is mined into a block.
func StoreNotifiedMempoolRecvTxs(add, remove chan btcwire.OutPoint,
	access chan NotifiedRecvTxRequest) {

	m := make(map[btcwire.OutPoint]struct{})
	for {
		select {
		case op := <-add:
			m[op] = struct{}{}

		case op := <-remove:
			if _, ok := m[op]; ok {
				delete(m, op)
			}

		case req := <-access:
			_, ok := m[req.op]
			req.response <- NotifiedRecvTxResponse(ok)
		}
	}
}

// Channel to send received transactions that were previously
// notified to frontends by the mempool.  A TxMined notification
// is sent to all connected frontends detailing the block information
// about the now confirmed transaction.
var NotifyMinedTx = make(chan *tx.RecvTx)

// NotifyMinedTxSender reads received transactions from in, notifying
// frontends that the tx has now been confirmed in a block.  Duplicates
// are filtered out.
func NotifyMinedTxSender(in chan *tx.RecvTx) {
	// Create a map to hold a set of already notified
	// txids.  Do not send duplicates.
	m := make(map[btcwire.ShaHash]struct{})

	for recv := range in {
		if _, ok := m[recv.TxID]; !ok {
			ntfn := btcws.NewTxMinedNtfn(recv.TxID.String(),
				recv.BlockHash.String(), recv.BlockHeight,
				recv.BlockTime, int(recv.BlockIndex))
			mntfn, _ := ntfn.MarshalJSON()
			frontendNotificationMaster <- mntfn

			// Mark as sent.
			m[recv.TxID] = struct{}{}
		}
	}
}

// NotifyBalanceSyncerChans holds channels for accessing
// the NotifyBalanceSyncer goroutine.
var NotifyBalanceSyncerChans = struct {
	add    chan NotifyBalanceWorker
	remove chan btcwire.ShaHash
	access chan NotifyBalanceRequest
}{
	add:    make(chan NotifyBalanceWorker),
	remove: make(chan btcwire.ShaHash),
	access: make(chan NotifyBalanceRequest),
}

// NotifyBalanceWorker holds a block hash to add a worker to
// NotifyBalanceSyncer and uses a chan to returns the WaitGroup
// which should be decremented with Done after the worker is finished.
type NotifyBalanceWorker struct {
	block btcwire.ShaHash
	wg    chan *sync.WaitGroup
}

// NotifyBalanceRequest is used by the blockconnected notification handler
// to access and wait on the the WaitGroup for workers currently processing
// transactions for a block.  If no handlers have been added, a nil
// WaitGroup is returned.
type NotifyBalanceRequest struct {
	block btcwire.ShaHash
	wg    chan *sync.WaitGroup
}

// NotifyBalanceSyncer maintains a map of block hashes to WaitGroups
// for worker goroutines that must finish before it is safe to notify
// frontends of a new balance in the blockconnected notification handler.
func NotifyBalanceSyncer(add chan NotifyBalanceWorker,
	remove chan btcwire.ShaHash,
	access chan NotifyBalanceRequest) {

	m := make(map[btcwire.ShaHash]*sync.WaitGroup)

	for {
		select {
		case worker := <-add:
			wg, ok := m[worker.block]
			if !ok {
				wg = &sync.WaitGroup{}
				m[worker.block] = wg
			}
			wg.Add(1)
			m[worker.block] = wg
			worker.wg <- wg

		case block := <-remove:
			if _, ok := m[block]; ok {
				delete(m, block)
			}

		case req := <-access:
			req.wg <- m[req.block]
		}
	}
}
