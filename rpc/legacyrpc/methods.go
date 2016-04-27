// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacyrpc

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jadeblaquiere/btcd/btcec"
	"github.com/jadeblaquiere/btcd/btcjson"
	"github.com/jadeblaquiere/btcd/chaincfg"
	"github.com/jadeblaquiere/btcd/txscript"
	"github.com/jadeblaquiere/btcd/wire"
	"github.com/btcsuite/btcrpcclient"
	"github.com/jadeblaquiere/btcutil"
	"github.com/jadeblaquiere/btcwallet/chain"
	"github.com/jadeblaquiere/btcwallet/waddrmgr"
	"github.com/jadeblaquiere/btcwallet/wallet"
	"github.com/jadeblaquiere/btcwallet/wallet/txrules"
	"github.com/jadeblaquiere/btcwallet/wtxmgr"
)

const (
	// maxEmptyAccounts is the number of accounts to scan even if they have no
	// transaction history. This is a deviation from BIP044 to make account
	// creation easier by allowing a limited number of empty accounts.
	maxEmptyAccounts = 100
)

// confirmed checks whether a transaction at height txHeight has met minconf
// confirmations for a blockchain at height curHeight.
func confirmed(minconf, txHeight, curHeight int32) bool {
	return confirms(txHeight, curHeight) >= minconf
}

// confirms returns the number of confirmations for a transaction in a block at
// height txHeight (or -1 for an unconfirmed tx) given the chain height
// curHeight.
func confirms(txHeight, curHeight int32) int32 {
	switch {
	case txHeight == -1, txHeight > curHeight:
		return 0
	default:
		return curHeight - txHeight + 1
	}
}

// requestHandler is a handler function to handle an unmarshaled and parsed
// request into a marshalable response.  If the error is a *btcjson.RPCError
// or any of the above special error classes, the server will respond with
// the JSON-RPC appropiate error code.  All other errors use the wallet
// catch-all error code, btcjson.ErrRPCWallet.
type requestHandler func(interface{}, *wallet.Wallet) (interface{}, error)

// requestHandlerChain is a requestHandler that also takes a parameter for
type requestHandlerChainRequired func(interface{}, *wallet.Wallet, *chain.RPCClient) (interface{}, error)

var rpcHandlers = map[string]struct {
	handler          requestHandler
	handlerWithChain requestHandlerChainRequired

	// Function variables cannot be compared against anything but nil, so
	// use a boolean to record whether help generation is necessary.  This
	// is used by the tests to ensure that help can be generated for every
	// implemented method.
	//
	// A single map and this bool is here is used rather than several maps
	// for the unimplemented handlers so every method has exactly one
	// handler function.
	noHelp bool
}{
	// Reference implementation wallet methods (implemented)
	"addmultisigaddress":     {handler: AddMultiSigAddress},
	"createmultisig":         {handler: CreateMultiSig},
	"dumpprivkey":            {handler: DumpPrivKey},
	"getaccount":             {handler: GetAccount},
	"getaccountaddress":      {handler: GetAccountAddress},
	"getaddressesbyaccount":  {handler: GetAddressesByAccount},
	"getbalance":             {handler: GetBalance},
	"getbestblockhash":       {handler: GetBestBlockHash},
	"getblockcount":          {handler: GetBlockCount},
	"getinfo":                {handlerWithChain: GetInfo},
	"getnewaddress":          {handler: GetNewAddress},
	"getrawchangeaddress":    {handler: GetRawChangeAddress},
	"getreceivedbyaccount":   {handler: GetReceivedByAccount},
	"getreceivedbyaddress":   {handler: GetReceivedByAddress},
	"gettransaction":         {handler: GetTransaction},
	"help":                   {handler: HelpNoChainRPC, handlerWithChain: HelpWithChainRPC},
	"importprivkey":          {handler: ImportPrivKey},
	"keypoolrefill":          {handler: KeypoolRefill},
	"listaccounts":           {handler: ListAccounts},
	"listlockunspent":        {handler: ListLockUnspent},
	"listreceivedbyaccount":  {handler: ListReceivedByAccount},
	"listreceivedbyaddress":  {handler: ListReceivedByAddress},
	"listsinceblock":         {handlerWithChain: ListSinceBlock},
	"listtransactions":       {handler: ListTransactions},
	"listunspent":            {handler: ListUnspent},
	"lockunspent":            {handler: LockUnspent},
	"sendfrom":               {handlerWithChain: SendFrom},
	"sendmany":               {handler: SendMany},
	"sendtoaddress":          {handler: SendToAddress},
	"settxfee":               {handler: SetTxFee},
	"signmessage":            {handler: SignMessage},
	"signrawtransaction":     {handlerWithChain: SignRawTransaction},
	"validateaddress":        {handler: ValidateAddress},
	"verifymessage":          {handler: VerifyMessage},
	"walletlock":             {handler: WalletLock},
	"walletpassphrase":       {handler: WalletPassphrase},
	"walletpassphrasechange": {handler: WalletPassphraseChange},

	// Reference implementation methods (still unimplemented)
	"backupwallet":         {handler: Unimplemented, noHelp: true},
	"dumpwallet":           {handler: Unimplemented, noHelp: true},
	"getwalletinfo":        {handler: Unimplemented, noHelp: true},
	"importwallet":         {handler: Unimplemented, noHelp: true},
	"listaddressgroupings": {handler: Unimplemented, noHelp: true},

	// Reference methods which can't be implemented by btcwallet due to
	// design decision differences
	"encryptwallet": {handler: Unsupported, noHelp: true},
	"move":          {handler: Unsupported, noHelp: true},
	"setaccount":    {handler: Unsupported, noHelp: true},

	// Extensions to the reference client JSON-RPC API
	"createnewaccount":     {handler: CreateNewAccount},
	"exportwatchingwallet": {handler: ExportWatchingWallet},
	"getbestblock":         {handler: GetBestBlock},
	// This was an extension but the reference implementation added it as
	// well, but with a different API (no account parameter).  It's listed
	// here because it hasn't been update to use the reference
	// implemenation's API.
	"getunconfirmedbalance":   {handler: GetUnconfirmedBalance},
	"listaddresstransactions": {handler: ListAddressTransactions},
	"listalltransactions":     {handler: ListAllTransactions},
	"renameaccount":           {handler: RenameAccount},
	"walletislocked":          {handler: WalletIsLocked},
}

// Unimplemented handles an unimplemented RPC request with the
// appropiate error.
func Unimplemented(interface{}, *wallet.Wallet) (interface{}, error) {
	return nil, &btcjson.RPCError{
		Code:    btcjson.ErrRPCUnimplemented,
		Message: "Method unimplemented",
	}
}

// Unsupported handles a standard bitcoind RPC request which is
// unsupported by btcwallet due to design differences.
func Unsupported(interface{}, *wallet.Wallet) (interface{}, error) {
	return nil, &btcjson.RPCError{
		Code:    -1,
		Message: "Request unsupported by btcwallet",
	}
}

// lazyHandler is a closure over a requestHandler or passthrough request with
// the RPC server's wallet and chain server variables as part of the closure
// context.
type lazyHandler func() (interface{}, *btcjson.RPCError)

// lazyApplyHandler looks up the best request handler func for the method,
// returning a closure that will execute it with the (required) wallet and
// (optional) consensus RPC server.  If no handlers are found and the
// chainClient is not nil, the returned handler performs RPC passthrough.
func lazyApplyHandler(request *btcjson.Request, w *wallet.Wallet, chainClient *chain.RPCClient) lazyHandler {
	handlerData, ok := rpcHandlers[request.Method]
	if ok && handlerData.handlerWithChain != nil && w != nil && chainClient != nil {
		return func() (interface{}, *btcjson.RPCError) {
			cmd, err := btcjson.UnmarshalCmd(request)
			if err != nil {
				return nil, btcjson.ErrRPCInvalidRequest
			}
			resp, err := handlerData.handlerWithChain(cmd, w, chainClient)
			if err != nil {
				return nil, jsonError(err)
			}
			return resp, nil
		}
	}
	if ok && handlerData.handler != nil && w != nil {
		return func() (interface{}, *btcjson.RPCError) {
			cmd, err := btcjson.UnmarshalCmd(request)
			if err != nil {
				return nil, btcjson.ErrRPCInvalidRequest
			}
			resp, err := handlerData.handler(cmd, w)
			if err != nil {
				return nil, jsonError(err)
			}
			return resp, nil
		}
	}

	// Fallback to RPC passthrough
	return func() (interface{}, *btcjson.RPCError) {
		if chainClient == nil {
			return nil, &btcjson.RPCError{
				Code:    -1,
				Message: "Chain RPC is inactive",
			}
		}
		resp, err := chainClient.RawRequest(request.Method, request.Params)
		if err != nil {
			return nil, jsonError(err)
		}
		return &resp, nil
	}
}

// makeResponse makes the JSON-RPC response struct for the result and error
// returned by a requestHandler.  The returned response is not ready for
// marshaling and sending off to a client, but must be
func makeResponse(id, result interface{}, err error) btcjson.Response {
	idPtr := idPointer(id)
	if err != nil {
		return btcjson.Response{
			ID:    idPtr,
			Error: jsonError(err),
		}
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return btcjson.Response{
			ID: idPtr,
			Error: &btcjson.RPCError{
				Code:    btcjson.ErrRPCInternal.Code,
				Message: "Unexpected error marshalling result",
			},
		}
	}
	return btcjson.Response{
		ID:     idPtr,
		Result: json.RawMessage(resultBytes),
	}
}

// jsonError creates a JSON-RPC error from the Go error.
func jsonError(err error) *btcjson.RPCError {
	if err == nil {
		return nil
	}

	code := btcjson.ErrRPCWallet
	switch e := err.(type) {
	case btcjson.RPCError:
		return &e
	case *btcjson.RPCError:
		return e
	case DeserializationError:
		code = btcjson.ErrRPCDeserialization
	case InvalidParameterError:
		code = btcjson.ErrRPCInvalidParameter
	case ParseError:
		code = btcjson.ErrRPCParse.Code
	case waddrmgr.ManagerError:
		switch e.ErrorCode {
		case waddrmgr.ErrWrongPassphrase:
			code = btcjson.ErrRPCWalletPassphraseIncorrect
		}
	}
	return &btcjson.RPCError{
		Code:    code,
		Message: err.Error(),
	}
}

// makeMultiSigScript is a helper function to combine common logic for
// AddMultiSig and CreateMultiSig.
func makeMultiSigScript(w *wallet.Wallet, keys []string, nRequired int) ([]byte, error) {
	keysesPrecious := make([]*btcutil.AddressPubKey, len(keys))

	// The address list will made up either of addreseses (pubkey hash), for
	// which we need to look up the keys in wallet, straight pubkeys, or a
	// mixture of the two.
	for i, a := range keys {
		// try to parse as pubkey address
		a, err := decodeAddress(a, w.ChainParams())
		if err != nil {
			return nil, err
		}

		switch addr := a.(type) {
		case *btcutil.AddressPubKey:
			keysesPrecious[i] = addr
		case *btcutil.AddressPubKeyHash:
			ainfo, err := w.Manager.Address(addr)
			if err != nil {
				return nil, err
			}

			apkinfo := ainfo.(waddrmgr.ManagedPubKeyAddress)

			// This will be an addresspubkey
			a, err := decodeAddress(apkinfo.ExportPubKey(),
				w.ChainParams())
			if err != nil {
				return nil, err
			}

			apk := a.(*btcutil.AddressPubKey)
			keysesPrecious[i] = apk
		default:
			return nil, err
		}
	}

	return txscript.MultiSigScript(keysesPrecious, nRequired)
}

// AddMultiSigAddress handles an addmultisigaddress request by adding a
// multisig address to the given wallet.
func AddMultiSigAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.AddMultisigAddressCmd)

	// If an account is specified, ensure that is the imported account.
	if cmd.Account != nil && *cmd.Account != waddrmgr.ImportedAddrAccountName {
		return nil, &ErrNotImportedAccount
	}

	script, err := makeMultiSigScript(w, cmd.Keys, cmd.NRequired)
	if err != nil {
		return nil, ParseError{err}
	}

	// TODO(oga) blockstamp current block?
	bs := &waddrmgr.BlockStamp{
		Hash:   *w.ChainParams().GenesisHash,
		Height: 0,
	}

	addr, err := w.Manager.ImportScript(script, bs)
	if err != nil {
		return nil, err
	}

	return addr.Address().EncodeAddress(), nil
}

// CreateMultiSig handles an createmultisig request by returning a
// multisig address for the given inputs.
func CreateMultiSig(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.CreateMultisigCmd)

	script, err := makeMultiSigScript(w, cmd.Keys, cmd.NRequired)
	if err != nil {
		return nil, ParseError{err}
	}

	address, err := btcutil.NewAddressScriptHash(script, w.ChainParams())
	if err != nil {
		// above is a valid script, shouldn't happen.
		return nil, err
	}

	return btcjson.CreateMultiSigResult{
		Address:      address.EncodeAddress(),
		RedeemScript: hex.EncodeToString(script),
	}, nil
}

// DumpPrivKey handles a dumpprivkey request with the private key
// for a single address, or an appropiate error if the wallet
// is locked.
func DumpPrivKey(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.DumpPrivKeyCmd)

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	key, err := w.DumpWIFPrivateKey(addr)
	if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
		// Address was found, but the private key isn't
		// accessible.
		return nil, &ErrWalletUnlockNeeded
	}
	return key, err
}

// DumpWallet handles a dumpwallet request by returning  all private
// keys in a wallet, or an appropiate error if the wallet is locked.
// TODO: finish this to match bitcoind by writing the dump to a file.
func DumpWallet(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	keys, err := w.DumpPrivKeys()
	if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
		return nil, &ErrWalletUnlockNeeded
	}

	return keys, err
}

// ExportWatchingWallet handles an exportwatchingwallet request by exporting the
// current wallet as a watching wallet (with no private keys), and returning
// base64-encoding of serialized account files.
func ExportWatchingWallet(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.ExportWatchingWalletCmd)

	if cmd.Account != nil && *cmd.Account != "*" {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCWallet,
			Message: "Individual accounts can not be exported as watching-only",
		}
	}

	return w.ExportWatchingWallet()
}

// GetAddressesByAccount handles a getaddressesbyaccount request by returning
// all addresses for an account, or an error if the requested account does
// not exist.
func GetAddressesByAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.GetAddressesByAccountCmd)

	account, err := w.Manager.LookupAccount(cmd.Account)
	if err != nil {
		return nil, err
	}

	var addrStrs []string
	err = w.Manager.ForEachAccountAddress(account,
		func(maddr waddrmgr.ManagedAddress) error {
			addrStrs = append(addrStrs, maddr.Address().EncodeAddress())
			return nil
		})
	return addrStrs, err
}

// GetBalance handles a getbalance request by returning the balance for an
// account (wallet), or an error if the requested account does not
// exist.
func GetBalance(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.GetBalanceCmd)

	var balance btcutil.Amount
	var err error
	accountName := "*"
	if cmd.Account != nil {
		accountName = *cmd.Account
	}
	if accountName == "*" {
		balance, err = w.CalculateBalance(int32(*cmd.MinConf))
		if err != nil {
			return nil, err
		}
	} else {
		var account uint32
		account, err = w.Manager.LookupAccount(accountName)
		if err != nil {
			return nil, err
		}
		bals, err := w.CalculateAccountBalances(account, int32(*cmd.MinConf))
		if err != nil {
			return nil, err
		}
		balance = bals.Spendable
	}
	return balance.ToBTC(), nil
}

// GetBestBlock handles a getbestblock request by returning a JSON object
// with the height and hash of the most recently processed block.
func GetBestBlock(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	blk := w.Manager.SyncedTo()
	result := &btcjson.GetBestBlockResult{
		Hash:   blk.Hash.String(),
		Height: blk.Height,
	}
	return result, nil
}

// GetBestBlockHash handles a getbestblockhash request by returning the hash
// of the most recently processed block.
func GetBestBlockHash(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	blk := w.Manager.SyncedTo()
	return blk.Hash.String(), nil
}

// GetBlockCount handles a getblockcount request by returning the chain height
// of the most recently processed block.
func GetBlockCount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	blk := w.Manager.SyncedTo()
	return blk.Height, nil
}

// GetInfo handles a getinfo request by returning the a structure containing
// information about the current state of btcwallet.
// exist.
func GetInfo(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	// Call down to btcd for all of the information in this command known
	// by them.
	info, err := chainClient.GetInfo()
	if err != nil {
		return nil, err
	}

	bal, err := w.CalculateBalance(1)
	if err != nil {
		return nil, err
	}

	// TODO(davec): This should probably have a database version as opposed
	// to using the manager version.
	info.WalletVersion = int32(waddrmgr.LatestMgrVersion)
	info.Balance = bal.ToBTC()
	info.PaytxFee = w.RelayFee().ToBTC()
	// We don't set the following since they don't make much sense in the
	// wallet architecture:
	//  - unlocked_until
	//  - errors

	return info, nil
}

func decodeAddress(s string, params *chaincfg.Params) (btcutil.Address, error) {
	addr, err := btcutil.DecodeAddress(s, params)
	if err != nil {
		msg := fmt.Sprintf("Invalid address %q: decode failed with %#q", s, err)
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidAddressOrKey,
			Message: msg,
		}
	}
	if !addr.IsForNet(params) {
		msg := fmt.Sprintf("Invalid address %q: not intended for use on %s",
			addr, params.Name)
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidAddressOrKey,
			Message: msg,
		}
	}
	return addr, nil
}

// GetAccount handles a getaccount request by returning the account name
// associated with a single address.
func GetAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.GetAccountCmd)

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	// Fetch the associated account
	account, err := w.Manager.AddrAccount(addr)
	if err != nil {
		return nil, &ErrAddressNotInWallet
	}

	acctName, err := w.Manager.AccountName(account)
	if err != nil {
		return nil, &ErrAccountNameNotFound
	}
	return acctName, nil
}

// GetAccountAddress handles a getaccountaddress by returning the most
// recently-created chained address that has not yet been used (does not yet
// appear in the blockchain, or any tx that has arrived in the btcd mempool).
// If the most recently-requested address has been used, a new address (the
// next chained address in the keypool) is used.  This can fail if the keypool
// runs out (and will return btcjson.ErrRPCWalletKeypoolRanOut if that happens).
func GetAccountAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.GetAccountAddressCmd)

	account, err := w.Manager.LookupAccount(cmd.Account)
	if err != nil {
		return nil, err
	}
	addr, err := w.CurrentAddress(account)
	if err != nil {
		return nil, err
	}

	return addr.EncodeAddress(), err
}

// GetUnconfirmedBalance handles a getunconfirmedbalance extension request
// by returning the current unconfirmed balance of an account.
func GetUnconfirmedBalance(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.GetUnconfirmedBalanceCmd)

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.Manager.LookupAccount(acctName)
	if err != nil {
		return nil, err
	}
	bals, err := w.CalculateAccountBalances(account, 1)
	if err != nil {
		return nil, err
	}

	return (bals.Total - bals.Spendable).ToBTC(), nil
}

// ImportPrivKey handles an importprivkey request by parsing
// a WIF-encoded private key and adding it to an account.
func ImportPrivKey(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.ImportPrivKeyCmd)

	// Ensure that private keys are only imported to the correct account.
	//
	// Yes, Label is the account name.
	if cmd.Label != nil && *cmd.Label != waddrmgr.ImportedAddrAccountName {
		return nil, &ErrNotImportedAccount
	}

	wif, err := btcutil.DecodeWIF(cmd.PrivKey)
	if err != nil {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidAddressOrKey,
			Message: "WIF decode failed: " + err.Error(),
		}
	}
	if !wif.IsForNet(w.ChainParams()) {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidAddressOrKey,
			Message: "Key is not intended for " + w.ChainParams().Name,
		}
	}

	// Import the private key, handling any errors.
	_, err = w.ImportPrivateKey(wif, nil, *cmd.Rescan)
	switch {
	case waddrmgr.IsError(err, waddrmgr.ErrDuplicateAddress):
		// Do not return duplicate key errors to the client.
		return nil, nil
	case waddrmgr.IsError(err, waddrmgr.ErrLocked):
		return nil, &ErrWalletUnlockNeeded
	}

	return nil, err
}

// KeypoolRefill handles the keypoolrefill command. Since we handle the keypool
// automatically this does nothing since refilling is never manually required.
func KeypoolRefill(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return nil, nil
}

// CreateNewAccount handles a createnewaccount request by creating and
// returning a new account. If the last account has no transaction history
// as per BIP 0044 a new account cannot be created so an error will be returned.
func CreateNewAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.CreateNewAccountCmd)

	// The wildcard * is reserved by the rpc server with the special meaning
	// of "all accounts", so disallow naming accounts to this string.
	if cmd.Account == "*" {
		return nil, &ErrReservedAccountName
	}

	// Check that we are within the maximum allowed non-empty accounts limit.
	account, err := w.Manager.LastAccount()
	if err != nil {
		return nil, err
	}
	if account > maxEmptyAccounts {
		used, err := w.AccountUsed(account)
		if err != nil {
			return nil, err
		}
		if !used {
			return nil, errors.New("cannot create account: " +
				"previous account has no transaction history")
		}
	}

	_, err = w.NextAccount(cmd.Account)
	if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
		return nil, &btcjson.RPCError{
			Code: btcjson.ErrRPCWalletUnlockNeeded,
			Message: "Creating an account requires the wallet to be unlocked. " +
				"Enter the wallet passphrase with walletpassphrase to unlock",
		}
	}
	return nil, err
}

// RenameAccount handles a renameaccount request by renaming an account.
// If the account does not exist an appropiate error will be returned.
func RenameAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.RenameAccountCmd)

	// The wildcard * is reserved by the rpc server with the special meaning
	// of "all accounts", so disallow naming accounts to this string.
	if cmd.NewAccount == "*" {
		return nil, &ErrReservedAccountName
	}

	// Check that given account exists
	account, err := w.Manager.LookupAccount(cmd.OldAccount)
	if err != nil {
		return nil, err
	}
	return nil, w.RenameAccount(account, cmd.NewAccount)
}

// GetNewAddress handles a getnewaddress request by returning a new
// address for an account.  If the account does not exist an appropiate
// error is returned.
// TODO: Follow BIP 0044 and warn if number of unused addresses exceeds
// the gap limit.
func GetNewAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.GetNewAddressCmd)

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.Manager.LookupAccount(acctName)
	if err != nil {
		return nil, err
	}
	addr, err := w.NewAddress(account)
	if err != nil {
		return nil, err
	}

	// Return the new payment address string.
	return addr.EncodeAddress(), nil
}

// GetRawChangeAddress handles a getrawchangeaddress request by creating
// and returning a new change address for an account.
//
// Note: bitcoind allows specifying the account as an optional parameter,
// but ignores the parameter.
func GetRawChangeAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.GetRawChangeAddressCmd)

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.Manager.LookupAccount(acctName)
	if err != nil {
		return nil, err
	}
	addr, err := w.NewChangeAddress(account)
	if err != nil {
		return nil, err
	}

	// Return the new payment address string.
	return addr.EncodeAddress(), nil
}

// GetReceivedByAccount handles a getreceivedbyaccount request by returning
// the total amount received by addresses of an account.
func GetReceivedByAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.GetReceivedByAccountCmd)

	account, err := w.Manager.LookupAccount(cmd.Account)
	if err != nil {
		return nil, err
	}

	bal, _, err := w.TotalReceivedForAccount(account, int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}

	return bal.ToBTC(), nil
}

// GetReceivedByAddress handles a getreceivedbyaddress request by returning
// the total amount received by a single address.
func GetReceivedByAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.GetReceivedByAddressCmd)

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}
	total, err := w.TotalReceivedForAddr(addr, int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}

	return total.ToBTC(), nil
}

// GetTransaction handles a gettransaction request by returning details about
// a single transaction saved by wallet.
func GetTransaction(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.GetTransactionCmd)

	txSha, err := wire.NewShaHashFromStr(cmd.Txid)
	if err != nil {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCDecodeHexString,
			Message: "Transaction hash string decode failed: " + err.Error(),
		}
	}

	details, err := w.TxStore.TxDetails(txSha)
	if err != nil {
		return nil, err
	}
	if details == nil {
		return nil, &ErrNoTransactionInfo
	}

	syncBlock := w.Manager.SyncedTo()

	// TODO: The serialized transaction is already in the DB, so
	// reserializing can be avoided here.
	var txBuf bytes.Buffer
	txBuf.Grow(details.MsgTx.SerializeSize())
	err = details.MsgTx.Serialize(&txBuf)
	if err != nil {
		return nil, err
	}

	// TODO: Add a "generated" field to this result type.  "generated":true
	// is only added if the transaction is a coinbase.
	ret := btcjson.GetTransactionResult{
		TxID:            cmd.Txid,
		Hex:             hex.EncodeToString(txBuf.Bytes()),
		Time:            details.Received.Unix(),
		TimeReceived:    details.Received.Unix(),
		WalletConflicts: []string{}, // Not saved
		//Generated:     blockchain.IsCoinBaseTx(&details.MsgTx),
	}

	if details.Block.Height != -1 {
		ret.BlockHash = details.Block.Hash.String()
		ret.BlockTime = details.Block.Time.Unix()
		ret.Confirmations = int64(confirms(details.Block.Height, syncBlock.Height))
	}

	var (
		debitTotal  btcutil.Amount
		creditTotal btcutil.Amount // Excludes change
		fee         btcutil.Amount
		feeF64      float64
	)
	for _, deb := range details.Debits {
		debitTotal += deb.Amount
	}
	for _, cred := range details.Credits {
		if !cred.Change {
			creditTotal += cred.Amount
		}
	}
	// Fee can only be determined if every input is a debit.
	if len(details.Debits) == len(details.MsgTx.TxIn) {
		var outputTotal btcutil.Amount
		for _, output := range details.MsgTx.TxOut {
			outputTotal += btcutil.Amount(output.Value)
		}
		fee = debitTotal - outputTotal
		feeF64 = fee.ToBTC()
	}

	if len(details.Debits) == 0 {
		// Credits must be set later, but since we know the full length
		// of the details slice, allocate it with the correct cap.
		ret.Details = make([]btcjson.GetTransactionDetailsResult, 0, len(details.Credits))
	} else {
		ret.Details = make([]btcjson.GetTransactionDetailsResult, 1, len(details.Credits)+1)

		ret.Details[0] = btcjson.GetTransactionDetailsResult{
			// Fields left zeroed:
			//   InvolvesWatchOnly
			//   Account
			//   Address
			//   Vout
			//
			// TODO(jrick): Address and Vout should always be set,
			// but we're doing the wrong thing here by not matching
			// core.  Instead, gettransaction should only be adding
			// details for transaction outputs, just like
			// listtransactions (but using the short result format).
			Category: "send",
			Amount:   (-debitTotal).ToBTC(), // negative since it is a send
			Fee:      &feeF64,
		}
		ret.Fee = feeF64
	}

	credCat := wallet.RecvCategory(details, syncBlock.Height).String()
	for _, cred := range details.Credits {
		// Change is ignored.
		if cred.Change {
			continue
		}

		var address string
		var accountName string
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			details.MsgTx.TxOut[cred.Index].PkScript, w.ChainParams())
		if err == nil && len(addrs) == 1 {
			addr := addrs[0]
			address = addr.EncodeAddress()
			account, err := w.Manager.AddrAccount(addr)
			if err == nil {
				accountName, err = w.Manager.AccountName(account)
				if err != nil {
					accountName = ""
				}
			}
		}

		ret.Details = append(ret.Details, btcjson.GetTransactionDetailsResult{
			// Fields left zeroed:
			//   InvolvesWatchOnly
			//   Fee
			Account:  accountName,
			Address:  address,
			Category: credCat,
			Amount:   cred.Amount.ToBTC(),
			Vout:     cred.Index,
		})
	}

	ret.Amount = creditTotal.ToBTC()
	return ret, nil
}

// These generators create the following global variables in this package:
//
//   var localeHelpDescs map[string]func() map[string]string
//   var requestUsages string
//
// localeHelpDescs maps from locale strings (e.g. "en_US") to a function that
// builds a map of help texts for each RPC server method.  This prevents help
// text maps for every locale map from being rooted and created during init.
// Instead, the appropiate function is looked up when help text is first needed
// using the current locale and saved to the global below for futher reuse.
//
// requestUsages contains single line usages for every supported request,
// separated by newlines.  It is set during init.  These usages are used for all
// locales.
//
//go:generate go run ../../internal/rpchelp/genrpcserverhelp.go legacyrpc
//go:generate gofmt -w rpcserverhelp.go

var helpDescs map[string]string
var helpDescsMu sync.Mutex // Help may execute concurrently, so synchronize access.

// HelpWithChainRPC handles the help request when the RPC server has been
// associated with a consensus RPC client.  The additional RPC client is used to
// include help messages for methods implemented by the consensus server via RPC
// passthrough.
func HelpWithChainRPC(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	return help(icmd, w, chainClient)
}

// HelpNoChainRPC handles the help request when the RPC server has not been
// associated with a consensus RPC client.  No help messages are included for
// passthrough requests.
func HelpNoChainRPC(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return help(icmd, w, nil)
}

// help handles the help request by returning one line usage of all available
// methods, or full help for a specific method.  The chainClient is optional,
// and this is simply a helper function for the HelpNoChainRPC and
// HelpWithChainRPC handlers.
func help(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*btcjson.HelpCmd)

	// btcd returns different help messages depending on the kind of
	// connection the client is using.  Only methods availble to HTTP POST
	// clients are available to be used by wallet clients, even though
	// wallet itself is a websocket client to btcd.  Therefore, create a
	// POST client as needed.
	//
	// Returns nil if chainClient is currently nil or there is an error
	// creating the client.
	//
	// This is hacky and is probably better handled by exposing help usage
	// texts in a non-internal btcd package.
	postClient := func() *btcrpcclient.Client {
		if chainClient == nil {
			return nil
		}
		c, err := chainClient.POSTClient()
		if err != nil {
			return nil
		}
		return c
	}
	if cmd.Command == nil || *cmd.Command == "" {
		// Prepend chain server usage if it is available.
		usages := requestUsages
		client := postClient()
		if client != nil {
			rawChainUsage, err := client.RawRequest("help", nil)
			var chainUsage string
			if err == nil {
				_ = json.Unmarshal([]byte(rawChainUsage), &chainUsage)
			}
			if chainUsage != "" {
				usages = "Chain server usage:\n\n" + chainUsage + "\n\n" +
					"Wallet server usage (overrides chain requests):\n\n" +
					requestUsages
			}
		}
		return usages, nil
	}

	defer helpDescsMu.Unlock()
	helpDescsMu.Lock()

	if helpDescs == nil {
		// TODO: Allow other locales to be set via config or detemine
		// this from environment variables.  For now, hardcode US
		// English.
		helpDescs = localeHelpDescs["en_US"]()
	}

	helpText, ok := helpDescs[*cmd.Command]
	if ok {
		return helpText, nil
	}

	// Return the chain server's detailed help if possible.
	var chainHelp string
	client := postClient()
	if client != nil {
		param := make([]byte, len(*cmd.Command)+2)
		param[0] = '"'
		copy(param[1:], *cmd.Command)
		param[len(param)-1] = '"'
		rawChainHelp, err := client.RawRequest("help", []json.RawMessage{param})
		if err == nil {
			_ = json.Unmarshal([]byte(rawChainHelp), &chainHelp)
		}
	}
	if chainHelp != "" {
		return chainHelp, nil
	}
	return nil, &btcjson.RPCError{
		Code:    btcjson.ErrRPCInvalidParameter,
		Message: fmt.Sprintf("No help for method '%s'", *cmd.Command),
	}
}

// ListAccounts handles a listaccounts request by returning a map of account
// names to their balances.
func ListAccounts(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.ListAccountsCmd)

	accountBalances := map[string]float64{}
	var accounts []uint32
	err := w.Manager.ForEachAccount(func(account uint32) error {
		accounts = append(accounts, account)
		return nil
	})
	if err != nil {
		return nil, err
	}
	minConf := int32(*cmd.MinConf)
	for _, account := range accounts {
		acctName, err := w.Manager.AccountName(account)
		if err != nil {
			return nil, &ErrAccountNameNotFound
		}
		bals, err := w.CalculateAccountBalances(account, minConf)
		if err != nil {
			return nil, err
		}
		accountBalances[acctName] = bals.Spendable.ToBTC()
	}
	// Return the map.  This will be marshaled into a JSON object.
	return accountBalances, nil
}

// ListLockUnspent handles a listlockunspent request by returning an slice of
// all locked outpoints.
func ListLockUnspent(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return w.LockedOutpoints(), nil
}

// ListReceivedByAccount handles a listreceivedbyaccount request by returning
// a slice of objects, each one containing:
//  "account": the receiving account;
//  "amount": total amount received by the account;
//  "confirmations": number of confirmations of the most recent transaction.
// It takes two parameters:
//  "minconf": minimum number of confirmations to consider a transaction -
//             default: one;
//  "includeempty": whether or not to include addresses that have no transactions -
//                  default: false.
func ListReceivedByAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.ListReceivedByAccountCmd)

	var accounts []uint32
	err := w.Manager.ForEachAccount(func(account uint32) error {
		accounts = append(accounts, account)
		return nil
	})
	if err != nil {
		return nil, err
	}

	ret := make([]btcjson.ListReceivedByAccountResult, 0, len(accounts))
	minConf := int32(*cmd.MinConf)
	for _, account := range accounts {
		acctName, err := w.Manager.AccountName(account)
		if err != nil {
			return nil, &ErrAccountNameNotFound
		}
		bal, confirmations, err := w.TotalReceivedForAccount(account,
			minConf)
		if err != nil {
			return nil, err
		}
		ret = append(ret, btcjson.ListReceivedByAccountResult{
			Account:       acctName,
			Amount:        bal.ToBTC(),
			Confirmations: uint64(confirmations),
		})
	}
	return ret, nil
}

// ListReceivedByAddress handles a listreceivedbyaddress request by returning
// a slice of objects, each one containing:
//  "account": the account of the receiving address;
//  "address": the receiving address;
//  "amount": total amount received by the address;
//  "confirmations": number of confirmations of the most recent transaction.
// It takes two parameters:
//  "minconf": minimum number of confirmations to consider a transaction -
//             default: one;
//  "includeempty": whether or not to include addresses that have no transactions -
//                  default: false.
func ListReceivedByAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.ListReceivedByAddressCmd)

	// Intermediate data for each address.
	type AddrData struct {
		// Total amount received.
		amount btcutil.Amount
		// Number of confirmations of the last transaction.
		confirmations int32
		// Hashes of transactions which include an output paying to the address
		tx []string
		// Account which the address belongs to
		account string
	}

	syncBlock := w.Manager.SyncedTo()

	// Intermediate data for all addresses.
	allAddrData := make(map[string]AddrData)
	// Create an AddrData entry for each active address in the account.
	// Otherwise we'll just get addresses from transactions later.
	sortedAddrs, err := w.SortedActivePaymentAddresses()
	if err != nil {
		return nil, err
	}
	for _, address := range sortedAddrs {
		// There might be duplicates, just overwrite them.
		allAddrData[address] = AddrData{}
	}

	minConf := *cmd.MinConf
	var endHeight int32
	if minConf == 0 {
		endHeight = -1
	} else {
		endHeight = syncBlock.Height - int32(minConf) + 1
	}
	err = w.TxStore.RangeTransactions(0, endHeight, func(details []wtxmgr.TxDetails) (bool, error) {
		confirmations := confirms(details[0].Block.Height, syncBlock.Height)
		for _, tx := range details {
			for _, cred := range tx.Credits {
				pkScript := tx.MsgTx.TxOut[cred.Index].PkScript
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(
					pkScript, w.ChainParams())
				if err != nil {
					// Non standard script, skip.
					continue
				}
				for _, addr := range addrs {
					addrStr := addr.EncodeAddress()
					addrData, ok := allAddrData[addrStr]
					if ok {
						addrData.amount += cred.Amount
						// Always overwrite confirmations with newer ones.
						addrData.confirmations = confirmations
					} else {
						addrData = AddrData{
							amount:        cred.Amount,
							confirmations: confirmations,
						}
					}
					addrData.tx = append(addrData.tx, tx.Hash.String())
					allAddrData[addrStr] = addrData
				}
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	// Massage address data into output format.
	numAddresses := len(allAddrData)
	ret := make([]btcjson.ListReceivedByAddressResult, numAddresses, numAddresses)
	idx := 0
	for address, addrData := range allAddrData {
		ret[idx] = btcjson.ListReceivedByAddressResult{
			Address:       address,
			Amount:        addrData.amount.ToBTC(),
			Confirmations: uint64(addrData.confirmations),
			TxIDs:         addrData.tx,
		}
		idx++
	}
	return ret, nil
}

// ListSinceBlock handles a listsinceblock request by returning an array of maps
// with details of sent and received wallet transactions since the given block.
func ListSinceBlock(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*btcjson.ListSinceBlockCmd)

	syncBlock := w.Manager.SyncedTo()
	targetConf := int64(*cmd.TargetConfirmations)

	// For the result we need the block hash for the last block counted
	// in the blockchain due to confirmations. We send this off now so that
	// it can arrive asynchronously while we figure out the rest.
	gbh := chainClient.GetBlockHashAsync(int64(syncBlock.Height) + 1 - targetConf)

	var start int32
	if cmd.BlockHash != nil {
		hash, err := wire.NewShaHashFromStr(*cmd.BlockHash)
		if err != nil {
			return nil, DeserializationError{err}
		}
		block, err := chainClient.GetBlockVerbose(hash, false)
		if err != nil {
			return nil, err
		}
		start = int32(block.Height) + 1
	}

	txInfoList, err := w.ListSinceBlock(start, -1, syncBlock.Height)
	if err != nil {
		return nil, err
	}

	// Done with work, get the response.
	blockHash, err := gbh.Receive()
	if err != nil {
		return nil, err
	}

	res := btcjson.ListSinceBlockResult{
		Transactions: txInfoList,
		LastBlock:    blockHash.String(),
	}
	return res, nil
}

// ListTransactions handles a listtransactions request by returning an
// array of maps with details of sent and recevied wallet transactions.
func ListTransactions(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.ListTransactionsCmd)

	// TODO: ListTransactions does not currently understand the difference
	// between transactions pertaining to one account from another.  This
	// will be resolved when wtxmgr is combined with the waddrmgr namespace.

	if cmd.Account != nil && *cmd.Account != "*" {
		// For now, don't bother trying to continue if the user
		// specified an account, since this can't be (easily or
		// efficiently) calculated.
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCWallet,
			Message: "Transactions are not yet grouped by account",
		}
	}

	return w.ListTransactions(*cmd.From, *cmd.Count)
}

// ListAddressTransactions handles a listaddresstransactions request by
// returning an array of maps with details of spent and received wallet
// transactions.  The form of the reply is identical to listtransactions,
// but the array elements are limited to transaction details which are
// about the addresess included in the request.
func ListAddressTransactions(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.ListAddressTransactionsCmd)

	if cmd.Account != nil && *cmd.Account != "*" {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidParameter,
			Message: "Listing transactions for addresses may only be done for all accounts",
		}
	}

	// Decode addresses.
	hash160Map := make(map[string]struct{})
	for _, addrStr := range cmd.Addresses {
		addr, err := decodeAddress(addrStr, w.ChainParams())
		if err != nil {
			return nil, err
		}
		hash160Map[string(addr.ScriptAddress())] = struct{}{}
	}

	return w.ListAddressTransactions(hash160Map)
}

// ListAllTransactions handles a listalltransactions request by returning
// a map with details of sent and recevied wallet transactions.  This is
// similar to ListTransactions, except it takes only a single optional
// argument for the account name and replies with all transactions.
func ListAllTransactions(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.ListAllTransactionsCmd)

	if cmd.Account != nil && *cmd.Account != "*" {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidParameter,
			Message: "Listing all transactions may only be done for all accounts",
		}
	}

	return w.ListAllTransactions()
}

// ListUnspent handles the listunspent command.
func ListUnspent(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.ListUnspentCmd)

	var addresses map[string]struct{}
	if cmd.Addresses != nil {
		addresses = make(map[string]struct{})
		// confirm that all of them are good:
		for _, as := range *cmd.Addresses {
			a, err := decodeAddress(as, w.ChainParams())
			if err != nil {
				return nil, err
			}
			addresses[a.EncodeAddress()] = struct{}{}
		}
	}

	return w.ListUnspent(int32(*cmd.MinConf), int32(*cmd.MaxConf), addresses)
}

// LockUnspent handles the lockunspent command.
func LockUnspent(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.LockUnspentCmd)

	switch {
	case cmd.Unlock && len(cmd.Transactions) == 0:
		w.ResetLockedOutpoints()
	default:
		for _, input := range cmd.Transactions {
			txSha, err := wire.NewShaHashFromStr(input.Txid)
			if err != nil {
				return nil, ParseError{err}
			}
			op := wire.OutPoint{Hash: *txSha, Index: input.Vout}
			if cmd.Unlock {
				w.UnlockOutpoint(op)
			} else {
				w.LockOutpoint(op)
			}
		}
	}
	return true, nil
}

// makeOutputs creates a slice of transaction outputs from a pair of address
// strings to amounts.  This is used to create the outputs to include in newly
// created transactions from a JSON object describing the output destinations
// and amounts.
func makeOutputs(pairs map[string]btcutil.Amount, chainParams *chaincfg.Params) ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0, len(pairs))
	for addrStr, amt := range pairs {
		addr, err := btcutil.DecodeAddress(addrStr, chainParams)
		if err != nil {
			return nil, fmt.Errorf("cannot decode address: %s", err)
		}

		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, fmt.Errorf("cannot create txout script: %s", err)
		}

		outputs = append(outputs, wire.NewTxOut(int64(amt), pkScript))
	}
	return outputs, nil
}

// sendPairs creates and sends payment transactions.
// It returns the transaction hash in string format upon success
// All errors are returned in btcjson.RPCError format
func sendPairs(w *wallet.Wallet, amounts map[string]btcutil.Amount,
	account uint32, minconf int32) (string, error) {
	outputs, err := makeOutputs(amounts, w.ChainParams())
	if err != nil {
		return "", err
	}
	txSha, err := w.SendOutputs(outputs, account, minconf)
	if err != nil {
		if err == txrules.ErrAmountNegative {
			return "", ErrNeedPositiveAmount
		}
		if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
			return "", &ErrWalletUnlockNeeded
		}
		switch err.(type) {
		case btcjson.RPCError:
			return "", err
		}

		return "", &btcjson.RPCError{
			Code:    btcjson.ErrRPCInternal.Code,
			Message: err.Error(),
		}
	}

	txShaStr := txSha.String()
	log.Infof("Successfully sent transaction %v", txShaStr)
	return txShaStr, nil
}

func isNilOrEmpty(s *string) bool {
	return s == nil || *s == ""
}

// SendFrom handles a sendfrom RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to another payment
// address.  Leftover inputs not sent to the payment address or a fee for
// the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func SendFrom(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*btcjson.SendFromCmd)

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) || !isNilOrEmpty(cmd.CommentTo) {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCUnimplemented,
			Message: "Transaction comments are not yet supported",
		}
	}

	account, err := w.Manager.LookupAccount(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Check that signed integer parameters are positive.
	if cmd.Amount < 0 {
		return nil, ErrNeedPositiveAmount
	}
	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, ErrNeedPositiveMinconf
	}
	// Create map of address and amount pairs.
	amt, err := btcutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, err
	}
	pairs := map[string]btcutil.Amount{
		cmd.ToAddress: amt,
	}

	return sendPairs(w, pairs, account, minConf)
}

// SendMany handles a sendmany RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to any number of
// payment addresses.  Leftover inputs not sent to the payment address
// or a fee for the miner are sent back to a new address in the wallet.
// Upon success, the TxID for the created transaction is returned.
func SendMany(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.SendManyCmd)

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCUnimplemented,
			Message: "Transaction comments are not yet supported",
		}
	}

	account, err := w.Manager.LookupAccount(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Check that minconf is positive.
	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, ErrNeedPositiveMinconf
	}

	// Recreate address/amount pairs, using btcutil.Amount.
	pairs := make(map[string]btcutil.Amount, len(cmd.Amounts))
	for k, v := range cmd.Amounts {
		amt, err := btcutil.NewAmount(v)
		if err != nil {
			return nil, err
		}
		pairs[k] = amt
	}

	return sendPairs(w, pairs, account, minConf)
}

// SendToAddress handles a sendtoaddress RPC request by creating a new
// transaction spending unspent transaction outputs for a wallet to another
// payment address.  Leftover inputs not sent to the payment address or a fee
// for the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func SendToAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.SendToAddressCmd)

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) || !isNilOrEmpty(cmd.CommentTo) {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCUnimplemented,
			Message: "Transaction comments are not yet supported",
		}
	}

	amt, err := btcutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, err
	}

	// Check that signed integer parameters are positive.
	if amt < 0 {
		return nil, ErrNeedPositiveAmount
	}

	// Mock up map of address and amount pairs.
	pairs := map[string]btcutil.Amount{
		cmd.Address: amt,
	}

	// sendtoaddress always spends from the default account, this matches bitcoind
	return sendPairs(w, pairs, waddrmgr.DefaultAccountNum, 1)
}

// SetTxFee sets the transaction fee per kilobyte added to transactions.
func SetTxFee(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.SetTxFeeCmd)

	// Check that amount is not negative.
	if cmd.Amount < 0 {
		return nil, ErrNeedPositiveAmount
	}

	relayFee, err := btcutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, err
	}
	w.SetRelayFee(relayFee)

	// A boolean true result is returned upon success.
	return true, nil
}

// SignMessage signs the given message with the private key for the given
// address
func SignMessage(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.SignMessageCmd)

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	ainfo, err := w.Manager.Address(addr)
	if err != nil {
		return nil, err
	}
	pka, ok := ainfo.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		msg := fmt.Sprintf("Address '%s' does not have an associated private key", addr)
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidAddressOrKey,
			Message: msg,
		}
	}
	privKey, err := pka.PrivKey()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, "Bitcoin Signed Message:\n")
	wire.WriteVarString(&buf, 0, cmd.Message)
	messageHash := wire.DoubleSha256(buf.Bytes())
	sigbytes, err := btcec.SignCompact(btcec.S256(), privKey,
		messageHash, ainfo.Compressed())
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.EncodeToString(sigbytes), nil
}

// SignRawTransaction handles the signrawtransaction command.
func SignRawTransaction(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*btcjson.SignRawTransactionCmd)

	serializedTx, err := decodeHexStr(cmd.RawTx)
	if err != nil {
		return nil, err
	}
	tx := wire.NewMsgTx()
	err = tx.Deserialize(bytes.NewBuffer(serializedTx))
	if err != nil {
		e := errors.New("TX decode failed")
		return nil, DeserializationError{e}
	}

	var hashType txscript.SigHashType
	switch *cmd.Flags {
	case "ALL":
		hashType = txscript.SigHashAll
	case "NONE":
		hashType = txscript.SigHashNone
	case "SINGLE":
		hashType = txscript.SigHashSingle
	case "ALL|ANYONECANPAY":
		hashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	case "NONE|ANYONECANPAY":
		hashType = txscript.SigHashNone | txscript.SigHashAnyOneCanPay
	case "SINGLE|ANYONECANPAY":
		hashType = txscript.SigHashSingle | txscript.SigHashAnyOneCanPay
	default:
		e := errors.New("Invalid sighash parameter")
		return nil, InvalidParameterError{e}
	}

	// TODO: really we probably should look these up with btcd anyway to
	// make sure that they match the blockchain if present.
	inputs := make(map[wire.OutPoint][]byte)
	scripts := make(map[string][]byte)
	var cmdInputs []btcjson.RawTxInput
	if cmd.Inputs != nil {
		cmdInputs = *cmd.Inputs
	}
	for _, rti := range cmdInputs {
		inputSha, err := wire.NewShaHashFromStr(rti.Txid)
		if err != nil {
			return nil, DeserializationError{err}
		}

		script, err := decodeHexStr(rti.ScriptPubKey)
		if err != nil {
			return nil, err
		}

		// redeemScript is only actually used iff the user provided
		// private keys. In which case, it is used to get the scripts
		// for signing. If the user did not provide keys then we always
		// get scripts from the wallet.
		// Empty strings are ok for this one and hex.DecodeString will
		// DTRT.
		if cmd.PrivKeys != nil && len(*cmd.PrivKeys) != 0 {
			redeemScript, err := decodeHexStr(rti.RedeemScript)
			if err != nil {
				return nil, err
			}

			addr, err := btcutil.NewAddressScriptHash(redeemScript,
				w.ChainParams())
			if err != nil {
				return nil, DeserializationError{err}
			}
			scripts[addr.String()] = redeemScript
		}
		inputs[wire.OutPoint{
			Hash:  *inputSha,
			Index: rti.Vout,
		}] = script
	}

	// Now we go and look for any inputs that we were not provided by
	// querying btcd with getrawtransaction. We queue up a bunch of async
	// requests and will wait for replies after we have checked the rest of
	// the arguments.
	requested := make(map[wire.OutPoint]btcrpcclient.FutureGetTxOutResult)
	for _, txIn := range tx.TxIn {
		// Did we get this outpoint from the arguments?
		if _, ok := inputs[txIn.PreviousOutPoint]; ok {
			continue
		}

		// Asynchronously request the output script.
		requested[txIn.PreviousOutPoint] = chainClient.GetTxOutAsync(
			&txIn.PreviousOutPoint.Hash, txIn.PreviousOutPoint.Index,
			true)
	}

	// Parse list of private keys, if present. If there are any keys here
	// they are the keys that we may use for signing. If empty we will
	// use any keys known to us already.
	var keys map[string]*btcutil.WIF
	if cmd.PrivKeys != nil {
		keys = make(map[string]*btcutil.WIF)

		for _, key := range *cmd.PrivKeys {
			wif, err := btcutil.DecodeWIF(key)
			if err != nil {
				return nil, DeserializationError{err}
			}

			if !wif.IsForNet(w.ChainParams()) {
				s := "key network doesn't match wallet's"
				return nil, DeserializationError{errors.New(s)}
			}

			addr, err := btcutil.NewAddressPubKey(wif.SerializePubKey(),
				w.ChainParams())
			if err != nil {
				return nil, DeserializationError{err}
			}
			keys[addr.EncodeAddress()] = wif
		}
	}

	// We have checked the rest of the args. now we can collect the async
	// txs. TODO: If we don't mind the possibility of wasting work we could
	// move waiting to the following loop and be slightly more asynchronous.
	for outPoint, resp := range requested {
		result, err := resp.Receive()
		if err != nil {
			return nil, err
		}
		script, err := hex.DecodeString(result.ScriptPubKey.Hex)
		if err != nil {
			return nil, err
		}
		inputs[outPoint] = script
	}

	// All args collected. Now we can sign all the inputs that we can.
	// `complete' denotes that we successfully signed all outputs and that
	// all scripts will run to completion. This is returned as part of the
	// reply.
	signErrs, err := w.SignTransaction(tx, hashType, inputs, keys, scripts)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())

	// All returned errors (not OOM, which panics) encounted during
	// bytes.Buffer writes are unexpected.
	if err = tx.Serialize(&buf); err != nil {
		panic(err)
	}

	signErrors := make([]btcjson.SignRawTransactionError, 0, len(signErrs))
	for _, e := range signErrs {
		input := tx.TxIn[e.InputIndex]
		signErrors = append(signErrors, btcjson.SignRawTransactionError{
			TxID:      input.PreviousOutPoint.Hash.String(),
			Vout:      input.PreviousOutPoint.Index,
			ScriptSig: hex.EncodeToString(input.SignatureScript),
			Sequence:  input.Sequence,
			Error:     e.Error.Error(),
		})
	}

	return btcjson.SignRawTransactionResult{
		Hex:      hex.EncodeToString(buf.Bytes()),
		Complete: len(signErrors) == 0,
		Errors:   signErrors,
	}, nil
}

// ValidateAddress handles the validateaddress command.
func ValidateAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.ValidateAddressCmd)

	result := btcjson.ValidateAddressWalletResult{}
	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		// Use result zero value (IsValid=false).
		return result, nil
	}

	// We could put whether or not the address is a script here,
	// by checking the type of "addr", however, the reference
	// implementation only puts that information if the script is
	// "ismine", and we follow that behaviour.
	result.Address = addr.EncodeAddress()
	result.IsValid = true

	ainfo, err := w.Manager.Address(addr)
	if err != nil {
		if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
			// No additional information available about the address.
			return result, nil
		}
		return nil, err
	}

	// The address lookup was successful which means there is further
	// information about it available and it is "mine".
	result.IsMine = true
	acctName, err := w.Manager.AccountName(ainfo.Account())
	if err != nil {
		return nil, &ErrAccountNameNotFound
	}
	result.Account = acctName

	switch ma := ainfo.(type) {
	case waddrmgr.ManagedPubKeyAddress:
		result.IsCompressed = ma.Compressed()
		result.PubKey = ma.ExportPubKey()

	case waddrmgr.ManagedScriptAddress:
		result.IsScript = true

		// The script is only available if the manager is unlocked, so
		// just break out now if there is an error.
		script, err := ma.Script()
		if err != nil {
			break
		}
		result.Hex = hex.EncodeToString(script)

		// This typically shouldn't fail unless an invalid script was
		// imported.  However, if it fails for any reason, there is no
		// further information available, so just set the script type
		// a non-standard and break out now.
		class, addrs, reqSigs, err := txscript.ExtractPkScriptAddrs(
			script, w.ChainParams())
		if err != nil {
			result.Script = txscript.NonStandardTy.String()
			break
		}

		addrStrings := make([]string, len(addrs))
		for i, a := range addrs {
			addrStrings[i] = a.EncodeAddress()
		}
		result.Addresses = addrStrings

		// Multi-signature scripts also provide the number of required
		// signatures.
		result.Script = class.String()
		if class == txscript.MultiSigTy {
			result.SigsRequired = int32(reqSigs)
		}
	}

	return result, nil
}

// VerifyMessage handles the verifymessage command by verifying the provided
// compact signature for the given address and message.
func VerifyMessage(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.VerifyMessageCmd)

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	// decode base64 signature
	sig, err := base64.StdEncoding.DecodeString(cmd.Signature)
	if err != nil {
		return nil, err
	}

	// Validate the signature - this just shows that it was valid at all.
	// we will compare it with the key next.
	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, "Bitcoin Signed Message:\n")
	wire.WriteVarString(&buf, 0, cmd.Message)
	expectedMessageHash := wire.DoubleSha256(buf.Bytes())
	pk, wasCompressed, err := btcec.RecoverCompact(btcec.S256(), sig,
		expectedMessageHash)
	if err != nil {
		return nil, err
	}

	var serializedPubKey []byte
	if wasCompressed {
		serializedPubKey = pk.SerializeCompressed()
	} else {
		serializedPubKey = pk.SerializeUncompressed()
	}
	// Verify that the signed-by address matches the given address
	switch checkAddr := addr.(type) {
	case *btcutil.AddressPubKeyHash: // ok
		return bytes.Equal(btcutil.Hash160(serializedPubKey), checkAddr.Hash160()[:]), nil
	case *btcutil.AddressPubKey: // ok
		return string(serializedPubKey) == checkAddr.String(), nil
	default:
		return nil, errors.New("address type not supported")
	}
}

// WalletIsLocked handles the walletislocked extension request by
// returning the current lock state (false for unlocked, true for locked)
// of an account.
func WalletIsLocked(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return w.Locked(), nil
}

// WalletLock handles a walletlock request by locking the all account
// wallets, returning an error if any wallet is not encrypted (for example,
// a watching-only wallet).
func WalletLock(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	w.Lock()
	return nil, nil
}

// WalletPassphrase responds to the walletpassphrase request by unlocking
// the wallet.  The decryption key is saved in the wallet until timeout
// seconds expires, after which the wallet is locked.
func WalletPassphrase(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.WalletPassphraseCmd)

	timeout := time.Second * time.Duration(cmd.Timeout)
	var unlockAfter <-chan time.Time
	if timeout != 0 {
		unlockAfter = time.After(timeout)
	}
	err := w.Unlock([]byte(cmd.Passphrase), unlockAfter)
	return nil, err
}

// WalletPassphraseChange responds to the walletpassphrasechange request
// by unlocking all accounts with the provided old passphrase, and
// re-encrypting each private key with an AES key derived from the new
// passphrase.
//
// If the old passphrase is correct and the passphrase is changed, all
// wallets will be immediately locked.
func WalletPassphraseChange(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*btcjson.WalletPassphraseChangeCmd)

	err := w.ChangePassphrase([]byte(cmd.OldPassphrase),
		[]byte(cmd.NewPassphrase))
	if waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase) {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCWalletPassphraseIncorrect,
			Message: "Incorrect passphrase",
		}
	}
	return nil, err
}

// decodeHexStr decodes the hex encoding of a string, possibly prepending a
// leading '0' character if there is an odd number of bytes in the hex string.
// This is to prevent an error for an invalid hex string when using an odd
// number of bytes when calling hex.Decode.
func decodeHexStr(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCDecodeHexString,
			Message: "Hex string decode failed: " + err.Error(),
		}
	}
	return decoded, nil
}
