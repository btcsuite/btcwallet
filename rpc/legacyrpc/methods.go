// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
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

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"

	"github.com/decred/dcrrpcclient"

	"github.com/decred/dcrutil"

	"github.com/decred/dcrwallet/chain"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/wallet"
	"github.com/decred/dcrwallet/wallet/txrules"
	"github.com/decred/dcrwallet/wstakemgr"
	"github.com/decred/dcrwallet/wtxmgr"
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
// request into a marshalable response.  If the error is a *dcrjson.RPCError
// or any of the above special error classes, the server will respond with
// the JSON-RPC appropiate error code.  All other errors use the wallet
// catch-all error code, dcrjson.ErrRPCWallet.
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

	// This is disabled on a mainnet wallet unless run with the specified
	// flag.
	requireUnsafeOnMainNet bool
}{
	// Reference implementation wallet methods (implemented)
	"accountaddressindex":     {handler: accountAddressIndex},
	"accountfetchaddresses":   {handler: accountFetchAddresses},
	"accountsyncaddressindex": {handler: accountSyncAddressIndex},
	"addmultisigaddress":      {handlerWithChain: addMultiSigAddress},
	"addticket":               {handler: addTicket},
	"consolidate":             {handler: consolidate},
	"createmultisig":          {handler: createMultiSig},
	"dumpprivkey":             {handler: dumpPrivKey, requireUnsafeOnMainNet: true},
	"getaccount":              {handler: getAccount},
	"getaccountaddress":       {handler: getAccountAddress},
	"getaddressesbyaccount":   {handler: getAddressesByAccount},
	"getbalance":              {handler: getBalance},
	"getbestblockhash":        {handler: getBestBlockHash},
	"getblockcount":           {handler: getBlockCount},
	"getinfo":                 {handlerWithChain: getInfo},
	"getbalancetomaintain":    {handler: getBalanceToMaintain},
	"getgenerate":             {handler: getGenerate},
	"getmasterpubkey":         {handler: getMasterPubkey},
	"getmultisigoutinfo":      {handlerWithChain: getMultisigOutInfo},
	"getnewaddress":           {handler: getNewAddress},
	"getrawchangeaddress":     {handler: getRawChangeAddress},
	"getreceivedbyaccount":    {handler: getReceivedByAccount},
	"getreceivedbyaddress":    {handler: getReceivedByAddress},
	"getseed":                 {handler: getSeed, requireUnsafeOnMainNet: true},
	"getstakeinfo":            {handlerWithChain: getStakeInfo},
	"getticketfee":            {handler: getTicketFee},
	"getticketmaxprice":       {handler: getTicketMaxPrice},
	"gettickets":              {handlerWithChain: getTickets},
	"getticketvotebits":       {handler: getTicketVoteBits},
	"getticketsvotebits":      {handler: getTicketsVoteBits},
	"gettransaction":          {handler: getTransaction},
	"getwalletfee":            {handler: getWalletFee},
	"help":                    {handler: helpNoChainRPC, handlerWithChain: helpWithChainRPC},
	"importprivkey":           {handlerWithChain: importPrivKey},
	"importscript":            {handlerWithChain: importScript},
	"keypoolrefill":           {handler: keypoolRefill},
	"listaccounts":            {handler: listAccounts},
	"listlockunspent":         {handler: listLockUnspent},
	"listreceivedbyaccount":   {handler: listReceivedByAccount},
	"listreceivedbyaddress":   {handler: listReceivedByAddress},
	"listsinceblock":          {handlerWithChain: listSinceBlock},
	"listscripts":             {handler: listScripts},
	"listtransactions":        {handler: listTransactions},
	"listunspent":             {handler: listUnspent},
	"lockunspent":             {handler: lockUnspent},
	"purchaseticket":          {handler: purchaseTicket},
	"sendfrom":                {handlerWithChain: sendFrom},
	"sendmany":                {handler: sendMany},
	"sendtoaddress":           {handler: sendToAddress},
	"sendtomultisig":          {handlerWithChain: sendToMultiSig},
	"sendtosstx":              {handlerWithChain: sendToSStx},
	"sendtossgen":             {handler: sendToSSGen},
	"sendtossrtx":             {handlerWithChain: sendToSSRtx},
	"setgenerate":             {handler: setGenerate},
	"setbalancetomaintain":    {handler: setBalanceToMaintain},
	"setticketfee":            {handler: setTicketFee},
	"setticketmaxprice":       {handler: setTicketMaxPrice},
	"setticketvotebits":       {handler: setTicketVoteBits},
	"settxfee":                {handler: setTxFee},
	"signmessage":             {handler: signMessage},
	"signrawtransaction":      {handlerWithChain: signRawTransaction},
	"signrawtransactions":     {handlerWithChain: signRawTransactions},
	"redeemmultisigout":       {handlerWithChain: redeemMultiSigOut},
	"redeemmultisigouts":      {handlerWithChain: redeemMultiSigOuts},
	"stakepooluserinfo":       {handler: stakePoolUserInfo},
	"ticketsforaddress":       {handler: ticketsForAddress},
	"validateaddress":         {handler: validateAddress},
	"verifymessage":           {handler: verifyMessage},
	"walletinfo":              {handlerWithChain: walletInfo},
	"walletlock":              {handler: walletLock},
	"walletpassphrase":        {handler: walletPassphrase},
	"walletpassphrasechange":  {handler: walletPassphraseChange},

	// Reference implementation methods (still unimplemented)
	"backupwallet":         {handler: unimplemented, noHelp: true},
	"dumpwallet":           {handler: unimplemented, noHelp: true},
	"getwalletinfo":        {handler: unimplemented, noHelp: true},
	"importwallet":         {handler: unimplemented, noHelp: true},
	"listaddressgroupings": {handler: unimplemented, noHelp: true},

	// Reference methods which can't be implemented by dcrwallet due to
	// design decision differences
	"encryptwallet": {handler: unsupported, noHelp: true},
	"move":          {handler: unsupported, noHelp: true},
	"setaccount":    {handler: unsupported, noHelp: true},

	// Extensions to the reference client JSON-RPC API
	"createnewaccount": {handler: createNewAccount},
	"getbestblock":     {handler: getBestBlock},
	// This was an extension but the reference implementation added it as
	// well, but with a different API (no account parameter).  It's listed
	// here because it hasn't been update to use the reference
	// implemenation's API.
	"getunconfirmedbalance":   {handler: getUnconfirmedBalance},
	"listaddresstransactions": {handler: listAddressTransactions},
	"listalltransactions":     {handler: listAllTransactions},
	"renameaccount":           {handler: renameAccount},
	"walletislocked":          {handler: walletIsLocked},
}

// unimplemented handles an unimplemented RPC request with the
// appropiate error.
func unimplemented(interface{}, *wallet.Wallet) (interface{}, error) {
	return nil, &dcrjson.RPCError{
		Code:    dcrjson.ErrRPCUnimplemented,
		Message: "Method unimplemented",
	}
}

// unsupported handles a standard bitcoind RPC request which is
// unsupported by dcrwallet due to design differences.
func unsupported(interface{}, *wallet.Wallet) (interface{}, error) {
	return nil, &dcrjson.RPCError{
		Code:    -1,
		Message: "Request unsupported by dcrwallet",
	}
}

// lazyHandler is a closure over a requestHandler or passthrough request with
// the RPC server's wallet and chain server variables as part of the closure
// context.
type lazyHandler func() (interface{}, *dcrjson.RPCError)

// lazyApplyHandler looks up the best request handler func for the method,
// returning a closure that will execute it with the (required) wallet and
// (optional) consensus RPC server.  If no handlers are found and the
// chainClient is not nil, the returned handler performs RPC passthrough.
func lazyApplyHandler(request *dcrjson.Request, w *wallet.Wallet, chainClient *chain.RPCClient, unsafeMainNet bool) lazyHandler {
	handlerData, ok := rpcHandlers[request.Method]
	if ok && handlerData.requireUnsafeOnMainNet &&
		w.ChainParams() == &chaincfg.MainNetParams && !unsafeMainNet {
		return func() (interface{}, *dcrjson.RPCError) {
			return nil, &ErrMainNetSafety
		}
	}
	if ok && handlerData.handlerWithChain != nil && w != nil && chainClient != nil {
		return func() (interface{}, *dcrjson.RPCError) {
			cmd, err := dcrjson.UnmarshalCmd(request)
			if err != nil {
				return nil, dcrjson.ErrRPCInvalidRequest
			}
			resp, err := handlerData.handlerWithChain(cmd, w, chainClient)
			if err != nil {
				return nil, jsonError(err)
			}
			return resp, nil
		}
	}
	if ok && handlerData.handler != nil && w != nil {
		return func() (interface{}, *dcrjson.RPCError) {
			cmd, err := dcrjson.UnmarshalCmd(request)
			if err != nil {
				return nil, dcrjson.ErrRPCInvalidRequest
			}
			resp, err := handlerData.handler(cmd, w)
			if err != nil {
				return nil, jsonError(err)
			}
			return resp, nil
		}
	}

	// Fallback to RPC passthrough
	return func() (interface{}, *dcrjson.RPCError) {
		if chainClient == nil {
			return nil, &dcrjson.RPCError{
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
func makeResponse(id, result interface{}, err error) dcrjson.Response {
	idPtr := idPointer(id)
	if err != nil {
		return dcrjson.Response{
			ID:    idPtr,
			Error: jsonError(err),
		}
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return dcrjson.Response{
			ID: idPtr,
			Error: &dcrjson.RPCError{
				Code:    dcrjson.ErrRPCInternal.Code,
				Message: "Unexpected error marshalling result",
			},
		}
	}
	return dcrjson.Response{
		ID:     idPtr,
		Result: json.RawMessage(resultBytes),
	}
}

// jsonError creates a JSON-RPC error from the Go error.
func jsonError(err error) *dcrjson.RPCError {
	if err == nil {
		return nil
	}

	code := dcrjson.ErrRPCWallet
	switch e := err.(type) {
	case dcrjson.RPCError:
		return &e
	case *dcrjson.RPCError:
		return e
	case DeserializationError:
		code = dcrjson.ErrRPCDeserialization
	case InvalidParameterError:
		code = dcrjson.ErrRPCInvalidParameter
	case ParseError:
		code = dcrjson.ErrRPCParse.Code
	case waddrmgr.ManagerError:
		switch e.ErrorCode {
		case waddrmgr.ErrWrongPassphrase:
			code = dcrjson.ErrRPCWalletPassphraseIncorrect
		}
	}
	return &dcrjson.RPCError{
		Code:    code,
		Message: err.Error(),
	}
}

// accountAddressIndex returns the current address index for the passed
// account and branch.
func accountAddressIndex(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.AccountAddressIndexCmd)
	account, err := w.Manager.LookupAccount(cmd.Account)
	if err != nil {
		return nil, err
	}

	// The branch may only be internal or external.
	branch := uint32(cmd.Branch)
	if branch > waddrmgr.InternalBranch {
		return nil, fmt.Errorf("invalid branch %v", branch)
	}

	idx, err := w.AddressPoolIndex(account, branch)
	if err != nil {
		return nil, err
	}

	return idx, nil
}

// accountFetchAddresses returns the all addresses from (start,end] for the
// passed account and branch.
func accountFetchAddresses(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.AccountFetchAddressesCmd)
	account, err := w.Manager.LookupAccount(cmd.Account)
	if err != nil {
		return nil, err
	}

	// The branch may only be internal or external.
	branch := uint32(cmd.Branch)
	if branch > waddrmgr.InternalBranch {
		return nil, fmt.Errorf("invalid branch %v", branch)
	}

	if cmd.End <= cmd.Start ||
		cmd.Start > waddrmgr.MaxAddressesPerAccount ||
		cmd.End > waddrmgr.MaxAddressesPerAccount {
		return nil, fmt.Errorf("bad indexes start %v, end %v", cmd.Start,
			cmd.End)
	}

	addrs, err := w.Manager.AddressesDerivedFromDbAcct(uint32(cmd.Start),
		uint32(cmd.End), account, branch)
	if err != nil {
		return nil, err
	}
	addrsStr := make([]string, cmd.End-cmd.Start)
	for i := range addrs {
		addrsStr[i] = addrs[i].EncodeAddress()
	}

	return dcrjson.AccountFetchAddressesResult{Addresses: addrsStr}, nil
}

// accountSyncAddressIndex synchronizes the address manager and local address
// pool for some account and branch to the passed index. If the current pool
// index is beyond the passed index, an error is returned. If the passed index
// is the same as the current pool index, nothing is returned. If the syncing
// is successful, nothing is returned.
func accountSyncAddressIndex(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.AccountSyncAddressIndexCmd)
	account, err := w.Manager.LookupAccount(cmd.Account)
	if err != nil {
		return nil, err
	}

	// The branch may only be internal or external.
	branch := uint32(cmd.Branch)
	if branch > waddrmgr.InternalBranch {
		return nil, fmt.Errorf("invalid branch %v", branch)
	}

	// Get the current address pool index for this branch
	// and do basic sanity checks.
	index := uint32(cmd.Index)
	currentIndex, err := w.AddressPoolIndex(account, branch)
	if err != nil {
		return nil, err
	}
	if index < currentIndex {
		return nil, fmt.Errorf("the passed index, %v, is before the "+
			"currently synced to address index %v", index, currentIndex)
	}
	if index == currentIndex {
		return nil, nil
	}

	return nil, w.SyncAddressPoolIndex(account, branch, index)
}

// makeMultiSigScript is a helper function to combine common logic for
// AddMultiSig and CreateMultiSig.
// all error codes are rpc parse error here to match bitcoind which just throws
// a runtime exception. *sigh*.
func makeMultiSigScript(w *wallet.Wallet, keys []string,
	nRequired int) ([]byte, error) {
	keysesPrecious := make([]*dcrutil.AddressSecpPubKey, len(keys))

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
		case *dcrutil.AddressSecpPubKey:
			keysesPrecious[i] = addr
		case *dcrutil.AddressPubKeyHash:
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

			apk := a.(*dcrutil.AddressSecpPubKey)
			keysesPrecious[i] = apk
		default:
			return nil, err
		}
	}

	return txscript.MultiSigScript(keysesPrecious, nRequired)
}

// addMultiSigAddress handles an addmultisigaddress request by adding a
// multisig address to the given wallet.
func addMultiSigAddress(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.AddMultisigAddressCmd)

	// If an account is specified, ensure that is the imported account.
	if cmd.Account != nil && *cmd.Account != waddrmgr.ImportedAddrAccountName {
		return nil, &ErrNotImportedAccount
	}

	script, err := makeMultiSigScript(w, cmd.Keys, cmd.NRequired)
	if err != nil {
		return nil, ParseError{err}
	}

	// Insert into the tx store.
	err = w.TxStore.InsertTxScript(script)
	if err != nil {
		return nil, err
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

	err = chainClient.NotifyReceived([]dcrutil.Address{addr.Address()})
	if err != nil {
		return nil, err
	}

	return addr.Address().EncodeAddress(), nil
}

// addTicket adds a ticket to the stake manager manually.
func addTicket(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.AddTicketCmd)

	rawTx, err := hex.DecodeString(cmd.TicketHex)
	if err != nil {
		return nil, err
	}

	mtx := new(wire.MsgTx)
	err = mtx.FromBytes(rawTx)
	if err != nil {
		return nil, err
	}
	tx := dcrutil.NewTx(mtx)

	err = w.StakeMgr.InsertSStx(tx, w.VoteBits)

	return nil, err
}

// consolidate handles a consolidate request by returning attempting to compress
// as many inputs as given and then returning the txHash and error.
func consolidate(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.ConsolidateCmd)

	account := uint32(waddrmgr.DefaultAccountNum)
	var err error
	if cmd.Account != nil {
		account, err = w.Manager.LookupAccount(*cmd.Account)
		if err != nil {
			return nil, err
		}
	}

	// TODO In the future this should take the optional account and
	// only consolidate UTXOs found within that account.
	txHash, err := w.Consolidate(cmd.Inputs, account)
	if err != nil {
		return nil, err
	}

	return txHash.String(), nil
}

// createMultiSig handles an createmultisig request by returning a
// multisig address for the given inputs.
func createMultiSig(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.CreateMultisigCmd)

	script, err := makeMultiSigScript(w, cmd.Keys, cmd.NRequired)
	if err != nil {
		return nil, ParseError{err}
	}

	address, err := dcrutil.NewAddressScriptHash(script, w.ChainParams())
	if err != nil {
		// above is a valid script, shouldn't happen.
		return nil, err
	}

	return dcrjson.CreateMultiSigResult{
		Address:      address.EncodeAddress(),
		RedeemScript: hex.EncodeToString(script),
	}, nil
}

// dumpPrivKey handles a dumpprivkey request with the private key
// for a single address, or an appropiate error if the wallet
// is locked.
func dumpPrivKey(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.DumpPrivKeyCmd)

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

// dumpWallet handles a dumpwallet request by returning  all private
// keys in a wallet, or an appropiate error if the wallet is locked.
// TODO: finish this to match bitcoind by writing the dump to a file.
func dumpWallet(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	keys, err := w.DumpPrivKeys()
	if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
		return nil, &ErrWalletUnlockNeeded
	}

	return keys, err
}

// getAddressesByAccount handles a getaddressesbyaccount request by returning
// all addresses for an account, or an error if the requested account does
// not exist.
func getAddressesByAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetAddressesByAccountCmd)

	account, err := w.Manager.LookupAccount(cmd.Account)
	if err != nil {
		return nil, err
	}

	// Find the current synced-to indexes from the address pool.
	endExt, err := w.AddressPoolIndex(account, waddrmgr.ExternalBranch)
	if err != nil {
		return nil, err
	}
	endInt, err := w.AddressPoolIndex(account, waddrmgr.InternalBranch)
	if err != nil {
		return nil, err
	}

	// Nothing to do if we have no addresses.
	if endExt+endInt == 0 {
		return nil, nil
	}

	// Derive the addresses.
	addrsStr := make([]string, endInt+endExt)
	addrsExt, err := w.Manager.AddressesDerivedFromDbAcct(0, endExt,
		account, waddrmgr.ExternalBranch)
	if err != nil {
		return nil, err
	}
	for i := range addrsExt {
		addrsStr[i] = addrsExt[i].EncodeAddress()
	}
	addrsInt, err := w.Manager.AddressesDerivedFromDbAcct(0, endInt,
		account, waddrmgr.InternalBranch)
	if err != nil {
		return nil, err
	}
	for i := range addrsInt {
		addrsStr[i+int(endExt)] = addrsInt[i].EncodeAddress()
	}

	return addrsStr, nil
}

// getBalance handles a getbalance request by returning the balance for an
// account (wallet), or an error if the requested account does not
// exist.
func getBalance(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetBalanceCmd)

	var balance dcrutil.Amount
	var err error
	accountName := "*"
	if cmd.Account != nil {
		accountName = *cmd.Account
	}
	balType := wtxmgr.BFBalanceSpendable
	if cmd.BalanceType != nil {
		switch *cmd.BalanceType {
		case "spendable":
			balType = wtxmgr.BFBalanceSpendable
		case "locked":
			balType = wtxmgr.BFBalanceLockedStake
		case "all":
			balType = wtxmgr.BFBalanceAll
		case "fullscan":
			balType = wtxmgr.BFBalanceFullScan
		default:
			return nil, fmt.Errorf("unknown balance type '%v', please use "+
				"spendable, locked, all, or fullscan", *cmd.BalanceType)
		}
	}
	if accountName == "*" {
		balance, err = w.CalculateBalance(int32(*cmd.MinConf),
			balType)
	} else {
		var account uint32
		account, err = w.Manager.LookupAccount(accountName)
		if err != nil {
			return nil, err
		}

		// For individual accounts, we always want to use full scan.
		if balType == wtxmgr.BFBalanceSpendable {
			balType = wtxmgr.BFBalanceFullScan
		}

		bal, err := w.CalculateAccountBalance(account, int32(*cmd.MinConf),
			balType)
		if err != nil {
			return nil, err
		}
		balance = bal
	}
	if err != nil {
		return nil, err
	}
	return balance.ToCoin(), nil
}

// getBestBlock handles a getbestblock request by returning a JSON object
// with the height and hash of the most recently processed block.
func getBestBlock(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	blk := w.Manager.SyncedTo()
	result := &dcrjson.GetBestBlockResult{
		Hash:   blk.Hash.String(),
		Height: int64(blk.Height),
	}
	return result, nil
}

// getBestBlockHash handles a getbestblockhash request by returning the hash
// of the most recently processed block.
func getBestBlockHash(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	blk := w.Manager.SyncedTo()
	return blk.Hash.String(), nil
}

// getBlockCount handles a getblockcount request by returning the chain height
// of the most recently processed block.
func getBlockCount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	blk := w.Manager.SyncedTo()
	return blk.Height, nil
}

// getInfo handles a getinfo request by returning the a structure containing
// information about the current state of dcrcwallet.
// exist.
func getInfo(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	// Call down to dcrd for all of the information in this command known
	// by them.
	info, err := chainClient.GetInfo()
	if err != nil {
		return nil, err
	}

	bal, err := w.CalculateBalance(1, wtxmgr.BFBalanceSpendable)
	if err != nil {
		return nil, err
	}

	// TODO(davec): This should probably have a database version as opposed
	// to using the manager version.
	info.WalletVersion = int32(waddrmgr.LatestMgrVersion)
	info.Balance = bal.ToCoin()
	info.KeypoolOldest = time.Now().Unix()
	info.KeypoolSize = 0
	info.PaytxFee = w.RelayFee().ToCoin()
	// We don't set the following since they don't make much sense in the
	// wallet architecture:
	//  - unlocked_until
	//  - errors

	return info, nil
}

func decodeAddress(s string, params *chaincfg.Params) (dcrutil.Address, error) {
	// Secp256k1 pubkey as a string, handle differently.
	if len(s) == 66 || len(s) == 130 {
		pubKeyBytes, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		pubKeyAddr, err := dcrutil.NewAddressSecpPubKey(pubKeyBytes,
			params)
		if err != nil {
			return nil, err
		}

		return pubKeyAddr, nil
	}

	addr, err := dcrutil.DecodeAddress(s, params)
	if err != nil {
		msg := fmt.Sprintf("Invalid address %q: decode failed with %#q", s, err)
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInvalidAddressOrKey,
			Message: msg,
		}
	}
	if !addr.IsForNet(params) {
		msg := fmt.Sprintf("Invalid address %q: not intended for use on %s",
			addr, params.Name)
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInvalidAddressOrKey,
			Message: msg,
		}
	}
	return addr, nil
}

// getAccount handles a getaccount request by returning the account name
// associated with a single address.
func getAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetAccountCmd)

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

// getAccountAddress handles a getaccountaddress by returning the most
// recently-created chained address that has not yet been used (does not yet
// appear in the blockchain, or any tx that has arrived in the dcrd mempool).
// If the most recently-requested address has been used, a new address (the
// next chained address in the keypool) is used.  This can fail if the keypool
// runs out (and will return dcrjson.ErrRPCWalletKeypoolRanOut if that happens).
func getAccountAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetAccountAddressCmd)

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

// getUnconfirmedBalance handles a getunconfirmedbalance extension request
// by returning the current unconfirmed balance of an account.
func getUnconfirmedBalance(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetUnconfirmedBalanceCmd)

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

	return (bals.Total - bals.Spendable).ToCoin(), nil
}

// importPrivKey handles an importprivkey request by parsing
// a WIF-encoded private key and adding it to an account.
func importPrivKey(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.ImportPrivKeyCmd)

	// Ensure that private keys are only imported to the correct account.
	//
	// Yes, Label is the account name.
	if cmd.Label != nil && *cmd.Label != waddrmgr.ImportedAddrAccountName {
		return nil, &ErrNotImportedAccount
	}

	wif, err := dcrutil.DecodeWIF(cmd.PrivKey)
	if err != nil {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInvalidAddressOrKey,
			Message: "WIF decode failed: " + err.Error(),
		}
	}
	if !wif.IsForNet(w.ChainParams()) {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInvalidAddressOrKey,
			Message: "Key is not intended for " + w.ChainParams().Name,
		}
	}

	rescan := true
	if cmd.Rescan != nil {
		rescan = *cmd.Rescan
	}

	scanFrom := 0
	if cmd.ScanFrom != nil {
		scanFrom = *cmd.ScanFrom
	}

	// Import the private key, handling any errors.
	_, err = w.ImportPrivateKey(wif, nil, rescan, int32(scanFrom))
	switch {
	case waddrmgr.IsError(err, waddrmgr.ErrDuplicateAddress):
		// Do not return duplicate key errors to the client.
		return nil, nil
	case waddrmgr.IsError(err, waddrmgr.ErrLocked):
		return nil, &ErrWalletUnlockNeeded
	}

	return nil, err
}

// importScript imports a redeem script for a P2SH output.
func importScript(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.ImportScriptCmd)
	rs, err := hex.DecodeString(cmd.Hex)
	if err != nil {
		return nil, err
	}

	if len(rs) == 0 {
		return nil, fmt.Errorf("passed empty script")
	}

	rescan := true
	if cmd.Rescan != nil {
		rescan = *cmd.Rescan
	}

	scanFrom := 0
	if cmd.ScanFrom != nil {
		scanFrom = *cmd.ScanFrom
	}

	return nil, w.ImportScript(rs, rescan, int32(scanFrom))
}

// keypoolRefill handles the keypoolrefill command. Since we handle the keypool
// automatically this does nothing since refilling is never manually required.
func keypoolRefill(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return nil, nil
}

// createNewAccount handles a createnewaccount request by creating and
// returning a new account. If the last account has no transaction history
// as per BIP 0044 a new account cannot be created so an error will be returned.
func createNewAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.CreateNewAccountCmd)

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
		return nil, &dcrjson.RPCError{
			Code: dcrjson.ErrRPCWalletUnlockNeeded,
			Message: "Creating an account requires the wallet to be unlocked. " +
				"Enter the wallet passphrase with walletpassphrase to unlock",
		}
	}
	return nil, err
}

// renameAccount handles a renameaccount request by renaming an account.
// If the account does not exist an appropiate error will be returned.
func renameAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.RenameAccountCmd)

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

// getMultisigOutInfo displays information about a given multisignature
// output.
func getMultisigOutInfo(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetMultisigOutInfoCmd)

	hash, err := chainhash.NewHashFromStr(cmd.Hash)
	if err != nil {
		return nil, err
	}

	// Multisig outs are always in TxTreeRegular.
	op := &wire.OutPoint{
		Hash:  *hash,
		Index: cmd.Index,
		Tree:  dcrutil.TxTreeRegular,
	}
	mso, err := w.TxStore.GetMultisigOutput(op)
	if err != nil {
		return nil, err
	}

	scriptAddr, err := dcrutil.NewAddressScriptHashFromHash(mso.ScriptHash[:],
		w.ChainParams())
	if err != nil {
		return nil, err
	}

	redeemScript, err := w.TxStore.GetTxScript(mso.ScriptHash[:])
	if err != nil {
		return nil, err
	}
	// Couldn't find it, look in the manager too.
	if redeemScript == nil {
		address, err := w.Manager.Address(scriptAddr)
		if err != nil {
			return nil, err
		}
		sa, ok := address.(waddrmgr.ManagedScriptAddress)
		if !ok {
			return nil, errors.New("address is not a script" +
				" address")
		}

		redeemScript, err = sa.Script()
		if err != nil {
			return nil, err
		}
	}

	// Get the list of pubkeys required to sign.
	var pubkeys []string
	_, pubkeyAddrs, _, err := txscript.ExtractPkScriptAddrs(
		txscript.DefaultScriptVersion, redeemScript, w.ChainParams())
	if err != nil {
		return nil, err
	}
	for _, pka := range pubkeyAddrs {
		pubkeys = append(pubkeys, hex.EncodeToString(pka.ScriptAddress()))
	}

	return dcrjson.GetMultisigOutInfoResult{
		Address:      scriptAddr.EncodeAddress(),
		RedeemScript: hex.EncodeToString(redeemScript),
		M:            mso.M,
		N:            mso.N,
		Pubkeys:      pubkeys,
		TxHash:       mso.TxHash.String(),
		BlockHeight:  mso.BlockHeight,
		BlockHash:    mso.BlockHash.String(),
		Spent:        mso.Spent,
		SpentBy:      mso.SpentBy.String(),
		SpentByIndex: mso.SpentByIndex,
		Amount:       mso.Amount.ToCoin(),
	}, nil
}

// getNewAddress handles a getnewaddress request by returning a new
// address for an account.  If the account does not exist an appropiate
// error is returned.
// TODO: Follow BIP 0044 and warn if number of unused addresses exceeds
// the gap limit.
func getNewAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetNewAddressCmd)

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.Manager.LookupAccount(acctName)
	if err != nil {
		return nil, err
	}

	addr, err := w.NewAddress(account, waddrmgr.ExternalBranch)
	if err != nil {
		return nil, err
	}

	if *cmd.Verbose {
		toReturn := make(map[string]string)
		toReturn["address"] = addr.EncodeAddress()

		ainfo, err := w.Manager.Address(addr)
		if err != nil {
			return nil, err
		}

		apkinfo := ainfo.(waddrmgr.ManagedPubKeyAddress)

		// This will be an addresspubkey.
		a, err := decodeAddress(apkinfo.ExportPubKey(),
			w.ChainParams())
		if err != nil {
			return nil, err
		}
		apk := a.(*dcrutil.AddressSecpPubKey)
		toReturn["pubkey"] = apk.String()

		// Return the new payment address string along with the pubkey.
		return toReturn, nil
	}

	return addr.EncodeAddress(), nil
}

// getRawChangeAddress handles a getrawchangeaddress request by creating
// and returning a new change address for an account.
//
// Note: bitcoind allows specifying the account as an optional parameter,
// but ignores the parameter.
func getRawChangeAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetRawChangeAddressCmd)

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.Manager.LookupAccount(acctName)
	if err != nil {
		return nil, err
	}

	// Use the address pool for the default or imported accounts.
	addr, err := w.NewAddress(account, waddrmgr.InternalBranch)
	if err != nil {
		return nil, err
	}

	// Return the new payment address string.
	return addr.EncodeAddress(), nil
}

// getReceivedByAccount handles a getreceivedbyaccount request by returning
// the total amount received by addresses of an account.
func getReceivedByAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetReceivedByAccountCmd)

	account, err := w.Manager.LookupAccount(cmd.Account)
	if err != nil {
		return nil, err
	}

	bal, _, err := w.TotalReceivedForAccount(account, int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}

	return bal.ToCoin(), nil
}

// getReceivedByAddress handles a getreceivedbyaddress request by returning
// the total amount received by a single address.
func getReceivedByAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetReceivedByAddressCmd)

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}
	total, err := w.TotalReceivedForAddr(addr, int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}

	return total.ToCoin(), nil
}

// getBalanceToMaintain handles a getbalancetomaintain request by returning the wallet
// balancetomaintain as a float64.
func getBalanceToMaintain(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	balance := w.BalanceToMaintain().ToCoin()
	return balance, nil
}

// getMasterPubkey handles a getmasterpubkey request by returning the wallet
// master pubkey encoded as a string.
func getMasterPubkey(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetMasterPubkeyCmd)

	// If no account is passed, we provide the extended public key
	// for the default account number.
	account := uint32(waddrmgr.DefaultAccountNum)
	if cmd.Account != nil {
		var err error
		account, err = w.Manager.LookupAccount(*cmd.Account)
		if err != nil {
			return nil, err
		}
	}

	pkString, err := w.Manager.GetMasterPubkey(account)
	if err != nil {
		return nil, err
	}

	return pkString, nil
}

// getSeed handles a getseed request by returning the wallet seed encoded as
// a string.
func getSeed(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	seedStr, err := w.Manager.GetSeed()
	if err != nil {
		return nil, err
	}

	return seedStr, nil
}

// getStakeInfo gets a large amounts of information about the stake environment
// and a number of statistics about local staking in the wallet.
func getStakeInfo(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	// Get the current difficulty.
	stakeDiff, err := w.StakeDifficulty()
	if err != nil {
		return nil, err
	}

	stakeInfo, err := w.StakeInfo()
	if err != nil {
		return nil, err
	}

	proportionLive := float64(0.0)
	if float64(stakeInfo.PoolSize) > 0.0 {
		proportionLive = float64(stakeInfo.Live) / float64(stakeInfo.PoolSize)
	}
	proportionMissed := float64(0.0)
	if stakeInfo.Missed > 0 {
		proportionMissed = float64(stakeInfo.Missed) /
			(float64(stakeInfo.Voted) + float64(stakeInfo.Missed))
	}

	resp := &dcrjson.GetStakeInfoResult{
		BlockHeight:      stakeInfo.BlockHeight,
		PoolSize:         stakeInfo.PoolSize,
		Difficulty:       dcrutil.Amount(stakeDiff).ToCoin(),
		AllMempoolTix:    stakeInfo.AllMempoolTix,
		OwnMempoolTix:    stakeInfo.OwnMempoolTix,
		Immature:         stakeInfo.Immature,
		Live:             stakeInfo.Live,
		ProportionLive:   proportionLive,
		Voted:            stakeInfo.Voted,
		TotalSubsidy:     stakeInfo.TotalSubsidy.ToCoin(),
		Missed:           stakeInfo.Missed,
		ProportionMissed: proportionMissed,
		Revoked:          stakeInfo.Revoked,
	}

	return resp, nil
}

// getTicketFee gets the currently set price per kb for tickets
func getTicketFee(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return w.TicketFeeIncrement().ToCoin(), nil
}

// getTicketMaxPrice gets the maximum price the user is willing to pay for a
// ticket.
func getTicketMaxPrice(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return w.GetTicketMaxPrice().ToCoin(), nil
}

// hashInSlice returns whether a hash exists in a slice or not.
func hashInSlice(h chainhash.Hash, list []chainhash.Hash) bool {
	for _, hash := range list {
		if h == hash {
			return true
		}
	}

	return false
}

// getTickets handles a gettickets request by returning the hashes of the tickets
// currently owned by wallet, encoded as strings.
func getTickets(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetTicketsCmd)
	blk := w.Manager.SyncedTo()

	// UnspentTickets collects all the tickets that pay out to a
	// public key hash for a public key owned by this wallet.
	tickets, err := w.TxStore.UnspentTickets(blk.Height, cmd.IncludeImmature)
	if err != nil {
		return nil, err
	}

	// Access the stake manager and see if there are any extra tickets
	// there. Likely they were either pruned because they failed to get
	// into the blockchain or they are P2SH for some script we own.
	var extraTickets []chainhash.Hash
	stakeMgrTickets, err := w.StakeMgr.DumpSStxHashes()
	if err != nil {
		return nil, err
	}
	for _, h := range stakeMgrTickets {
		if !hashInSlice(h, tickets) {
			extraTickets = append(extraTickets, h)
		}
	}
	for _, h := range extraTickets {
		// Get the raw transaction information from daemon and add
		// any relevant tickets. The ticket output is always the
		// zeroeth output.
		spent, err := chainClient.GetTxOut(&h, 0, true)
		if err != nil {
			continue
		}
		// This returns nil if the output is spent.
		if spent == nil {
			continue
		}

		ticketTx, err := chainClient.GetRawTransactionVerbose(&h)
		if err != nil {
			continue
		}

		txHeight := ticketTx.BlockHeight
		unconfirmed := (txHeight == 0)
		immature := (blk.Height-int32(txHeight) <
			int32(w.ChainParams().TicketMaturity))
		if cmd.IncludeImmature {
			tickets = append(tickets, h)
		} else {
			if !(unconfirmed || immature) {
				tickets = append(tickets, h)
			}
		}
	}

	// Compose a slice of strings to return.
	ticketsStr := make([]string, len(tickets), len(tickets))
	for i, ticket := range tickets {
		ticketsStr[i] = ticket.String()
	}

	return &dcrjson.GetTicketsResult{Hashes: ticketsStr}, nil
}

// getTicketVoteBits fetches the per-ticket voteBits for a given ticket from
// a ticket hash. If the voteBits are unset, it returns the default voteBits.
// Otherwise, it returns the voteBits it finds. Missing tickets return an
// error.
func getTicketVoteBits(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetTicketVoteBitsCmd)
	ticket, err := chainhash.NewHashFromStr(cmd.TxHash)
	if err != nil {
		return nil, err
	}

	set, voteBits, err := w.StakeMgr.SStxVoteBits(ticket)
	if err != nil {
		return nil, err
	}
	if !set {
		return &dcrjson.GetTicketVoteBitsResult{
			VoteBitsData: dcrjson.VoteBitsData{
				VoteBits:    w.VoteBits,
				VoteBitsExt: "",
			},
		}, nil
	}

	return &dcrjson.GetTicketVoteBitsResult{
		VoteBitsData: dcrjson.VoteBitsData{
			VoteBits:    voteBits,
			VoteBitsExt: "",
		},
	}, nil
}

// getTicketsVoteBits fetches the per-ticket voteBits for a given array of ticket
// hashes. If the voteBits are unset, it returns the default voteBits.
// Otherwise, it returns the voteBits it finds. Missing tickets return an
// error.
func getTicketsVoteBits(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetTicketsVoteBitsCmd)
	ticketsLen := len(cmd.TxHashes)
	ticketHashes := make([]*chainhash.Hash, 0, ticketsLen)
	for _, thStr := range cmd.TxHashes {
		h, err := chainhash.NewHashFromStr(thStr)
		if err != nil {
			return nil, err
		}
		ticketHashes = append(ticketHashes, h)
	}

	voteBitsData := make([]dcrjson.VoteBitsData, 0, ticketsLen)
	for _, th := range ticketHashes {
		set, voteBits, err := w.StakeMgr.SStxVoteBits(th)
		if err != nil {
			return nil, err
		}
		var vbr dcrjson.VoteBitsData
		if !set {
			vbr.VoteBits = w.VoteBits
			vbr.VoteBitsExt = ""
		} else {
			vbr.VoteBits = voteBits
			vbr.VoteBitsExt = ""
		}
		voteBitsData = append(voteBitsData, vbr)
	}

	return &dcrjson.GetTicketsVoteBitsResult{VoteBitsList: voteBitsData}, nil
}

// getTransaction handles a gettransaction request by returning details about
// a single transaction saved by wallet.
func getTransaction(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetTransactionCmd)

	txSha, err := chainhash.NewHashFromStr(cmd.Txid)
	if err != nil {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCDecodeHexString,
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
	ret := dcrjson.GetTransactionResult{
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
		ret.Confirmations = int64(confirms(details.Block.Height,
			syncBlock.Height))
	}

	var (
		debitTotal  dcrutil.Amount
		creditTotal dcrutil.Amount // Excludes change
		fee         dcrutil.Amount
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
		var outputTotal dcrutil.Amount
		for _, output := range details.MsgTx.TxOut {
			outputTotal += dcrutil.Amount(output.Value)
		}
		fee = debitTotal - outputTotal
		feeF64 = fee.ToCoin()
	}

	if len(details.Debits) == 0 {
		// Credits must be set later, but since we know the full length
		// of the details slice, allocate it with the correct cap.
		ret.Details = make([]dcrjson.GetTransactionDetailsResult, 0,
			len(details.Credits))
	} else {
		ret.Details = make([]dcrjson.GetTransactionDetailsResult, 1,
			len(details.Credits)+1)

		ret.Details[0] = dcrjson.GetTransactionDetailsResult{
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
			Amount:   (-debitTotal).ToCoin(), // negative since it is a send
			Fee:      &feeF64,
		}
		ret.Fee = feeF64
	}

	credCat := wallet.RecvCategory(details, syncBlock.Height,
		w.ChainParams()).String()
	for _, cred := range details.Credits {
		// Change is ignored.
		if cred.Change {
			continue
		}

		var address string
		var accountName string
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			details.MsgTx.TxOut[cred.Index].Version,
			details.MsgTx.TxOut[cred.Index].PkScript,
			w.ChainParams())
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

		ret.Details = append(ret.Details, dcrjson.GetTransactionDetailsResult{
			// Fields left zeroed:
			//   InvolvesWatchOnly
			//   Fee
			Account:  accountName,
			Address:  address,
			Category: credCat,
			Amount:   cred.Amount.ToCoin(),
			Vout:     cred.Index,
		})
	}

	ret.Amount = creditTotal.ToCoin()
	return ret, nil
}

// getWalletFee returns the currently set tx fee for the requested wallet
func getWalletFee(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return w.RelayFee().ToCoin(), nil
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

// helpWithChainRPC handles the help request when the RPC server has been
// associated with a consensus RPC client.  The additional RPC client is used to
// include help messages for methods implemented by the consensus server via RPC
// passthrough.
func helpWithChainRPC(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	return help(icmd, w, chainClient)
}

// helpNoChainRPC handles the help request when the RPC server has not been
// associated with a consensus RPC client.  No help messages are included for
// passthrough requests.
func helpNoChainRPC(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return help(icmd, w, nil)
}

// help handles the help request by returning one line usage of all available
// methods, or full help for a specific method.  The chainClient is optional,
// and this is simply a helper function for the HelpNoChainRPC and
// HelpWithChainRPC handlers.
func help(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.HelpCmd)

	// dcrd returns different help messages depending on the kind of
	// connection the client is using.  Only methods availble to HTTP POST
	// clients are available to be used by wallet clients, even though
	// wallet itself is a websocket client to dcrd.  Therefore, create a
	// POST client as needed.
	//
	// Returns nil if chainClient is currently nil or there is an error
	// creating the client.
	//
	// This is hacky and is probably better handled by exposing help usage
	// texts in a non-internal dcrd package.
	postClient := func() *dcrrpcclient.Client {
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
	return nil, &dcrjson.RPCError{
		Code:    dcrjson.ErrRPCInvalidParameter,
		Message: fmt.Sprintf("No help for method '%s'", *cmd.Command),
	}
}

// listAccounts handles a listaccounts request by returning a map of account
// names to their balances.
func listAccounts(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListAccountsCmd)

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
		bal, err := w.CalculateAccountBalance(account, minConf,
			wtxmgr.BFBalanceFullScan)
		if err != nil {
			return nil, err
		}
		accountBalances[acctName] = bal.ToCoin()
	}
	// Return the map.  This will be marshaled into a JSON object.
	return accountBalances, nil
}

// listLockUnspent handles a listlockunspent request by returning an slice of
// all locked outpoints.
func listLockUnspent(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return w.LockedOutpoints(), nil
}

// listReceivedByAccount handles a listreceivedbyaccount request by returning
// a slice of objects, each one containing:
//  "account": the receiving account;
//  "amount": total amount received by the account;
//  "confirmations": number of confirmations of the most recent transaction.
// It takes two parameters:
//  "minconf": minimum number of confirmations to consider a transaction -
//             default: one;
//  "includeempty": whether or not to include addresses that have no transactions -
//                  default: false.
func listReceivedByAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListReceivedByAccountCmd)

	var accounts []uint32
	err := w.Manager.ForEachAccount(func(account uint32) error {
		accounts = append(accounts, account)
		return nil
	})
	if err != nil {
		return nil, err
	}

	ret := make([]dcrjson.ListReceivedByAccountResult, 0, len(accounts))
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
		ret = append(ret, dcrjson.ListReceivedByAccountResult{
			Account:       acctName,
			Amount:        bal.ToCoin(),
			Confirmations: uint64(confirmations),
		})
	}
	return ret, nil
}

// listReceivedByAddress handles a listreceivedbyaddress request by returning
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
func listReceivedByAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListReceivedByAddressCmd)

	// Intermediate data for each address.
	type AddrData struct {
		// Total amount received.
		amount dcrutil.Amount
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
				pkVersion := tx.MsgTx.TxOut[cred.Index].Version
				pkScript := tx.MsgTx.TxOut[cred.Index].PkScript
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkVersion,
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
	ret := make([]dcrjson.ListReceivedByAddressResult, numAddresses, numAddresses)
	idx := 0
	for address, addrData := range allAddrData {
		ret[idx] = dcrjson.ListReceivedByAddressResult{
			Address:       address,
			Amount:        addrData.amount.ToCoin(),
			Confirmations: uint64(addrData.confirmations),
			TxIDs:         addrData.tx,
		}
		idx++
	}
	return ret, nil
}

// listSinceBlock handles a listsinceblock request by returning an array of maps
// with details of sent and received wallet transactions since the given block.
func listSinceBlock(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListSinceBlockCmd)

	syncBlock := w.Manager.SyncedTo()
	targetConf := int64(*cmd.TargetConfirmations)

	// For the result we need the block hash for the last block counted
	// in the blockchain due to confirmations. We send this off now so that
	// it can arrive asynchronously while we figure out the rest.
	gbh := chainClient.GetBlockHashAsync(int64(syncBlock.Height) + 1 - targetConf)

	var start int32
	if cmd.BlockHash != nil {
		hash, err := chainhash.NewHashFromStr(*cmd.BlockHash)
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

	res := dcrjson.ListSinceBlockResult{
		Transactions: txInfoList,
		LastBlock:    blockHash.String(),
	}
	return res, nil
}

// scriptInfo models the binary or interface versions of JSON data to
// return in a ListScriptsResult.
type scriptInfo struct {
	redeemScript []byte
	address      dcrutil.Address
}

// listScripts handles a listscripts request by returning an
// array of script details for all scripts in the wallet.
func listScripts(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	scriptList := make(map[[20]byte]scriptInfo)

	// Fetch all the address manager scripts first.
	importedAcct, err := w.Manager.LookupAccount(waddrmgr.ImportedAddrAccountName)
	if err != nil {
		return nil, err
	}

	var managerScriptAddrs []waddrmgr.ManagedScriptAddress
	err = w.Manager.ForEachAccountAddress(importedAcct,
		func(maddr waddrmgr.ManagedAddress) error {
			msa, is := maddr.(waddrmgr.ManagedScriptAddress)
			if is {
				managerScriptAddrs = append(managerScriptAddrs, msa)
			}
			return nil
		})
	if err != nil {
		log.Errorf("failed to iterate through the addrmgr scripts: %v", err)
	}
	for _, msa := range managerScriptAddrs {
		h := msa.Address().Hash160()
		scr, err := msa.Script()
		if err != nil {
			return nil, err
		}
		scriptList[*h] = scriptInfo{
			redeemScript: scr,
			address:      msa.Address(),
		}
	}

	// Fetch all the scripts from the transaction manager.
	txsScripts, err := w.TxStore.StoredTxScripts()
	if err != nil {
		return nil, fmt.Errorf("failed to access stored txmgr scripts")
	}
	for _, scr := range txsScripts {
		addr, err := dcrutil.NewAddressScriptHash(scr, w.ChainParams())
		if err != nil {
			log.Errorf("failed to parse txstore script: %v", err)
			continue
		}
		h := addr.Hash160()
		scriptList[*h] = scriptInfo{
			redeemScript: scr,
			address:      addr,
		}
	}

	// Generate the JSON struct result.
	listScriptsResultSIs := make([]dcrjson.ScriptInfo, len(scriptList))
	itr := 0
	for h, si := range scriptList {
		listScriptsResultSIs[itr].Hash160 = hex.EncodeToString(h[:])
		listScriptsResultSIs[itr].RedeemScript =
			hex.EncodeToString(si.redeemScript)
		listScriptsResultSIs[itr].Address = si.address.EncodeAddress()
		itr++
	}

	return &dcrjson.ListScriptsResult{Scripts: listScriptsResultSIs}, nil
}

// listTransactions handles a listtransactions request by returning an
// array of maps with details of sent and recevied wallet transactions.
func listTransactions(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListTransactionsCmd)

	// TODO: ListTransactions does not currently understand the difference
	// between transactions pertaining to one account from another.  This
	// will be resolved when wtxmgr is combined with the waddrmgr namespace.

	if cmd.Account != nil && *cmd.Account != "*" {
		// For now, don't bother trying to continue if the user
		// specified an account, since this can't be (easily or
		// efficiently) calculated.
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCWallet,
			Message: "Transactions are not yet grouped by account",
		}
	}

	return w.ListTransactions(*cmd.From, *cmd.Count)
}

// listAddressTransactions handles a listaddresstransactions request by
// returning an array of maps with details of spent and received wallet
// transactions.  The form of the reply is identical to listtransactions,
// but the array elements are limited to transaction details which are
// about the addresess included in the request.
func listAddressTransactions(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListAddressTransactionsCmd)

	if cmd.Account != nil && *cmd.Account != "*" {
		return nil, &dcrjson.RPCError{
			Code: dcrjson.ErrRPCInvalidParameter,
			Message: "Listing transactions for addresses may only " +
				"be done for all accounts",
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

// listAllTransactions handles a listalltransactions request by returning
// a map with details of sent and recevied wallet transactions.  This is
// similar to ListTransactions, except it takes only a single optional
// argument for the account name and replies with all transactions.
func listAllTransactions(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListAllTransactionsCmd)

	if cmd.Account != nil && *cmd.Account != "*" {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInvalidParameter,
			Message: "Listing all transactions may only be done for all accounts",
		}
	}

	return w.ListAllTransactions()
}

// listUnspent handles the listunspent command.
func listUnspent(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListUnspentCmd)

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

// listUnspentMultisig handles the listunspentmultisig command.
func listUnspentMultisig(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return nil, nil
}

// lockUnspent handles the lockunspent command.
func lockUnspent(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.LockUnspentCmd)

	switch {
	case cmd.Unlock && len(cmd.Transactions) == 0:
		w.ResetLockedOutpoints()
	default:
		for _, input := range cmd.Transactions {
			txSha, err := chainhash.NewHashFromStr(input.Txid)
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

// purchaseTicket indicates to the wallet that a ticket should be purchased
// using all currently available funds. If the ticket could not be purchased
// because there are not enough eligible funds, an error will be returned.
func purchaseTicket(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	// Enforce valid and positive spend limit.
	cmd := icmd.(*dcrjson.PurchaseTicketCmd)
	spendLimit, err := dcrutil.NewAmount(cmd.SpendLimit)
	if err != nil {
		return nil, err
	}
	if spendLimit < 0 {
		return nil, ErrNeedPositiveSpendLimit
	}

	account, err := w.Manager.LookupAccount(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Override the minimum number of required confirmations if specified
	// and enforce it is positive.
	minConf := int32(1)
	if cmd.MinConf != nil {
		minConf = int32(*cmd.MinConf)
		if minConf < 0 {
			return nil, ErrNeedPositiveMinconf
		}
	}

	// Set ticket address if specified.
	var ticketAddr dcrutil.Address
	if cmd.TicketAddress != nil {
		if *cmd.TicketAddress != "" {
			addr, err := decodeAddress(*cmd.TicketAddress, w.ChainParams())
			if err != nil {
				return nil, err
			}
			ticketAddr = addr
		}
	}

	numTickets := 1
	if cmd.NumTickets != nil {
		if *cmd.NumTickets > 1 {
			numTickets = *cmd.NumTickets
		}
	}

	// Set pool address if specified.
	var poolAddr dcrutil.Address
	var poolFee float64
	if cmd.PoolAddress != nil {
		if *cmd.PoolAddress != "" {
			addr, err := decodeAddress(*cmd.PoolAddress, w.ChainParams())
			if err != nil {
				return nil, err
			}
			poolAddr = addr

			// Attempt to get the amount to send to
			// the pool after.
			if cmd.PoolFees == nil {
				return nil, fmt.Errorf("gave pool address but no pool fee")
			}
			poolFee = *cmd.PoolFees
			err = txrules.IsValidPoolFeeRate(poolFee)
			if err != nil {
				return nil, err
			}
		}
	}

	// Set the expiry if specified.
	expiry := int32(0)
	if cmd.Expiry != nil {
		expiry = int32(*cmd.Expiry)
	}

	hashes, err := w.PurchaseTickets(0, spendLimit, minConf, ticketAddr,
		account, numTickets, poolAddr, poolFee, expiry, w.RelayFee(),
		w.TicketFeeIncrement())
	if err != nil {
		return nil, err
	}

	hashesTyped, ok := hashes.([]*chainhash.Hash)
	if !ok {
		return nil, fmt.Errorf("Unable to cast response as a slice " +
			"of hash strings")
	}

	hashStrs := make([]string, len(hashesTyped))
	for i := range hashesTyped {
		hashStrs[i] = hashesTyped[i].String()
	}

	return hashStrs, err
}

// makeOutputs creates a slice of transaction outputs from a pair of address
// strings to amounts.  This is used to create the outputs to include in newly
// created transactions from a JSON object describing the output destinations
// and amounts.
func makeOutputs(pairs map[string]dcrutil.Amount, chainParams *chaincfg.Params) ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0, len(pairs))
	for addrStr, amt := range pairs {
		addr, err := dcrutil.DecodeAddress(addrStr, chainParams)
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
// All errors are returned in dcrjson.RPCError format
func sendPairs(w *wallet.Wallet, amounts map[string]dcrutil.Amount,
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
		case dcrjson.RPCError:
			return "", err
		}

		return "", &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInternal.Code,
			Message: err.Error(),
		}
	}

	return txSha.String(), err
}

// redeemMultiSigOut receives a transaction hash/idx and fetches the first output
// index or indices with known script hashes from the transaction. It then
// construct a transaction with a single P2PKH paying to a specified address.
// It signs any inputs that it can, then provides the raw transaction to
// the user to export to others to sign.
func redeemMultiSigOut(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.RedeemMultiSigOutCmd)

	// Convert the address to a useable format. If
	// we have no address, create a new address in
	// this wallet to send the output to.
	var addr dcrutil.Address
	var err error
	if cmd.Address != nil {
		addr, err = decodeAddress(*cmd.Address, w.ChainParams())
	} else {
		account := uint32(waddrmgr.DefaultAccountNum)
		addr, err = w.NewAddress(account, waddrmgr.InternalBranch)
		if err != nil {
			return nil, err
		}
	}

	// Lookup the multisignature output and get the amount
	// along with the script for that transaction. Then,
	// begin crafting a MsgTx.
	hash, err := chainhash.NewHashFromStr(cmd.Hash)
	if err != nil {
		return nil, err
	}
	op := wire.OutPoint{
		Hash:  *hash,
		Index: cmd.Index,
		Tree:  cmd.Tree,
	}
	msCredit, err := w.TxStore.GetMultisigCredit(&op)
	if err != nil {
		return nil, err
	}
	sc := txscript.GetScriptClass(txscript.DefaultScriptVersion,
		msCredit.MSScript)
	if sc != txscript.MultiSigTy {
		return nil, fmt.Errorf("invalid P2SH script: not multisig")
	}
	var msgTx wire.MsgTx
	msgTx.AddTxIn(wire.NewTxIn(&op, nil))

	// Calculate the fees required, and make sure we have enough.
	// Then produce the txout.
	size := wallet.EstimateTxSize(1, 1)
	feeEst := wallet.FeeForSize(w.RelayFee(), size)
	if feeEst >= msCredit.Amount {
		return nil, fmt.Errorf("multisig out amt is too small "+
			"(have %v, %v fee suggested)", msCredit.Amount, feeEst)
	}
	toReceive := msCredit.Amount - feeEst
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, fmt.Errorf("cannot create txout script: %s", err)
	}
	msgTx.AddTxOut(wire.NewTxOut(int64(toReceive), pkScript))

	// Start creating the SignRawTransactionCmd.
	outpointScript, err := txscript.PayToScriptHashScript(msCredit.ScriptHash[:])
	if err != nil {
		return nil, err
	}
	outpointScriptStr := hex.EncodeToString(outpointScript)

	rti := dcrjson.RawTxInput{
		Txid:         cmd.Hash,
		Vout:         cmd.Index,
		Tree:         cmd.Tree,
		ScriptPubKey: outpointScriptStr,
		RedeemScript: "",
	}
	rtis := []dcrjson.RawTxInput{rti}

	var buf bytes.Buffer
	buf.Grow(msgTx.SerializeSize())
	if err = msgTx.Serialize(&buf); err != nil {
		return nil, err
	}
	txDataStr := hex.EncodeToString(buf.Bytes())
	sigHashAll := "ALL"

	srtc := &dcrjson.SignRawTransactionCmd{
		RawTx:    txDataStr,
		Inputs:   &rtis,
		PrivKeys: &[]string{},
		Flags:    &sigHashAll,
	}

	// Sign it and give the results to the user.
	signedTxResult, err := signRawTransaction(srtc, w, chainClient)
	if signedTxResult == nil || err != nil {
		return nil, err
	}
	srtTyped := signedTxResult.(dcrjson.SignRawTransactionResult)
	return dcrjson.RedeemMultiSigOutResult{
		Hex:      srtTyped.Hex,
		Complete: srtTyped.Complete,
		Errors:   srtTyped.Errors,
	}, nil
}

// redeemMultisigOuts receives a script hash (in the form of a
// script hash address), looks up all the unspent outpoints associated
// with that address, then generates a list of partially signed
// transactions spending to either an address specified or internal
// addresses in this wallet.
func redeemMultiSigOuts(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.RedeemMultiSigOutsCmd)

	// Get all the multisignature outpoints that are unspent for this
	// address.
	addr, err := decodeAddress(cmd.FromScrAddress, w.ChainParams())
	if err != nil {
		return nil, err
	}
	msos, err := w.TxStore.UnspentMultisigCreditsForAddress(addr)
	if err != nil {
		return nil, err
	}
	max := uint32(0xffffffff)
	if cmd.Number != nil {
		max = uint32(*cmd.Number)
	}

	itr := uint32(0)
	rmsoResults := make([]dcrjson.RedeemMultiSigOutResult, len(msos), len(msos))
	for i, mso := range msos {
		if itr > max {
			break
		}

		rmsoRequest := &dcrjson.RedeemMultiSigOutCmd{
			Hash:    mso.OutPoint.Hash.String(),
			Index:   mso.OutPoint.Index,
			Tree:    mso.OutPoint.Tree,
			Address: cmd.ToAddress,
		}
		redeemResult, err := redeemMultiSigOut(rmsoRequest, w, chainClient)
		if err != nil {
			return nil, err
		}
		redeemResultTyped := redeemResult.(dcrjson.RedeemMultiSigOutResult)
		rmsoResults[i] = redeemResultTyped

		itr++
	}

	return dcrjson.RedeemMultiSigOutsResult{Results: rmsoResults}, nil
}

// stakePoolUserInfo returns the ticket information for a given user from the
// stake pool.
func stakePoolUserInfo(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.StakePoolUserInfoCmd)

	userAddr, err := dcrutil.DecodeAddress(cmd.User, w.ChainParams())
	if err != nil {
		return nil, err
	}
	_, isScriptHash := userAddr.(*dcrutil.AddressScriptHash)
	_, isP2PKH := userAddr.(*dcrutil.AddressPubKeyHash)
	if !(isScriptHash || isP2PKH) {
		return nil, fmt.Errorf("invalid user address %v, must be P2SH or "+
			"P2PKH", userAddr.EncodeAddress())
	}

	// Access the stake manager and fetch the user information.
	spui, err := w.StakeMgr.StakePoolUserInfo(userAddr)
	if err != nil {
		return nil, err
	}

	resp := new(dcrjson.StakePoolUserInfoResult)
	for _, ticket := range spui.Tickets {
		var ticketRes dcrjson.PoolUserTicket

		status := ""
		switch ticket.Status {
		case wstakemgr.TSImmatureOrLive:
			status = "live"
		case wstakemgr.TSVoted:
			status = "voted"
		case wstakemgr.TSMissed:
			status = "missed"
		}
		ticketRes.Status = status

		ticketRes.Ticket = ticket.Ticket.String()
		ticketRes.TicketHeight = ticket.HeightTicket
		ticketRes.SpentBy = ticket.SpentBy.String()
		ticketRes.SpentByHeight = ticket.HeightSpent

		resp.Tickets = append(resp.Tickets, ticketRes)
	}
	for _, invalid := range spui.InvalidTickets {
		invalidTicket := invalid.String()

		resp.InvalidTickets = append(resp.InvalidTickets, invalidTicket)
	}

	return resp, nil
}

// ticketsForAddress retrieves all ticket hashes that have the passed voting
// address. It will only return tickets that are in the mempool or blockchain,
// and should not return pruned tickets.
func ticketsForAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.TicketsForAddressCmd)

	addr, err := dcrutil.DecodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	ticketsAll, err := w.StakeMgr.DumpSStxHashesForAddress(addr)
	if err != nil {
		return nil, err
	}

	// Check the wallet database.
	tickets := make([]chainhash.Hash, 0, len(ticketsAll))
	for i := range ticketsAll {
		exists, err := w.TxStore.ExistsTx(&ticketsAll[i])
		if err != nil {
			log.Errorf("Enountered database error while retrieving "+
				"tickets for address: %v", err.Error())
		}
		if exists {
			tickets = append(tickets, ticketsAll[i])
		}
	}

	ticketsStr := make([]string, len(tickets), len(tickets))
	for i, h := range tickets {
		ticketsStr[i] = h.String()
	}

	return dcrjson.TicketsForAddressResult{Tickets: ticketsStr}, nil
}

func isNilOrEmpty(s *string) bool {
	return s == nil || *s == ""
}

// sendFrom handles a sendfrom RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to another payment
// address.  Leftover inputs not sent to the payment address or a fee for
// the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func sendFrom(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendFromCmd)

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) || !isNilOrEmpty(cmd.CommentTo) {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCUnimplemented,
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
	amt, err := dcrutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, err
	}
	pairs := map[string]dcrutil.Amount{
		cmd.ToAddress: amt,
	}

	return sendPairs(w, pairs, account, minConf)
}

// sendMany handles a sendmany RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to any number of
// payment addresses.  Leftover inputs not sent to the payment address
// or a fee for the miner are sent back to a new address in the wallet.
// Upon success, the TxID for the created transaction is returned.
func sendMany(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendManyCmd)

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCUnimplemented,
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

	// Recreate address/amount pairs, using dcrutil.Amount.
	pairs := make(map[string]dcrutil.Amount, len(cmd.Amounts))
	for k, v := range cmd.Amounts {
		amt, err := dcrutil.NewAmount(v)
		if err != nil {
			return nil, err
		}
		pairs[k] = amt
	}

	return sendPairs(w, pairs, account, minConf)
}

// sendToAddress handles a sendtoaddress RPC request by creating a new
// transaction spending unspent transaction outputs for a wallet to another
// payment address.  Leftover inputs not sent to the payment address or a fee
// for the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func sendToAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendToAddressCmd)

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) || !isNilOrEmpty(cmd.CommentTo) {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCUnimplemented,
			Message: "Transaction comments are not yet supported",
		}
	}

	amt, err := dcrutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, err
	}

	// Check that signed integer parameters are positive.
	if amt < 0 {
		return nil, ErrNeedPositiveAmount
	}

	// Mock up map of address and amount pairs.
	pairs := map[string]dcrutil.Amount{
		cmd.Address: amt,
	}

	// sendtoaddress always spends from the default account, this matches bitcoind
	return sendPairs(w, pairs, waddrmgr.DefaultAccountNum, 1)
}

// sendToMultiSig handles a sendtomultisig RPC request by creating a new
// transaction spending amount many funds to an output containing a multi-
// signature script hash. The function will fail if there isn't at least one
// public key in the public key list that corresponds to one that is owned
// locally.
// Upon successfully sending the transaction to the daemon, the script hash
// is stored in the transaction manager and the corresponding address
// specified to be watched by the daemon.
// The function returns a tx hash, P2SH address, and a multisig script if
// successful.
// TODO Use with non-default accounts as well
func sendToMultiSig(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendToMultiSigCmd)
	account := uint32(waddrmgr.DefaultAccountNum)
	amount, err := dcrutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, err
	}
	nrequired := int8(*cmd.NRequired)
	minconf := int32(*cmd.MinConf)
	pubkeys := make([]*dcrutil.AddressSecpPubKey, len(cmd.Pubkeys))

	// The address list will made up either of addreseses (pubkey hash), for
	// which we need to look up the keys in wallet, straight pubkeys, or a
	// mixture of the two.
	for i, a := range cmd.Pubkeys {
		// Try to parse as pubkey address.
		a, err := decodeAddress(a, w.ChainParams())
		if err != nil {
			return nil, err
		}

		switch addr := a.(type) {
		case *dcrutil.AddressSecpPubKey:
			pubkeys[i] = addr
		case *dcrutil.AddressPubKeyHash:
			ainfo, err := w.Manager.Address(addr)
			if err != nil {
				return nil, err
			}

			apkinfo := ainfo.(waddrmgr.ManagedPubKeyAddress)

			// This will be an addresspubkey.
			a, err := decodeAddress(apkinfo.ExportPubKey(),
				w.ChainParams())
			if err != nil {
				return nil, err
			}

			apk := a.(*dcrutil.AddressSecpPubKey)
			pubkeys[i] = apk
		default:
			return nil, err
		}
	}

	ctx, addr, script, err :=
		w.CreateMultisigTx(account, amount, pubkeys, nrequired, minconf)
	if err != nil {
		return nil, fmt.Errorf("CreateMultisigTx error: %v", err.Error())
	}

	result := &dcrjson.SendToMultiSigResult{
		TxHash:       ctx.MsgTx.TxSha().String(),
		Address:      addr.EncodeAddress(),
		RedeemScript: hex.EncodeToString(script),
	}

	err = chainClient.NotifyReceived([]dcrutil.Address{addr})
	if err != nil {
		return nil, err
	}

	log.Infof("Successfully sent funds to multisignature output in "+
		"transaction %v", ctx.MsgTx.TxSha().String())

	return result, nil
}

// sendToSStx handles a sendtosstx RPC request by creating a new transaction
// payment addresses.  Leftover inputs not sent to the payment address
// or a fee for the miner are sent back to a new address in the wallet.
// Upon success, the TxID for the created transaction is returned.
// DECRED TODO: Clean these up
func sendToSStx(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendToSStxCmd)
	minconf := int32(*cmd.MinConf)

	account, err := w.Manager.LookupAccount(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Check that minconf is positive.
	if minconf < 0 {
		return nil, ErrNeedPositiveMinconf
	}

	// Recreate address/amount pairs, using dcrutil.Amount.
	pair := make(map[string]dcrutil.Amount, len(cmd.Amounts))
	for k, v := range cmd.Amounts {
		pair[k] = dcrutil.Amount(v)
	}
	// Get current block's height and hash.
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	usedEligible := []wtxmgr.Credit{}
	eligible, err := w.FindEligibleOutputs(account, minconf, bs)
	if err != nil {
		return nil, err
	}
	// check to properly find utxos from eligible to help signMsgTx later on
	for _, input := range cmd.Inputs {
		for _, allEligible := range eligible {

			if allEligible.Hash.String() == input.Txid &&
				allEligible.Index == input.Vout &&
				allEligible.Tree == input.Tree {
				usedEligible = append(usedEligible, allEligible)
				break
			}
		}
	}
	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := w.CreateSStxTx(pair, usedEligible, cmd.Inputs,
		cmd.COuts, minconf)
	if err != nil {
		switch err {
		case wallet.ErrNonPositiveAmount:
			return nil, ErrNeedPositiveAmount
		default:
			return nil, err
		}
	}

	txSha, err := chainClient.SendRawTransaction(createdTx.MsgTx, w.AllowHighFees)
	if err != nil {
		return nil, err
	}
	log.Infof("Successfully sent SStx purchase transaction %v", txSha)
	return txSha.String(), nil
}

// sendToSSGen handles a sendtossgen RPC request by creating a new transaction
// spending a stake ticket and generating stake rewards.
// Upon success, the TxID for the created transaction is returned.
// DECRED TODO: Clean these up
func sendToSSGen(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendToSSGenCmd)

	_, err := w.Manager.LookupAccount(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Get the tx hash for the ticket.
	ticketHash, err := chainhash.NewHashFromStr(cmd.TicketHash)
	if err != nil {
		return nil, err
	}

	// Get the block header hash that the SSGen tx votes on.
	blockHash, err := chainhash.NewHashFromStr(cmd.BlockHash)
	if err != nil {
		return nil, err
	}

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := w.CreateSSGenTx(*ticketHash, *blockHash,
		cmd.Height, cmd.VoteBits)
	if err != nil {
		switch err {
		case wallet.ErrNonPositiveAmount:
			return nil, ErrNeedPositiveAmount
		default:
			return nil, err
		}
	}

	txSha := createdTx.MsgTx.TxSha()

	log.Infof("Successfully sent transaction %v", txSha)
	return txSha.String(), nil
}

// sendToSSRtx handles a sendtossrtx RPC request by creating a new transaction
// spending a stake ticket and generating stake rewards.
// Upon success, the TxID for the created transaction is returned.
// DECRED TODO: Clean these up
func sendToSSRtx(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendToSSRtxCmd)

	_, err := w.Manager.LookupAccount(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Get the tx hash for the ticket.
	ticketHash, err := chainhash.NewHashFromStr(cmd.TicketHash)
	if err != nil {
		return nil, err
	}

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := w.CreateSSRtx(*ticketHash)
	if err != nil {
		switch err {
		case wallet.ErrNonPositiveAmount:
			return nil, ErrNeedPositiveAmount
		default:
			return nil, err
		}
	}

	txSha, err := chainClient.SendRawTransaction(createdTx.MsgTx, w.AllowHighFees)
	if err != nil {
		return nil, err
	}
	log.Infof("Successfully sent transaction %v", txSha)
	return txSha.String(), nil
}

// getGenerate returns if stake mining is enabled for the wallet.
func getGenerate(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return w.StakeMiningEnabled, nil
}

// setGenerate enables or disables stake mining the wallet (ticket
// autopurchase, vote generation, and revocation generation). The
// number of processors may be declared but is ignored (as this is
// non-PoW work).
func setGenerate(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.SetGenerateCmd)
	err := w.SetGenerate(cmd.Generate)

	return nil, err
}

// setTicketMaxPrice sets the maximum price the user is willing to pay for a
// ticket.
func setTicketMaxPrice(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.SetTicketMaxPriceCmd)

	amt, err := dcrutil.NewAmount(cmd.Max)
	if err != nil {
		return nil, err
	}

	w.SetTicketMaxPrice(amt)
	return nil, nil
}

// setTicketVoteBits sets the per-ticket voteBits for a given ticket from
// a ticket hash. Missing tickets return an error.
func setTicketVoteBits(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.SetTicketVoteBitsCmd)
	ticket, err := chainhash.NewHashFromStr(cmd.TxHash)
	if err != nil {
		return nil, err
	}

	err = w.StakeMgr.UpdateSStxVoteBits(ticket, cmd.VoteBits)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// setBalanceToMaintain sets the balance to maintain for automatic ticket pur.
func setBalanceToMaintain(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.SetBalanceToMaintainCmd)

	// Check that amount is not negative.
	if cmd.Balance < 0 {
		return nil, ErrNeedPositiveAmount
	}
	// XXX this is a temporary check until proper checks are added to
	// dcrutil.NewAmount() to avoid overflows
	if cmd.Balance > dcrutil.Amount(dcrutil.MaxAmount).ToCoin() {
		return nil, ErrNeedBelowMaxAmount
	}

	balance, err := dcrutil.NewAmount(cmd.Balance)
	if err != nil {
		return nil, err
	}

	w.SetBalanceToMaintain(balance)

	// A boolean true result is returned upon success.
	return nil, nil
}

// setTicketFee sets the transaction fee per kilobyte added to tickets.
func setTicketFee(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.SetTicketFeeCmd)

	// Check that amount is not negative.
	if cmd.Fee < 0 {
		return nil, ErrNeedPositiveAmount
	}

	incr, err := dcrutil.NewAmount(cmd.Fee)
	if err != nil {
		return nil, err
	}
	w.SetTicketFeeIncrement(incr)

	// A boolean true result is returned upon success.
	return true, nil
}

// setTxFee sets the transaction fee per kilobyte added to transactions.
func setTxFee(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.SetTxFeeCmd)

	// Check that amount is not negative.
	if cmd.Amount < 0 {
		return nil, ErrNeedPositiveAmount
	}

	relayFee, err := dcrutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, err
	}
	w.SetRelayFee(relayFee)

	// A boolean true result is returned upon success.
	return true, nil
}

// signMessage signs the given message with the private key for the given
// address
func signMessage(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.SignMessageCmd)

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
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInvalidAddressOrKey,
			Message: msg,
		}
	}
	privKey, err := pka.PrivKey()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, "Decred Signed Message:\n")
	wire.WriteVarString(&buf, 0, cmd.Message)
	messageHash := chainhash.HashFuncB(buf.Bytes())
	pkCast, ok := privKey.(*secp256k1.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Unable to create secp256k1.PrivateKey" +
			"from chainec.PrivateKey")
	}
	sig, err := secp256k1.SignCompact(secp256k1.S256(), pkCast, messageHash, true)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

// signRawTransaction handles the signrawtransaction command.
func signRawTransaction(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.SignRawTransactionCmd)

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
	case "ssgen": // Special case of SigHashAll
		hashType = txscript.SigHashAll
	case "ssrtx": // Special case of SigHashAll
		hashType = txscript.SigHashAll
	default:
		e := errors.New("Invalid sighash parameter")
		return nil, InvalidParameterError{e}
	}

	// TODO: really we probably should look these up with dcrd anyway to
	// make sure that they match the blockchain if present.
	inputs := make(map[wire.OutPoint][]byte)
	scripts := make(map[string][]byte)
	var cmdInputs []dcrjson.RawTxInput
	if cmd.Inputs != nil {
		cmdInputs = *cmd.Inputs
	}
	for _, rti := range cmdInputs {
		inputSha, err := chainhash.NewHashFromStr(rti.Txid)
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
		// Note that redeemScript is NOT only the redeemscript
		// required to be appended to the end of a P2SH output
		// spend, but the entire signature script for spending
		// *any* outpoint with dummy values inserted into it
		// that can later be replacing by txscript's sign.
		if cmd.PrivKeys != nil && len(*cmd.PrivKeys) != 0 {
			redeemScript, err := decodeHexStr(rti.RedeemScript)
			if err != nil {
				return nil, err
			}

			addr, err := dcrutil.NewAddressScriptHash(redeemScript,
				w.ChainParams())
			if err != nil {
				return nil, DeserializationError{err}
			}
			scripts[addr.String()] = redeemScript
		}
		inputs[wire.OutPoint{
			Hash:  *inputSha,
			Tree:  rti.Tree,
			Index: rti.Vout,
		}] = script
	}

	for _, input := range tx.TxIn {
		if txscript.IsMultisigSigScript(input.SignatureScript) {
			rs, err :=
				txscript.MultisigRedeemScriptFromScriptSig(
					input.SignatureScript)
			if err != nil {
				return nil, err
			}

			class, addrs, _, err := txscript.ExtractPkScriptAddrs(
				txscript.DefaultScriptVersion, rs, w.ChainParams())
			if err != nil {
				// Non-standard outputs are skipped.
				continue
			}
			if class != txscript.MultiSigTy {
				// This should never happen, but be paranoid.
				continue
			}

			isRelevant := false
			for _, addr := range addrs {
				_, err := w.Manager.Address(addr)
				if err == nil {
					isRelevant = true
					err = w.Manager.MarkUsed(addr)
					if err != nil {
						return nil, err
					}
					log.Debugf("Marked address %v used", addr)
				} else {
					// Missing addresses are skipped.  Other errors should
					// be propagated.
					if !waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
						return nil, err
					}
				}
			}
			// Add the script to the script databases.
			if isRelevant {
				err = w.TxStore.InsertTxScript(rs)
				if err != nil {
					return nil, err
				}

				// Get current block's height and hash.
				bs, err := chainClient.BlockStamp()
				if err != nil {
					return nil, err
				}
				mscriptaddr, err := w.Manager.ImportScript(rs, bs)
				if err != nil {
					switch {
					// Don't care if it's already there.
					case waddrmgr.IsError(err, waddrmgr.ErrDuplicateAddress):
						break
					case waddrmgr.IsError(err, waddrmgr.ErrLocked):
						log.Debugf("failed to attempt script importation " +
							"of incoming tx because addrmgr was locked")
						break
					default:
						return nil, err
					}
				} else {
					// This is the first time seeing this script address
					// belongs to us, so do a rescan and see if there are
					// any other outputs to this address.
					job := &wallet.RescanJob{
						Addrs:     []dcrutil.Address{mscriptaddr.Address()},
						OutPoints: nil,
						BlockStamp: waddrmgr.BlockStamp{
							Height: 0,
							Hash:   *w.ChainParams().GenesisHash,
						},
					}

					// Submit rescan job and log when the import has completed.
					// Do not block on finishing the rescan.  The rescan success
					// or failure is logged elsewhere, and the channel is not
					// required to be read, so discard the return value.
					_ = w.SubmitRescan(job)
				}
			}
		}
	}

	// Now we go and look for any inputs that we were not provided by
	// querying dcrd with getrawtransaction. We queue up a bunch of async
	// requests and will wait for replies after we have checked the rest of
	// the arguments.
	requested := make(map[wire.OutPoint]dcrrpcclient.FutureGetTxOutResult)
	for i, txIn := range tx.TxIn {
		// We don't need the first input of a stakebase tx, as it's garbage
		// anyway.
		if i == 0 && *cmd.Flags == "ssgen" {
			continue
		}

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
	var keys map[string]*dcrutil.WIF
	if cmd.PrivKeys != nil {
		keys = make(map[string]*dcrutil.WIF)

		for _, key := range *cmd.PrivKeys {
			wif, err := dcrutil.DecodeWIF(key)
			if err != nil {
				return nil, DeserializationError{err}
			}

			if !wif.IsForNet(w.ChainParams()) {
				s := "key network doesn't match wallet's"
				return nil, DeserializationError{errors.New(s)}
			}

			var addr dcrutil.Address
			switch wif.DSA() {
			case chainec.ECTypeSecp256k1:
				addr, err = dcrutil.NewAddressSecpPubKey(wif.SerializePubKey(),
					w.ChainParams())
				if err != nil {
					return nil, DeserializationError{err}
				}
			case chainec.ECTypeEdwards:
				addr, err = dcrutil.NewAddressEdwardsPubKey(
					wif.SerializePubKey(),
					w.ChainParams())
				if err != nil {
					return nil, DeserializationError{err}
				}
			case chainec.ECTypeSecSchnorr:
				addr, err = dcrutil.NewAddressSecSchnorrPubKey(
					wif.SerializePubKey(),
					w.ChainParams())
				if err != nil {
					return nil, DeserializationError{err}
				}
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

	signErrors := make([]dcrjson.SignRawTransactionError, 0, len(signErrs))
	for _, e := range signErrs {
		input := tx.TxIn[e.InputIndex]
		signErrors = append(signErrors, dcrjson.SignRawTransactionError{
			TxID:      input.PreviousOutPoint.Hash.String(),
			Vout:      input.PreviousOutPoint.Index,
			ScriptSig: hex.EncodeToString(input.SignatureScript),
			Sequence:  input.Sequence,
			Error:     e.Error.Error(),
		})
	}

	return dcrjson.SignRawTransactionResult{
		Hex:      hex.EncodeToString(buf.Bytes()),
		Complete: len(signErrors) == 0,
		Errors:   signErrors,
	}, nil
}

// signRawTransactions handles the signrawtransactions command.
func signRawTransactions(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*dcrjson.SignRawTransactionsCmd)

	// Sign each transaction sequentially and record the results.
	// Error out if we meet some unexpected failure.
	results := make([]dcrjson.SignRawTransactionResult,
		len(cmd.RawTxs), len(cmd.RawTxs))
	for i, etx := range cmd.RawTxs {
		flagAll := "ALL"
		srtc := &dcrjson.SignRawTransactionCmd{
			RawTx: etx,
			Flags: &flagAll,
		}
		result, err := signRawTransaction(srtc, w, chainClient)
		if err != nil {
			return nil, err
		}

		tResult := result.(dcrjson.SignRawTransactionResult)
		results[i] = tResult
	}

	// If the user wants completed transactions to be automatically send,
	// do that now. Otherwise, construct the slice and return it.
	toReturn := make([]dcrjson.SignedTransaction,
		len(cmd.RawTxs), len(cmd.RawTxs))

	if *cmd.Send {
		for i, result := range results {
			if result.Complete {
				// Slow/mem hungry because of the deserializing.
				serializedTx, err := decodeHexStr(result.Hex)
				if err != nil {
					return nil, err
				}
				msgTx := wire.NewMsgTx()
				err = msgTx.Deserialize(bytes.NewBuffer(serializedTx))
				if err != nil {
					e := errors.New("TX decode failed")
					return nil, DeserializationError{e}
				}
				sent := false
				hashStr := ""
				hash, err := chainClient.SendRawTransaction(msgTx, w.AllowHighFees)
				// If sendrawtransaction errors out (blockchain rule
				// issue, etc), continue onto the next transaction.
				if err == nil {
					sent = true
					hashStr = hash.String()
				}

				st := dcrjson.SignedTransaction{
					SigningResult: result,
					Sent:          sent,
					TxHash:        &hashStr,
				}
				toReturn[i] = st
			} else {
				st := dcrjson.SignedTransaction{
					SigningResult: result,
					Sent:          false,
					TxHash:        nil,
				}
				toReturn[i] = st
			}
		}
	} else { // Just return the results.
		for i, result := range results {
			st := dcrjson.SignedTransaction{
				SigningResult: result,
				Sent:          false,
				TxHash:        nil,
			}
			toReturn[i] = st
		}
	}

	return &dcrjson.SignRawTransactionsResult{Results: toReturn}, nil
}

// validateAddress handles the validateaddress command.
func validateAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.ValidateAddressCmd)

	result := dcrjson.ValidateAddressWalletResult{}
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
		pubKeyBytes, err := hex.DecodeString(result.PubKey)
		if err != nil {
			return nil, err
		}
		pubKeyAddr, err := dcrutil.NewAddressSecpPubKey(pubKeyBytes,
			w.ChainParams())
		if err != nil {
			return nil, err
		}
		result.PubKeyAddr = pubKeyAddr.String()

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
			txscript.DefaultScriptVersion, script, w.ChainParams())
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

// verifyMessage handles the verifymessage command by verifying the provided
// compact signature for the given address and message.
func verifyMessage(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.VerifyMessageCmd)

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
	wire.WriteVarString(&buf, 0, "Decred Signed Message:\n")
	wire.WriteVarString(&buf, 0, cmd.Message)
	expectedMessageHash := chainhash.HashFuncB(buf.Bytes())
	pk, wasCompressed, err := chainec.Secp256k1.RecoverCompact(sig,
		expectedMessageHash)
	if err != nil {
		return nil, err
	}

	// Decred: This should actually be a universalized constructor.
	pkDcr := chainec.Secp256k1.NewPublicKey(pk.GetX(), pk.GetY())

	var serializedPubKey []byte
	if wasCompressed {
		serializedPubKey = pkDcr.SerializeCompressed()
	} else {
		serializedPubKey = pkDcr.SerializeUncompressed()
	}
	// Verify that the signed-by address matches the given address
	switch checkAddr := addr.(type) {
	case *dcrutil.AddressPubKeyHash: // ok
		return bytes.Equal(dcrutil.Hash160(serializedPubKey),
			checkAddr.Hash160()[:]), nil
	case *dcrutil.AddressSecpPubKey: // ok
		return string(serializedPubKey) == checkAddr.String(), nil
	default:
		return nil, errors.New("address type not supported")
	}
}

// walletInfo gets the current information about the wallet. If the daemon
// is connected and fails to ping, the function will still return that the
// daemon is disconnected.
func walletInfo(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	connected := !(chainClient.Disconnected())
	if connected {
		err := chainClient.Ping()
		if err != nil {
			log.Warnf("Ping failed on connected daemon client: %s", err.Error())
			connected = false
		}
	}

	unlocked := !(w.Locked())
	fi := w.RelayFee()
	tfi := w.TicketFeeIncrement()
	tmp := w.GetTicketMaxPrice()
	btm := w.BalanceToMaintain()
	sm := w.Generate()

	return &dcrjson.WalletInfoResult{
		DaemonConnected:   connected,
		Unlocked:          unlocked,
		TxFee:             fi.ToCoin(),
		TicketFee:         tfi.ToCoin(),
		TicketMaxPrice:    tmp.ToCoin(),
		BalanceToMaintain: btm.ToCoin(),
		StakeMining:       sm,
	}, nil
}

// walletIsLocked handles the walletislocked extension request by
// returning the current lock state (false for unlocked, true for locked)
// of an account.
func walletIsLocked(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return w.Locked(), nil
}

// walletLock handles a walletlock request by locking the all account
// wallets, returning an error if any wallet is not encrypted (for example,
// a watching-only wallet).
func walletLock(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	w.Lock()
	return nil, nil
}

// walletPassphrase responds to the walletpassphrase request by unlocking
// the wallet.  The decryption key is saved in the wallet until timeout
// seconds expires, after which the wallet is locked.
func walletPassphrase(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.WalletPassphraseCmd)

	timeout := time.Second * time.Duration(cmd.Timeout)
	var unlockAfter <-chan time.Time
	if timeout != 0 {
		unlockAfter = time.After(timeout)
	}
	err := w.Unlock([]byte(cmd.Passphrase), unlockAfter)
	return nil, err
}

// walletPassphraseChange responds to the walletpassphrasechange request
// by unlocking all accounts with the provided old passphrase, and
// re-encrypting each private key with an AES key derived from the new
// passphrase.
//
// If the old passphrase is correct and the passphrase is changed, all
// wallets will be immediately locked.
func walletPassphraseChange(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*dcrjson.WalletPassphraseChangeCmd)

	err := w.ChangePassphrase([]byte(cmd.OldPassphrase),
		[]byte(cmd.NewPassphrase))
	if waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase) {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCWalletPassphraseIncorrect,
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
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCDecodeHexString,
			Message: "Hex string decode failed: " + err.Error(),
		}
	}
	return decoded, nil
}
