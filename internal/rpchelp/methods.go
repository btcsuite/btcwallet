// Copyright (c) 2015 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//+build !generate

package rpchelp

import "github.com/decred/dcrd/dcrjson"

// Common return types.
var (
	returnsBool        = []interface{}{(*bool)(nil)}
	returnsNumber      = []interface{}{(*float64)(nil)}
	returnsString      = []interface{}{(*string)(nil)}
	returnsStringArray = []interface{}{(*[]string)(nil)}
	returnsLTRArray    = []interface{}{(*[]dcrjson.ListTransactionsResult)(nil)}
)

// Methods contains all methods and result types that help is generated for,
// for every locale.
var Methods = []struct {
	Method      string
	ResultTypes []interface{}
}{
	{"accountaddressindex", []interface{}{(*int)(nil)}},
	{"accountfetchaddresses", []interface{}{(*dcrjson.AccountFetchAddressesResult)(nil)}},
	{"accountsyncaddressindex", nil},
	{"addmultisigaddress", returnsString},
	{"consolidate", returnsString},
	{"createmultisig", []interface{}{(*dcrjson.CreateMultiSigResult)(nil)}},
	{"dumpprivkey", returnsString},
	{"getaccount", returnsString},
	{"getaccountaddress", returnsString},
	{"getaddressesbyaccount", returnsStringArray},
	{"getbalance", append(returnsNumber, returnsNumber[0])},
	{"getbestblockhash", returnsString},
	{"getblockcount", returnsNumber},
	{"getinfo", []interface{}{(*dcrjson.InfoWalletResult)(nil)}},
	{"getgenerate", returnsBool},
	{"getmasterpubkey", []interface{}{(*string)(nil)}},
	{"getmultisigoutinfo", []interface{}{(*dcrjson.GetMultisigOutInfoResult)(nil)}},
	{"getseed", []interface{}{(*string)(nil)}},
	{"getnewaddress", returnsString},
	{"getrawchangeaddress", returnsString},
	{"getreceivedbyaccount", returnsNumber},
	{"getreceivedbyaddress", returnsNumber},
	{"gettickets", []interface{}{(*dcrjson.GetTicketsResult)(nil)}},
	{"getticketmaxprice", returnsNumber},
	{"gettransaction", []interface{}{(*dcrjson.GetTransactionResult)(nil)}},
	{"help", append(returnsString, returnsString[0])},
	{"importprivkey", nil},
	{"importscript", nil},
	{"keypoolrefill", nil},
	{"listaccounts", []interface{}{(*map[string]float64)(nil)}},
	{"listlockunspent", []interface{}{(*[]dcrjson.TransactionInput)(nil)}},
	{"listreceivedbyaccount", []interface{}{(*[]dcrjson.ListReceivedByAccountResult)(nil)}},
	{"listreceivedbyaddress", []interface{}{(*[]dcrjson.ListReceivedByAddressResult)(nil)}},
	{"listsinceblock", []interface{}{(*dcrjson.ListSinceBlockResult)(nil)}},
	{"listtransactions", returnsLTRArray},
	{"listunspent", []interface{}{(*dcrjson.ListUnspentResult)(nil)}},
	{"lockunspent", returnsBool},
	{"redeemmultisigout", []interface{}{(*dcrjson.RedeemMultiSigOutResult)(nil)}},
	{"redeemmultisigouts", []interface{}{(*dcrjson.RedeemMultiSigOutResult)(nil)}},
	{"sendfrom", returnsString},
	{"sendmany", returnsString},
	{"sendtoaddress", returnsString},
	{"sendtomultisig", returnsString},
	{"setgenerate", nil},
	{"setticketmaxprice", nil},
	{"settxfee", returnsBool},
	{"signmessage", returnsString},
	{"signrawtransaction", []interface{}{(*dcrjson.SignRawTransactionResult)(nil)}},
	{"signrawtransactions", []interface{}{(*dcrjson.SignRawTransactionsResult)(nil)}},
	{"validateaddress", []interface{}{(*dcrjson.ValidateAddressWalletResult)(nil)}},
	{"verifymessage", returnsBool},
	{"walletlock", nil},
	{"walletpassphrase", nil},
	{"walletpassphrasechange", nil},
	{"createnewaccount", nil},
	{"exportwatchingwallet", returnsString},
	{"getbestblock", []interface{}{(*dcrjson.GetBestBlockResult)(nil)}},
	{"getunconfirmedbalance", returnsNumber},
	{"listaddresstransactions", returnsLTRArray},
	{"listalltransactions", returnsLTRArray},
	{"renameaccount", nil},
	{"walletislocked", returnsBool},
	{"walletinfo", []interface{}{(*dcrjson.WalletInfoResult)(nil)}},

	// TODO Alphabetize
	{"purchaseticket", returnsString},
	{"sendtossrtx", returnsString},
	{"sendtosstx", returnsString},
	{"sendtossgen", returnsString},
	{"getticketvotebits", []interface{}{(*dcrjson.GetTicketVoteBitsResult)(nil)}},
	{"getticketsvotebits", []interface{}{(*dcrjson.GetTicketsVoteBitsResult)(nil)}},
	{"setticketvotebits", nil},
	{"getstakeinfo", []interface{}{(*dcrjson.GetStakeInfoResult)(nil)}},
	{"getticketfee", returnsNumber},
	{"setticketfee", returnsBool},
	{"getwalletfee", returnsNumber},
	{"addticket", nil},
	{"listscripts", []interface{}{(*dcrjson.ListScriptsResult)(nil)}},
	{"stakepooluserinfo", []interface{}{(*dcrjson.StakePoolUserInfoResult)(nil)}},
	{"setbalancetomaintain", returnsBool},
	{"getbalancetomaintain", returnsBool},
	{"ticketsforaddress", returnsBool},
}

// HelpDescs contains the locale-specific help strings along with the locale.
var HelpDescs = []struct {
	Locale   string // Actual locale, e.g. en_US
	GoLocale string // Locale used in Go names, e.g. EnUS
	Descs    map[string]string
}{
	{"en_US", "EnUS", helpDescsEnUS}, // helpdescs_en_US.go
}
