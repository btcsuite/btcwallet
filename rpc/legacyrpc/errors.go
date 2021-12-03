// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacyrpc

import (
	"errors"

	"github.com/btcsuite/btcd/btcjson"
)

// TODO(jrick): There are several error paths which 'replace' various errors
// with a more appropriate error from the btcjson package.  Create a map of
// these replacements so they can be handled once after an RPC handler has
// returned and before the error is marshaled.

// Error types to simplify the reporting of specific categories of
// errors, and their *btcjson.RPCError creation.
type (
	// DeserializationError describes a failed deserializaion due to bad
	// user input.  It corresponds to btcjson.ErrRPCDeserialization.
	DeserializationError struct {
		error
	}

	// InvalidParameterError describes an invalid parameter passed by
	// the user.  It corresponds to btcjson.ErrRPCInvalidParameter.
	InvalidParameterError struct {
		error
	}

	// ParseError describes a failed parse due to bad user input.  It
	// corresponds to btcjson.ErrRPCParse.
	ParseError struct {
		error
	}
)

// Errors variables that are defined once here to avoid duplication below.
var (
	ErrNeedPositiveAmount = InvalidParameterError{
		errors.New("amount must be positive"),
	}

	ErrNeedPositiveMinconf = InvalidParameterError{
		errors.New("minconf must be positive"),
	}

	ErrAddressNotInWallet = btcjson.RPCError{
		Code:    btcjson.ErrRPCWallet,
		Message: "address not found in wallet",
	}

	ErrAddressTypeUnknown = btcjson.RPCError{
		Code:    btcjson.ErrRPCWalletInvalidAddressType,
		Message: "unknown address type",
	}

	ErrAccountNameNotFound = btcjson.RPCError{
		Code:    btcjson.ErrRPCWalletInvalidAccountName,
		Message: "account name not found",
	}

	ErrUnloadedWallet = btcjson.RPCError{
		Code:    btcjson.ErrRPCWallet,
		Message: "Request requires a wallet but wallet has not loaded yet",
	}

	ErrWalletUnlockNeeded = btcjson.RPCError{
		Code:    btcjson.ErrRPCWalletUnlockNeeded,
		Message: "Enter the wallet passphrase with walletpassphrase first",
	}

	ErrNotImportedAccount = btcjson.RPCError{
		Code:    btcjson.ErrRPCWallet,
		Message: "imported addresses must belong to the imported account",
	}

	ErrNoTransactionInfo = btcjson.RPCError{
		Code:    btcjson.ErrRPCNoTxInfo,
		Message: "No information for transaction",
	}

	ErrReservedAccountName = btcjson.RPCError{
		Code:    btcjson.ErrRPCInvalidParameter,
		Message: "Account name is reserved by RPC server",
	}
)
