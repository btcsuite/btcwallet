/*
 * Copyright (c) 2013-2015 The btcsuite developers
 * Copyright (c) 2016 The Decred developers
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

package legacyrpc

import (
	"errors"

	"github.com/decred/dcrd/dcrjson"
)

// TODO(jrick): There are several error paths which 'replace' various errors
// with a more appropiate error from the dcrjson package.  Create a map of
// these replacements so they can be handled once after an RPC handler has
// returned and before the error is marshaled.

// Error types to simplify the reporting of specific categories of
// errors, and their *dcrjson.RPCError creation.
type (
	// DeserializationError describes a failed deserializaion due to bad
	// user input.  It cooresponds to dcrjson.ErrRPCDeserialization.
	DeserializationError struct {
		error
	}

	// InvalidParameterError describes an invalid parameter passed by
	// the user.  It cooresponds to dcrjson.ErrRPCInvalidParameter.
	InvalidParameterError struct {
		error
	}

	// ParseError describes a failed parse due to bad user input.  It
	// cooresponds to dcrjson.ErrRPCParse.
	ParseError struct {
		error
	}
)

// Errors variables that are defined once here to avoid duplication below.
var (
	ErrNeedPositiveAmount = InvalidParameterError{
		errors.New("amount must be positive"),
	}

	ErrNeedBelowMaxAmount = InvalidParameterError{
		errors.New("amount must be below max amount"),
	}

	ErrNeedPositiveSpendLimit = InvalidParameterError{
		errors.New("spend limit must be positive"),
	}

	ErrNeedPositiveMinconf = InvalidParameterError{
		errors.New("minconf must be positive"),
	}

	ErrAddressNotInWallet = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCWallet,
		Message: "address not found in wallet",
	}

	ErrAccountNameNotFound = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCWalletInvalidAccountName,
		Message: "account name not found",
	}

	ErrUnloadedWallet = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCWallet,
		Message: "Request requires a wallet but wallet has not loaded yet",
	}

	ErrWalletUnlockNeeded = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCWalletUnlockNeeded,
		Message: "Enter the wallet passphrase with walletpassphrase first",
	}

	ErrNotImportedAccount = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCWallet,
		Message: "imported addresses must belong to the imported account",
	}

	ErrNoTransactionInfo = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCNoTxInfo,
		Message: "No information for transaction",
	}

	ErrReservedAccountName = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCInvalidParameter,
		Message: "Account name is reserved by RPC server",
	}

	ErrMainNetSafety = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCWallet,
		Message: "RPC function disabled on MainNet wallets for security purposes",
	}
)
