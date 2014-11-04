/*
 * Copyright (c) 2014 Conformal Systems LLC <info@conformal.com>
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

package votingpool

import "fmt"

// ErrorCode identifies a kind of error
type ErrorCode int

const (
	// ErrInputSelection indicates an error in the input selection
	// algorithm.
	ErrInputSelection ErrorCode = iota

	// ErrWithdrawalProcessing indicates an internal error when processing a
	// withdrawal request.
	ErrWithdrawalProcessing

	// ErrUnknownPubKey indicates a pubkey that does not belong to a given
	// series.
	ErrUnknownPubKey

	// ErrSeriesSerialization indicates that an error occurred while
	// serializing or deserializing one or more series for storing into
	// the database.
	ErrSeriesSerialization

	// ErrSeriesVersion indicates that we've been asked to deal with a series
	// whose version is unsupported
	ErrSeriesVersion

	// ErrSeriesNotExists indicates that an attempt has been made to access
	// a series that does not exist.
	ErrSeriesNotExists

	// ErrSeriesAlreadyExists indicates that an attempt has been made to
	// create a series that already exists.
	ErrSeriesAlreadyExists

	// ErrSeriesAlreadyEmpowered indicates that an already empowered series
	// was used where a not empowered one was expected.
	ErrSeriesAlreadyEmpowered

	// ErrSeriesNotActive indicates that an active series was needed but the
	// selected one is not.
	ErrSeriesNotActive

	// ErrKeyIsPrivate indicates that a private key was used where a public
	// one was expected.
	ErrKeyIsPrivate

	// ErrKeyIsPublic indicates that a public key was used where a private
	// one was expected.
	ErrKeyIsPublic

	// ErrKeyNeuter indicates a problem when trying to neuter a private key.
	ErrKeyNeuter

	// ErrKeyMismatch indicates that the key is not the expected one.
	ErrKeyMismatch

	// ErrKeysPrivatePublicMismatch indicates that the number of private and
	// public keys is not the same.
	ErrKeysPrivatePublicMismatch

	// ErrKeyDuplicate indicates that a key is duplicated.
	ErrKeyDuplicate

	// ErrTooFewPublicKeys indicates that a required minimum of public
	// keys was not met.
	ErrTooFewPublicKeys

	// ErrPoolAlreadyExists indicates that an attempt has been made to
	// create a voting pool that already exists.
	ErrPoolAlreadyExists

	// ErrPoolNotExists indicates that an attempt has been made to access
	// a voting pool that does not exist.
	ErrPoolNotExists

	// ErrScriptCreation indicates that the creation of a deposit script
	// failed.
	ErrScriptCreation

	// ErrTooManyReqSignatures indicates that too many required
	// signatures are requested.
	ErrTooManyReqSignatures

	// ErrInvalidBranch indicates that the given branch number is not valid
	// for a given set of public keys.
	ErrInvalidBranch

	// ErrInvalidValue indicates that the value of a given function argument
	// is invalid.
	ErrInvalidValue

	// ErrDatabase indicates an error with the underlying database.
	ErrDatabase

	// ErrKeyChain indicates an error with the key chain typically either
	// due to the inability to create an extended key or deriving a child
	// extended key.
	ErrKeyChain

	// ErrCrypto indicates an error with the cryptography related operations
	// such as decrypting or encrypting data, parsing an EC public key,
	// or deriving a secret key from a password.
	ErrCrypto

	// ErrRawSigning indicates an error in the process of generating raw
	// signatures for a transaction input.
	ErrRawSigning

	// ErrPreconditionNotMet indicates a programming error since a
	// preconditon has not been met.
	ErrPreconditionNotMet

	// ErrTxSigning indicates an error when signing a transaction.
	ErrTxSigning

	// ErrSeriesIDNotSequential indicates an attempt to create a series with
	// an ID that is not sequantial.
	ErrSeriesIDNotSequential

	// ErrInvalidScriptHash indicates an invalid P2SH.
	ErrInvalidScriptHash

	// ErrWithdrawFromUnusedAddr indicates an attempt to withdraw funds from
	// an address which has not been used before.
	ErrWithdrawFromUnusedAddr

	// ErrSeriesIDInvalid indicates an attempt to create a series with an
	// invalid ID.
	ErrSeriesIDInvalid

	// lastErr is used for testing, making it possible to iterate over
	// the error codes in order to check that they all have proper
	// translations in errorCodeStrings.
	lastErr
)

// Map of ErrorCode values back to their constant names for pretty printing.
var errorCodeStrings = map[ErrorCode]string{
	ErrInputSelection:            "ErrInputSelection",
	ErrWithdrawalProcessing:      "ErrWithdrawalProcessing",
	ErrUnknownPubKey:             "ErrUnknownPubKey",
	ErrSeriesSerialization:       "ErrSeriesSerialization",
	ErrSeriesVersion:             "ErrSeriesVersion",
	ErrSeriesNotExists:           "ErrSeriesNotExists",
	ErrSeriesAlreadyExists:       "ErrSeriesAlreadyExists",
	ErrSeriesAlreadyEmpowered:    "ErrSeriesAlreadyEmpowered",
	ErrSeriesIDNotSequential:     "ErrSeriesIDNotSequential",
	ErrSeriesIDInvalid:           "ErrSeriesIDInvalid",
	ErrSeriesNotActive:           "ErrSeriesNotActive",
	ErrKeyIsPrivate:              "ErrKeyIsPrivate",
	ErrKeyIsPublic:               "ErrKeyIsPublic",
	ErrKeyNeuter:                 "ErrKeyNeuter",
	ErrKeyMismatch:               "ErrKeyMismatch",
	ErrKeysPrivatePublicMismatch: "ErrKeysPrivatePublicMismatch",
	ErrKeyDuplicate:              "ErrKeyDuplicate",
	ErrTooFewPublicKeys:          "ErrTooFewPublicKeys",
	ErrPoolAlreadyExists:         "ErrPoolAlreadyExists",
	ErrPoolNotExists:             "ErrPoolNotExists",
	ErrScriptCreation:            "ErrScriptCreation",
	ErrTooManyReqSignatures:      "ErrTooManyReqSignatures",
	ErrInvalidBranch:             "ErrInvalidBranch",
	ErrInvalidValue:              "ErrInvalidValue",
	ErrDatabase:                  "ErrDatabase",
	ErrKeyChain:                  "ErrKeyChain",
	ErrCrypto:                    "ErrCrypto",
	ErrRawSigning:                "ErrRawSigning",
	ErrPreconditionNotMet:        "ErrPreconditionNotMet",
	ErrTxSigning:                 "ErrTxSigning",
	ErrInvalidScriptHash:         "ErrInvalidScriptHash",
	ErrWithdrawFromUnusedAddr:    "ErrWithdrawFromUnusedAddr",
}

// String returns the ErrorCode as a human-readable name.
func (e ErrorCode) String() string {
	if s := errorCodeStrings[e]; s != "" {
		return s
	}
	return fmt.Sprintf("Unknown ErrorCode (%d)", int(e))
}

// Error is a typed error for all errors arising during the
// operation of the voting pool.
type Error struct {
	ErrorCode   ErrorCode // Describes the kind of error
	Description string    // Human readable description of the issue
	Err         error     // Underlying error
}

// Error satisfies the error interface and prints human-readable errors.
func (e Error) Error() string {
	if e.Err != nil {
		return e.Description + ": " + e.Err.Error()
	}
	return e.Description
}

// newError creates a new Error.
func newError(c ErrorCode, desc string, err error) Error {
	return Error{ErrorCode: c, Description: desc, Err: err}
}
