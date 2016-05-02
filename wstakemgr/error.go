/*
 * Copyright (c) 2015 Conformal Systems LLC <info@conformal.com>
 * Copyright (c) 2015 The Decred developers
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

package wstakemgr

import "fmt"

// ErrorCode identifies a kind of error.
type ErrorCode int

// These constants are used to identify a specific StakeStoreError.
const (
	// ErrDatabase indicates a generic error with the underlying database.
	// When this error code is set, the Err field of the TxStoreError will
	// be set to the underlying error returned from the database.
	ErrDatabase ErrorCode = iota

	// ErrInput indicates there was a problem with the input given.
	ErrInput

	// ErrNoExist indicates that the specified database does not exist.
	ErrNoExist

	// ErrAlreadyExists indicates that the specified database already exists.
	ErrAlreadyExists

	// ErrSStxNotFound indicates that the requested tx hash is not known to
	// the SStx store.
	ErrSStxNotFound

	// ErrSSGensNotFound indicates that the requested tx hash is not known to
	// the SSGens store.
	ErrSSGensNotFound

	// ErrSSRtxsNotFound indicates that the requested tx hash is not known to
	// the SSRtxs store.
	ErrSSRtxsNotFound

	// ErrPoolUserTicketsNotFound indicates that the requested script hash
	// is not known to the meta bucket.
	ErrPoolUserTicketsNotFound

	// ErrPoolUserInvalTcktsNotFound indicates that the requested script hash
	// is not known to the meta bucket.
	ErrPoolUserInvalTcktsNotFound

	// ErrBadPoolUserAddr indicates that the passed pool user address was
	// faulty.
	ErrBadPoolUserAddr

	// ErrStoreClosed indicates that a function was called after the stake
	// store was closed.
	ErrStoreClosed
)

// Map of ErrorCode values back to their constant names for pretty printing.
var errorCodeStrings = map[ErrorCode]string{
	ErrDatabase:                   "ErrDatabase",
	ErrInput:                      "ErrInput",
	ErrNoExist:                    "ErrNoExist",
	ErrAlreadyExists:              "ErrAlreadyExists",
	ErrSStxNotFound:               "ErrSStxNotFound",
	ErrSSGensNotFound:             "ErrSSGensNotFound",
	ErrSSRtxsNotFound:             "ErrSSRtxsNotFound",
	ErrPoolUserTicketsNotFound:    "ErrPoolUserTicketsNotFound",
	ErrPoolUserInvalTcktsNotFound: "ErrPoolUserInvalTcktsNotFound",
	ErrBadPoolUserAddr:            "ErrBadPoolUserAddr",
	ErrStoreClosed:                "ErrStoreClosed",
}

// String returns the ErrorCode as a human-readable name.
func (e ErrorCode) String() string {
	if s := errorCodeStrings[e]; s != "" {
		return s
	}
	return fmt.Sprintf("Unknown ErrorCode (%d)", int(e))
}

// StakeStoreError provides a single type for errors that can happen during stake
// store operation. It is similar to waddrmgr.ManagerError.
type StakeStoreError struct {
	ErrorCode   ErrorCode // Describes the kind of error
	Description string    // Human readable description of the issue
	Err         error     // Underlying error
}

// Error satisfies the error interface and prints human-readable errors.
func (e StakeStoreError) Error() string {
	if e.Err != nil {
		return e.Description + ": " + e.Err.Error()
	}
	return e.Description
}

// txstoreError creates a TxStoreError given a set of arguments.
func stakeStoreError(c ErrorCode, desc string, err error) StakeStoreError {
	return StakeStoreError{ErrorCode: c, Description: desc, Err: err}
}
